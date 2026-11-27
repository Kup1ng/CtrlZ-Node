package agent_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// labPart is a part that records what the agent hands it and fills the Heartbeat
// from atomics-free state guarded by its own lock, as a part may.
type labPart struct {
	mu      sync.Mutex
	configs []*hubv1.NodeConfig
	ran     chan struct{}
	once    sync.Once
}

func (p *labPart) Run(ctx context.Context) { p.once.Do(func() { close(p.ran) }); <-ctx.Done() }
func (p *labPart) Config(nc *hubv1.NodeConfig) {
	p.mu.Lock()
	p.configs = append(p.configs, nc)
	p.mu.Unlock()
}
func (p *labPart) Fragments() bool { return true }
func (p *labPart) Heartbeat(hb *hubv1.Heartbeat) {
	hb.Proxy = &hubv1.ProxyState{Listening: true, OpenConnections: 3}
}
func (p *labPart) got() []*hubv1.NodeConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*hubv1.NodeConfig(nil), p.configs...)
}

// The parts get the NodeConfig with its Xray fragments; dns and the disk get it
// without them (p4b-proxy 7.5, finding 15); the Heartbeat carries the parts' fields
// and the faults they raised.
func TestPartsGetFragmentsAndNobodyElseDoes(t *testing.T) {
	secret := []byte(`{"outbounds":[{"settings":{"password":"fragment-secret-for-the-test"}}]}`)
	p := &labPart{ran: make(chan struct{})}
	faults := agent.NewFaults()
	l := newLab(t, func(l *lab) { l.cfg.Parts, l.cfg.Faults = []agent.Part{p}, faults })
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	<-p.ran
	faults.Set(hubv1.NodeFault_NODE_FAULT_XRAY_DOWN, true)

	c := testNodeConfig(6, make([]byte, 16))
	c.XrayConfigs = []*hubv1.XrayConfig{{Id: bytes.Repeat([]byte{1}, 16), Location: 2, Tag: "exit-a", Priority: 1, Enabled: true, FragmentJson: secret}}
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: c}})

	eventually(t, "the part got the config", func() bool { return len(p.got()) == 1 })
	if got := p.got()[0].XrayConfigs[0].FragmentJson; !bytes.Equal(got, secret) {
		t.Fatal("the part did not get its fragment")
	}
	l.waitDNS("the NodeConfig at dns", func() bool { return l.lastDNS(sock.TypeConfig) != nil })
	var at hubv1.NodeConfig
	if err := proto.Unmarshal(l.lastDNS(sock.TypeConfig).Config.NodeConfig, &at); err != nil || at.Version != 6 {
		t.Fatalf("%v %+v", err, at.Version)
	}
	if len(at.XrayConfigs) != 1 || at.XrayConfigs[0].Tag != "exit-a" || len(at.XrayConfigs[0].FragmentJson) != 0 {
		t.Fatalf("dns got %+v", at.XrayConfigs)
	}
	eventually(t, "the Heartbeat reports the config", func() bool { return lastHB(s).NodeConfigVersion == 6 })
	if storetest.Contains(t, l.dir, []byte("fragment-secret-for-the-test")) {
		t.Fatal("a fragment reached a file under the node's directory")
	}

	hb := lastHB(s)
	if hb.Proxy == nil || hb.Proxy.OpenConnections != 3 || len(hb.Faults) != 1 || hb.Faults[0] != hubv1.NodeFault_NODE_FAULT_XRAY_DOWN {
		t.Fatalf("heartbeat: %+v", hb)
	}

	// The same version again, and an older one, are not applied: the part hears of
	// neither.
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: c}})
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: testNodeConfig(5, make([]byte, 16))}})
	eventually(t, "heartbeat after the replays", func() bool { return lastHB(s).NodeConfigVersion == 6 })
	if n := len(p.got()); n != 1 {
		t.Fatalf("the part got %d configs, want 1", n)
	}

	// After a restart the stored config has no fragment, so the hub's resend of the
	// same version is the one source of it: it reaches the part once, whole. The
	// part's Config is idempotent for this reason.
	l.restart()
	s = l.session()
	_ = s.Send(serverTime())
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: c}})
	eventually(t, "the part got the resend after a restart", func() bool { return len(p.got()) == 2 })
	if got := p.got()[1].XrayConfigs[0].FragmentJson; !bytes.Equal(got, secret) {
		t.Fatal("the resend reached the part without its fragment")
	}
}
