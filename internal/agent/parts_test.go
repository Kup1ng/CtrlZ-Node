package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
)

func TestFaultsSetListAndRange(t *testing.T) {
	f := NewFaults()
	if len(f.List()) != 0 {
		t.Fatal("a new set is not empty")
	}
	f.Set(hubv1.NodeFault_NODE_FAULT_XRAY_STUCK, true)
	f.Set(hubv1.NodeFault_NODE_FAULT_NFT_FAILED, true)
	f.Set(hubv1.NodeFault_NODE_FAULT_NFT_FAILED, true) // twice: still once
	got := f.List()
	if len(got) != 2 || got[0] != hubv1.NodeFault_NODE_FAULT_NFT_FAILED || got[1] != hubv1.NodeFault_NODE_FAULT_XRAY_STUCK {
		t.Fatalf("%v", got)
	}
	f.Set(hubv1.NodeFault_NODE_FAULT_NFT_FAILED, false)
	if f.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) || !f.Has(hubv1.NodeFault_NODE_FAULT_XRAY_STUCK) {
		t.Fatal("off did not turn only its own fault off")
	}
	// Zero, a value the hub does not know, and one past the bit set change nothing:
	// the hub refuses a whole Heartbeat that carries one.
	for _, v := range []hubv1.NodeFault{0, -1, 6, 40} {
		f.Set(v, true)
	}
	if got := f.List(); len(got) != 1 {
		t.Fatalf("an out-of-range fault was set: %v", got)
	}
}

// Parts raise faults from many goroutines at once: no set may be lost.
func TestFaultsAreAtomic(t *testing.T) {
	f := NewFaults()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		for _, v := range []hubv1.NodeFault{1, 2, 3, 4, 5} {
			wg.Add(1)
			go func() { defer wg.Done(); f.Set(v, true) }()
		}
	}
	wg.Wait()
	if len(f.List()) != 5 {
		t.Fatalf("%v", f.List())
	}
}

type fakePart struct {
	ran     atomic.Bool
	configs []*hubv1.NodeConfig
	mu      sync.Mutex
	hb      func(*hubv1.Heartbeat)
	cfg     func(*hubv1.NodeConfig)
}

func (p *fakePart) Run(ctx context.Context) { p.ran.Store(true); <-ctx.Done() }
func (p *fakePart) Config(nc *hubv1.NodeConfig) {
	p.mu.Lock()
	p.configs = append(p.configs, nc)
	p.mu.Unlock()
	if p.cfg != nil {
		p.cfg(nc)
	}
}
func (p *fakePart) Heartbeat(hb *hubv1.Heartbeat) {
	if p.hb != nil {
		p.hb(hb)
	}
}

func TestPartsHeartbeatKeepsGoodPartsAndDropsBadOnes(t *testing.T) {
	faults := NewFaults()
	good := &fakePart{hb: func(hb *hubv1.Heartbeat) { hb.Proxy = &hubv1.ProxyState{Listening: true, OpenConnections: 7} }}
	panics := &fakePart{hb: func(hb *hubv1.Heartbeat) { hb.XrayVersion = "v1"; panic("boom") }}
	// The hub refuses an xray_version that is not a release tag, and then the whole
	// Heartbeat; the part's change must not survive.
	invalid := &fakePart{hb: func(hb *hubv1.Heartbeat) { hb.XrayVersion = "not a tag" }}
	later := &fakePart{hb: func(hb *hubv1.Heartbeat) { hb.XrayVersion = "v26.11.9" }}
	a := &Agent{cfg: Config{Parts: []Part{good, panics, invalid, later}, Faults: faults}}
	faults.Set(hubv1.NodeFault_NODE_FAULT_XRAY_DOWN, true)
	in := &hubv1.Heartbeat{NodeTime: 5, NodeVersion: "vtest", BlobMajorMax: 1}
	out := a.partsHeartbeat(in)
	if out.Proxy == nil || out.Proxy.OpenConnections != 7 {
		t.Fatalf("a good part's fields were lost: %+v", out)
	}
	if out.XrayVersion != "v26.11.9" {
		t.Fatalf("xray_version %q: a bad part's change survived, or a later good part was lost", out.XrayVersion)
	}
	if out.NodeVersion != "vtest" || len(out.Faults) != 1 || out.Faults[0] != hubv1.NodeFault_NODE_FAULT_XRAY_DOWN {
		t.Fatalf("%+v", out)
	}
}

// fragPart opts in to the fragments.
type fragPart struct{ fakePart }

func (*fragPart) Fragments() bool { return true }

func TestPartsConfigGoesToEveryPartAndSurvivesAPanic(t *testing.T) {
	p1 := &fakePart{cfg: func(*hubv1.NodeConfig) { panic("boom") }}
	p2 := &fakePart{}
	a := &Agent{cfg: Config{Parts: []Part{p1, p2}}}
	nc := &hubv1.NodeConfig{Version: 4, XrayConfigs: []*hubv1.XrayConfig{{FragmentJson: []byte("{}")}}}
	a.partsConfig(nc, nodecfg.Strip(nc))
	if len(p2.configs) != 1 || p2.configs[0].Version != 4 {
		t.Fatal("the part after a panicking one did not get the config")
	}
	if a.PartPanics() != 1 {
		t.Fatalf("the panic was not counted: %d", a.PartPanics())
	}
}

// B1n-r1-3: a fragment reaches only the part that asked for it, and every part has
// a copy of its own, so an edit by one changes neither the agent's config nor
// another part's.
func TestPartsConfigFragmentsOnlyToTheirPartAndCopiesAreOwn(t *testing.T) {
	var edit = func(nc *hubv1.NodeConfig) { nc.Version = 99; nc.XrayConfigs[0].Tag = "edited" }
	plain := &fakePart{cfg: edit}
	frag := &fragPart{}
	plain2 := &fakePart{}
	a := &Agent{cfg: Config{Parts: []Part{plain, frag, plain2}}}
	nc := &hubv1.NodeConfig{Version: 4, XrayConfigs: []*hubv1.XrayConfig{{Tag: "t", FragmentJson: []byte("{}")}}}
	a.partsConfig(nc, nodecfg.Strip(nc))
	if len(plain.configs[0].XrayConfigs[0].FragmentJson) != 0 || len(plain2.configs[0].XrayConfigs[0].FragmentJson) != 0 {
		t.Fatal("a part that did not ask for fragments got one")
	}
	if string(frag.configs[0].XrayConfigs[0].FragmentJson) != "{}" {
		t.Fatal("the fragment part did not get its fragment")
	}
	if nc.Version != 4 || nc.XrayConfigs[0].Tag != "t" || frag.configs[0].Version != 4 || plain2.configs[0].XrayConfigs[0].Tag != "t" {
		t.Fatal("one part's edit reached the agent's config or another part")
	}
	if frag.configs[0] == nc {
		t.Fatal("the part got the agent's own pointer")
	}
}

func TestRunPartSurvivesAPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	a := &Agent{}
	go func() { defer close(done); a.runPart(ctx, &panicRunner{}) }()
	<-done
	if a.PartPanics() != 1 {
		t.Fatalf("the panic of Run was not counted: %d", a.PartPanics())
	}
}

type panicRunner struct{ fakePart }

func (*panicRunner) Run(context.Context) { panic("boom") }

// DNS holds what a part publishes before the agent has its socket, and hands it
// over when the socket is there.
func TestDNSBridgeBeforeAndAfterBind(t *testing.T) {
	d := &DNS{}
	if d.Send(&sock.Msg{Type: sock.TypeGrantSent}) {
		t.Fatal("sent with no server")
	}
	if err := d.Publish(&sock.Msg{Type: sock.TypeLocations, Locations: &sock.Locations{}}); err != nil {
		t.Fatal(err)
	}
	if len(d.held) != 1 {
		t.Fatal("the published slot was not held")
	}
	// Two publishes before the server: only the last is held, so a replay cannot put
	// an older list over a newer one (B1n-r1-6).
	newer := &sock.Msg{Type: sock.TypeLocations, Locations: &sock.Locations{Direct: "127.0.0.1:1"}}
	_ = d.Publish(newer)
	if len(d.held) != 1 || d.held[0] != newer {
		t.Fatalf("held %d messages, the last one is not the newer", len(d.held))
	}
	if err := d.Publish(&sock.Msg{Type: sock.TypeImage}); err == nil {
		t.Fatal("a part published a slot that is not its own")
	}
	var got []string
	d.Subscribe(func(m *sock.Msg) { got = append(got, "a:"+m.Type) })
	d.Subscribe(func(m *sock.Msg) { panic("subscriber") })
	d.Subscribe(func(m *sock.Msg) { got = append(got, "c:"+m.Type) })
	d.dispatch(&sock.Msg{Type: sock.TypeProxyState})
	if len(got) != 2 || got[0] != "a:proxy_state" || got[1] != "c:proxy_state" {
		t.Fatalf("%v", got)
	}
}
