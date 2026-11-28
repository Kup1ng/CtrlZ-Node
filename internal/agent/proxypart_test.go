package agent

import (
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// The proxy part reports what dns says of the proxy, sets grants_full while dns says
// the node is full, and stops vouching for a state nobody has seen for 30 s.
func TestProxyPartReportsDNSState(t *testing.T) {
	cfg := Config{}
	now := time.Unix(1_800_000_000, 0)
	cfg.Now = func() time.Time { return now }
	p := addProxyPart(&cfg)
	var hb hubv1.Heartbeat
	p.Heartbeat(&hb)
	if hb.Proxy == nil || hb.Proxy.Listening || hb.Proxy.OpenConnections != 0 {
		t.Fatalf("before any state: %v", hb.Proxy)
	}
	cfg.DNS.dispatch(&sock.Msg{Type: sock.TypeProxyState, ProxyState: &sock.ProxyState{Listening: true, Open: 5, Full: true}})
	hb.Reset()
	p.Heartbeat(&hb)
	if !hb.Proxy.Listening || hb.Proxy.OpenConnections != 5 || !cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_GRANTS_FULL) {
		t.Fatalf("%v faults %v", hb.Proxy, cfg.Faults.List())
	}
	cfg.DNS.dispatch(&sock.Msg{Type: sock.TypeProxyState, ProxyState: &sock.ProxyState{Listening: true, Open: 5}})
	if cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_GRANTS_FULL) {
		t.Fatal("grants_full stays only while dns says so")
	}
	now = now.Add(31 * time.Second)
	hb.Reset()
	p.Heartbeat(&hb)
	if hb.Proxy.Listening {
		t.Fatal("a state 30 s old is no state")
	}
	// Other messages of dns change nothing.
	cfg.DNS.dispatch(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: make([]byte, 16)}})
}
