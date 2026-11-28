package main

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
)

// The addresses that `direct` refuses beside the non-public ranges include the panel
// and this node's own four (B5 r1-2, r1-18); the other nodes of the table come from
// the store, whose reader has its own test.
func TestXrayNodeAddrsHoldThePanelAndTheNodesOwn(t *testing.T) {
	cfg := &agent.Config{Root: t.TempDir(), Conf: conf.Agent{
		DNSBindIP: netip.MustParseAddr("192.0.2.1"), DNSAdvertisedIP: netip.MustParseAddr("192.0.2.2"),
		ProxyBindIP: netip.MustParseAddr("192.0.2.3"), ProxyAdvertisedIP: netip.MustParseAddr("192.0.2.4"),
		PanelAddrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
	}}
	got := xrayNodeAddrs(cfg)()
	for _, want := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "203.0.113.9"} {
		if !slices.Contains(got, netip.MustParseAddr(want)) {
			t.Errorf("%s missing from %v", want, got)
		}
	}
}

// A hub that is a name is resolved once at the start and the list only grows, so a
// resolver that answers another subset each time does not rebuild the slot.
func TestHubNameIsResolvedAtStartAndTheListOnlyGrows(t *testing.T) {
	answers := [][]netip.Addr{
		{netip.MustParseAddr("198.51.100.1")},
		{netip.MustParseAddr("198.51.100.2")},
	}
	n := 0
	h := &hubAddrs{ac: conf.Agent{Hub: "hub.example.org"}, lookup: func(context.Context, string) []netip.Addr {
		a := answers[n%len(answers)]
		n++
		return a
	}}
	h.prime()
	if len(h.got) != 1 {
		t.Fatalf("after prime: %v", h.got)
	}
	h.merge(answers[1])
	h.merge(answers[0])
	if len(h.got) != 2 {
		t.Errorf("after two answers: %v", h.got)
	}
}

// B5-r2-10: a full list says so and does not silently drop what the panel moves to; an
// address that the name stopped answering makes room.
func TestHubAddrsCapAlertsAndStaleAddressesMakeRoom(t *testing.T) {
	mem := &alert.Memory{}
	h := &hubAddrs{ac: conf.Agent{Hub: "hub.example.org"}, alert: mem}
	var first []netip.Addr
	for i := 0; i < hubMax+8; i++ {
		first = append(first, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
	}
	h.merge(first)
	if len(h.got) != hubMax {
		t.Fatalf("list holds %d, want %d", len(h.got), hubMax)
	}
	if mem.Count("xray_hub_addrs_capped") != 1 {
		t.Errorf("alerts: %d, want 1", mem.Count("xray_hub_addrs_capped"))
	}
	// A day later the old answers are stale and the new address replaces them.
	for a := range h.seen {
		h.seen[a] = time.Now().Add(-2 * hubStale)
	}
	next := netip.MustParseAddr("203.0.113.77")
	h.merge([]netip.Addr{next})
	if !slices.Contains(h.got, next) {
		t.Errorf("the panel's new address is missing from %v", h.got)
	}
}
