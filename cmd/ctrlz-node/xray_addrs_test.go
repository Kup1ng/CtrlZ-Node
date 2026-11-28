package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"sync/atomic"
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

// B5-r3-6: an empty answer at a node boot leaves the list of the last run, and an empty
// list is asked for again soon, not after the long wait.
func TestHubAddrsSurviveAnEmptyAnswerAtBootAndAreAskedAgainSoon(t *testing.T) {
	file := filepath.Join(t.TempDir(), "hub.json")
	want := netip.MustParseAddr("198.51.100.9")
	h1 := &hubAddrs{ac: conf.Agent{Hub: "hub.example.org"}, file: file,
		lookup: func(context.Context, string) []netip.Addr { return []netip.Addr{want} }}
	h1.prime()
	var calls atomic.Int64
	h2 := &hubAddrs{ac: conf.Agent{Hub: "hub.example.org"}, file: file,
		lookup: func(context.Context, string) []netip.Addr { calls.Add(1); return nil }}
	h2.prime() // Unbound is not up yet
	if got := h2.get(); !slices.Equal(got, []netip.Addr{want}) {
		t.Fatalf("the last run's list is gone after an empty answer: %v", got)
	}
	// With nothing known at all, the next ask comes after hubRetry, not hubRefresh.
	h3 := &hubAddrs{ac: conf.Agent{Hub: "hub.example.org"}, lookup: func(context.Context, string) []netip.Addr { calls.Add(1); return nil }}
	h3.at = time.Now().Add(-2 * hubRetry)
	before := calls.Load()
	h3.get()
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() == before {
		t.Error("an empty list was not asked for again after hubRetry")
	}
}

// B5-r1-7: the stored list keeps each address's own last-answer time, so a restart does
// not make a forged address young again and the stale eviction can still reach it.
func TestHubAddrsKeepTheirLastAnswerTimeAcrossARestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "hub.json")
	old, fresh := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	h1 := &hubAddrs{ac: conf.Agent{Hub: "hub.example.org"}, file: file}
	h1.merge([]netip.Addr{old, fresh})
	h1.seen[old] = time.Now().Add(-2 * hubStale)
	h1.save()
	h2 := &hubAddrs{ac: conf.Agent{Hub: "hub.example.org"}, file: file}
	h2.load()
	if !slices.Equal(h2.got, []netip.Addr{fresh}) {
		t.Fatalf("an address that was stale before the restart came back: %v", h2.got)
	}
	if time.Since(h2.seen[fresh]) > time.Minute {
		t.Errorf("a fresh address lost its time: %v", h2.seen[fresh])
	}
}

// B5-r1-7: the hosts-file resolver never opens a socket, so a name the file does not
// hold fails at once and no plain DNS answer can reach the block list.
func TestHostsOnlyResolverNeverAsksDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if ips, err := hostsOnlyResolver().LookupNetIP(ctx, "ip", "no-such-name.ctrlz-test.invalid"); err == nil {
		t.Fatalf("a name that is not in the hosts file resolved: %v", ips)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("the lookup waited on the network")
	}
}
