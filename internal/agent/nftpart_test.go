package agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nft"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
)

func nftAgent(t *testing.T, lookup func(...string) ([]uint32, error)) (*Agent, *fake.Runner, *alert.Memory) {
	t.Helper()
	k := &fakeKernel{}
	r := &fake.Runner{Reply: k.reply}
	al := &alert.Memory{}
	cfg := Config{
		Runner: r, Alert: al, LookupUIDs: lookup,
		Conf: conf.Agent{Hub: "198.51.100.20", DNSBindIP: netip.MustParseAddr("203.0.114.9"), ProxyBindIP: netip.MustParseAddr("203.0.115.7")},
	}
	wireNftGuard(&cfg)
	a := &Agent{cfg: cfg, al: al}
	a.nftTable.g = cfg.NftGuard
	return a, r, al
}

func goodUIDs(names ...string) ([]uint32, error) {
	out := make([]uint32, len(names))
	for i := range names {
		out[i] = 900 + uint32(i)
	}
	return out, nil
}

// The agent's own table gains the proxy chains through the guard, and the guard says
// on once it has read the table back.
func TestNftAppliesTheProxyChainsThroughTheGuard(t *testing.T) {
	a, r, al := nftAgent(t, goodUIDs)
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	var script string
	for _, c := range r.Calls() {
		if c.Name == "nft" && len(c.Args) == 2 && c.Args[0] == "-f" {
			script = string(c.Stdin)
		}
	}
	for _, want := range []string{"chain xray_out", "meta skuid 900 ", "ip daddr 203.0.115.7 tcp dport { 80, 443 } notrack", "ip daddr 127.0.0.10 tcp dport 5300 accept"} {
		if !strings.Contains(script, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	if !a.cfg.NftGuard.Check() {
		t.Error("the guard is off after a good apply")
	}
	if len(al.Codes()) != 0 {
		t.Errorf("alerts %v", al.Codes())
	}
}

// An unknown account is never a table of P4 passed off as a complete one: the
// agent alerts and the guard stays off.
func TestNftWithAnUnknownAccountLeavesTheGuardOff(t *testing.T) {
	a, _, al := nftAgent(t, func(...string) ([]uint32, error) { return nil, errors.New("unknown") })
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if a.cfg.NftGuard.Check() {
		t.Error("the guard is on without the proxy chains")
	}
	found := false
	for _, c := range al.Codes() {
		found = found || c == alert.NftFailed
	}
	if !found {
		t.Error("no alert for an unknown account")
	}
}

func TestNftFailureRaisesTheFault(t *testing.T) {
	a, r, _ := nftAgent(t, goodUIDs)
	r.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) == 2 && c.Args[0] == "-f" {
			return nil, errors.New("refused")
		}
		return nil, nil
	}
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if !a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the fault nft_failed is not set")
	}
	r.Reply = nil
	a.cfg.NftGuard.Heal(context.Background())
	if a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the fault stays after the table is back")
	}
}

func TestNftPartIsWired(t *testing.T) {
	cfg := Config{Runner: &fake.Runner{}}
	wireNftGuard(&cfg)
	if cfg.NftGuard == nil || cfg.Faults == nil || len(cfg.Parts) != 1 {
		t.Fatal("not wired")
	}
	var _ Part = cfg.Parts[0]
}

// B4-r1-3 and B4-r1-7: a table that cannot be rendered (here PROXY_IP equal to
// DNS_IP) is not left as "the guard is on over the older table": the older table does
// not carry the new deny sets. The same text as the one in the kernel, once it can be
// rendered again, ends the failure.
func TestNftUnrenderableTableTurnsTheGuardOff(t *testing.T) {
	a, r, _ := nftAgent(t, goodUIDs)
	ctx := context.Background()
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if !a.cfg.NftGuard.Check() {
		t.Fatal("the guard is off after a good apply")
	}
	good := a.cfg.Conf.ProxyBindIP

	a.cfg.Conf.ProxyBindIP = a.cfg.Conf.DNSBindIP
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if a.cfg.NftGuard.Check() {
		t.Fatal("the guard is on over a table that is not the wanted one")
	}
	if !a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the fault nft_failed is not set")
	}
	// The timer puts the older table back if it is flushed, but does not turn the
	// guard on.
	a.cfg.NftGuard.Heal(ctx)
	if a.cfg.NftGuard.Check() {
		t.Fatal("heal turned the guard on over an unrenderable wanted table")
	}

	a.cfg.Conf.ProxyBindIP = good
	before := len(r.Calls())
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if len(r.Calls()) == before {
		t.Fatal("the same text was skipped while the guard was failed")
	}
	if !a.cfg.NftGuard.Check() {
		t.Error("the guard stays off after the table could be rendered again")
	}
	if a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the fault stays")
	}
}

// B4-r1-2: a proxy part that cannot be rendered does not take the table of P4 with it.
// On a node with no table yet, the notrack rules of DNS_IP are still applied while the
// guard stays off and nft_failed is raised.
func TestNftUnrenderableProxyPartStillAppliesTheDNSTable(t *testing.T) {
	a, r, al := nftAgent(t, goodUIDs)
	a.cfg.Conf.ProxyBindIP = a.cfg.Conf.DNSBindIP
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	var script string
	for _, c := range r.Calls() {
		if c.Name == "nft" && len(c.Args) == 2 && c.Args[0] == "-f" {
			script = string(c.Stdin)
		}
	}
	if !strings.Contains(script, "notrack") || !strings.Contains(script, "203.0.114.9") {
		t.Fatalf("the table of P4 was not applied: %q", script)
	}
	if strings.Contains(script, "chain xray_out") {
		t.Error("the proxy chains were applied")
	}
	if a.cfg.NftGuard.Check() {
		t.Error("the guard is on without the proxy chains")
	}
	if !a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the fault nft_failed is not set")
	}
	found := false
	for _, c := range al.Codes() {
		found = found || c == alert.NftFailed
	}
	if !found {
		t.Error("no alert")
	}
}

func nftScripts(r *fake.Runner) []string {
	var out []string
	for _, c := range r.Calls() {
		if c.Name == "nft" && len(c.Args) == 2 && c.Args[0] == "-f" {
			out = append(out, string(c.Stdin))
		}
	}
	return out
}

// B4-r2-1 and B4-r2-4: while the proxy part stays unrenderable, the fallback table is
// applied once. A second pass must not reload the table nor clear and raise nft_failed.
func TestNftUnrenderableProxyPartIsAppliedOnce(t *testing.T) {
	a, r, _ := nftAgent(t, goodUIDs)
	a.cfg.Conf.ProxyBindIP = a.cfg.Conf.DNSBindIP
	ctx := context.Background()
	var flips []bool
	a.cfg.NftGuard.OnFailure(func(f bool) { flips = append(flips, f) })
	for i := 0; i < 3; i++ {
		a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	}
	if n := len(nftScripts(r)); n != 1 {
		t.Errorf("nft -f ran %d times, want 1", n)
	}
	if len(flips) != 1 || !flips[0] {
		t.Errorf("failure callbacks %v, want one raise and no clear", flips)
	}
	if !a.cfg.NftGuard.Failed() || a.cfg.NftGuard.Check() {
		t.Error("the guard is not failed and off")
	}
}

// B4-r2-3: on a node that already runs the proxy chains, a proxy part that can no
// longer be rendered must not replace the table with the one of P4: the chains that
// bound the running uids would go with it.
func TestNftUnrenderableProxyPartKeepsTheRunningProxyChains(t *testing.T) {
	a, r, _ := nftAgent(t, goodUIDs)
	ctx := context.Background()
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if n := len(nftScripts(r)); n != 1 {
		t.Fatalf("first apply: %d scripts", n)
	}
	a.cfg.Conf.ProxyBindIP = a.cfg.Conf.DNSBindIP
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if n := len(nftScripts(r)); n != 1 {
		t.Errorf("the table was replaced: %d scripts", n)
	}
	if a.cfg.NftGuard.Check() {
		t.Error("the guard is on over a table that is not the wanted one")
	}
	if !a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the fault nft_failed is not set")
	}
}

// B4-r2-2: a proxy script that renders but that nft refuses, on a node with no table
// yet, still leaves the DNS_IP rules in place, with the guard off.
func TestNftRefusedProxyScriptStillAppliesTheDNSTable(t *testing.T) {
	a, r, _ := nftAgent(t, goodUIDs)
	r.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) == 2 && c.Args[0] == "-f" && strings.Contains(string(c.Stdin), "chain xray_out") {
			return nil, errors.New("refused")
		}
		if len(c.Args) > 0 && c.Args[0] == "-s" {
			return []byte("table inet ctrlz_agent"), nil
		}
		return nil, nil
	}
	ctx := context.Background()
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	sc := nftScripts(r)
	if len(sc) != 2 {
		t.Fatalf("%d scripts, want the refused one and the fallback", len(sc))
	}
	if strings.Contains(sc[1], "chain xray_out") || !strings.Contains(sc[1], "notrack") {
		t.Errorf("the fallback is not the table of P4: %q", sc[1])
	}
	if a.cfg.NftGuard.Check() {
		t.Error("the guard is on without the proxy chains")
	}
	if !a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the fault nft_failed is not set")
	}
	// Heal leaves the fallback in the kernel and does not turn the guard on.
	a.cfg.NftGuard.Heal(ctx)
	if a.cfg.NftGuard.Check() {
		t.Error("heal turned the guard on")
	}
}

// INT2-r1-2: the tune makes the guard for the Xray manager before boot reaches
// wireNftGuard. The part must run that guard, not a second one, or the manager would
// wait on a table nobody heals.
func TestNftPartKeepsAGuardSetBeforeIt(t *testing.T) {
	own := nft.NewGuard(&fake.Runner{})
	cfg := Config{Runner: &fake.Runner{}, NftGuard: own}
	wireNftGuard(&cfg)
	if cfg.NftGuard != own || len(cfg.Parts) != 1 || cfg.Parts[0].(*nftPart).g != own {
		t.Fatal("the part runs another guard than the one set before it")
	}
}

// fakeKernel is the part of nft the agent reads: the table last loaded, which
// outlives an Agent value exactly as the real one outlives the process.
type fakeKernel struct {
	mu     sync.Mutex
	table  string
	refuse func(script string) bool
	// failRead makes every read of the kernel fail with an error that is not "no such
	// table" (nft busy, a timeout): the answer is unknown.
	failRead bool
}

func (k *fakeKernel) reply(c fake.Call) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case len(c.Args) == 2 && c.Args[0] == "-f":
		if k.refuse != nil && k.refuse(string(c.Stdin)) {
			return nil, errors.New("refused")
		}
		k.table = string(c.Stdin)
	case len(c.Args) == 2 && c.Args[0] == "list" && c.Args[1] == "tables":
		if k.failRead {
			return nil, errors.New("busy")
		}
		if k.table != "" {
			return []byte("table inet ctrlz_agent\n"), nil
		}
	case len(c.Args) > 0 && c.Args[0] == "-s":
		if k.failRead {
			return nil, errors.New("busy")
		}
		if k.table == "" {
			return nil, errors.New("no such table")
		}
		return []byte("table inet ctrlz_agent\n" + k.table), nil
	}
	return nil, nil
}

// restarted is an agent process that starts over a kernel that already holds the table
// of the one before it: its nftApplier has applied nothing.
func restarted(t *testing.T, k *fakeKernel, lookup func(...string) ([]uint32, error)) (*Agent, *fake.Runner) {
	t.Helper()
	a, _, _ := nftAgent(t, lookup)
	r := &fake.Runner{Reply: k.reply}
	a.cfg.Runner = r
	a.cfg.NftGuard = nft.NewGuard(r)
	a.cfg.Faults = NewFaults()
	f := a.cfg.Faults
	a.cfg.NftGuard.OnFailure(func(failed bool) { f.Set(hubv1.NodeFault_NODE_FAULT_NFT_FAILED, failed) })
	a.nftTable = nftApplier{g: a.cfg.NftGuard}
	return a, r
}

// kernelWithChains is what a running node holds: the table of a full apply.
func kernelWithChains(t *testing.T) *fakeKernel {
	t.Helper()
	a, r, _ := nftAgent(t, goodUIDs)
	k := &fakeKernel{}
	r.Reply = k.reply
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if !strings.Contains(k.table, "chain xray_out") {
		t.Fatal("the helper kernel holds no proxy chains")
	}
	return k
}

// INT2-r1-1, INT2-r1-4: freshness comes from the kernel. A restarted agent whose proxy
// part cannot be rendered must keep the table of the agent before it.
func TestNftRestartedAgentKeepsChainsAgainstAnUnrenderablePart(t *testing.T) {
	k := kernelWithChains(t)
	before := k.table
	a, r := restarted(t, k, goodUIDs)
	a.cfg.Conf.ProxyBindIP = a.cfg.Conf.DNSBindIP
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if n := len(nftScripts(r)); n != 0 || k.table != before {
		t.Errorf("the table was replaced (%d scripts)", n)
	}
	if a.cfg.NftGuard.Check() || !a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the guard is on, or nft_failed is not raised")
	}
}

// The same restart when nft refuses the proxy script: no fallback over the chains.
func TestNftRestartedAgentKeepsChainsWhenNftRefusesTheScript(t *testing.T) {
	k := kernelWithChains(t)
	before := k.table
	k.refuse = func(s string) bool { return strings.Contains(s, "chain xray_out") }
	a, r := restarted(t, k, goodUIDs)
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	for _, s := range nftScripts(r) {
		if !strings.Contains(s, "chain xray_out") {
			t.Fatal("the table of P4 was applied over the running chains")
		}
	}
	if k.table != before {
		t.Error("the kernel table changed")
	}
	if a.cfg.NftGuard.Check() {
		t.Error("the guard is on over a table that is not the wanted one")
	}
}

// INT2-r1-3, INT2-r1-6: a pass that cannot build the proxy part (an account that did not
// resolve) leaves the chains of a running node alone, with the guard off.
func TestNftNoProxyPartKeepsTheRunningChains(t *testing.T) {
	k := kernelWithChains(t)
	before := k.table
	a, r := restarted(t, k, func(...string) ([]uint32, error) { return nil, errors.New("unknown") })
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if n := len(nftScripts(r)); n != 0 || k.table != before {
		t.Errorf("the table was replaced (%d scripts)", n)
	}
	if a.cfg.NftGuard.Check() {
		t.Error("the guard is on")
	}
	// The next pass that has its accounts again puts the full table back and the guard on.
	a.cfg.LookupUIDs = goodUIDs
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if !a.cfg.NftGuard.Check() || a.cfg.Faults.Has(hubv1.NodeFault_NODE_FAULT_NFT_FAILED) {
		t.Error("the guard did not come back")
	}
}

// INT2-r1-2, INT2-r1-5: the hub is a name that does not answer, and the agent restarts.
// The addresses of the last answer come from disk, so the table is rendered and the
// guard settles on, not rejected.
func TestNftRestartWithAnUnresolvedHubUsesTheStoredAddresses(t *testing.T) {
	k := kernelWithChains(t)
	a, _ := restarted(t, k, goodUIDs)
	a.cfg.Conf.Hub = "hub.invalid:443"
	a.nftTable.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	a.cfg.Root = "/var/lib/ctrlz"
	a.cfg.Files = fake.NewFiles(nil) // panelFile needs Files to name a path
	a.cfg.Files.(*fake.Files).Set(panelFile(a.cfg), "198.51.100.20\n")
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if !a.cfg.NftGuard.Check() || a.cfg.NftGuard.Failed() {
		t.Error("the guard is not on with the stored addresses")
	}
}

// With nothing stored and no answer, the first attempt does not settle the guard as
// rejected; a later one does.
func TestNftUnresolvedHubWithNothingStoredDoesNotSettleAtOnce(t *testing.T) {
	k := kernelWithChains(t)
	a, _ := restarted(t, k, goodUIDs)
	a.cfg.Conf.Hub = "hub.invalid:443"
	a.nftTable.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	a.cfg.Root = "/var/lib/ctrlz"
	a.cfg.Files = fake.NewFiles(nil)
	ctx := context.Background()
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if a.cfg.NftGuard.IsSettled() {
		t.Fatal("the guard settled on a hub that has not been resolved yet")
	}
	a.cfg.Conf.Hub = "198.51.100.20"
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if !a.cfg.NftGuard.IsSettled() || !a.cfg.NftGuard.Check() {
		t.Error("the guard is not settled and on once the hub has an address")
	}
}

// An answered lookup is written down, and read back by an applier that has none.
func TestNftAnsweredLookupIsStored(t *testing.T) {
	want := netip.MustParseAddr("198.51.100.20")
	n := nftApplier{lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{want}, nil }}
	cfg := Config{Root: "/var/lib/ctrlz", Files: fake.NewFiles(nil)}
	cfg.Conf.Hub = "hub.example:443"
	if got := n.resolvePanel(context.Background(), cfg); len(got) != 1 || got[0] != want {
		t.Fatalf("answer %v", got)
	}
	var later nftApplier
	later.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if got := later.resolvePanel(context.Background(), cfg); len(got) != 1 || got[0] != want {
		t.Errorf("the stored address was not used: %v", got)
	}
}

// INT2-r2-1, INT2-r2-4: a kernel that cannot be read is not a kernel with no chains. The
// older table stays over an unrenderable proxy part, and over a script nft refuses.
func TestNftUnreadableKernelKeepsTheOlderTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(a *Agent, k *fakeKernel)
	}{
		{"unrenderable part", func(a *Agent, k *fakeKernel) { a.cfg.Conf.ProxyBindIP = a.cfg.Conf.DNSBindIP }},
		{"nft refuses the script", func(a *Agent, k *fakeKernel) {
			k.refuse = func(s string) bool { return strings.Contains(s, "chain xray_out") }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := kernelWithChains(t)
			before := k.table
			a, r := restarted(t, k, goodUIDs)
			tc.prep(a, k)
			k.failRead = true
			a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
			for _, s := range nftScripts(r) {
				if !strings.Contains(s, "chain xray_out") {
					t.Fatal("the table of P4 was applied over a kernel that could not be read")
				}
			}
			k.failRead = false
			if k.table != before {
				t.Error("the kernel table changed")
			}
		})
	}
}

// HoldsProxyChains tells a table that is absent from a kernel that cannot be asked.
func TestHoldsProxyChainsKnownAndUnknown(t *testing.T) {
	ctx := context.Background()
	k := &fakeKernel{}
	g := nft.NewGuard(&fake.Runner{Reply: k.reply})
	if holds, known := g.HoldsProxyChains(ctx); holds || !known {
		t.Errorf("no table: holds=%v known=%v, want false true", holds, known)
	}
	k.table = "chain input {}"
	if holds, known := g.HoldsProxyChains(ctx); holds || !known {
		t.Errorf("a table without chains: holds=%v known=%v, want false true", holds, known)
	}
	k.table = "chain xray_out {}"
	if holds, known := g.HoldsProxyChains(ctx); !holds || !known {
		t.Errorf("a table with chains: holds=%v known=%v, want true true", holds, known)
	}
	k.failRead = true
	if _, known := g.HoldsProxyChains(ctx); known {
		t.Error("a failed read was taken as an answer")
	}
	// The read fails but the table is listed: nft is struggling, not the table missing.
	k.failRead = false
	g2 := nft.NewGuard(&fake.Runner{Reply: func(c fake.Call) ([]byte, error) {
		if len(c.Args) > 0 && c.Args[0] == "-s" {
			return nil, errors.New("busy")
		}
		return []byte("table inet ctrlz_agent\n"), nil
	}})
	if _, known := g2.HoldsProxyChains(ctx); known {
		t.Error("a listed table that could not be read was taken as absent")
	}
}

// INT2-r2-2, INT2-r2-3: a hub lookup that never answers is cut short, so the first
// apply is made with the stored addresses well inside the guard's settle wait.
func TestNftBlockedHubLookupFallsBackToTheStoredAddresses(t *testing.T) {
	k := kernelWithChains(t)
	a, _ := restarted(t, k, goodUIDs)
	a.cfg.Conf.Hub = "hub.invalid:443"
	a.nftTable.lookupWait = 50 * time.Millisecond
	a.nftTable.lookup = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done() // a resolver that drops packets
		return nil, ctx.Err()
	}
	a.cfg.Root = "/var/lib/ctrlz"
	a.cfg.Files = fake.NewFiles(nil)
	a.cfg.Files.(*fake.Files).Set(panelFile(a.cfg), "198.51.100.20\n")
	start := time.Now()
	a.nftTable.applyWith(context.Background(), a.cfg, a.al, a.dnsIP(), a.proxyNft())
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the apply waited %s on the lookup", d)
	}
	if !a.cfg.NftGuard.IsSettled() || !a.cfg.NftGuard.Check() {
		t.Error("the guard is not on with the stored addresses")
	}
}
