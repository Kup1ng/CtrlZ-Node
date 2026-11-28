package agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nft"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
)

func nftAgent(t *testing.T, lookup func(...string) ([]uint32, error)) (*Agent, *fake.Runner, *alert.Memory) {
	t.Helper()
	r := &fake.Runner{Reply: func(c fake.Call) ([]byte, error) {
		if len(c.Args) > 0 && c.Args[0] == "-s" {
			return []byte("table inet ctrlz_agent"), nil
		}
		return nil, nil
	}}
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
