package nft

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
)

func proxyParams() Params {
	p := params()
	p.Proxy = &ProxyParams{
		ProxyIP:   netip.MustParseAddr("203.0.115.7"),
		Uids:      Uids{Xray: 991, Proxy: 992, Block: 993, DNS: 994, Agent: 995},
		Unbound:   netip.MustParseAddrPort("127.0.0.10:5300"),
		DenyAddrs: []netip.Addr{netip.MustParseAddr("203.0.114.77"), netip.MustParseAddr("203.0.115.78")},
	}
	return p
}

func TestProxyChainsAreRendered(t *testing.T) {
	s, err := Render(proxyParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		// notrack for PROXY_IP's ports and the SOCKS ports, both directions, both chains
		"ip daddr 203.0.115.7 tcp dport { 80, 443 } notrack",
		"ip saddr 203.0.115.7 tcp sport { 80, 443 } notrack",
		"ip daddr { 127.0.0.20, 127.0.0.21 } tcp dport 20000-20255 notrack",
		"ip saddr { 127.0.0.20, 127.0.0.21 } tcp sport 20000-20255 notrack",
		"chain xray_out {", "chain proxy_out {", "chain block_out {", "chain socks_guard {",
		"meta skuid 991 tcp flags & (fin | syn | rst | ack) != syn accept",
		"meta skuid 991 ip daddr 127.0.0.10 tcp dport 5300 accept",
		"meta skuid 991 fib daddr type { local, broadcast, anycast, multicast } drop",
		"meta skuid 992 ip daddr { 127.0.0.20, 127.0.0.21 } tcp dport 20000-20255 accept",
		"meta skuid 992 drop",
		"meta skuid 993 drop",
		"meta skuid { 992, 994, 995 } accept",
		// the P4 rules are still there
		"ip daddr 203.0.114.9 udp dport 53 notrack",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q\n%s", want, s)
		}
	}
	if n := strings.Count(s, "tcp dport { 80, 443 } notrack"); n != 2 {
		t.Errorf("the PROXY_IP notrack is in %d chains, want raw_in and raw_out", n)
	}
	// Every address of the nodes, the panel and the non-public ranges is in the deny set.
	deny := regexp.MustCompile(`meta skuid 991 ip daddr \{ ([^}]*) \} drop`).FindStringSubmatch(s)
	if deny == nil {
		t.Fatal("no deny set for IPv4")
	}
	for _, a := range []string{"203.0.114.9/32", "203.0.115.7/32", "198.51.100.0/24", "203.0.114.77/32", "203.0.115.78/32", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16"} {
		if !strings.Contains(deny[1], a) {
			t.Errorf("the deny set lacks %s", a)
		}
	}
	if !regexp.MustCompile(`meta skuid 991 ip6 daddr \{ [^}]*fc00::/7[^}]* \} drop`).MatchString(s) {
		t.Error("no IPv6 deny set with the unique-local range")
	}
}

// The accepted shapes of 5.5: an output chain accepts first what is not a first SYN,
// no rule rates or counts, and none names a DNS_IP listener.
func TestProxyChainsKeepTheRules(t *testing.T) {
	s, err := Render(proxyParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"limit", "meter", "quota", "ct count", "ct state", "flowtable", "dynamic", "timeout", "size ", "counter", "queue", "reject", "set ", "ct "} {
		if strings.Contains(s, banned) {
			t.Errorf("the table holds %q", banned)
		}
	}
	chains := regexp.MustCompile(`(?s)chain (\w+) \{(.*?)\n\t\}`).FindAllStringSubmatch(s, -1)
	seen := map[string]bool{}
	for _, c := range chains {
		seen[c[1]] = true
		body := c[2]
		switch c[1] {
		case "xray_out", "proxy_out", "socks_guard":
			lines := strings.Split(strings.TrimSpace(body), "\n")
			if len(lines) < 3 || !strings.Contains(lines[1], "tcp flags & (fin | syn | rst | ack) != syn accept") {
				t.Errorf("%s does not accept a non-SYN first:\n%s", c[1], body)
			}
		}
		if c[1] == "xray_out" || c[1] == "proxy_out" || c[1] == "block_out" || c[1] == "socks_guard" {
			// L13: nothing judges a packet by DNS_IP's port 53, or by the DoT and DoH ports of it.
			if regexp.MustCompile(`dport (53|853)\b`).MatchString(body) || strings.Contains(body, "203.0.114.9 tcp") {
				t.Errorf("%s judges a DNS_IP listener:\n%s", c[1], body)
			}
		}
	}
	for _, n := range []string{"xray_out", "proxy_out", "block_out", "socks_guard"} {
		if !seen[n] {
			t.Errorf("no chain %s", n)
		}
	}
}

func TestProxyParamsAreChecked(t *testing.T) {
	for name, mod := range map[string]func(*Params){
		"no proxy ip":      func(p *Params) { p.Proxy.ProxyIP = netip.Addr{} },
		"proxy is dns":     func(p *Params) { p.Proxy.ProxyIP = p.DNSIP },
		"uid zero":         func(p *Params) { p.Proxy.Uids.Xray = 0 },
		"same account":     func(p *Params) { p.Proxy.Uids.Block = p.Proxy.Uids.Proxy },
		"xray is the dns":  func(p *Params) { p.Proxy.Uids.DNS = p.Proxy.Uids.Xray },
		"no unbound":       func(p *Params) { p.Proxy.Unbound = netip.AddrPort{} },
		"unspecified ip":   func(p *Params) { p.Proxy.ProxyIP = netip.IPv4Unspecified() },
		"multicast ip":     func(p *Params) { p.Proxy.ProxyIP = netip.MustParseAddr("224.0.0.1") },
		"xray is an agent": func(p *Params) { p.Proxy.Uids.Agent = p.Proxy.Uids.Xray },
	} {
		p := proxyParams()
		mod(&p)
		if _, err := Render(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProxyIPv6(t *testing.T) {
	p := proxyParams()
	p.Proxy.ProxyIP = netip.MustParseAddr("2001:db8::7")
	s, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "ip6 daddr 2001:db8::7 tcp dport { 80, 443 } notrack") {
		t.Error(s)
	}
}

// The text the P4 test reads is unchanged when no proxy is asked for.
func TestNoProxyNoChains(t *testing.T) {
	s, err := Render(params())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "xray_out") || strings.Contains(s, "skuid") {
		t.Error(s)
	}
}

// listing is a fake nft: it keeps the script applied last and prints a listing of it.
type listing struct {
	mu      sync.Mutex
	table   string
	failApp bool
	failLs  bool
	applied int
}

func (l *listing) run(c fake.Call) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case len(c.Args) > 0 && c.Args[0] == "-c":
		return nil, nil
	case len(c.Args) == 2 && c.Args[0] == "-f":
		if l.failApp {
			return nil, errors.New("refused")
		}
		l.table = string(c.Stdin)
		l.applied++
		return nil, nil
	case len(c.Args) > 0 && c.Args[0] == "-s":
		if l.failLs || l.table == "" {
			return nil, errors.New("no such table")
		}
		return []byte(l.table), nil
	}
	return nil, nil
}

func (l *listing) flush() { l.mu.Lock(); l.table = ""; l.mu.Unlock() }
func (l *listing) tamper() {
	l.mu.Lock()
	l.table += "\nrule added by another tool"
	l.mu.Unlock()
}

func newGuard() (*Guard, *listing, *[]bool) {
	l := &listing{}
	g := NewGuard(&fake.Runner{Reply: l.run})
	var fails []bool
	g.OnFailure(func(f bool) { fails = append(fails, f) })
	return g, l, &fails
}

func TestGuardReadsBackAndHeals(t *testing.T) {
	ctx := context.Background()
	g, l, fails := newGuard()
	if g.Check() {
		t.Fatal("on before any table")
	}
	if err := g.Apply(ctx, proxyParams()); err != nil {
		t.Fatal(err)
	}
	if !g.Check() {
		t.Fatal("off after a good apply")
	}
	if v := <-g.Changed(); !v {
		t.Fatal("the change was not announced")
	}

	// A table another tool flushed, or added a rule to, is not the one we applied.
	l.flush()
	if g.Check() {
		t.Fatal("a flushed table passed")
	}
	if v := <-g.Changed(); v {
		t.Fatal("the change to off was not announced")
	}
	g.Heal(ctx)
	if !g.Check() || g.Failed() {
		t.Fatal("the table was not applied again")
	}
	l.tamper()
	if g.Check() {
		t.Fatal("a table with an added rule passed")
	}
	g.Heal(ctx)
	if !g.Check() {
		t.Fatal("not healed")
	}
	if len(*fails) != 0 {
		t.Fatalf("a fault was raised for a repair that worked: %v", *fails)
	}
}

func TestGuardStaysOffWhenTheApplyFails(t *testing.T) {
	ctx := context.Background()
	g, l, fails := newGuard()
	if err := g.Apply(ctx, proxyParams()); err != nil {
		t.Fatal(err)
	}
	l.flush()
	l.mu.Lock()
	l.failApp = true
	l.mu.Unlock()
	g.Heal(ctx)
	if g.Check() || !g.Failed() {
		t.Fatal("the guard is on though the table could not be put back")
	}
	if len(*fails) != 1 || !(*fails)[0] {
		t.Fatalf("faults %v", *fails)
	}
	// It tries on, and the fault ends with the first apply that works.
	l.mu.Lock()
	l.failApp = false
	l.mu.Unlock()
	g.Heal(ctx)
	if !g.Check() || g.Failed() {
		t.Fatal("not back on")
	}
	if len(*fails) != 2 || (*fails)[1] {
		t.Fatalf("faults %v", *fails)
	}
}

// A first apply that fails is still tried again by Heal.
func TestGuardRetriesAFirstApplyThatFailed(t *testing.T) {
	ctx := context.Background()
	g, l, _ := newGuard()
	l.mu.Lock()
	l.failApp = true
	l.mu.Unlock()
	if err := g.Apply(ctx, proxyParams()); err == nil {
		t.Fatal("no error")
	}
	l.mu.Lock()
	l.failApp = false
	l.mu.Unlock()
	g.Heal(ctx)
	if !g.Check() {
		t.Fatal("never applied")
	}
}

// A table without the proxy chains never makes the guard say on: a slot started
// behind it would reach the host.
func TestGuardIsOffForATableOfP4Alone(t *testing.T) {
	g, _, _ := newGuard()
	if err := g.Apply(context.Background(), params()); err != nil {
		t.Fatal(err)
	}
	if g.Check() {
		t.Fatal("on without the proxy chains")
	}
}

func TestGuardUnreadableListingIsOff(t *testing.T) {
	g, l, _ := newGuard()
	if err := g.Apply(context.Background(), proxyParams()); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.failLs = true
	l.mu.Unlock()
	if g.Check() {
		t.Fatal("an unreadable table passed")
	}
}

// A table with no proxy chains is correct when it reads back as applied, so the
// timer leaves it alone: before, every pass tore it down and built it again.
func TestHealLeavesATableOfP4Alone(t *testing.T) {
	ctx := context.Background()
	g, l, _ := newGuard()
	if err := g.Apply(ctx, params()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		g.Heal(ctx)
	}
	l.mu.Lock()
	n := l.applied
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("the table was applied %d times", n)
	}
	// It is still repaired when it does differ.
	l.tamper()
	g.Heal(ctx)
	l.mu.Lock()
	n = l.applied
	l.mu.Unlock()
	if n != 2 {
		t.Fatalf("the tampered table was applied %d times in all", n)
	}
}
