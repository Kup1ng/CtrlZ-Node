package nft

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
)

func params() Params {
	return Params{
		DNSIP:      netip.MustParseAddr("203.0.114.9"),
		PanelAddrs: []netip.Addr{netip.MustParseAddr("198.51.100.20")},
		FreePortLo: 40000, FreePortHi: 40999,
	}
}

func TestRenderNotrackRules(t *testing.T) {
	s, err := Render(params())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip daddr 203.0.114.9 udp dport 53 notrack",
		"ip daddr 203.0.114.9 tcp dport 53 notrack",
		"ip saddr 203.0.114.9 udp sport 53 notrack",
		"ip saddr 203.0.114.9 tcp sport 53 notrack",
		"udp sport 53 udp dport 40000-40999 notrack",
		"udp sport 40000-40999 udp dport 53 notrack",
		"udp dport 123 ip daddr != { 198.51.100.20 } drop",
		"tcp dport 4460 ip daddr != { 198.51.100.20 } drop",
		"delete table inet ctrlz_agent",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q\n%s", want, s)
		}
	}
	// no panel address of a family: that family's NTP is closed entirely
	if !strings.Contains(s, "udp dport 123 meta nfproto ipv6 drop") {
		t.Error("IPv6 NTP is not closed when the panel has no IPv6 address")
	}
}

// L13 clause 1: nothing in the table rates, meters or counts packets, and the
// only drops are the NTP and NTS-KE rules that name the panel host.
func TestNothingRatesOrMeters(t *testing.T) {
	for _, p := range []Params{
		params(),
		{DNSIP: netip.MustParseAddr("2001:db8::53"), PanelAddrs: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.20")}, FreePortLo: 40000, FreePortHi: 40999},
	} {
		s, err := Render(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"limit", "meter", "quota", "ct count", "ct state", "flowtable", "dynamic", "timeout", "size ", "counter", "queue", "reject", "set "} {
			if strings.Contains(s, banned) {
				t.Errorf("the table holds %q", banned)
			}
		}
		for _, line := range strings.Split(s, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasSuffix(l, " drop") && !regexp.MustCompile(`^(udp|tcp) dport (123|4460) `).MatchString(l) {
				t.Errorf("a drop that is not an NTP or NTS-KE rule: %s", l)
			}
			// Nothing but notrack touches port 53 traffic.
			if strings.Contains(l, "53") && strings.Contains(l, "dport") && !strings.HasSuffix(l, "notrack") {
				t.Errorf("a rule on port 53 that is not notrack: %s", l)
			}
		}
	}
}

func TestIPv6DNSIP(t *testing.T) {
	s, err := Render(Params{DNSIP: netip.MustParseAddr("2001:db8::53"), PanelAddrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")}, FreePortLo: 40000, FreePortHi: 40999})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "ip6 daddr 2001:db8::53 udp dport 53 notrack") || !strings.Contains(s, "ip6 daddr != { 2001:db8::1 } drop") {
		t.Error(s)
	}
}

func TestRenderRefuses(t *testing.T) {
	for _, m := range []func(*Params){
		func(p *Params) { p.DNSIP = netip.Addr{} },
		func(p *Params) { p.DNSIP = netip.IPv4Unspecified() },
		func(p *Params) { p.PanelAddrs = nil },
		func(p *Params) { p.FreePortLo = 10 },
	} {
		p := params()
		m(&p)
		if _, err := Render(p); err == nil {
			t.Error("accepted")
		}
	}
}

func TestApplyChecksThenApplies(t *testing.T) {
	r := &fake.Runner{}
	if err := Apply(context.Background(), r, params()); err != nil {
		t.Fatal(err)
	}
	c := r.Calls()
	if len(c) != 2 || c[0].String() != "nft -c -f -" || c[1].String() != "nft -f -" {
		t.Fatalf("calls: %v", r.Lines())
	}
	if !strings.Contains(string(c[1].Stdin), "notrack") || string(c[0].Stdin) != string(c[1].Stdin) {
		t.Error("the script that was checked is not the one applied")
	}
	// a refused check applies nothing
	r2 := &fake.Runner{Reply: func(c fake.Call) ([]byte, error) {
		if len(c.Args) > 0 && c.Args[0] == "-c" {
			return nil, errors.New("bad")
		}
		return nil, nil
	}}
	if err := Apply(context.Background(), r2, params()); err == nil || len(r2.Calls()) != 1 {
		t.Errorf("err=%v calls=%v", err, r2.Lines())
	}
}
