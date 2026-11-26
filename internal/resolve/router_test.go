package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/route"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// fake is an Exchanger a test can break.
type fake struct {
	name  string
	down  atomic.Bool
	rcode atomic.Int32
	hits  atomic.Int64
	stall atomic.Bool
}

func (f *fake) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.hits.Add(1)
	if f.stall.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.down.Load() {
		return nil, errors.New("down")
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = int(f.rcode.Load())
	if m.Rcode != 0 {
		return m, nil
	}
	// the answer names the answerer, so a test can see who answered
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{f.name}})
	return m, nil
}

func id(b byte) [16]byte { return [16]byte{b} }

func idb(b byte) []byte { x := id(b); return x[:] }

func who(t *testing.T, r *Router, name string, qt uint16) string {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qt)
	resp, _, err := r.Exchange(context.Background(), q)
	if err != nil {
		return "error"
	}
	if len(resp.Answer) == 0 {
		return "rcode" + dns.RcodeToString[resp.Rcode]
	}
	return resp.Answer[0].(*dns.TXT).Txt[0]
}

func newTestRouter(t *testing.T, cfg RouterConfig) *Router {
	t.Helper()
	cfg.IntervalUnit = 5 * time.Millisecond
	r, err := NewRouter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestRecursiveUsesOnlyLocal(t *testing.T) {
	local, up := &fake{name: "local"}, &fake{name: "up"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: local}, Upstreams: []Member{{ID: id(1), X: up}}})
	if got := who(t, r, "example.com", dns.TypeA); got != "local" {
		t.Fatal(got)
	}
	if up.hits.Load() != 0 {
		t.Fatal("recursive mode touched an upstream")
	}
	if rt := r.Route(&names.Name{}, 1); rt != "" {
		t.Fatalf("route %q", rt)
	}
}

// Upstream mode: the configured order, failover on a transport error and on
// SERVFAIL, and the first upstream killed.
func TestUpstreamModeFailsOverInOrder(t *testing.T) {
	a, b, c := &fake{name: "a"}, &fake{name: "b"}, &fake{name: "c"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
		Upstreams: []Member{{ID: id(1), X: a, Every: 3600 * time.Second}, {ID: id(2), X: b, Every: 3600 * time.Second}, {ID: id(3), X: c, Every: 3600 * time.Second}}})
	if got := who(t, r, "example.com", dns.TypeA); got != "a" {
		t.Fatalf("first: %s", got)
	}
	a.down.Store(true)
	if got := who(t, r, "example.com", dns.TypeA); got != "b" {
		t.Fatalf("after killing a: %s", got)
	}
	b.rcode.Store(dns.RcodeServerFailure) // SERVFAIL is a failure of that upstream too
	if got := who(t, r, "example.com", dns.TypeA); got != "c" {
		t.Fatalf("after b SERVFAIL: %s", got)
	}
	c.down.Store(true)
	// All fail: the last reply is returned (the SERVFAIL), not a hang.
	if got := who(t, r, "example.com", dns.TypeA); got != "rcodeSERVFAIL" {
		t.Fatalf("all down: %s", got)
	}
	b.down.Store(true)
	if got := who(t, r, "example.com", dns.TypeA); got != "error" {
		t.Fatalf("all errors: %s", got)
	}
}

// Three failed checks in a row take an upstream out of the order until a check
// passes; the unhealthy one is still tried when nothing else is left.
func TestHealthDownAndUp(t *testing.T) {
	a, b := &fake{name: "a"}, &fake{name: "b"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
		Upstreams: []Member{{ID: id(1), X: a, Every: 1 * time.Second}, {ID: id(2), X: b, Every: 3600 * time.Second}}})
	a.down.Store(true)
	waitFor(t, func() bool { return !healthOf(r, id(1)) }, "a to go down by its checks")
	if !healthOf(r, id(2)) {
		t.Fatal("b is down too")
	}
	before := a.hits.Load()
	for i := 0; i < 5; i++ {
		who(t, r, "example.com", dns.TypeA) // b answers first now
	}
	// a is last in the order while it is down, so b answered.
	if got := who(t, r, "example.com", dns.TypeA); got != "b" {
		t.Fatalf("got %s", got)
	}
	_ = before
	a.down.Store(false)
	waitFor(t, func() bool { return healthOf(r, id(1)) }, "a to come back")
	if got := who(t, r, "example.com", dns.TypeA); got != "a" {
		t.Fatalf("a recovered but %s answered", got)
	}
}

func TestLocalHealthUnderTheReservedID(t *testing.T) {
	local := &fake{name: "local"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: local, Every: time.Second}})
	local.down.Store(true)
	lid := wire.LocalUnboundID()
	waitFor(t, func() bool { return !healthOf(r, lid) }, "the local Unbound to be seen down")
	local.down.Store(false)
	waitFor(t, func() bool { return healthOf(r, lid) }, "the local Unbound to recover")
	if h := r.Health(); len(h) != 1 {
		t.Fatalf("recursive mode reports %d paths, want only the local Unbound", len(h))
	}
}

func healthOf(r *Router, id [16]byte) bool {
	for _, h := range r.Health() {
		if h.ID == id {
			return h.Healthy
		}
	}
	return false
}

func waitFor(t *testing.T, f func() bool, what string) {
	t.Helper()
	waitWithin(t, 5*time.Second, f, what)
}

func waitWithin(t *testing.T, d time.Duration, f func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type geo map[string]bool

func (g geo) Has(tag string, n *names.Name) bool { return g[tag+"|"+string(n.Wire())] }

// Hybrid: rules in order, the first match wins, one rule of each kind, the route
// is in the cache key, and an unmatched name goes to the local Unbound.
func TestHybridRuleOrderAndKinds(t *testing.T) {
	local := &fake{name: "local"}
	g1, g2, g3, g4, g5 := &fake{name: "g-domain"}, &fake{name: "g-suffix"}, &fake{name: "g-geo"}, &fake{name: "g-qtype"}, &fake{name: "g-tld"}
	mk := func(order uint32, typ, val, group string) route.Rule {
		r, err := route.ParseRule(order, typ, val, group, false)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	ex := names.MustString("geo.example.org")
	r := newTestRouter(t, RouterConfig{
		Mode:  commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
		Local: Member{X: local},
		Upstreams: []Member{
			{ID: id(1), X: g1, Every: 3600 * time.Second}, {ID: id(2), X: g2, Every: 3600 * time.Second}, {ID: id(3), X: g3, Every: 3600 * time.Second},
			{ID: id(4), X: g4, Every: 3600 * time.Second}, {ID: id(5), X: g5, Every: 3600 * time.Second},
		},
		Groups: map[string][][16]byte{"dom": {id(1)}, "suf": {id(2)}, "geo": {id(3)}, "qt": {id(4)}, "tld": {id(5)}},
		// Deliberately not in order, and two rules that would both match
		// "www.corp.example.com": the lower order must win.
		Rules: []route.Rule{
			mk(50, "tld", "net", "tld"),
			mk(10, "domain", "www.corp.example.com", "dom"),
			mk(20, "suffix", "example.com", "suf"),
			mk(30, "geosite", "geosite:ir", "geo"),
			mk(40, "qtype", "MX", "qt"),
		},
		Geo: geo{"geosite:ir|" + string(ex.Wire()): true},
	})
	cases := []struct {
		name string
		qt   uint16
		want string
		rt   string
	}{
		{"www.corp.example.com", dns.TypeA, "g-domain", "g:dom"},
		{"mail.corp.example.com", dns.TypeA, "g-suffix", "g:suf"},
		{"example.com", dns.TypeA, "g-suffix", "g:suf"},
		{"geo.example.org", dns.TypeA, "g-geo", "g:geo"},
		{"other.example.org", dns.TypeMX, "g-qtype", "g:qt"},
		{"host.example.net", dns.TypeA, "g-tld", "g:tld"},
		{"plain.example.org", dns.TypeA, "local", ""},
	}
	for _, tc := range cases {
		if got := who(t, r, tc.name, tc.qt); got != tc.want {
			t.Errorf("%s: answered by %s, want %s", tc.name, got, tc.want)
		}
		n := names.MustString(tc.name)
		if rt := r.Route(&n, tc.qt); rt != tc.rt {
			t.Errorf("%s: route %q, want %q", tc.name, rt, tc.rt)
		}
	}
	// A group whose upstreams fail falls to the node's default mode (the local
	// Unbound), in order.
	g1.down.Store(true)
	if got := who(t, r, "www.corp.example.com", dns.TypeA); got != "local" {
		t.Fatalf("failed group did not fall to the default: %s", got)
	}
}

// The route Exchange takes must equal the route the cache key was built with,
// for a name whose presentation form carries escapes (p4n-W7-r3-1): a label of
// 20 bytes of 0x80 renders as 80 characters of \DDD.
func TestExchangeRouteMatchesKeyRouteForEscapedLabels(t *testing.T) {
	local, g := &fake{name: "local"}, &fake{name: "g-ir"}
	rule, err := route.ParseRule(10, "suffix", "ir", "ir", false)
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRouter(t, RouterConfig{
		Mode:      commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
		Local:     Member{X: local},
		Upstreams: []Member{{ID: id(1), X: g, Every: 3600 * time.Second}},
		Groups:    map[string][][16]byte{"ir": {id(1)}},
		Rules:     []route.Rule{rule},
	})
	w := append([]byte{20}, make([]byte, 20)...)
	for i := 1; i <= 20; i++ {
		w[i] = 0x80
	}
	w = append(w, "\x02ir\x00"...)
	n, err := names.FromCanonicalWire(w)
	if err != nil {
		t.Fatal(err)
	}
	keyRoute := r.Route(&n, dns.TypeA)
	if keyRoute != "g:ir" {
		t.Fatalf("key route %q", keyRoute)
	}
	dn, _, err := dns.UnpackDomainName(n.Wire(), 0)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion(dn, dns.TypeA)
	_, got, err := r.Exchange(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if got != keyRoute {
		t.Fatalf("Exchange route %q, key route %q", got, keyRoute)
	}
	if g.hits.Load() == 0 {
		t.Fatal("the rule's group was bypassed")
	}
}

// An upstream that stalls costs its timeout and then the next one answers.
func TestStalledUpstreamFailsOverWithinTheCallersContext(t *testing.T) {
	a, b := &fake{name: "a"}, &fake{name: "b"}
	a.stall.Store(true)
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
		Upstreams: []Member{{ID: id(1), X: a, Every: 3600 * time.Second}, {ID: id(2), X: b, Every: 3600 * time.Second}}})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	// The stalled first upstream gets half of what is left, so b still answers
	// inside the caller's deadline (p4n-W7-r7-1).
	resp, _, err := r.Exchange(ctx, q)
	if err != nil || resp.Answer[0].(*dns.TXT).Txt[0] != "b" {
		t.Fatalf("a stalled first upstream starved the second: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the stalled upstream held the caller past its context")
	}
	// With every upstream stalled the caller's deadline still bounds the call.
	b.stall.Store(true)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	start = time.Now()
	if _, _, err := r.Exchange(ctx2, q); err == nil {
		t.Fatal("answered through stalled upstreams")
	}
	if time.Since(start) > time.Second {
		t.Fatal("stalled upstreams held the caller past its context")
	}
}

// p4n-W7-r7-1: an upstream that goes dark between two checks (packets dropped,
// so every call runs to its timeout) must not stay first in the order for
// 3 x health_interval_s, and must not use the whole fetch deadline while the
// next upstream is healthy. Health still follows the checks alone.
func TestDeadFirstUpstreamIsPassedOverBeforeItsChecksFail(t *testing.T) {
	for _, mode := range []commonv1.ResolveMode{commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, commonv1.ResolveMode_RESOLVE_MODE_HYBRID} {
		t.Run(mode.String(), func(t *testing.T) {
			rule, rerr := route.ParseRule(10, "suffix", "example.com", "g", false)
			if rerr != nil {
				t.Fatal(rerr)
			}
			a, b, local := &fake{name: "a"}, &fake{name: "b"}, &fake{name: "local"}
			cfg := RouterConfig{Mode: mode, Local: Member{X: local, Every: 3600 * time.Second},
				Upstreams: []Member{{ID: id(1), X: a, Every: 3600 * time.Second}, {ID: id(2), X: b, Every: 3600 * time.Second}},
				Groups:    map[string][][16]byte{"g": {id(1), id(2)}},
				Rules:     []route.Rule{rule}}
			r := newTestRouter(t, cfg)
			// the first checks have run and passed
			// upstream mode does not check the local Unbound (only used paths are)
			waitFor(t, func() bool {
				return a.hits.Load() >= 1 && b.hits.Load() >= 1 && (mode == commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM || local.hits.Load() >= 1)
			}, "the first checks")
			a.stall.Store(true)
			want := "b"
			// The first query: a gets half the deadline, b answers inside the rest.
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			q := new(dns.Msg)
			q.SetQuestion("www.example.com.", dns.TypeA)
			start := time.Now()
			resp, _, err := r.Exchange(ctx, q)
			if err != nil || resp.Answer[0].(*dns.TXT).Txt[0] != want {
				t.Fatalf("first query after a went dark: %v", err)
			}
			if time.Since(start) > 500*time.Millisecond {
				t.Fatalf("took %v", time.Since(start))
			}
			// After three live failures a is suspect and its check is kicked; the check
			// stalls too, and when it fails a is dark and out of the order, so b
			// answers at once. Dark needs the check's word: a deliberate change of the
			// model after review round 8, not a looser assertion.
			for i := 0; i < failsToDown; i++ {
				c, cn := context.WithTimeout(context.Background(), 200*time.Millisecond)
				_, _, _ = r.Exchange(c, q)
				cn()
			}
			waitWithin(t, 3*probeTimeout+time.Second, func() bool { return !r.ups[0].preferred() }, "the kicked check to confirm a dark")
			start = time.Now()
			c, cn := context.WithTimeout(context.Background(), 5*time.Second)
			resp, _, err = r.Exchange(c, q)
			cn()
			if err != nil || resp.Answer[0].(*dns.TXT).Txt[0] != want || time.Since(start) > 100*time.Millisecond {
				t.Fatalf("a is still first: err=%v after %v", err, time.Since(start))
			}
			// Health is the checks' alone: a is still healthy (its checks run hourly).
			if !healthOf(r, id(1)) {
				t.Fatal("live errors changed Health")
			}
			if mode != commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM {
				return // a hybrid group leaves a member out until a check passes it
			}
			// In upstream mode a is still tried last: when b fails and a answers, a
			// is back in front for the next query.
			a.stall.Store(false)
			b.down.Store(true)
			if got := who(t, r, "www.example.com", dns.TypeA); got != "a" {
				t.Fatalf("a recovered but %s answered", got)
			}
			b.down.Store(false)
			if got := who(t, r, "www.example.com", dns.TypeA); got != "a" {
				t.Fatalf("a answered once and is not first again: %s", got)
			}
		})
	}
}

// p4n-W7-r7-2: upstream mode whose every row was refused still gives a Router,
// so the hub can be told those paths are unhealthy; queries get no path.
func TestFromWireAllRefusedStillReports(t *testing.T) {
	addr, _, _ := startPlain(t, false)
	loc := &hubv1.Upstream{Id: idb(2), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr.String(), TimeoutMs: 1000, ViaLocation: 7}
	nc := &hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, Upstreams: []*hubv1.Upstream{loc}}
	r, err := NewRouterFromWire(nc, Member{}, nil, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.Refused()) != 1 || healthOf(r, id(2)) {
		t.Fatalf("refused %+v, healthy %v", r.Refused(), healthOf(r, id(2)))
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if _, _, err := r.Exchange(context.Background(), q); !errors.Is(err, ErrNoPath) {
		t.Fatalf("err %v", err)
	}
	// No row at all is still an error.
	if _, err := NewRouterFromWire(&hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM}, Member{}, nil, 0); err == nil {
		t.Fatal("upstream mode with no rows")
	}
}

func TestExchangeNeedsOneQuestion(t *testing.T) {
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: &fake{name: "l"}}})
	if _, _, err := r.Exchange(context.Background(), new(dns.Msg)); !errors.Is(err, ErrBadQuery) {
		t.Fatal(err)
	}
}

func TestNewRouterRefusals(t *testing.T) {
	if _, err := NewRouter(RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID}); err == nil {
		t.Fatal("hybrid with no Unbound")
	}
	if _, err := NewRouter(RouterConfig{Mode: 9}); err == nil {
		t.Fatal("bad mode")
	}
	if _, err := NewRouter(RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM}); err == nil {
		t.Fatal("upstream mode with none")
	}
}

// NewRouterFromWire builds every upstream through NewUpstream, leaves out one it
// refuses (via_location, until P4b), and reports it unhealthy.
func TestFromWireRefusesViaLocationAndReportsIt(t *testing.T) {
	addr, _, _ := startPlain(t, false)
	local := &fake{name: "local"}
	good := &hubv1.Upstream{Id: idb(1), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr.String(), TimeoutMs: 1000, HealthIntervalS: 3600}
	loc := &hubv1.Upstream{Id: idb(2), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr.String(), TimeoutMs: 1000, ViaLocation: 7}
	nc := &hubv1.NodeConfig{
		Mode:      commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
		Upstreams: []*hubv1.Upstream{good, loc},
		Groups:    []*hubv1.UpstreamGroup{{Name: "g", UpstreamIds: [][]byte{idb(2), idb(1)}}},
		Rules:     []*hubv1.ResolverRule{{Order: 1, MatchType: "suffix", MatchValue: "example.com", Group: "g"}},
	}
	r, err := NewRouterFromWire(nc, Member{X: local, Every: 3600 * time.Second}, nil, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.Refused()) != 1 || !errors.Is(r.Refused()[0].Err, ErrViaLocation) {
		t.Fatalf("refused: %+v", r.Refused())
	}
	if healthOf(r, id(2)) {
		t.Fatal("a refused upstream reports healthy")
	}
	// The group still answers through the one that was built: the stand-in
	// server answers an A with 192.0.2.1.
	q := new(dns.Msg)
	q.SetQuestion("www.example.com.", dns.TypeA)
	resp, rt, err := r.Exchange(context.Background(), q)
	if err != nil || rt != "g:g" || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("resp=%v rt=%q err=%v", resp, rt, err)
	}
}

// The upstream killed for real: two loopback servers behind NewUpstream, the
// first shut down, and the second answers.
func TestFailoverOverRealUpstreams(t *testing.T) {
	first, _, _ := startPlain(t, false)
	second, _, _ := startPlain(t, false)
	// Own the first server so it can be stopped: a closed port answers nothing.
	var stop net.PacketConn
	var err error
	killable := scanAndListenUDP(t, &stop)
	_ = first
	mkUp := func(ap netip.AddrPort) *Upstream {
		u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: ap.String(), Timeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = u.Close() })
		return u
	}
	_ = err
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
		Upstreams: []Member{{ID: id(1), X: mkUp(killable), Every: 3600 * time.Second}, {ID: id(2), X: mkUp(second), Every: 3600 * time.Second}}})
	// The killable port is open but silent: the query to it times out, then the
	// second upstream answers.
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	resp, _, err := r.Exchange(context.Background(), q)
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("%v %v", resp, err)
	}
	_ = stop.Close()
}

func scanAndListenUDP(t *testing.T, out *net.PacketConn) netip.AddrPort {
	t.Helper()
	var pc net.PacketConn
	port := scanPorts(t, func(p int) error {
		var err error
		pc, err = net.ListenPacket("udp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	*out = pc
	t.Cleanup(func() { _ = pc.Close() })
	return netip.AddrPortFrom(loopback, uint16(port))
}

// A burst of concurrent queries during a failover never panics or races.
func TestConcurrentExchangeAndHealth(t *testing.T) {
	a, b := &fake{name: "a"}, &fake{name: "b"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
		Upstreams: []Member{{ID: id(1), X: a, Every: time.Second}, {ID: id(2), X: b, Every: time.Second}}})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if j == 10 && i == 0 {
					a.down.Store(true)
				}
				who(t, r, "example.com", dns.TypeA)
			}
		}(i)
	}
	wg.Wait()
	if !strings.HasPrefix(who(t, r, "example.com", dns.TypeA), "b") {
		t.Fatal("not failed over")
	}
}

// adFake answers with AD set and a bogus Extended DNS Error, as a forging or
// careless upstream could.
type adFake struct{ name string }

func (f *adFake) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.AuthenticatedData = true
	m.SetEdns0(1232, true)
	m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: 6}, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 24, Address: net.ParseIP("192.0.2.0").To4()})
	m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{f.name}}}
	return m, nil
}

func exchangeOnce(t *testing.T, r *Router) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("a.example.com.", dns.TypeTXT)
	q.SetEdns0(1232, true)
	resp, _, err := r.Exchange(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func hasEDE(m *dns.Msg) bool {
	if o := m.IsEdns0(); o != nil {
		for _, x := range o.Option {
			if _, ok := x.(*dns.EDNS0_EDE); ok {
				return true
			}
		}
	}
	return false
}

// SC 5.11: the validation verdict is the local Unbound's, or an encrypted upstream
// the admin marked trusted. An untrusted member's AD and Extended DNS Errors do
// not reach the evaluator; its other EDNS options (ECS) do (p4n-W7-r1-2, -8).
func TestADOnlyFromTrustedMembers(t *testing.T) {
	for _, c := range []struct {
		name   string
		trust  bool
		wantAD bool
	}{{"untrusted", false, false}, {"trusted", true, true}} {
		r := newTestRouter(t, RouterConfig{
			Mode:      commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
			Upstreams: []Member{{ID: id(1), X: &adFake{name: "u"}, Every: time.Hour, Trusted: c.trust}},
		})
		resp := exchangeOnce(t, r)
		if resp.AuthenticatedData != c.wantAD {
			t.Errorf("%s: AD=%v", c.name, resp.AuthenticatedData)
		}
		if !c.trust && hasEDE(resp) {
			t.Errorf("%s: an EDE of an untrusted upstream survived", c.name)
		}
		if c.trust && !hasEDE(resp) {
			t.Errorf("%s: a trusted upstream's EDE was dropped", c.name)
		}
		var sawECS bool
		for _, o := range resp.IsEdns0().Option {
			if _, ok := o.(*dns.EDNS0_SUBNET); ok {
				sawECS = true
			}
		}
		if !sawECS {
			t.Errorf("%s: the ECS option was lost", c.name)
		}
	}
	// The local Unbound is trusted by construction.
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: &adFake{name: "l"}, Every: time.Hour}})
	if !exchangeOnce(t, r).AuthenticatedData {
		t.Error("the local Unbound's AD was cleared")
	}
}

// A plain udp upstream is never trusted, even when its row says so.
func TestFromWireTrustedMapping(t *testing.T) {
	addr, _, _ := startPlain(t, false)
	mk := func(b byte, kind commonv1.UpstreamKind, trusted bool) *hubv1.Upstream {
		return &hubv1.Upstream{Id: idb(b), Kind: kind, Address: addr.String(), TlsName: "dns.example", BootstrapIp: addr.Addr().AsSlice(), TimeoutMs: 1000, HealthIntervalS: 3600, Trusted: trusted}
	}
	nc := &hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, Upstreams: []*hubv1.Upstream{
		mk(1, commonv1.UpstreamKind_UPSTREAM_KIND_UDP, true),
		mk(2, commonv1.UpstreamKind_UPSTREAM_KIND_DOT, true),
		mk(3, commonv1.UpstreamKind_UPSTREAM_KIND_DOT, false),
		mk(4, commonv1.UpstreamKind_UPSTREAM_KIND_DOH, true),
	}}
	r, err := NewRouterFromWire(nc, Member{}, nil, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.Refused()) != 0 {
		t.Fatalf("refused: %+v", r.Refused())
	}
	got := map[byte]bool{}
	for _, m := range r.ups {
		got[m.ID[0]] = m.Trusted
	}
	if got[1] || !got[2] || got[3] || !got[4] {
		t.Fatalf("trusted by id: %v", got)
	}
}

// pathCut stands for an Unbound that lost its path to the authorities: names it
// has cached (serve-expired) still answer, anything new, which is what a health
// probe asks, is SERVFAIL.
type pathCut struct{ cut atomic.Bool }

func (p *pathCut) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetReply(req)
	label := strings.SplitN(req.Question[0].Name, ".", 2)[0]
	if p.cut.Load() && len(label) == 32 { // the probe's 16 random bytes in hex
		m.Rcode = dns.RcodeServerFailure
	}
	return m, nil
}

// p4n-W7-r6-3: Health comes from the checks alone. Client queries that are
// answered between two checks (from the cache, or with SERVFAIL) must neither
// keep a dead path "healthy" nor reset the failure count.
func TestHealthIsTheChecksAloneUnderTraffic(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  func(*pathCut)
	}{
		{"fresh names SERVFAIL, cached names answer", func(p *pathCut) { p.cut.Store(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &pathCut{}
			r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: p, Every: time.Second}})
			lid := wire.LocalUnboundID()
			if !healthOf(r, lid) {
				t.Fatal("not healthy to begin with")
			}
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() { // client traffic: a cached name that answers, a new name that SERVFAILs
				defer close(done)
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					q := new(dns.Msg)
					q.SetQuestion("cached.example.com.", dns.TypeA)
					_, _, _ = r.Exchange(context.Background(), q)
					q = new(dns.Msg)
					q.SetQuestion("0123456789abcdef0123456789abcdef.example.com.", dns.TypeA)
					_, _, _ = r.Exchange(context.Background(), q)
					time.Sleep(200 * time.Microsecond)
				}
			}()
			defer func() { close(stop); <-done }()
			tc.cut(p)
			waitFor(t, func() bool { return !healthOf(r, lid) }, "the cut path to be seen down while traffic flows")
			p.cut.Store(false)
			waitFor(t, func() bool { return healthOf(r, lid) }, "the path to come back by a check")
		})
	}
}

// Live transport errors on a quiet node do not mark a member down: three tenant
// queries into a zone whose servers never answer must not fire F2.
func TestLiveErrorsDoNotTakeAMemberDown(t *testing.T) {
	local := &fake{name: "local"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: local, Every: 3600 * time.Second}})
	lid := wire.LocalUnboundID()
	waitFor(t, func() bool { return local.hits.Load() >= 1 }, "the first check")
	local.down.Store(true)
	for i := 0; i < 10; i++ {
		who(t, r, "blackholed.example.com", dns.TypeA)
	}
	if !healthOf(r, lid) {
		t.Fatal("ten live errors marked the member down; only checks may")
	}
}

// nameFake answers at once, except for names under stallUnder, where its servers
// "never answer" and the call runs to its deadline. Probes (a random 32-hex label
// under com, net or org) are counted and answered.
type nameFake struct {
	name       string
	stallUnder string
	delay      time.Duration
	probeDelay time.Duration // how long a check waits for its answer
	down       atomic.Bool
	probes     atomic.Int64
}

func (f *nameFake) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	qn := req.Question[0].Name
	if label := strings.SplitN(qn, ".", 2)[0]; len(label) == 32 {
		f.probes.Add(1)
		if f.probeDelay > 0 {
			select {
			case <-time.After(f.probeDelay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	} else {
		if f.stallUnder != "" && strings.HasSuffix(qn, f.stallUnder) || f.down.Load() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: qn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{f.name}})
	return m, nil
}

// p4n-W7-r8-3: members the checks hold down must not take their share of the
// deadline ahead of time. The one healthy upstream, slow but inside its own
// timeout, still answers.
func TestHealthyMemberKeepsItsShareBehindHeldDownOnes(t *testing.T) {
	a := &nameFake{name: "a", delay: 700 * time.Millisecond}
	ups := []Member{{ID: id(1), X: a, Every: 3600 * time.Second}}
	var dead []*nameFake
	for i := 2; i <= 4; i++ {
		d := &nameFake{name: "d"}
		d.down.Store(true)
		dead = append(dead, d)
		ups = append(ups, Member{ID: id(byte(i)), X: d, Every: 3600 * time.Second})
	}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, Upstreams: ups})
	waitFor(t, func() bool {
		n := a.probes.Load()
		for _, d := range dead {
			n += d.probes.Load()
		}
		return n >= 4
	}, "the first checks")
	for _, m := range r.ups[1:] {
		m.healthy.Store(false) // what three failed checks do
	}
	q := new(dns.Msg)
	q.SetQuestion("slow.example.com.", dns.TypeA)
	// 2 s in all: the healthy member has one half, 1 s, for its 0.7 s. Before the
	// fix it had a quarter, 0.5 s.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, _, err := r.Exchange(ctx, q)
	if err != nil || resp.Answer[0].(*dns.TXT).Txt[0] != "a" {
		t.Fatalf("the healthy member was cut short by members that are down: %v", err)
	}
}

// p4n-W7-r8-4: a name whose servers never answer must not take a group member
// out of service. A member that answers other names is not on a dark path, and
// a burst that reaches the threshold gets a probe of a random name at once.
func TestStallingNameDoesNotDemoteAGroupMember(t *testing.T) {
	rule, err := route.ParseRule(10, "suffix", "test", "g", false)
	if err != nil {
		t.Fatal(err)
	}
	build := func(t *testing.T) (*Router, *nameFake) {
		u1, local := &nameFake{name: "u1", stallUnder: ".y.test."}, &nameFake{name: "local"}
		r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
			Local:     Member{X: local, Every: 3600 * time.Second},
			Upstreams: []Member{{ID: id(1), X: u1, Every: 3600 * time.Second}},
			Groups:    map[string][][16]byte{"g": {id(1)}}, Rules: []route.Rule{rule}})
		waitFor(t, func() bool { return u1.probes.Load() >= 1 && local.probes.Load() >= 1 }, "the first checks")
		return r, u1
	}
	burst := func(r *Router, n int, between func()) {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				q := new(dns.Msg)
				q.SetQuestion("n"+string(rune('a'+i))+".y.test.", dns.TypeA)
				ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
				defer cancel()
				_, _, _ = r.Exchange(ctx, q)
			}(i)
		}
		if between != nil {
			time.Sleep(50 * time.Millisecond)
			between()
		}
		wg.Wait()
	}

	t.Run("answers to other names while the burst is out", func(t *testing.T) {
		r, _ := build(t)
		burst(r, 10, func() {
			if got := who(t, r, "x.test", dns.TypeA); got != "u1" {
				t.Errorf("x.test answered by %s", got)
			}
		})
		if !r.ups[0].preferred() {
			t.Fatal("a burst of stalling names took the member out while it answered others")
		}
		if got := who(t, r, "x.test", dns.TypeA); got != "u1" {
			t.Fatalf("after the burst x.test is answered by %s", got)
		}
	})

	t.Run("a burst alone is checked at once and the member comes back", func(t *testing.T) {
		r, u1 := build(t)
		burst(r, 10, nil)
		waitFor(t, func() bool { return u1.probes.Load() >= 2 }, "the probe after the burst")
		waitFor(t, func() bool { return r.ups[0].preferred() }, "the member to be preferred again")
		if got := who(t, r, "x.test", dns.TypeA); got != "u1" {
			t.Fatalf("x.test answered by %s", got)
		}
	})
}
