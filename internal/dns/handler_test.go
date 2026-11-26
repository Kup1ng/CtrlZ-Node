package dns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
)

func wantA(t *testing.T, label string, r listen.Reply, want ...string) {
	t.Helper()
	if r.Msg == nil {
		t.Fatalf("%s: no message (drop=%v status=%d)", label, r.Drop, r.Status)
	}
	got := aAddrs(r.Msg)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: A %v (rcode %s), want %v", label, got, rcodeOf(r), want)
	}
}

// Identity on every transport, and the policy of that identity: Endpoint A blocks
// what it does not allow, Endpoint B lets everything but ads through.
func TestIdentifiedPolicyOnEveryTransport(t *testing.T) {
	w := newWorld(t)
	for _, a := range allAskers() {
		t.Run(a.name, func(t *testing.T) {
			// A: Default Block answers 0.0.0.0, one explicit Bypass is the true answer.
			wantA(t, "A blocked", a.ask(w, epA, "www.example.com", dns.TypeA), "0.0.0.0")
			wantA(t, "A allowed", a.ask(w, epA, "allow.example.com", dns.TypeA), "192.0.2.30")
			// B: Default Bypass, one Block rule.
			wantA(t, "B bypass", a.ask(w, epB, "www.example.com", dns.TypeA), "192.0.2.20")
			wantA(t, "B blocked", a.ask(w, epB, "ads.example.com", dns.TypeA), "0.0.0.0")
		})
	}
}

// A query on tenant A's identity never gets tenant B's policy, cache entry or
// answer, in either order, on any transport (T-041, two-tenant).
func TestTwoTenantsShareNoPolicyOrCacheEntry(t *testing.T) {
	for _, a := range allAskers() {
		for _, bFirst := range []bool{true, false} {
			t.Run(a.name, func(t *testing.T) {
				w := newWorld(t)
				first, second := byte(epA), byte(epB)
				if bFirst {
					first, second = epB, epA
				}
				// "www.example.com": A blocks, B passes.
				r1 := a.ask(w, first, "www.example.com", dns.TypeA)
				r2 := a.ask(w, second, "www.example.com", dns.TypeA)
				want := map[byte]string{epA: "0.0.0.0", epB: "192.0.2.20"}
				wantA(t, "first", r1, want[first])
				wantA(t, "second", r2, want[second])
				// What the cache holds is the true answer, never a synthesized one.
				n := names.MustString("www.example.com")
				key := cache.KeyOf(n, dns.TypeA, 1, sharedpolicy.ResolveParams{}, "")
				ta, ok := w.cache.Get(cache.Shared, key)
				if !ok {
					t.Fatal("true answer not cached")
				}
				for _, rr := range ta.Answer {
					if addr, _ := rr.Addr(); addr.String() != "192.0.2.20" {
						t.Fatalf("cache holds %v: a synthesized answer got in", addr)
					}
				}
				// B's cached lookup serves A's next query without a second fetch.
				if h := w.back.hitCount("www.example.com", dns.TypeA); h != 1 {
					t.Fatalf("backend asked %d times for one name", h)
				}
				// And the free segment never saw it.
				if _, ok := w.cache.Get(cache.Free, key); ok {
					t.Fatal("identified answer reached the free segment")
				}
			})
		}
	}
}

// Label tricks: a client label never selects another Endpoint's stack, and a
// label with no row resolves as no client (P3 identities).
func TestClientLabelSelectsOnlyItsOwnEndpointsStack(t *testing.T) {
	w := newWorld(t)
	// G has a client "kid" that blocks www.example.com; G's base passes it.
	r := w.call(qopt{t: listen.DoT, sni: rid(epG) + "-kid." + testZone}, "www.example.com", dns.TypeA)
	wantA(t, "kid on G", r, "0.0.0.0")
	r = w.call(qopt{t: listen.DoT, sni: rid(epG) + "-other." + testZone}, "www.example.com", dns.TypeA)
	wantA(t, "unknown label on G", r, "192.0.2.20")
	// The same label on B, which has no such client, changes nothing.
	r = w.call(qopt{t: listen.DoT, sni: rid(epB) + "-kid." + testZone}, "www.example.com", dns.TypeA)
	wantA(t, "kid on B", r, "192.0.2.20")
	// DoH: the path client, and the authority client when the path has none.
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+tok(epG)+"/kid", rid(epG)+"."+testZone)}, "www.example.com", dns.TypeA)
	wantA(t, "path client", r, "0.0.0.0")
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+tok(epG), rid(epG)+"-kid."+testZone)}, "www.example.com", dns.TypeA)
	wantA(t, "authority client", r, "0.0.0.0")
	// Form B of the path: id in the path, token second, the authority may be the apex.
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+rid(epG)+"/"+tok(epG)+"/kid", testZone)}, "www.example.com", dns.TypeA)
	wantA(t, "form B", r, "0.0.0.0")
	// A's token under B's rid is not B's, and not A's: 404.
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+tok(epA), rid(epB)+"."+testZone)}, "www.example.com", dns.TypeA)
	if r.Status != 404 {
		t.Fatalf("token of A on B's rid: %+v", r)
	}
	// B's rid in the path overrides an authority that names A (form B): B's stack.
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+rid(epB)+"/"+tok(epB), rid(epA)+"."+testZone)}, "www.example.com", dns.TypeA)
	wantA(t, "form B, authority of A", r, "192.0.2.20")
}

func TestDoHIdentityFailuresAre404BeforeAnyStep(t *testing.T) {
	w := newWorld(t)
	cases := map[string]*listen.HTTPInfo{
		"unknown rid":     dohInfo("/"+tok(epA), rid(20)+"."+testZone),
		"wrong token":     dohInfo("/"+tok(21), rid(epA)+"."+testZone),
		"apex, form A":    dohInfo("/"+tok(epA), testZone),
		"bad path":        dohInfo("/hello", rid(epA)+"."+testZone),
		"extra segments":  dohInfo("/"+tok(epA)+"/a/b", rid(epA)+"."+testZone),
		"out of zone":     dohInfo("/"+tok(epA), "example.net"),
		"no http info":    nil,
		"form B, bad tok": dohInfo("/"+rid(epA)+"/"+tok(21), testZone),
	}
	for name, info := range cases {
		for _, tr := range []listen.Transport{listen.DoH, listen.DoH3} {
			// Even a system name, which step 2 would answer for anybody, is 404.
			r := w.call(qopt{t: tr, http: info}, "captive.apple.com", dns.TypeA)
			if r.Status != 404 || r.Msg != nil {
				t.Errorf("%s %s: %+v", name, tr, r)
			}
		}
	}
}

// Without an identity: DoT and DoQ are REFUSED, Plain DNS from a stranger is
// REFUSED, a claim whose Endpoint is not held is REFUSED, and a source that is a
// node's dns_ip is dropped (SC 5.2a (b)).
func TestNoIdentity(t *testing.T) {
	w := newWorld(t)
	for _, tr := range []listen.Transport{listen.DoT, listen.DoQ} {
		for _, sni := range []string{testZone, "", "nobody." + testZone, rid(20) + "." + testZone, "www.example.net", "x.y." + testZone} {
			r := w.call(qopt{t: tr, sni: sni}, "www.example.com", dns.TypeA)
			if rcodeOf(r) != "REFUSED" {
				t.Errorf("%s sni=%q: %s", tr, sni, rcodeOf(r))
			}
		}
	}
	for _, tr := range []listen.Transport{listen.UDP, listen.TCP} {
		r := w.call(qopt{t: tr, src: "127.0.0.3"}, "www.example.com", dns.TypeA)
		if rcodeOf(r) != "REFUSED" {
			t.Errorf("%s stranger: %s", tr, rcodeOf(r))
		}
		r = w.call(qopt{t: tr, src: "8.8.4.4"}, "www.example.com", dns.TypeA)
		if !r.Drop || r.Msg != nil {
			t.Errorf("%s node address: %+v", tr, r)
		}
	}
}

// Plain DNS identified by a claim whose Endpoint does not want Plain DNS is a
// stranger, and one whose record is missing from the image is REFUSED, not free.
func TestPlainClaimCases(t *testing.T) {
	w := newWorld(t)
	free := &fakeFree{}
	w.h.cfg.Free = free
	// A stranger goes to the free path when there is one.
	r := w.call(qopt{t: listen.TCP, src: "127.0.0.3"}, "www.example.com", dns.TypeA)
	if !free.called || r.Msg == nil || aAddrs(r.Msg)[0] != "192.0.2.123" {
		t.Fatalf("free path not used: %+v", r)
	}
	// A node's own address is dropped before the free path is asked.
	free.called = false
	r = w.call(qopt{t: listen.TCP, src: "8.8.4.4"}, "www.example.com", dns.TypeA)
	if !r.Drop || free.called {
		t.Fatalf("hop guard: %+v called=%v", r, free.called)
	}
	// A free path that does not take the query leaves REFUSED.
	free.refuse = true
	r = w.call(qopt{t: listen.TCP, src: "127.0.0.3"}, "www.example.com", dns.TypeA)
	if rcodeOf(r) != "REFUSED" {
		t.Fatalf("%s", rcodeOf(r))
	}
}

type fakeFree struct {
	called bool
	refuse bool
}

func (f *fakeFree) Serve(_ context.Context, req *listen.Request, q FreeQuery) (listen.Reply, bool) {
	f.called = true
	if f.refuse {
		return listen.Reply{}, false
	}
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Answer = []dns.RR{rrA(req.Msg.Question[0].Name, "192.0.2.123")}
	return listen.Reply{Msg: m}, true
}

// DoH identity is per request and never the connection's SNI (R7): a request on a
// connection whose SNI names tenant B, with tenant A's token and authority, is A's;
// DoT folds the case of its SNI and takes a trailing dot.
func TestDoHIgnoresConnectionSNIAndDoTFoldsCase(t *testing.T) {
	w := newWorld(t)
	for _, tr := range []listen.Transport{listen.DoH, listen.DoH3} {
		r := w.call(qopt{t: tr, sni: rid(epB) + "." + testZone, http: dohInfo("/"+tok(epA), rid(epA)+"."+testZone)}, "www.example.com", dns.TypeA)
		wantA(t, string(rune('0'+int(tr))), r, "0.0.0.0") // A's policy
	}
	r := w.call(qopt{t: listen.DoT, sni: strings.ToUpper(rid(epA)) + ".DNS.TEST."}, "www.example.com", dns.TypeA)
	wantA(t, "upper-case SNI", r, "0.0.0.0")
	// The token is compared in constant time against the stored hash, and a token
	// that differs in one character is not A's.
	bad := []byte(tok(epA))
	bad[31] = 'z'
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+string(bad), rid(epA)+"."+testZone)}, "www.example.com", dns.TypeA)
	if r.Status != 404 {
		t.Fatalf("%+v", r)
	}
}

// p4b-n0 (b): a Plain DNS identity is the client "default" (P3 3.3), so the stack of
// that client applies to it; an encrypted query with no label is the identity "no
// client" and takes the base, whatever "default" holds. The activity label of both is
// "default".
func TestPlainDNSIsTheDefaultClientForTheStack(t *testing.T) {
	w := newWorld(t)
	// G's base passes www.example.com; its "default" client blocks it.
	src := "127.0.0." + itoa(int(epG))
	for _, tr := range []listen.Transport{listen.TCP, listen.UDP} {
		r := w.call(qopt{t: tr, src: src}, "www.example.com", dns.TypeA)
		wantA(t, "plain "+tr.String()+" is client default", r, "0.0.0.0")
	}
	r := w.call(qopt{t: listen.DoT, sni: rid(epG) + "." + testZone}, "www.example.com", dns.TypeA)
	wantA(t, "unlabelled DoT is no client", r, "192.0.2.20")
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+tok(epG), rid(epG)+"."+testZone)}, "www.example.com", dns.TypeA)
	wantA(t, "unlabelled DoH is no client", r, "192.0.2.20")
	// Another Endpoint with the same source shape has no "default" client: its Plain DNS is its base.
	r = w.call(qopt{t: listen.TCP, src: "127.0.0." + itoa(int(epB))}, "www.example.com", dns.TypeA)
	wantA(t, "plain on B", r, "192.0.2.20")
}

func TestClientKeysOfAnIdentity(t *testing.T) {
	var none, plain, labelled ident
	plain.claim = &claimEntry{}
	labelled.client = "pc"
	if none.activityLabel() != "default" || plain.activityLabel() != "default" || labelled.activityLabel() != "pc" {
		t.Fatal("activity label")
	}
	if none.stackClient() != ([16]byte{}) {
		t.Error("an unlabelled encrypted query must take no client stack")
	}
	if plain.stackClient() != identity.ClientHash("default") || labelled.stackClient() != identity.ClientHash("pc") {
		t.Error("stack client")
	}
}
