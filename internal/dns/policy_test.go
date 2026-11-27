package dns

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
)

// D42 and T-524: a Redirect, to an address or a location, never applies to an
// Iranian name; it is a Bypass with the true answer and no Grant. The same rule
// pointed at a non-Iranian name is applied.
func TestRedirectNeverAppliesToIranianNames(t *testing.T) {
	w := newWorld(t)
	var grants []GrantRequest
	var mu sync.Mutex
	w.h.cfg.Grants = grantFunc(func(g GrantRequest) { mu.Lock(); grants = append(grants, g); mu.Unlock() })
	for _, a := range allAskers() {
		wantA(t, a.name+" redirect", a.ask(w, epR, "www.example.com", dns.TypeA), "192.0.2.250")
		wantA(t, a.name+" .ir", a.ask(w, epR, "www.example.ir", dns.TypeA), "192.0.2.88")
		// A wildcard rule is no different.
		wantA(t, a.name+" .ir wildcard", a.ask(w, epR, "x.example.ir", dns.TypeA), "192.0.2.99")
		// A redirect to a location with no proxy is a Bypass, true answer.
		wantA(t, a.name+" location", a.ask(w, epR, "loc.example.com", dns.TypeA), "192.0.2.99")
	}
	if len(grants) != 0 {
		t.Fatalf("%d grants written for redirects to an address or an unavailable location", len(grants))
	}
}

type grantFunc func(GrantRequest)

func (f grantFunc) Grant(g GrantRequest) { f(g) }

// A CNAME hop that matches a rule decides the answer (5.10): B blocks ads.example.com,
// and cloak.example.com is a CNAME to it. The chain is built from the upstream's
// answer, a record for another name in that answer is dropped, and the cache keeps
// the true chain.
func TestCNAMEChainAndStrayRecords(t *testing.T) {
	w := newWorld(t)
	wantA(t, "cname hop blocked", w.dot(epB, "cloak.example.com", dns.TypeA), "0.0.0.0")
	// A client that is not blocked sees the whole chain.
	r := w.dot(epD, "cloak.example.com", dns.TypeA) // soft_disabled: default answer
	if len(r.Msg.Answer) != 2 || r.Msg.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("%v", r.Msg.Answer)
	}
	r = w.dot(epD, "alias.example.com", dns.TypeA)
	if len(r.Msg.Answer) != 2 {
		t.Fatalf("%v", r.Msg.Answer)
	}
	// A hostile upstream adds a record for www.example.com: it does not reach the client.
	r = w.dot(epD, "stray.example.com", dns.TypeA)
	if got := aAddrs(r.Msg); len(got) != 1 || got[0] != "192.0.2.61" {
		t.Fatalf("stray record passed: %v", got)
	}
}

// The case of the question is echoed, and an answer for the qname keeps it.
func TestQuestionCaseEchoed(t *testing.T) {
	w := newWorld(t)
	r := w.dot(epB, "WwW.ExAmPlE.CoM", dns.TypeA)
	if r.Msg.Question[0].Name != "WwW.ExAmPlE.CoM." || r.Msg.Answer[0].Header().Name != "WwW.ExAmPlE.CoM." {
		t.Fatalf("%v", r.Msg)
	}
	// One cache entry serves every spelling.
	w.dot(epB, "www.example.com", dns.TypeA)
	if w.back.hitCount("www.example.com", dns.TypeA) != 1 {
		t.Fatalf("%d fetches for two spellings", w.back.hitCount("www.example.com", dns.TypeA))
	}
}

// The Sanity Gate stands between the resolver and everyone: an injected, private
// or loopback answer for a public name is a SERVFAIL, nothing is stored, and the
// counter moves without a name or address (T-042).
func TestSanityGateRejectsInjectedAnswers(t *testing.T) {
	w := newWorld(t)
	rejected := 0
	w.res.Rejected = func() { rejected++ }
	for _, a := range allAskers() {
		for _, name := range []string{"inject.example.com", "private.example.com", "loop.example.com"} {
			if got := rcodeOf(a.ask(w, epB, name, dns.TypeA)); got != "SERVFAIL" {
				t.Errorf("%s %s: %s", a.name, name, got)
			}
		}
	}
	if rejected == 0 {
		t.Fatal("not counted")
	}
	k := cache.KeyOf(names.MustString("inject.example.com"), dns.TypeA, 1, sharedpolicy.ResolveParams{}, "")
	if _, ok := w.cache.Get(cache.Shared, k); ok {
		t.Fatal("an injected answer was cached")
	}
	// soft_disabled goes through the same gate.
	if rcodeOf(w.dot(epD, "inject.example.com", dns.TypeA)) != "SERVFAIL" {
		t.Fatal("soft_disabled passed the injected answer")
	}
}

// A dead resolver is SERVFAIL, never cached, and the first answer after it
// recovers is served (a dead Unbound stand-in, T-026).
func TestDeadResolverIsServfailAndNotCached(t *testing.T) {
	w := newWorld(t)
	w.back.fail.Store(true)
	for _, a := range allAskers() {
		if got := rcodeOf(a.ask(w, epB, "www.example.com", dns.TypeA)); got != "SERVFAIL" {
			t.Fatalf("%s: %s", a.name, got)
		}
	}
	w.back.fail.Store(false)
	wantA(t, "recovered", w.dot(epB, "www.example.com", dns.TypeA), "192.0.2.20")
	// And a SERVFAIL the upstream itself gave is not stored either.
	for i := 0; i < 2; i++ {
		if rcodeOf(w.dot(epB, "servfail.example.com", dns.TypeA)) != "SERVFAIL" {
			t.Fatal("servfail")
		}
	}
	if w.back.hitCount("servfail.example.com", dns.TypeA) != 2 {
		t.Fatal("a SERVFAIL was cached")
	}
}

// An upstream that stalls costs the fetch deadline and no more, and a client that
// gives up does not cancel a fetch others wait for (the fetch has no client
// context), so its result is there for the next query.
func TestStalledUpstreamAndClientCancel(t *testing.T) {
	w := newWorld(t)
	w.res.Deadline = 400 * time.Millisecond
	w.back.stall.Store(true)
	start := time.Now()
	if rcodeOf(w.dot(epB, "www.example.com", dns.TypeA)) != "SERVFAIL" {
		t.Fatal("stall was not SERVFAIL")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a stalled upstream held the query for %s", d)
	}
	w.back.stall.Store(false)
	w.res.Deadline = 5 * time.Second
	w.back.delay.Store(int64(300 * time.Millisecond))
	// A client that goes away at 50 ms.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := &listen.Request{Msg: mkq("shared.example.com", dns.TypeA, qopt{}), Transport: listen.DoT, Source: netip.MustParseAddrPort("127.0.0.1:5000"), Validated: true, SNI: rid(epB) + "." + testZone}
	r := w.h.ServeDNS(ctx, req)
	if rcodeOf(r) != "SERVFAIL" {
		t.Fatalf("cancelled client: %s", rcodeOf(r))
	}
	// The fetch finished on its own and stored the answer.
	deadline := time.Now().Add(3 * time.Second)
	k := cache.KeyOf(names.MustString("shared.example.com"), dns.TypeA, 1, sharedpolicy.ResolveParams{}, "")
	for time.Now().Before(deadline) {
		if _, ok := w.cache.Get(cache.Shared, k); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the fetch was cancelled with its client")
}

// Concurrent misses for one name make one fetch.
func TestConcurrentMissesCoalesce(t *testing.T) {
	w := newWorld(t)
	w.back.delay.Store(int64(200 * time.Millisecond))
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wantA(t, "coalesced", w.dot(epB, "www.example.com", dns.TypeA), "192.0.2.20")
		}()
	}
	wg.Wait()
	if n := w.back.hitCount("www.example.com", dns.TypeA); n != 1 {
		t.Fatalf("%d fetches", n)
	}
}

// DNSSEC: the node asks with DO, so the reply for a client that asked for it carries
// AD when the answer is Secure, and one that did not ask gets no AD (5.11).
func TestADBitOnlyForClientsThatAskedForIt(t *testing.T) {
	w := newWorld(t)
	r := w.call(qopt{t: listen.DoT, sni: rid(epB) + "." + testZone, do: true}, "secure.example.com", dns.TypeA)
	if !r.Msg.AuthenticatedData {
		t.Fatal("no AD for a DO client")
	}
	if opt := r.Msg.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatal("no OPT with DO echoed")
	}
	r = w.call(qopt{t: listen.DoT, sni: rid(epB) + "." + testZone}, "secure.example.com", dns.TypeA)
	if r.Msg.AuthenticatedData {
		t.Fatal("AD for a client that did not ask")
	}
	// The query sent upstream asked for DNSSEC (DO) and carried the client's CD.
	w.cache.Purge(cache.Shared)
	w.call(qopt{t: listen.DoT, sni: rid(epB) + "." + testZone, cd: true}, "www.example.com", dns.TypeA)
	w.back.mu.Lock()
	last := w.back.last
	w.back.mu.Unlock()
	if last == nil || !last.CheckingDisabled || last.IsEdns0() == nil || !last.IsEdns0().Do() || !last.RecursionDesired {
		t.Fatalf("upstream query %v", last)
	}
	// CD is in the cache key: a client without CD does not read the CD answer.
	if w.back.hitCount("www.example.com", dns.TypeA) < 1 {
		t.Fatal("no fetch")
	}
	before := w.back.hitCount("www.example.com", dns.TypeA)
	w.call(qopt{t: listen.DoT, sni: rid(epB) + "." + testZone}, "www.example.com", dns.TypeA)
	if w.back.hitCount("www.example.com", dns.TypeA) != before+1 {
		t.Fatal("the CD and non-CD answers shared an entry")
	}
}

// ECS goes upstream in the query when the evaluator asks for it, and is part of the
// key (Lookup is the evaluator's port).
func TestResolverSendsECS(t *testing.T) {
	w := newWorld(t)
	n := names.MustString("www.example.com")
	p := sharedpolicy.ResolveParams{ECS: netip.MustParsePrefix("198.51.100.0/24")}
	if _, err := w.res.Lookup(context.Background(), n, dns.TypeA, p); err != nil {
		t.Fatal(err)
	}
	w.back.mu.Lock()
	opt := w.back.last.IsEdns0()
	w.back.mu.Unlock()
	var found *dns.EDNS0_SUBNET
	for _, o := range opt.Option {
		if s, ok := o.(*dns.EDNS0_SUBNET); ok {
			found = s
		}
	}
	if found == nil || found.SourceNetmask != 24 || found.Address.String() != "198.51.100.0" {
		t.Fatalf("%v", found)
	}
	if _, err := w.res.Lookup(context.Background(), n, dns.TypeA, sharedpolicy.ResolveParams{}); err != nil {
		t.Fatal(err)
	}
	if w.back.hitCount("www.example.com", dns.TypeA) != 2 {
		t.Fatal("a query with ECS and one without shared an entry")
	}
}

// The UDP size rule (SC 7): an answer larger than the client's payload size is TC=1
// with no records, over TCP it is whole.
func TestUDPSizeRule(t *testing.T) {
	w := newWorld(t)
	udp := qopt{t: listen.UDP, src: "127.0.0.2", validated: vptr(true)}
	// 60 A records are about 1 KB: over 512, under 1232.
	r := w.call(udp, "big.example.com", dns.TypeA)
	if !r.Msg.Truncated || len(r.Msg.Answer) != 0 {
		t.Fatalf("no EDNS: truncated=%v answers=%d", r.Msg.Truncated, len(r.Msg.Answer))
	}
	o := udp
	o.edns = true
	r = w.call(o, "big.example.com", dns.TypeA)
	if r.Msg.Truncated || len(r.Msg.Answer) != 60 {
		t.Fatalf("EDNS 1232: truncated=%v answers=%d", r.Msg.Truncated, len(r.Msg.Answer))
	}
	r = w.call(qopt{t: listen.TCP, src: "127.0.0.2"}, "big.example.com", dns.TypeA)
	if r.Msg.Truncated || len(r.Msg.Answer) != 60 {
		t.Fatal("TCP truncated")
	}
	// A small EDNS size is raised to 512, and a big one is capped at 1232: 60 records
	// still fit the cap.
	m := mkq("big.example.com", dns.TypeA, qopt{})
	m.SetEdns0(4096, false)
	r = w.callMsg(udp, m)
	if r.Msg.Truncated {
		t.Fatal("cap")
	}
	m = mkq("big.example.com", dns.TypeA, qopt{})
	m.SetEdns0(100, false)
	r = w.callMsg(udp, m)
	if !r.Msg.Truncated {
		t.Fatal("a 100-byte size was not raised to 512 and then exceeded")
	}
}

// ANY is never resolved: the RFC 8482 HINFO, for a Bypass answer.
func TestANYIsHINFO(t *testing.T) {
	w := newWorld(t)
	before := w.back.total.Load()
	r := w.dot(epB, "www.example.com", dns.TypeANY)
	if len(r.Msg.Answer) != 1 || r.Msg.Answer[0].Header().Rrtype != dns.TypeHINFO {
		t.Fatalf("%v", r.Msg.Answer)
	}
	if w.back.total.Load() != before {
		t.Fatal("ANY was resolved")
	}
}

// Malformed queries: no question, two questions, a non-query opcode, a class that is
// not IN.
func TestMalformedQueries(t *testing.T) {
	w := newWorld(t)
	o := qopt{t: listen.DoT, sni: rid(epB) + "." + testZone}
	m := new(dns.Msg)
	m.Id = 1
	if got := rcodeOf(w.callMsg(o, m)); got != "FORMERR" {
		t.Fatalf("no question: %s", got)
	}
	m = mkq("a.example.com", dns.TypeA, o)
	m.Question = append(m.Question, dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if got := rcodeOf(w.callMsg(o, m)); got != "FORMERR" {
		t.Fatalf("two questions: %s", got)
	}
	m = mkq("a.example.com", dns.TypeA, o)
	m.Opcode = dns.OpcodeNotify
	if got := rcodeOf(w.callMsg(o, m)); got != "NOTIMP" {
		t.Fatalf("opcode: %s", got)
	}
	m = mkq("version.bind", dns.TypeTXT, o)
	m.Question[0].Qclass = dns.ClassCHAOS
	if got := rcodeOf(w.callMsg(o, m)); got != "REFUSED" {
		t.Fatalf("chaos: %s", got)
	}
}

// Without settings or an image every query is REFUSED, and a handler with no
// resolver or no NeverProxied predicate is refused at construction (T-524: a node
// must never decide without the Iranian-name predicate).
func TestHandlerConstruction(t *testing.T) {
	if _, err := New(Config{NeverProxied: neverIR}); err == nil {
		t.Fatal("no resolver")
	}
	w := newWorld(t)
	if _, err := New(Config{Resolver: w.res}); err == nil {
		t.Fatal("no NeverProxied")
	}
	h, err := New(Config{Resolver: w.res, NeverProxied: neverIR})
	if err != nil {
		t.Fatal(err)
	}
	req := &listen.Request{Msg: mkq("www.example.com", dns.TypeA, qopt{}), Transport: listen.TCP, Source: netip.MustParseAddrPort("127.0.0.1:1"), Validated: true}
	if r := h.ServeDNS(context.Background(), req); r.Msg == nil || r.Msg.Rcode != dns.RcodeRefused {
		t.Fatalf("%+v", r)
	}
}

// The free path's resolver (W9) is the same adapter over the Free segment and its
// own backend: a free miss never reaches the identified resolver, and an
// identified one never reads or waits on the free segment (SC 5.2a, T-559).
func TestFreeAndSharedResolversNeverCross(t *testing.T) {
	w := newWorld(t)
	freeBack := newFakeBackend()
	free := &policy.Resolver{Cache: w.cache, Segment: cache.Free, Backend: freeBack, Deadline: 2 * time.Second}
	n := names.MustString("www.example.com")
	p := sharedpolicy.ResolveParams{}

	freeBack.delay.Store(int64(150 * time.Millisecond))
	w.back.delay.Store(int64(150 * time.Millisecond))
	var wg sync.WaitGroup
	for _, r := range []*policy.Resolver{free, w.res, free, w.res} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Lookup(context.Background(), n, dns.TypeA, p); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// One fetch per segment: the in-flight work is shared inside a segment and
	// never across the two, and each went to its own backend.
	if freeBack.hitCount("www.example.com", dns.TypeA) != 1 || w.back.hitCount("www.example.com", dns.TypeA) != 1 {
		t.Fatalf("free %d, shared %d", freeBack.hitCount("www.example.com", dns.TypeA), w.back.hitCount("www.example.com", dns.TypeA))
	}
	if w.cache.Stats(cache.Free).Entries != 1 || w.cache.Stats(cache.Shared).Entries != 1 {
		t.Fatal("an entry is missing from a segment")
	}
	// An answer the free backend gives is not what the identified path serves.
	freeBack2 := newFakeBackend()
	other := &policy.Resolver{Cache: w.cache, Segment: cache.Free, Backend: freeBack2, Deadline: time.Second}
	a, _ := other.Lookup(context.Background(), names.MustString("shared.example.com"), dns.TypeA, p)
	if a == nil || a.Failed {
		t.Fatal("free lookup")
	}
	if _, ok := w.cache.Get(cache.Shared, cache.KeyOf(names.MustString("shared.example.com"), dns.TypeA, 1, p, "")); ok {
		t.Fatal("a free answer is readable from the shared segment")
	}
}

// R9 of SC 7: no Grant when the cache already holds a true A for the name that is
// not public (p4n-W7-r1-4). The cache is read through policy.Resolver.CachedA.
func TestGrantSafetyReadsTheCache(t *testing.T) {
	w := newWorld(t)
	name := names.MustString("www.example.com")
	if _, ok := w.res.CachedA(name, sharedpolicy.ResolveParams{}); ok {
		t.Fatal("the cache held an answer before any query")
	}
	if !w.h.grantSafe(name, sharedpolicy.ResolveParams{}) { // no CachedA configured: the Grant is written
		t.Fatal("unconfigured check refused a Grant")
	}
	w.h.cfg.CachedA = w.res.CachedA
	if !w.h.grantSafe(name, sharedpolicy.ResolveParams{}) {
		t.Fatal("a name the cache does not hold refused a Grant")
	}
	w.dot(epD, "www.example.com", dns.TypeA) // 192.0.2.20: documentation range, not public
	before := w.res.Cache.Stats(w.res.Segment)
	if a, ok := w.res.CachedA(name, sharedpolicy.ResolveParams{}); !ok || len(a) != 1 || a[0].String() != "192.0.2.20" {
		t.Fatalf("cached A: %v %v", a, ok)
	}
	// the Grant-safety read is no client lookup (p4n-W7-r9-1)
	if after := w.res.Cache.Stats(w.res.Segment); after.Hits != before.Hits || after.Misses != before.Misses {
		t.Fatalf("CachedA moved the hit counters: %+v -> %+v", before, after)
	}
	if w.h.grantSafe(name, sharedpolicy.ResolveParams{}) {
		t.Fatal("a Grant was allowed for a name whose true A is not public")
	}
	// A public address allows it.
	w.h.cfg.CachedA = func(names.Name, sharedpolicy.ResolveParams) ([]netip.Addr, bool) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, true
	}
	if !w.h.grantSafe(name, sharedpolicy.ResolveParams{}) {
		t.Fatal("a public address refused a Grant")
	}
	// One non-public address among public ones is enough to refuse.
	w.h.cfg.CachedA = func(names.Name, sharedpolicy.ResolveParams) ([]netip.Addr, bool) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.1")}, true
	}
	if w.h.grantSafe(name, sharedpolicy.ResolveParams{}) {
		t.Fatal("a mixed set was allowed")
	}
}

// Purge after a resolve change: a lookup that was already running against the old
// route does not store its answer, and a lookup made after the purge asks the new
// route itself (p4n-W7-r2-3).
func TestPurgeDoesNotKeepAnOldRouteAnswer(t *testing.T) {
	w := newWorld(t)
	n := names.MustString("purge.example.com")
	p := sharedpolicy.ResolveParams{}
	w.back.delay.Store(int64(400 * time.Millisecond))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.res.Lookup(context.Background(), n, dns.TypeA, p)
	}()
	time.Sleep(100 * time.Millisecond) // the first fetch is at the backend
	w.cache.Purge(cache.Shared)
	if a, err := w.res.Lookup(context.Background(), n, dns.TypeA, p); err != nil || a == nil || a.Failed {
		t.Fatalf("lookup after the purge: %v %v", a, err)
	}
	<-done
	if got := w.back.hitCount("purge.example.com", dns.TypeA); got != 2 {
		t.Fatalf("backend asked %d times, want 2 (the new query must not join the old flight)", got)
	}
	if e := w.cache.Stats(cache.Shared).Entries; e != 1 {
		t.Fatalf("%d entries, want only the new route's answer", e)
	}
}

// R9 reads the key of the evaluator's own lookup: an answer cached under the
// profile's ECS prefix is found (p4n-W7-r2-2).
func TestGrantSafetyReadsTheECSKey(t *testing.T) {
	w := newWorld(t)
	name := names.MustString("www.example.com")
	p := sharedpolicy.ResolveParams{ECS: netip.MustParsePrefix("198.51.100.0/24")}
	if _, err := w.res.Lookup(context.Background(), name, dns.TypeA, p); err != nil { // 192.0.2.20: not public
		t.Fatal(err)
	}
	w.h.cfg.CachedA = w.res.CachedA
	if w.h.grantSafe(name, p) {
		t.Fatal("a Grant was allowed although the evaluator cached a non-public A under its ECS key")
	}
	if !w.h.grantSafe(name, sharedpolicy.ResolveParams{}) {
		t.Fatal("the plain key holds nothing, so the check should pass for it")
	}
	// CD changes the key as well.
	cd := sharedpolicy.ResolveParams{EffectiveCD: true}
	if _, err := w.res.Lookup(context.Background(), names.MustString("cd.example.com"), dns.TypeA, cd); err != nil {
		t.Fatal(err)
	}
	if w.h.grantSafe(names.MustString("cd.example.com"), cd) {
		t.Fatal("CD key not read")
	}
}

// A message that is not one IN question is judged after identity and 4b, so the
// refusal of its transport comes first (p4n-W7-r5-3): 404 for a DoH request that
// names nobody, 403 for a hard_disabled Endpoint, a silent drop for a Plain source
// that 4b refuses, and the node's own address.
func TestMalformedShapeKeepsIdentityAndRefusalOrder(t *testing.T) {
	w := newWorld(t)
	noQuestion := func(o qopt) *dns.Msg { m := new(dns.Msg); m.Id = 7; return m }
	chaos := func(o qopt) *dns.Msg {
		m := mkq("version.bind", dns.TypeTXT, o)
		m.Question[0].Qclass = dns.ClassCHAOS
		return m
	}
	update := func(o qopt) *dns.Msg { m := mkq("a.example.com", dns.TypeA, o); m.Opcode = dns.OpcodeUpdate; return m }
	for name, shape := range map[string]func(qopt) *dns.Msg{"no question": noQuestion, "chaos": chaos, "update": update} {
		t.Run(name, func(t *testing.T) {
			// An unknown DoH token: 404 whatever the message.
			o := qopt{t: listen.DoH, sni: "x." + testZone, http: dohInfo("/"+strings.Repeat("z", 32), rid(epB)+"."+testZone)}
			if r := w.callMsg(o, shape(o)); r.Status != 404 {
				t.Fatalf("unknown token: %+v", r)
			}
			// hard_disabled over DoH: 403, not an error message.
			o = qopt{t: listen.DoH, sni: "x." + testZone, http: dohInfo("/"+tok(epC), rid(epC)+"."+testZone)}
			if r := w.callMsg(o, shape(o)); r.Status != 403 || r.Msg != nil {
				t.Fatalf("hard_disabled: %+v", r)
			}
			// Plain DNS from a claim of the hard_disabled Endpoint: silence.
			o = qopt{t: listen.TCP, src: "127.0.0." + itoa(int(epC))}
			if r := w.callMsg(o, shape(o)); !r.Drop {
				t.Fatalf("plain hard_disabled: %+v", r)
			}
			// The node's own dns_ip: silence (SC 5.2a (b)).
			o = qopt{t: listen.TCP, src: selfDNSIP}
			if r := w.callMsg(o, shape(o)); !r.Drop {
				t.Fatalf("own dns_ip: %+v", r)
			}
			// A stranger and an identified, admitted source still get the error.
			o = qopt{t: listen.DoT, sni: rid(epB) + "." + testZone}
			if r := w.callMsg(o, shape(o)); r.Msg == nil || r.Msg.Rcode == dns.RcodeSuccess {
				t.Fatalf("identified: %+v", r)
			}
		})
	}
}
