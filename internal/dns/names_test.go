package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// Panel and admin hostnames and the system names get the true answer through the
// identified resolver, never a policy answer: Endpoint A is Default Block, and a
// Default Block profile must not lock its owner out of the panel (T-040).
func TestSystemNamesAreTrueAnswersForABlockingEndpoint(t *testing.T) {
	w := newWorld(t)
	for _, a := range allAskers() {
		wantA(t, a.name+" panel", a.ask(w, epA, "panel.example.org", dns.TypeA), "192.0.2.77")
		wantA(t, a.name+" admin", a.ask(w, epA, "admin.example.org", dns.TypeA), "192.0.2.78")
		wantA(t, a.name+" captive", a.ask(w, epA, "captive.apple.com", dns.TypeA), "17.253.1.1")
		wantA(t, a.name+" localhost", a.ask(w, epA, "localhost", dns.TypeA), "127.0.0.1")
		wantA(t, a.name+" ipv4only", a.ask(w, epA, "ipv4only.arpa", dns.TypeA), "192.0.0.170", "192.0.0.171")
		if rcodeOf(a.ask(w, epA, "1.168.192.in-addr.arpa", dns.TypePTR)) != "NXDOMAIN" {
			t.Errorf("%s: local_nx", a.name)
		}
		r := a.ask(w, epA, "resolver.arpa", dns.TypeSVCB)
		if rcodeOf(r) != "NOERROR" || len(r.Msg.Answer) != 0 || len(r.Msg.Ns) != 1 {
			t.Errorf("%s: nodata: %v", a.name, r.Msg)
		}
	}
	// Policy never ran for them: no tenant decision touched the cache entry.
	// Contrast: the same panel name for a blocked tenant domain is blocked.
	wantA(t, "control", w.dot(epA, "www.example.com", dns.TypeA), "0.0.0.0")
}

// A system name for a query with no identity (SC 8, Queries with no identity).
func TestSystemNamesWithNoIdentity(t *testing.T) {
	w := newWorld(t)
	free := &fakeFree{}
	w.h.cfg.Free = free
	apex := qopt{t: listen.DoT, sni: testZone}

	// local rows need no lookup.
	wantA(t, "local", w.call(apex, "localhost", dns.TypeA), "127.0.0.1")
	before := w.back.total.Load()
	// A true_answer row without a wildcard answers A, AAAA and HTTPS, through the
	// identified path: the shared segment, never the free one.
	wantA(t, "captive A", w.call(apex, "captive.apple.com", dns.TypeA), "17.253.1.1")
	if w.back.total.Load() != before+1 {
		t.Fatal("no lookup")
	}
	n := names.MustString("captive.apple.com")
	k := cache.KeyOf(n, dns.TypeA, 1, sharedpolicy.ResolveParams{}, "")
	if _, ok := w.cache.Get(cache.Shared, k); !ok {
		t.Fatal("not in the shared segment")
	}
	if w.cache.Stats(cache.Free).Puts != 0 {
		t.Fatal("the free segment was written")
	}
	// Another type goes on as if no row matched: REFUSED on DoT.
	if rcodeOf(w.call(apex, "captive.apple.com", dns.TypeTXT)) != "REFUSED" {
		t.Fatal("TXT of a system name with no identity")
	}
	if rcodeOf(w.call(apex, "captive.apple.com", dns.TypeMX)) != "REFUSED" {
		t.Fatal("MX")
	}
	// A wildcard row lets the source pick a name: REFUSED over DoT and DoQ...
	for _, tr := range []listen.Transport{listen.DoT, listen.DoQ} {
		if rcodeOf(w.call(qopt{t: tr, sni: testZone}, "pick-any-name.metric.gstatic.com", dns.TypeA)) != "REFUSED" {
			t.Fatalf("%s wildcard", tr)
		}
	}
	// ...a free query on Plain DNS...
	stranger := qopt{t: listen.TCP, src: "127.0.0.3"}
	r := w.call(stranger, "pick-any-name.metric.gstatic.com", dns.TypeA)
	if !free.called || len(aAddrs(r.Msg)) != 1 || aAddrs(r.Msg)[0] != "192.0.2.123" {
		t.Fatalf("free: %+v", r)
	}
	// ...and what the identity gives when the free path does not take it: the
	// silent drop for a node's address.
	free.called = false
	if r := w.call(qopt{t: listen.TCP, src: "8.8.4.4"}, "pick-any-name.metric.gstatic.com", dns.TypeA); !r.Drop || free.called {
		t.Fatalf("hop guard on a wildcard name: %+v", r)
	}
	// A non-wildcard name from a stranger on Plain DNS does not use the free path.
	free.called = false
	wantA(t, "plain stranger captive", w.call(stranger, "captive.apple.com", dns.TypeA), "17.253.1.1")
	if free.called {
		t.Fatal("a non-wildcard system name used the free path")
	}
}

// The isolated_synth row: A is this node's own DNS_IP in Isolated mode and when
// the resolve fails, and the true answer otherwise.
func TestIsolatedSynth(t *testing.T) {
	w := newWorld(t)
	const name = "abc-dnsotls-ds.metric.gstatic.com"
	wantA(t, "true", w.dot(epA, name, dns.TypeA), "192.0.2.99")
	w.back.fail.Store(true)
	w.cache.Purge(cache.Shared)
	r := w.dot(epA, name, dns.TypeA)
	wantA(t, "resolve failed", r, selfDNSIP)
	if r.Msg.Answer[0].Header().Ttl != 60 {
		t.Fatalf("ttl %d", r.Msg.Answer[0].Header().Ttl)
	}
	if r := w.dot(epA, name, dns.TypeAAAA); len(r.Msg.Answer) != 0 || len(r.Msg.Ns) != 1 {
		t.Fatalf("AAAA: %v", r.Msg)
	}
	w.back.fail.Store(false)
	w.cache.Purge(cache.Shared)
	// Isolated mode.
	w.h.SetSettings(NewSettings(w.settings.zones, w.settings.panel, w.settings.selfIP, w.proof, true))
	before := w.back.total.Load()
	wantA(t, "isolated", w.dot(epA, name, dns.TypeA), selfDNSIP)
	if w.back.total.Load() != before {
		t.Fatal("isolated mode resolved")
	}
}

// The zone answers of step 3 on every transport, and for a stranger.
func TestZoneAnswersNeedNoIdentity(t *testing.T) {
	w := newWorld(t)
	apex := qopt{t: listen.DoT, sni: testZone}
	// A resolver name, known or not, answers the global pair's primary.
	wantA(t, "known rid", w.call(apex, rid(epA)+"."+testZone, dns.TypeA), "8.8.8.8")
	wantA(t, "unknown rid", w.call(apex, rid(20)+"."+testZone, dns.TypeA), "8.8.8.8")
	wantA(t, "with client", w.call(apex, rid(20)+"-pc."+testZone, dns.TypeA), "8.8.8.8")
	// A malformed name is NXDOMAIN with the zone SOA, the apex SOA and NS answer.
	r := w.call(apex, "a.b.c."+testZone, dns.TypeA)
	if rcodeOf(r) != "NXDOMAIN" || !r.Msg.Authoritative || len(r.Msg.Ns) != 1 {
		t.Fatalf("malformed: %v", r.Msg)
	}
	r = w.call(qopt{t: listen.UDP, src: "127.0.0.3"}, testZone, dns.TypeNS)
	if len(r.Msg.Answer) != 3 {
		t.Fatalf("apex NS: %v", r.Msg)
	}
	r = w.call(qopt{t: listen.TCP, src: "127.0.0.3"}, "ns2."+testZone, dns.TypeA)
	wantA(t, "ns2", r, "8.8.4.4")
	// The zone answers through every transport for an identified Endpoint too,
	// with AA set and the question echoed byte for byte.
	for _, a := range allAskers() {
		r := a.ask(w, epB, "Mixed-Case."+rid(epB)+"."+testZone, dns.TypeA)
		if rcodeOf(r) != "NOERROR" {
			// "Mixed-Case.<rid>" has a dot in its left part: malformed, NXDOMAIN.
			if rcodeOf(r) != "NXDOMAIN" {
				t.Errorf("%s: %s", a.name, rcodeOf(r))
			}
		}
		r = a.ask(w, epB, rid(epB)+"."+testZone, dns.TypeA)
		if !r.Msg.Authoritative || r.Msg.Question[0].Name != rid(epB)+"."+testZone+"." {
			t.Errorf("%s: %v", a.name, r.Msg)
		}
	}
	// With no table in use (the agent says so) the resolver names, the apex NS and
	// ns1 to ns4 are REFUSED, and the rest still answers (SC 8a.5).
	w.h.SetZoneState(&ZoneState{})
	if rcodeOf(w.call(apex, rid(epA)+"."+testZone, dns.TypeA)) != "REFUSED" || rcodeOf(w.call(apex, testZone, dns.TypeNS)) != "REFUSED" ||
		rcodeOf(w.call(apex, "ns1."+testZone, dns.TypeA)) != "REFUSED" {
		t.Fatal("no table in use did not REFUSE")
	}
	if rcodeOf(w.call(apex, testZone, dns.TypeSOA)) != "NOERROR" || rcodeOf(w.call(apex, "a.b."+testZone, dns.TypeA)) != "NXDOMAIN" {
		t.Fatal("apex SOA or malformed changed")
	}
	w.h.SetZoneState(&ZoneState{Table: w.img.Zone()})
}

// ACME DNS-01 names answer the active values, never NXDOMAIN.
func TestAcmeNames(t *testing.T) {
	w := newWorld(t)
	w.h.SetZoneState(&ZoneState{Table: w.img.Zone(), Acme: func(fqdn string) []string {
		if fqdn == "_acme-challenge."+testZone {
			return []string{"tokenvalue1"}
		}
		return nil
	}})
	apex := qopt{t: listen.DoT, sni: testZone}
	r := w.call(apex, "_acme-challenge."+testZone, dns.TypeTXT)
	if len(r.Msg.Answer) != 1 || r.Msg.Answer[0].(*dns.TXT).Txt[0] != "tokenvalue1" || r.Msg.Answer[0].Header().Ttl != 0 {
		t.Fatalf("%v", r.Msg)
	}
	for _, name := range []string{"_acme-challenge.verify." + testZone, "verify." + testZone} {
		r = w.call(apex, name, dns.TypeTXT)
		if rcodeOf(r) != "NOERROR" || len(r.Msg.Answer) != 0 || len(r.Msg.Ns) != 1 {
			t.Fatalf("%s: %v", name, r.Msg)
		}
	}
}

// myip: the source address for an Endpoint with Expose IP, NODATA without it, and
// the identity case for a source with no identity (T-048).
func TestMyIP(t *testing.T) {
	w := newWorld(t)
	for _, a := range allAskers() {
		r := a.ask(w, epA, "myip."+testZone, dns.TypeA)
		wantA(t, a.name+" expose", r, "127.0.0.1")
		if r.Msg.Answer[0].Header().Ttl != 0 {
			t.Errorf("%s: ttl", a.name)
		}
		r = a.ask(w, epB, "myip."+testZone, dns.TypeA)
		if rcodeOf(r) != "NOERROR" || len(r.Msg.Answer) != 0 || len(r.Msg.Ns) != 1 {
			t.Errorf("%s: no expose: %v", a.name, r.Msg)
		}
	}
	// An IPv6 source gets AAAA; an A query for it is NODATA.
	o := qopt{t: listen.DoT, src: "2001:db8::7", sni: rid(epA) + "." + testZone}
	r := w.call(o, "myip."+testZone, dns.TypeAAAA)
	if len(r.Msg.Answer) != 1 || r.Msg.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::7" {
		t.Fatalf("%v", r.Msg)
	}
	if r := w.call(o, "myip."+testZone, dns.TypeA); len(r.Msg.Answer) != 0 {
		t.Fatal("A for an IPv6 source")
	}
	// No identity: REFUSED over DoT, and over Plain DNS the drop of a node's own
	// address, otherwise REFUSED (the free path never answers myip).
	if rcodeOf(w.call(qopt{t: listen.DoT, sni: testZone}, "myip."+testZone, dns.TypeA)) != "REFUSED" {
		t.Fatal("dot")
	}
	free := &fakeFree{}
	w.h.cfg.Free = free
	if rcodeOf(w.call(qopt{t: listen.TCP, src: "127.0.0.3"}, "myip."+testZone, dns.TypeA)) != "REFUSED" || free.called {
		t.Fatal("stranger on Plain")
	}
	if !w.call(qopt{t: listen.TCP, src: "8.8.4.4"}, "myip."+testZone, dns.TypeA).Drop {
		t.Fatal("hop guard")
	}
	// A hard-disabled or unauthorized source gets the refusal, not its address.
	if rcodeOf(w.dot(epC, "myip."+testZone, dns.TypeA)) != "REFUSED" {
		t.Fatal("hard_disabled myip")
	}
}

// During a domain change the node serves two zones: the names, the apex and the
// verify names of both are answered, each with its own SOA, and a name under
// neither is out of zone.
func TestTwoZones(t *testing.T) {
	w := newWorld(t)
	other := names.MustString("dns.other.test")
	w.h.SetSettings(NewSettings(append(w.settings.zones, other), w.settings.panel, w.settings.selfIP, w.proof, false))
	apex := qopt{t: listen.DoT, sni: "dns.other.test"}
	wantA(t, "name in the second zone", w.call(apex, rid(epA)+".dns.other.test", dns.TypeA), "8.8.8.8")
	r := w.call(apex, "dns.other.test", dns.TypeSOA)
	if len(r.Msg.Answer) != 1 || r.Msg.Answer[0].Header().Name != "dns.other.test." {
		t.Fatalf("%v", r.Msg)
	}
	wantA(t, "verify in the second zone", w.call(apex, newLabel(t)+".verify.dns.other.test", dns.TypeA), selfDNSIP)
	// The DoH identity works with the authority in either zone.
	r = w.call(qopt{t: listen.DoH, http: dohInfo("/"+tok(epB), rid(epB)+".dns.other.test")}, "www.example.com", dns.TypeA)
	wantA(t, "doh authority in zone 2", r, "192.0.2.20")
	// A name under neither is no zone name.
	if rcodeOf(w.call(apex, rid(epA)+".dns.third.test", dns.TypeA)) != "REFUSED" {
		t.Fatal("out of zone name answered")
	}
}

// Before the agent has told dns a table (a start, a restart, the plain-only
// fallback) none is in use, and the image's own table, which has no withdrawal
// flags, is never served: a primary the hub withdrew would be advertised
// (p4n-W7-r1-9).
func TestNoZoneStateMeansNoTableInUse(t *testing.T) {
	w := newWorld(t)
	w.h.SetZoneState(nil)
	apex := qopt{t: listen.DoT, sni: testZone}
	for _, c := range []struct {
		name string
		qt   uint16
	}{{rid(epA) + "." + testZone, dns.TypeA}, {testZone, dns.TypeNS}, {"ns1." + testZone, dns.TypeA}} {
		if got := rcodeOf(w.call(apex, c.name, c.qt)); got != "REFUSED" {
			t.Errorf("%s: %s with no zone state", c.name, got)
		}
	}
	if rcodeOf(w.call(apex, testZone, dns.TypeSOA)) != "NOERROR" {
		t.Error("the SOA needs no table")
	}
	w.h.SetZoneState(&ZoneState{Table: w.img.Zone()})
	if rcodeOf(w.call(apex, rid(epA)+"."+testZone, dns.TypeA)) != "NOERROR" {
		t.Error("the agent's table does not answer")
	}
}

// A source that 4b refuses (hard_disabled, Require Authorized IPs, a revocation)
// gets no more from the system names than a source with no identity: a wildcard
// row is the 4b refusal and never reaches the resolver, and an exact row answers
// only A, AAAA and HTTPS (p4n-W7-r3-3, p4n-W7-r3-4).
func TestRefusedIdentityGetsNoWildcardSystemNames(t *testing.T) {
	w := newWorld(t)
	check := func(label string, ask func(string, uint16) listen.Reply, tr listen.Transport) {
		t.Helper()
		before := w.back.total.Load()
		for _, name := range []string{"random-1.metric.gstatic.com", "abc-dnsotls-ds.metric.gstatic.com"} {
			r := ask(name, dns.TypeA)
			switch tr {
			case listen.TCP, listen.UDP:
				if !r.Drop || r.Msg != nil {
					t.Errorf("%s %s: %+v", label, name, r)
				}
			case listen.DoH, listen.DoH3:
				if r.Status != 403 || r.Msg != nil {
					t.Errorf("%s %s: %+v", label, name, r)
				}
			default:
				if rcodeOf(r) != "REFUSED" {
					t.Errorf("%s %s: %s", label, name, rcodeOf(r))
				}
			}
		}
		if got := w.back.total.Load(); got != before {
			t.Errorf("%s: the resolver was asked %d times", label, got-before)
		}
		// An exact row still answers A, but not another type.
		wantA(t, label+" exact A", ask("captive.apple.com", dns.TypeA), "17.253.1.1")
		if r := ask("captive.apple.com", dns.TypeTXT); r.Msg != nil && len(r.Msg.Answer) != 0 {
			t.Errorf("%s: TXT of an exact row answered", label)
		}
	}
	for _, ep := range []byte{epC, epE} {
		for _, a := range allAskers() {
			a, ep := a, ep
			if a.t == listen.TCP && ep == epE {
				continue // Plain DNS by claim passes Require Authorized IPs
			}
			check(a.name+" "+rid(ep)[:1], func(n string, qt uint16) listen.Reply { return a.ask(w, ep, n, qt) }, a.t)
		}
	}
	// A revoked claim on Plain DNS.
	now := w.now()
	w.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_CLAIM, IDs: [][16]byte{claimOf(w, epA)}, RevSeq: 8, ExpiresAt: now.Add(time.Minute)}})
	check("revoked claim", func(n string, qt uint16) listen.Reply { return w.plain(epA, n, qt) }, listen.TCP)
	w.h.Revocations().Set(nil)
	// An accepted identity still gets the wildcard row.
	wantA(t, "identified", w.dot(epA, "abc-dnsotls-ds.metric.gstatic.com", dns.TypeA), "192.0.2.99")
}

// A qname whose last label carries a ":port" is not a name of the zone (Name.String
// escapes the colon, so ParseHost never strips it); it gets
// no verify answer, no observation, and myip does not take it (p4n-W7-r3-2).
func TestQnameWithPortSuffixIsOutOfZone(t *testing.T) {
	w := newWorld(t)
	apex := qopt{t: listen.UDP, src: "127.0.0.3"}
	label := newLabel(t)
	proofs, _, _ := w.rep.counts()
	r := w.call(apex, label+".verify."+testZone+":80", dns.TypeA)
	if r.Msg != nil && (r.Msg.Authoritative || len(r.Msg.Answer) != 0) {
		t.Fatalf("answered as the zone: %v", r.Msg)
	}
	if p, _, _ := w.rep.counts(); p != proofs {
		t.Fatal("an observation was reported")
	}
	// myip with a port is not the reserved name: with no identity it is a plain
	// out-of-zone name for the free path, not the myip refusal.
	free := &fakeFree{}
	w.h.cfg.Free = free
	w.call(apex, "myip."+testZone+":53", dns.TypeA)
	if !free.called {
		t.Fatal("an out-of-zone name was not offered to the free path")
	}
}
