package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// 4b, hard_disabled: Plain is a silent drop, DoT and DoQ REFUSED, DoH and DoH3 HTTP
// 403, and only a counter records it (T-047).
func TestHardDisabledOnEveryTransport(t *testing.T) {
	w := newWorld(t)
	before := w.h.Counters().HardDisabled
	for _, a := range allAskers() {
		r := a.ask(w, epC, "www.example.com", dns.TypeA)
		switch a.t {
		case listen.TCP, listen.UDP:
			if !r.Drop || r.Msg != nil {
				t.Errorf("%s: %+v", a.name, r)
			}
		case listen.DoT, listen.DoQ:
			if rcodeOf(r) != "REFUSED" {
				t.Errorf("%s: %s", a.name, rcodeOf(r))
			}
		default:
			if r.Status != 403 || r.Msg != nil {
				t.Errorf("%s: %+v", a.name, r)
			}
		}
	}
	// UDP too (a claim source, validated by a cookie).
	r := w.call(qopt{t: listen.UDP, src: "127.0.0.4", validated: vptr(true)}, "www.example.com", dns.TypeA)
	if !r.Drop {
		t.Fatalf("udp: %+v", r)
	}
	if got := w.h.Counters().HardDisabled - before; got != 6 {
		t.Fatalf("counter moved by %d, want 6", got)
	}
	// Nothing else is told: no activity, no learned address.
	if p, l, a := w.rep.counts(); p+l+a != 0 {
		t.Fatalf("a refused query was reported: %d %d %d", p, l, a)
	}
}

// soft_disabled: no profile, the true answer through the default resolve; ANY is
// the RFC 8482 HINFO; no Grant.
func TestSoftDisabledAnswersByPostDefault(t *testing.T) {
	w := newWorld(t)
	for _, a := range allAskers() {
		// D's profile is Default Block, and is not used.
		wantA(t, a.name, a.ask(w, epD, "www.example.com", dns.TypeA), "192.0.2.20")
		r := a.ask(w, epD, "www.example.com", dns.TypeANY)
		if len(r.Msg.Answer) != 1 || r.Msg.Answer[0].Header().Rrtype != dns.TypeHINFO {
			t.Errorf("%s: ANY %v", a.name, r.Msg.Answer)
		}
		// NXDOMAIN is the true one.
		if rcodeOf(a.ask(w, epD, "nx.example.com", dns.TypeA)) != "NXDOMAIN" {
			t.Errorf("%s: nx", a.name)
		}
	}
	// A true failure is SERVFAIL (5.12), never a made-up answer.
	if rcodeOf(w.dot(epD, "servfail.example.com", dns.TypeA)) != "SERVFAIL" {
		t.Fatal("servfail")
	}
}

// The degraded mode of 9.7 item 7: a binding whose blob is not on disk is served
// like soft_disabled until a valid binding arrives, and it is counted.
func TestDegradedEndpointServedLikeSoftDisabled(t *testing.T) {
	w := newWorld(t)
	wantA(t, "degraded", w.dot(epH, "www.example.com", dns.TypeA), "192.0.2.20")
	if w.h.Counters().Degraded == 0 {
		t.Fatal("not counted")
	}
	// An Endpoint whose image row says it is fine but whose blob vanished after the
	// image was built degrades too, rather than guessing a policy.
}

// Require Authorized IPs: a source outside the list is refused as hard_disabled is,
// a source inside passes, Plain DNS identified by a claim passes (the claim is the
// authorization), and the refusal reports a LearnedIP only over DoH and DoH3.
func TestRequireAuthorizedIPs(t *testing.T) {
	w := newWorld(t)
	// E: the list holds 10.9.9.0/24 only. The source is 127.0.0.1.
	if rcodeOf(w.dot(epE, "www.example.com", dns.TypeA)) != "REFUSED" || rcodeOf(w.doq(epE, "www.example.com", dns.TypeA)) != "REFUSED" {
		t.Fatal("DoT or DoQ passed")
	}
	if w.doh(epE, "www.example.com", dns.TypeA).Status != 403 || w.doh3(epE, "www.example.com", dns.TypeA).Status != 403 {
		t.Fatal("DoH or DoH3 passed")
	}
	// From inside the list it is answered.
	in := qopt{t: listen.DoT, src: "10.9.9.7", sni: rid(epE) + "." + testZone}
	wantA(t, "inside", w.call(in, "www.example.com", dns.TypeA), "0.0.0.0")
	// F: the list holds loopback.
	wantA(t, "F", w.dot(epF, "www.example.com", dns.TypeA), "0.0.0.0")
	// Plain DNS by claim passes on E.
	wantA(t, "plain by claim", w.plain(epE, "www.example.com", dns.TypeA), "0.0.0.0")
	if w.h.Counters().RequireAuth != 4 {
		t.Fatalf("counter %d", w.h.Counters().RequireAuth)
	}
	// LearnedIP: DoH and DoH3 only (the roaming case), once for the source.
	_, learned, _ := w.rep.counts()
	if learned != 1 {
		t.Fatalf("learned %d, want 1 (the DoH and DoH3 refusals share one source and bucket)", learned)
	}
	l := w.rep.learned[0]
	if l.SourceIp[0] != 127 || len(l.SourceIp) != 4 {
		t.Fatalf("learned %v", l)
	}
}

// A priority revocation acts like hard_disabled until the entry is applied or it
// expires (SC 5.2a case 1, 4b), for an Endpoint on every transport and for a claim
// on Plain DNS, even when the record is gone.
func TestRevocations(t *testing.T) {
	w := newWorld(t)
	now := w.now()
	epID := [16]byte{}
	copy(epID[:], w.img.Claims()[0].EndpointID[:])
	for _, c := range w.img.Claims() {
		if c.EndpointID[0] == epB {
			epID = c.EndpointID
		}
	}
	w.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, IDs: [][16]byte{epID}, RevSeq: 8, ExpiresAt: now.Add(10 * time.Minute)}})
	if rcodeOf(w.dot(epB, "www.example.com", dns.TypeA)) != "REFUSED" {
		t.Fatal("dot not refused")
	}
	if w.doh(epB, "www.example.com", dns.TypeA).Status != 403 {
		t.Fatal("doh not refused")
	}
	if !w.plain(epB, "www.example.com", dns.TypeA).Drop {
		t.Fatal("plain not dropped")
	}
	if w.h.Counters().Revoked != 3 {
		t.Fatalf("revoked counter %d", w.h.Counters().Revoked)
	}
	// Another Endpoint is untouched.
	wantA(t, "A", w.dot(epA, "allow.example.com", dns.TypeA), "192.0.2.30")
	// A revocation of a claim drops only that claim's source, even with no record
	// of its Endpoint: the claim id is that of Endpoint A's claim.
	w.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_CLAIM, IDs: [][16]byte{claimOf(w, epA)}, RevSeq: 8, ExpiresAt: now.Add(time.Minute)}})
	if !w.plain(epA, "www.example.com", dns.TypeA).Drop {
		t.Fatal("claim revocation did not drop")
	}
	wantA(t, "A over dot, claim revoked", w.dot(epA, "allow.example.com", dns.TypeA), "192.0.2.30")
	// Expired: no longer acts.
	w.advance(2 * time.Minute)
	wantA(t, "expired", w.plain(epA, "allow.example.com", dns.TypeA), "192.0.2.30")
	// An applied entry at or above rev_seq ends it: the image's seq is 7.
	w.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, IDs: [][16]byte{epID}, RevSeq: 7, ExpiresAt: w.now().Add(time.Hour)}})
	wantA(t, "applied", w.dot(epB, "www.example.com", dns.TypeA), "192.0.2.20")
}

func claimOf(w *world, ep byte) [16]byte {
	for _, c := range w.img.Claims() {
		if c.EndpointID[0] == ep {
			return c.ID
		}
	}
	w.t.Fatal("no claim")
	return [16]byte{}
}

// The Plain DNS claim rule: an unvalidated UDP query of a claim that no validated
// query has refreshed in the last hour is answered TC=1 with no records, a TCP
// query or a cookie-validated UDP query refreshes it, and the claim then answers
// plain UDP for an hour (p4-nodes.md 7.6).
func TestUnvalidatedUDPOfAStaleClaimGetsTC(t *testing.T) {
	w := newWorld(t)
	udp := func(validated bool) listen.Reply {
		return w.call(qopt{t: listen.UDP, src: "127.0.0.2", validated: vptr(validated)}, "www.example.com", dns.TypeA)
	}
	r := udp(false)
	if !r.Msg.Truncated || len(r.Msg.Answer) != 0 {
		t.Fatalf("first unvalidated UDP: %+v", r.Msg)
	}
	// Nothing is reported for it.
	if _, _, a := w.rep.counts(); a != 0 {
		t.Fatal("activity for an unvalidated claim query")
	}
	// The TCP retry validates the source.
	wantA(t, "tcp", w.plain(epB, "www.example.com", dns.TypeA), "192.0.2.20")
	_, _, a := w.rep.counts()
	if a != 1 {
		t.Fatalf("activity %d after the TCP query", a)
	}
	// Now UDP with no cookie is answered, and still reports nothing.
	wantA(t, "udp after tcp", udp(false), "192.0.2.20")
	w.advance(10 * time.Minute) // another bucket
	udp(false)
	if _, _, a2 := w.rep.counts(); a2 != 1 {
		t.Fatalf("an unvalidated UDP query reported activity (%d)", a2)
	}
	// A cookie-validated UDP query reports.
	wantA(t, "udp with cookie", udp(true), "192.0.2.20")
	if _, _, a3 := w.rep.counts(); a3 != 2 {
		t.Fatalf("validated UDP activity %d", a3)
	}
	// An hour of silence makes the claim stale again.
	w.advance(61 * time.Minute)
	if r := udp(false); !r.Msg.Truncated {
		t.Fatal("stale claim answered an unvalidated query")
	}
	// A claim on another Endpoint was never validated and is stale too.
	r = w.call(qopt{t: listen.UDP, src: "127.0.0.1", validated: vptr(false)}, "www.example.com", dns.TypeA)
	if !r.Msg.Truncated {
		t.Fatal("A's claim answered an unvalidated query")
	}
}

// The refusal counters follow the order of 4b: Require Authorized IPs first, then
// admin_state, then a revocation (p4n-W7-r2-1).
func TestRefusalCounterOrder(t *testing.T) {
	w := newWorld(t)
	req := &listen.Request{Transport: listen.DoT, Msg: new(dns.Msg).SetQuestion("a.example.com.", dns.TypeA)}
	w.h.refusal(req, gateResult{auth: true, hard: true, revoked: true})
	w.h.refusal(req, gateResult{hard: true, revoked: true})
	w.h.refusal(req, gateResult{revoked: true})
	c := w.h.Counters()
	if c.RequireAuth != 1 || c.HardDisabled != 1 || c.Revoked != 1 {
		t.Fatalf("counters %+v", c)
	}
}
