package dns

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

func (w *world) onlyActivity(t *testing.T) *telemetryv1.ActivityEntry {
	t.Helper()
	w.rep.mu.Lock()
	defer w.rep.mu.Unlock()
	if len(w.rep.acts) != 1 {
		t.Fatalf("%d activity entries, want 1", len(w.rep.acts))
	}
	a := w.rep.acts[0]
	if err := wire.ValidateActivityBatch(&telemetryv1.ActivityBatch{Entries: []*telemetryv1.ActivityEntry{a}}, w.now().Unix()); err != nil {
		t.Fatalf("the hub's validator refuses the entry: %v", err)
	}
	return a
}

// Activity is reported for a query that passes 4b, with the client label, the
// protocol and the bucket, and with the source_ip_hash of the longest authorized
// prefix that holds the source (T-086, SC 12).
func TestActivityForAPassingQuery(t *testing.T) {
	w := newWorld(t)
	w.setNow(time.Unix(1_800_000_123, 0))
	// A DoT query with a client label.
	w.call(qopt{t: listen.DoT, sni: rid(epG) + "-pc." + testZone}, "www.example.com", dns.TypeA)
	a := w.onlyActivity(t)
	if a.ClientLabel != "pc" || a.Protocol != commonv1.Protocol_PROTOCOL_DOT || a.EndpointId[0] != epG ||
		a.FirstSeenBucket != 1_800_000_000 || a.LastSeenBucket != 1_800_000_000 || len(a.ClaimId) != 0 {
		t.Fatalf("%v", a)
	}
	// G's authorized list holds 127.0.0.0/8 and 127.0.0.0/24; the source is 127.0.0.1,
	// so the longest prefix is the /24. The hash is over the endpoint id and the
	// masked prefix text, on node and hub alike.
	sum := sha256.Sum256(append(bytes.Repeat([]byte{epG}, 16), "127.0.0.0/24"...))
	if !bytes.Equal(a.SourceIpHash, sum[:16]) {
		t.Fatalf("source_ip_hash %x", a.SourceIpHash)
	}
	// Several sources inside the /24 give the same hash.
	w.rep.reset()
	w.call(qopt{t: listen.DoQ, src: "127.0.0.77", sni: rid(epG) + "-pc." + testZone}, "www.example.com", dns.TypeA)
	if b := w.onlyActivity(t); !bytes.Equal(b.SourceIpHash, sum[:16]) || b.Protocol != commonv1.Protocol_PROTOCOL_DOQ {
		t.Fatalf("%v", b)
	}
	// A source in /8 only has the /8 hash, and one outside both has neither field.
	w.rep.reset()
	w.call(qopt{t: listen.DoT, src: "127.9.9.9", sni: rid(epG) + "." + testZone}, "www.example.com", dns.TypeA)
	b := w.onlyActivity(t)
	sum8 := sha256.Sum256(append(bytes.Repeat([]byte{epG}, 16), "127.0.0.0/8"...))
	if !bytes.Equal(b.SourceIpHash, sum8[:16]) || b.ClientLabel != "default" {
		t.Fatalf("%v", b)
	}
	w.rep.reset()
	w.call(qopt{t: listen.DoT, src: "198.51.100.5", sni: rid(epB) + "." + testZone}, "www.example.com", dns.TypeA)
	c := w.onlyActivity(t)
	if len(c.SourceIpHash) != 0 || len(c.ClaimId) != 0 || c.EndpointId[0] != epB {
		t.Fatalf("%v", c)
	}
	// Plain DNS identified by a claim carries the claim id, not a hash.
	w.rep.reset()
	w.plain(epB, "www.example.com", dns.TypeA)
	d := w.onlyActivity(t)
	if !bytes.Equal(d.ClaimId, bytes.Repeat([]byte{epB + 0x40}, 16)) || len(d.SourceIpHash) != 0 || d.Protocol != commonv1.Protocol_PROTOCOL_TCP {
		t.Fatalf("%v", d)
	}
}

// What creates no activity: a query 4b refuses (so no client row, no
// *_query_at), a DoH query that names nobody, a query with no identity, and a
// Plain DNS claim query from an unvalidated source.
func TestNoActivityForRefusedOrUnidentified(t *testing.T) {
	w := newWorld(t)
	check := func(what string) {
		t.Helper()
		if p, l, a := w.rep.counts(); a != 0 {
			t.Fatalf("%s: %d activity (%d proofs, %d learned)", what, a, p, l)
		}
	}
	w.dot(epC, "www.example.com", dns.TypeA) // hard_disabled
	w.doh(epC, "www.example.com", dns.TypeA)
	check("hard_disabled")
	// Under Require Authorized IPs a DoT query with a new label is refused and
	// creates no client row (mutant: activity reported before 4b).
	w.call(qopt{t: listen.DoT, sni: rid(epE) + "-newlabel." + testZone}, "www.example.com", dns.TypeA)
	check("require authorized ips")
	w.doh(20, "www.example.com", dns.TypeA)
	check("404")
	w.call(qopt{t: listen.DoT, sni: testZone}, "www.example.com", dns.TypeA)
	w.call(qopt{t: listen.TCP, src: "127.0.0.3"}, "www.example.com", dns.TypeA)
	check("no identity")
	w.call(qopt{t: listen.UDP, src: "127.0.0.1", validated: vptr(false)}, "www.example.com", dns.TypeA)
	check("unvalidated claim")
	// A revoked Endpoint.
	w.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, IDs: [][16]byte{{epB, epB, epB, epB, epB, epB, epB, epB, epB, epB, epB, epB, epB, epB, epB, epB}}, RevSeq: 99, ExpiresAt: w.now().Add(time.Hour)}})
	w.dot(epB, "www.example.com", dns.TypeA)
	check("revoked")
}

// Verify queries, system names, zone answers and soft_disabled queries of an
// identified source that passes 4b are activity too (T-049: they count for the
// Pending to Active step); their rows reach no dns_raw because this side sends no
// log at all.
func TestActivityForVerifyAndSystemAndSoftDisabled(t *testing.T) {
	w := newWorld(t)
	for _, q := range []struct {
		name string
		ep   byte
		n    string
	}{{"verify", epA, verifyName(newLabel(t))}, {"system", epA, "captive.apple.com"}, {"zone", epA, rid(epA) + "." + testZone}, {"soft", epD, "www.example.com"}} {
		w.rep.reset()
		w.advance(5 * time.Minute) // a bucket of its own, or the once-per-bucket rule hides it
		w.dot(q.ep, q.n, dns.TypeA)
		if _, _, a := w.rep.counts(); a != 1 {
			t.Errorf("%s: %d activity entries", q.name, a)
		}
	}
}

// One entry for each key and bucket: the second query of the same device in the
// same 5 minutes reports nothing, the next bucket reports again.
func TestActivityIsOncePerKeyAndBucket(t *testing.T) {
	w := newWorld(t)
	w.setNow(time.Unix(1_800_000_000, 0))
	for i := 0; i < 5; i++ {
		w.dot(epB, "www.example.com", dns.TypeA)
	}
	if _, _, a := w.rep.counts(); a != 1 {
		t.Fatalf("%d entries for five queries", a)
	}
	w.dot(epA, "www.example.com", dns.TypeA) // another Endpoint
	w.doq(epB, "www.example.com", dns.TypeA) // another protocol
	w.call(qopt{t: listen.DoT, sni: rid(epB) + "-pc." + testZone}, "www.example.com", dns.TypeA)
	if _, _, a := w.rep.counts(); a != 4 {
		t.Fatalf("%d entries", a)
	}
	w.advance(5 * time.Minute)
	w.dot(epB, "www.example.com", dns.TypeA)
	if _, _, a := w.rep.counts(); a != 5 {
		t.Fatalf("%d entries after the bucket changed", a)
	}
}

// LearnedIP (P3 3.3, 7.6): only DoH and DoH3 with the token, also when 4b refuses
// the query for Require Authorized IPs alone, never when admin_state or a
// revocation refuses it, never for DoT, DoQ or Plain DNS.
func TestLearnedIPConditions(t *testing.T) {
	w := newWorld(t)
	learned := func() int { _, l, _ := w.rep.counts(); return l }

	// A has Authorize Secure DNS and no list: a DoH query from anywhere is learned.
	w.call(qopt{t: listen.DoH, src: "198.51.100.5", http: dohInfo("/"+tok(epA), rid(epA)+"."+testZone)}, "www.example.com", dns.TypeA)
	if learned() != 1 {
		t.Fatal("DoH not learned")
	}
	l := w.rep.learned[0]
	if l.EndpointId[0] != epA || l.Protocol != commonv1.Protocol_PROTOCOL_DOH || len(l.SourceIp) != 4 || l.SourceIp[0] != 198 {
		t.Fatalf("%v", l)
	}
	if err := wire.ValidateLearnedIP(l, w.now().Unix()); err != nil {
		t.Fatalf("the hub's validator: %v", err)
	}
	// The same source again in the same bucket is not sent twice.
	w.call(qopt{t: listen.DoH, src: "198.51.100.5", http: dohInfo("/"+tok(epA), rid(epA)+"."+testZone)}, "www.example.com", dns.TypeA)
	if learned() != 1 {
		t.Fatal("learned twice in one bucket")
	}
	// DoH3 learns, with its own protocol.
	w.rep.reset()
	w.call(qopt{t: listen.DoH3, src: "198.51.100.6", http: dohInfo("/"+tok(epA), rid(epA)+"."+testZone)}, "www.example.com", dns.TypeA)
	if learned() != 1 || w.rep.learned[0].Protocol != commonv1.Protocol_PROTOCOL_DOH3 {
		t.Fatal("DoH3")
	}
	// Never from DoT, DoQ or Plain DNS: the rid in clear SNI is not a secret, so a
	// known rid must not open Require Authorized IPs (open question 12).
	w.rep.reset()
	w.call(qopt{t: listen.DoT, src: "198.51.100.7", sni: rid(epA) + "." + testZone}, "www.example.com", dns.TypeA)
	w.call(qopt{t: listen.DoQ, src: "198.51.100.8", sni: rid(epA) + "." + testZone}, "www.example.com", dns.TypeA)
	w.plain(epA, "www.example.com", dns.TypeA)
	w.call(qopt{t: listen.UDP, src: "127.0.0.1", validated: vptr(true)}, "www.example.com", dns.TypeA)
	if learned() != 0 {
		t.Fatal("learned from DoT, DoQ or Plain DNS")
	}
	// An Endpoint with Authorize Secure DNS off learns nothing.
	w.call(qopt{t: listen.DoH, src: "198.51.100.9", http: dohInfo("/"+tok(epB), rid(epB)+"."+testZone)}, "www.example.com", dns.TypeA)
	if learned() != 0 {
		t.Fatal("learned with the switch off")
	}
	// Roaming: E requires authorized IPs, and a DoH query from a new address is
	// refused and learned.
	r := w.call(qopt{t: listen.DoH, src: "198.51.100.10", http: dohInfo("/"+tok(epE), rid(epE)+"."+testZone)}, "www.example.com", dns.TypeA)
	if r.Status != 403 || learned() != 1 {
		t.Fatalf("roaming: status %d learned %d", r.Status, learned())
	}
	// A source the list already holds is not learned again.
	w.rep.reset()
	w.call(qopt{t: listen.DoH, src: "10.9.9.9", http: dohInfo("/"+tok(epE), rid(epE)+"."+testZone)}, "www.example.com", dns.TypeA)
	if learned() != 0 {
		t.Fatal("an authorized source was learned")
	}
	// Never when admin_state refuses it, nor when a revocation does.
	w.rep.reset()
	hard := w.call(qopt{t: listen.DoH, src: "198.51.100.11", http: dohInfo("/"+tok(epC), rid(epC)+"."+testZone)}, "www.example.com", dns.TypeA)
	if hard.Status != 403 || learned() != 0 {
		t.Fatalf("hard_disabled learned %d", learned())
	}
	w.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, IDs: [][16]byte{[16]byte(bytes.Repeat([]byte{epE}, 16))}, RevSeq: 99, ExpiresAt: w.now().Add(time.Hour)}})
	w.call(qopt{t: listen.DoH, src: "198.51.100.12", http: dohInfo("/"+tok(epE), rid(epE)+"."+testZone)}, "www.example.com", dns.TypeA)
	if learned() != 0 {
		t.Fatal("a revoked Endpoint learned")
	}
	// A wrong token names nobody, and learns nothing.
	w.call(qopt{t: listen.DoH, src: "198.51.100.13", http: dohInfo("/"+tok(21), rid(epA)+"."+testZone)}, "www.example.com", dns.TypeA)
	if learned() != 0 {
		t.Fatal("a wrong token learned")
	}
}

var _ = hubv1.LearnedIP{}
