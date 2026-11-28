package dns

import (
	"crypto/sha256"
	"mime"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
)

type nopReporter struct{}

func (nopReporter) Proof(*hubv1.ProofObservation)       {}
func (nopReporter) LearnedIP(*hubv1.LearnedIP)          {}
func (nopReporter) Activity(*telemetryv1.ActivityEntry) {}

const (
	activityBucket = 300 // seconds, the 5-minute bucket of SC 13
	seenSize       = 65536
)

// seenFilter lets a report through once for each key. Activity is one entry for
// each (Endpoint, client, source, protocol, bucket) and a learned address one for
// each (Endpoint, source) for a bucket; the key holds the bucket, so the filter
// needs no clock. It is bounded: when it is full the oldest key goes, and a key
// seen again is reported again, which the agent's own deduplication absorbs.
type seenFilter struct {
	mu sync.Mutex
	l  *lru.Cache[string, struct{}]
}

func newSeenFilter() *seenFilter { return &seenFilter{l: lru.New[string, struct{}](seenSize)} }

func (s *seenFilter) first(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.l.Get(key); ok {
		return false
	}
	s.l.Add(key, struct{}{}, 1)
	return true
}

// activity reports a query that passed 4b (T-086, p4-nodes.md 7.6): so a refused
// query creates no client row and moves no *_query_at. A Plain DNS query that a
// claim identifies is reported only when its source is validated (TCP, or UDP
// with a server cookie this node made), because spoofed UDP would otherwise keep
// the claim's last_seen_at alive and block the idle takeover of ip_claim_take.
func (h *Handler) activity(req *listen.Request, id *ident, now time.Time) {
	if id.claim != nil && !req.Validated {
		return
	}
	label := id.activityLabel() // a query that names no client sends the default label (SC 12)
	bucket := now.Unix() / activityBucket * activityBucket
	e := &telemetryv1.ActivityEntry{
		EndpointId: id.st.id[:], ClientLabel: label,
		FirstSeenBucket: bucket, LastSeenBucket: bucket,
		Protocol: protocolOf(req.Transport),
	}
	var who string
	switch {
	case id.claim != nil:
		e.ClaimId = id.claim.ID[:]
		who = string(id.claim.ID[:])
	default:
		// source_ip_hash: the first 16 bytes of SHA-256(endpoint_id || the longest
		// prefix of the record's authorized list that holds the source, in
		// Masked().String() form), on node and hub alike. With no prefix that holds
		// the source the entry carries neither field and still counts the device as
		// alive (SC 12).
		if p, ok := longestAuthorized(id.st.authorized, req.Source.Addr()); ok {
			sum := sha256.Sum256(append(append([]byte(nil), id.st.id[:]...), p.Masked().String()...))
			e.SourceIpHash = sum[:16]
			who = string(e.SourceIpHash)
		}
	}
	key := string(id.st.id[:]) + "|" + label + "|" + who + "|" + strconv.Itoa(int(e.Protocol)) + "|" + strconv.FormatInt(bucket, 10)
	if h.seen.first("a" + key) {
		h.cfg.Reporter.Activity(e)
	}
}

// learn reports the source of a DoH or DoH3 query whose token matched, as an
// address the Endpoint may learn (P3 3.3, p4-nodes.md 7.6). It is also reported
// when 4b refuses the query for Require Authorized IPs alone, which is the
// roaming case: the token proves the user, the address is new. It is never
// reported when admin_state or a revocation refuses the query, and never for DoT,
// DoQ or Plain DNS, whose identity is the rid in clear SNI or an address, so a
// known rid cannot open Require Authorized IPs (open question 12).
func (h *Handler) learn(req *listen.Request, id *ident, g *gateResult, now time.Time) {
	if !id.tokenMatched || id.st == nil || g.hard || g.revoked || !id.st.rec.AuthorizeSecureDns {
		return
	}
	src := req.Source.Addr().Unmap()
	if inAny(id.st.authorized, src) {
		return // already authorized, nothing to learn
	}
	bucket := now.Unix() / activityBucket
	key := "l" + string(id.st.id[:]) + "|" + src.String() + "|" + strconv.FormatInt(bucket, 10)
	if !h.seen.first(key) {
		return
	}
	h.cfg.Reporter.LearnedIP(&hubv1.LearnedIP{
		EndpointId: id.st.id[:], SourceIp: src.AsSlice(),
		Protocol: protocolOf(req.Transport), ObservedAt: now.Unix(),
	})
}

// proof reports a verify query as a ProofObservation, exactly under the
// conditions of p4-nodes.md 7.6 and SC 3.5:
//
//   - udp and tcp: only a TXT query (the proof ways of P3 4.2 ask TXT, while a
//     page can make a stub ask A, AAAA or HTTPS, and spoofed UDP filling step 1's
//     limits pushes that lookup to TCP by TC=1);
//   - dot and doq: whatever the type, and only on a connection that has an
//     identity, because the validator refuses an encrypted observation with no
//     rid_hash and the node never pads the field;
//   - doh and doh3: only a POST of application/dns-message with none of Origin,
//     Referer and Sec-Fetch-Site, so a page cannot cause one (a GET never does).
//
// rid_hash is identity.RIDHash of the identity the query arrived on for the
// encrypted four, and empty for udp and tcp.
func (h *Handler) proof(req *listen.Request, id *ident, label string, qtype uint16, now time.Time) {
	var rid []byte
	switch req.Transport {
	case listen.UDP, listen.TCP:
		if qtype != dns.TypeTXT {
			return
		}
	case listen.DoT, listen.DoQ:
		if id.st == nil {
			return
		}
		rid = id.ridHash[:]
	case listen.DoH, listen.DoH3:
		hi := req.HTTP
		if hi == nil || id.st == nil || hi.Method != "POST" || hi.HasOrigin || hi.HasReferer || hi.HasSecFetchSite {
			return
		}
		if mt, _, err := mime.ParseMediaType(hi.ContentType); err != nil || mt != "application/dns-message" {
			return
		}
		rid = id.ridHash[:]
	default:
		return
	}
	src := req.Source.Addr().Unmap()
	if !src.IsValid() {
		return
	}
	h.cfg.Reporter.Proof(&hubv1.ProofObservation{
		Label: label, SourceIp: addrBytes(src), Protocol: protocolOf(req.Transport),
		ObservedAt: now.Unix(), RidHash: rid,
	})
}

// addrBytes is the 4-byte form for IPv4 and the 16-byte form for IPv6, never an
// IPv4-mapped address (SC 3.5).
func addrBytes(a netip.Addr) []byte { return a.Unmap().AsSlice() }
