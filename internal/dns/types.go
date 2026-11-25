package dns

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/sysnames"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// Image is what the query path reads of a serving image. *image.Image is one; a
// test can stand in. Nothing in it changes after it is opened, so any number of
// queries may read it at once.
type Image interface {
	Seq() uint64
	ByResolverID(rid string) (*image.Endpoint, bool)
	ByEndpointID(id [16]byte) (*image.Endpoint, bool)
	Claims() []image.Claim
	ProfilePath(h [32]byte) (string, bool)
	PairTable() *policyv1.PairTable
	Zone() *zone.Table
}

// Reporter takes what the query path tells the agent: proof observations,
// learned addresses and activity (p4-nodes.md 7.6). The agent's socket is
// behind it (W5b). Every method must be cheap and must not block, because it is
// called on the query's goroutine: the agent's end drops when its queue is full
// (SC 8a.11 L10), which is why these messages are never retried here. The
// messages carry no qname.
type Reporter interface {
	Proof(*hubv1.ProofObservation)
	LearnedIP(*hubv1.LearnedIP)
	Activity(*telemetryv1.ActivityEntry)
}

// FreeQuery is what the free path (SC 5.2a, W9) is given.
type FreeQuery struct {
	Name  names.Name
	QType uint16
	// Synth is set for a wildcard system name of step 2 that has a synthesized
	// answer (isolated_synth, SC 8): the DNS_IP A answer. SynthAlways says it is the
	// answer itself, which needs no lookup and so passes points 6 and 7 of 5.2a; with
	// it clear it stands in for a SERVFAIL, so the validation name of Android keeps
	// passing while the resolver is down.
	Synth       func() *dns.Msg
	SynthAlways bool
	// ImageSeq is the seq of the image the Handler identified the source with. The
	// free gate's caught-up fact is judged against it (p4n-MD-r3-1).
	ImageSeq uint64
}

// FreeCases is implemented by a FreePath that also counts the queries of identity
// case 3 that it is never asked to answer (SC 5.2a, Counters): Hop is a query that
// point (b) dropped, MyIP one for myip.<zone>, which the caller answers REFUSED.
type FreeCases interface {
	FreePath
	Hop(req *listen.Request)
	MyIP(req *listen.Request, imageSeq uint64)
}

// FreePath is the seam of SC 5.2a. It is called at step 4 for a Plain DNS query
// whose source has no identity and is not the dns_ip of a node (point (b) of 5.2a
// is judged here, before the call), and for a wildcard system name from such a
// source. It answers the query as a free query, or says handled=false when the
// free path does not take it (switch off, node not caught up, RD=0 and the
// rest are its own business), and the caller then answers REFUSED. A nil
// FreePath is a node with free DNS off.
type FreePath interface {
	Serve(ctx context.Context, req *listen.Request, q FreeQuery) (rep listen.Reply, handled bool)
}

// GrantRequest is a Grant the query path wants written (SC 10.4). The proxy is
// idle in P4, so nothing consumes it yet; the seam keeps the order of step 7 and
// step 9 right for P4b.
type GrantRequest struct {
	Endpoint [16]byte
	Source   netip.Addr
	Name     names.Name
	Final    *sharedpolicy.Final
}

// GrantSink takes Grants.
type GrantSink interface {
	Grant(GrantRequest)
}

// Settings are the parts of NodeConfig the query path reads. Build one with
// NewSettings and hand it to Handler.SetSettings.
type Settings struct {
	zones    []names.Name
	panel    []names.Name
	selfIP   netip.Addr
	proofKey []byte
	isolated bool

	matcher *sysnames.Matcher
	origins map[string]bool // CORS origins of the panel, for /v
}

// NewSettings builds the settings. selfIP is this node's own DNS_IP as clients
// reach it (dns_advertised_ip): the answer of a verify name. proofKey is
// NodeConfig.proof_key; an all-zero or empty key means no proof code is given
// (p4-nodes.md 7.2). isolated is the node's Isolated mode.
func NewSettings(zones, panelHostnames []names.Name, selfIP netip.Addr, proofKey []byte, isolated bool) *Settings {
	s := &Settings{
		zones: append([]names.Name(nil), zones...), panel: append([]names.Name(nil), panelHostnames...),
		selfIP: selfIP, proofKey: append([]byte(nil), proofKey...), isolated: isolated,
		matcher: sysnames.NewMatcher(panelHostnames), origins: map[string]bool{},
	}
	for i := range panelHostnames {
		s.origins["https://"+NameText(panelHostnames[i])] = true
	}
	return s
}

// hasProofKey: a key of all zero bytes is the placeholder the agent keeps on
// disk (7.2) and means no code.
func (s *Settings) hasProofKey() bool {
	for _, b := range s.proofKey {
		if b != 0 {
			return true
		}
	}
	return false
}

// ZoneState is what the agent hands dns about the zone: the table in use (nil
// when none is in use yet, SC 8a.5), the node's own view for local mode, and the
// active DNS-01 challenge values by fqdn.
type ZoneState struct {
	Table *zone.Table
	Local zone.Local
	// Acme gives the TXT values of the active AcmeChallenges whose fqdn is the
	// name (lower case, no trailing dot). Nil means none.
	Acme func(fqdn string) []string
}

// Revocation is a priority revocation from the hub (SC 5.2a case 1, 4b, 5.5).
type Revocation struct {
	Kind      policyv1.RevocationKind
	IDs       [][16]byte
	RevSeq    uint64
	ExpiresAt time.Time
}

// Revocations is the set in force. The agent replaces it whenever the hub sends
// or renews one, or the node acks. A revocation acts until the node's applied
// seq reaches RevSeq or ExpiresAt passes; the handler reads the applied seq from
// the image it serves, so an entry that has been applied ends it by itself.
type Revocations struct {
	mu    sync.RWMutex
	items []Revocation
}

// Set replaces the set.
func (r *Revocations) Set(items []Revocation) {
	r.mu.Lock()
	r.items = append([]Revocation(nil), items...)
	r.mu.Unlock()
}

func (r *Revocations) acts(kind policyv1.RevocationKind, id [16]byte, applied uint64, now time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := range r.items {
		it := &r.items[i]
		if it.Kind != kind || applied >= it.RevSeq || !now.Before(it.ExpiresAt) {
			continue
		}
		for _, x := range it.IDs {
			if x == id {
				return true
			}
		}
	}
	return false
}

// Counters are node-local counts of refusals, for the e2e tests and for P5's
// upload. They hold no name and no address. The Sanity Gate's rejection count is
// not here: it is counted where the Gate runs, through policy.Resolver.Rejected,
// and the wiring feeds that hook (a second field here would always read 0).
type Counters struct {
	HardDisabled uint64
	RequireAuth  uint64
	Revoked      uint64
	Degraded     uint64
}
