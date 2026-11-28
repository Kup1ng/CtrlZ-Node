// Package grant is the Grant table of p4b-proxy section 4 and the table of open
// connections that goes with it (4.1, 4.3, 4.6, 5.4). It is the one place in the
// dns process that judges caps, charging and the end of Grants, so a limit is read
// in one process and not in two.
//
// The package knows nothing of DNS messages, profiles or the image: the query
// path (internal/dns) turns a decision into a PutReq and a Lookup into a verdict,
// and tells the table which holders have ended. Everything here is memory only
// (4.1): a restart of dns empties the table and the next queries rebuild it.
//
// Nothing in this package holds a query name in a log, an error or a counter name.
package grant

import (
	"time"
)

// Kinds of an outcome (shared policy.GrantRedirect and GrantBlockPage).
const (
	KindRedirect  uint8 = 1
	KindBlockPage uint8 = 2
)

// Pick is how a Redirect chose its location.
type Pick uint8

// The picks of a holder (4.1): the location is fixed, or Auto or Random drew it.
const (
	PickFixed Pick = iota
	PickAuto
	PickRandom
)

// Outcome is what one (name, source) entry says to do. Two outcomes are equal when
// every field is, which is what "equal outcome" means in 4.2. Dial is the dial
// host in canonical wire form ("" for none), Page the block page hash (all zero is
// our default page).
type Outcome struct {
	Kind     uint8
	Location uint16 // kind 1 only
	Dial     string
	Page     [32]byte // kind 2 only
}

// Holder is one right to an entry (4.1): one per (Endpoint, client, origin).
type Holder struct {
	Endpoint [16]byte
	// Client is the client hash when the Endpoint's record has a ClientRecord of it,
	// else zero.
	Client [16]byte
	// Origin is zero for a Grant decided here, else the node that forwarded it.
	Origin [16]byte
	// Ident is the first 16 bytes of the SHA-256 of rid_hash and doh_token_hash: a
	// rotated resolver ID ends the holder (4.6).
	Ident [16]byte
	// Claim is the claim that made the holder, zero for none.
	Claim [16]byte
	// Account is the share-rule key of the Endpoint (account_hash, or the Endpoint
	// id when the record has none).
	Account [16]byte
	// Open says Require Authorized IPs was off when the holder was written.
	Open      bool
	Widenable bool
	Pick      Pick
	// Alone says the peer holds no copy (4.5). It never changes what a holder may
	// do, only the answer: the peer's address is left out while it is set.
	Alone bool

	// Expires and LastDecide are Unix seconds. LastDecide is the newest deciding
	// query, which orders the holders of a charge (4.3) and tells the one that has
	// been silent for MaxProxyTTL (4.2 step 3).
	Expires    int64
	LastDecide int64
	// OfferAt is when this holder may be offered to the peer again (4.5); SentAt is
	// the last accepted forward.
	OfferAt int64
	SentAt  int64
}

// id is the identity of a holder inside an entry.
type holderID struct{ ep, client, origin [16]byte }

func (h *Holder) id() holderID { return holderID{h.Endpoint, h.Client, h.Origin} }

func (h *Holder) forwarded() bool { return h.Origin != [16]byte{} }

// Limits are the numbers of 12 that this package judges. A test may shrink them.
type Limits struct {
	// Holders (Grants).
	DefaultEndpointCap int // grant_cap of an Endpoint that has none
	NodeHolders        int
	NodeForwarded      int
	// Waits of 4.3 step 3: per source, node.
	WaitPerSource int
	WaitNode      int
	// Open connections, kind 1.
	EntryPerEndpoint   int // 256, for each Endpoint in an entry, at most 8 counted
	EndpointSource     int // 1024
	EndpointOpen       int // 2048
	ExitOpen           int // 20,000 under the share rule
	NodeOpen           int // 30,000 under the share rule
	OpenedLast30s      int // 60,000 under the share rule
	BlockEndpoint      int // 128
	BlockNode          int // 2048 under the share rule
	DialHold           time.Duration
	ForwardQueue       int // 4096 under the share rule
	ForwardUnanswered  int // 256
	EndpointForwardDiv int // forwarded room of an Endpoint is cap/Div: 2
}

// DefaultLimits are the values of 12 (all D31).
func DefaultLimits() Limits {
	return Limits{
		DefaultEndpointCap: 4096,
		NodeHolders:        500_000,
		NodeForwarded:      125_000,
		WaitPerSource:      16,
		WaitNode:           4096,
		EntryPerEndpoint:   256,
		EndpointSource:     1024,
		EndpointOpen:       2048,
		ExitOpen:           20_000,
		NodeOpen:           30_000,
		OpenedLast30s:      60_000,
		BlockEndpoint:      128,
		BlockNode:          2048,
		DialHold:           90 * time.Second,
		ForwardQueue:       4096,
		ForwardUnanswered:  256,
		EndpointForwardDiv: 2,
	}
}

// Lifetimes (4.1, 4.5).
const (
	// HolderLife is the absolute lifetime of a holder, set again by each deciding
	// query of a validated source.
	HolderLife = 4 * time.Hour
	// MaxEndpoints and MaxPerEndpoint bound an entry: holders of at most 64 Endpoints,
	// 8 of one.
	MaxEndpoints   = 64
	MaxPerEndpoint = 8
	// MaxProxyTTL is shared policy.MaxProxyTTL, in seconds: the longest an answer
	// that carries PROXY_IPs may be cached. Copied here so the package stays free of
	// the evaluator; a test pins the two together.
	MaxProxyTTL = 3600
	// RefusedRetry and UnsentRetry are the waits of 4.5 before a holder is offered
	// to the peer again.
	RefusedRetry = 10 * time.Minute
	UnsentRetry  = 60 * time.Second
)
