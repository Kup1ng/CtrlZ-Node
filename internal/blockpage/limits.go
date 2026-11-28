// Package blockpage is the process of unit ctrlz-block (p4b-proxy 10): the branded
// block page over HTTP and, with a leaf minted on the spot, over HTTPS.
//
// It sits behind two unix sockets. serve.sock carries one connection from the
// proxy (a frame that names the client, then the client's raw bytes); the block
// agent socket carries pages, intermediate keys and unblock requests between this
// process and the agent. The process holds no capability and no network address
// family but AF_UNIX, and the only secret it ever sees is an account's
// short-lived intermediate key, kept in memory.
package blockpage

import (
	"sync"
	"time"
)

// Limits of 12 and 10.2. They are named here so a test and the unit's MemoryMax
// arithmetic read the same numbers.
const (
	// MaxHeaderBytes is the request header cap of 12 (16 KiB).
	MaxHeaderBytes = 16 << 10
	// MaxFormBody is the body cap of the unblock form (10.4).
	MaxFormBody = 4 << 10
	// MaxMessageChars is the message cap of the form (10.4); wire.MaxUnblockNoteChars.
	MaxMessageChars = 500

	// ReadTimeout is the time to read a request, TLS handshake included, and
	// ConnTimeout the life of a whole connection (10.2).
	ReadTimeout = 5 * time.Second
	ConnTimeout = 30 * time.Second

	// MaxConns bounds the connections the process serves at once: the node cap of
	// kind 2 connections of 12 (2048) with a little room, so that a proxy that
	// miscounts cannot take the 512 MiB of MemoryMax.
	MaxConns = 2048 + 64

	// PageCacheBytes is the LRU of pages by hash (10.2).
	PageCacheBytes = 32 << 20
	// PageWait is how long a connection waits for the agent's page (10.2).
	PageWait = time.Second
	// NoPageTTL is how long a hash the agent had no page for is remembered, so a
	// profile that waits for its replacement does not cost one ask per connection.
	NoPageTTL = 30 * time.Second

	// MaxKeys is the account LRU of keys; MaxLeaves the (account, name) LRU of
	// leaves and MaxLeavesPerAccount its per-account bound (10.2).
	MaxKeys             = 4096
	MaxLeaves           = 4096
	MaxLeavesPerAccount = 256
	// KeyWait is how long a TLS handshake waits for a missing key (10.2).
	KeyWait = 2 * time.Second
	// AskEvery is the least time between two need_key frames for one account.
	AskEvery = 10 * time.Second

	// LeafLife and LeafBackdate are the leaf's validity (10.2).
	LeafLife     = 24 * time.Hour
	LeafBackdate = time.Hour

	// Unblock form: at most 5 an hour per (Endpoint, source) and 60 an hour per
	// Endpoint (10.4, D31).
	UnblockPerSource   = 5
	UnblockPerEndpoint = 60
)

// bucket is a token bucket with a burst. Its zero value allows nothing; use
// newBucket. It is safe for concurrent use, so one node-wide bucket is shared by
// every connection.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // tokens a second
	burst  float64
	tokens float64
	at     time.Time
}

func newBucket(rate, burst float64, now time.Time) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, at: now}
}

// allow takes one token when there is one.
func (b *bucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(b.burst, b.tokens+d.Seconds()*b.rate)
		b.at = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Rates of 12: page asks per account 10 a second, per node 100; leaf mints per
// account 10 a second with a burst of 40, per node 200.
const (
	pageAskAccountRate = 10
	pageAskNodeRate    = 100
	mintAccountRate    = 10
	mintAccountBurst   = 40
	mintNodeRate       = 200
)

// accountBuckets keeps one bucket per account, bounded so that a flood of
// accounts' worth of frames cannot grow it. Past the bound the oldest is dropped,
// which hands that account a full bucket again: the node-wide bucket is what holds
// the line then.
type accountBuckets struct {
	mu          sync.Mutex
	rate, burst float64
	m           map[[16]byte]*bucket
	order       [][16]byte
	max         int
}

func newAccountBuckets(rate, burst float64, max int) *accountBuckets {
	return &accountBuckets{rate: rate, burst: burst, m: map[[16]byte]*bucket{}, max: max}
}

func (a *accountBuckets) allow(acct [16]byte, now time.Time) bool {
	a.mu.Lock()
	b := a.m[acct]
	if b == nil {
		if len(a.order) >= a.max {
			delete(a.m, a.order[0])
			a.order = a.order[1:]
		}
		b = newBucket(a.rate, a.burst, now)
		a.m[acct] = b
		a.order = append(a.order, acct)
	}
	a.mu.Unlock()
	return b.allow(now)
}
