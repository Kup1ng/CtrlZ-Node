// Package freelimit holds the counters that bound the free DNS path (SC 5.2a,
// p4-nodes 7.9): the response limit in bytes per destination prefix, the shares
// and the node-wide budget in queries a second, and the miss cap.
//
// None of it knows what a query means. It sees an address, a time and a number,
// and answers yes or no, so the order of the points of 5.2a stays in one place
// (internal/dns/free.go) and each limit can be tested on its own. Nothing here
// holds a name, and an address lives only as long as its second or its bucket.
//
// All numbers are provisional (D31).
package freelimit

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
)

// The response limit of 7.9: per destination prefix, 64 KiB of free UDP replies a
// second with a burst of 256 KiB.
const (
	DefaultRateBytes  = 64 << 10
	DefaultBurstBytes = 256 << 10
)

// Prefix is the prefix a free source is judged by: /24 for IPv4, /56 for IPv6.
// It is the key of the response limit and of the prefix shares.
func Prefix(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 56
	}
	p, _ := a.Prefix(bits)
	return p
}

// Host is the address share's key: /32 for IPv4, /64 for IPv6.
func Host(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits)
	return p
}

// ---- response limit

// prefixesPerShard times responseShards bounds the number of destination prefixes
// the limit remembers. A spoofed flood names as many victims as it likes, so the
// table cannot grow with them: when it is full the coldest prefix is forgotten,
// which gives that victim a new burst and no one else anything.
const (
	responseShards   = 16
	prefixesPerShard = 4096
)

type allowance struct {
	tokens float64
	at     time.Time
}

type respShard struct {
	mu sync.Mutex
	m  *lru.Cache[netip.Prefix, *allowance]
}

// ResponseLimit is the response-rate limit of 5.2a, keyed on the prefix a free UDP
// reply goes to and measured in response bytes. Over verdicts are taken at point 3
// of the order, bytes are charged at step 10, so a reply may take a prefix a little
// below zero: the debt is one reply for each query in flight and is paid by time.
type ResponseLimit struct {
	rate, burst float64
	now         func() time.Time
	seed        maphash.Seed
	sh          [responseShards]respShard
}

// NewResponseLimit builds the limit. Zero rate or burst take the defaults of 7.9.
// now may be nil.
func NewResponseLimit(rateBytes, burstBytes int, now func() time.Time) *ResponseLimit {
	if rateBytes <= 0 {
		rateBytes = DefaultRateBytes
	}
	if burstBytes <= 0 {
		burstBytes = DefaultBurstBytes
	}
	if now == nil {
		now = time.Now
	}
	r := &ResponseLimit{rate: float64(rateBytes), burst: float64(burstBytes), now: now, seed: maphash.MakeSeed()}
	for i := range r.sh {
		r.sh[i].m = lru.New[netip.Prefix, *allowance](prefixesPerShard)
	}
	return r
}

func (r *ResponseLimit) shard(p netip.Prefix) *respShard {
	return &r.sh[maphash.Comparable(r.seed, p)%responseShards]
}

// refill brings b up to now. Time that goes backwards adds nothing.
func (r *ResponseLimit) refill(b *allowance, now time.Time) {
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(r.burst, b.tokens+d.Seconds()*r.rate)
		b.at = now
	}
}

// Over says whether the prefix has used up its rate (point 3): a prefix the limit
// does not know has its whole burst.
func (r *ResponseLimit) Over(p netip.Prefix) bool {
	s := r.shard(p)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m.Get(p)
	if !ok {
		return false
	}
	r.refill(b, r.now())
	return b.tokens <= 0
}

// Charge counts n bytes of a reply that went to the prefix (step 10).
func (r *ResponseLimit) Charge(p netip.Prefix, n int) {
	s := r.shard(p)
	now := r.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m.Get(p)
	if !ok {
		b = &allowance{tokens: r.burst, at: now}
		s.m.Add(p, b, 1)
	}
	r.refill(b, now)
	b.tokens -= float64(n)
}

// ---- shares and budget

// Share names what stopped a query at point 4 or 5, for the counter.
type Share uint8

const (
	ShareOK Share = iota
	ShareUnvalidatedPrefix
	ShareUnvalidatedAll
	ShareSource
	ShareValidatedPrefix
	ShareValidatedAll
	ShareBudget
)

// Meter counts free queries in one-second windows: the node-wide budget and the
// shares of 5.2a. A fixed window is crude (a source may spend two shares across a
// second boundary) and cheap, and every limit here is a share of a number that is
// itself provisional.
//
// Keys are added only for a query that every aggregate lets through, so the maps
// of one window hold at most as many keys as the aggregate admits, which is at
// most half the budget (50,000 at the ceiling), however many addresses a spoofed
// flood uses.
type Meter struct {
	mu  sync.Mutex
	sec int64

	budget uint32
	// unvalidated: UDP without a valid server cookie, whose source may be spoofed.
	unvPrefix map[netip.Prefix]uint32
	unvAll    uint32
	// validated: TCP, and UDP with a valid server cookie.
	valHost, valPrefix map[netip.Prefix]uint32
	valAll             uint32
}

// NewMeter returns an empty Meter.
func NewMeter() *Meter {
	return &Meter{unvPrefix: map[netip.Prefix]uint32{}, valHost: map[netip.Prefix]uint32{}, valPrefix: map[netip.Prefix]uint32{}}
}

// clockSkew is how far behind the current window a caller's reading may be and
// still be counted in it.
const clockSkew = 2

func (m *Meter) roll(now time.Time) {
	// Only forward for a small skew: a caller that read its clock before another one
	// took the lock must not clear the counters of the second in force
	// (p4n-W9-r1-2). A clock that stepped back by more than clockSkew is a step, not
	// a skew, and starts a window again, or the node would stay over budget until the
	// old time came round.
	if s := now.Unix(); s > m.sec || s < m.sec-clockSkew {
		m.sec = s
		m.budget, m.unvAll, m.valAll = 0, 0, 0
		clear(m.unvPrefix)
		clear(m.valHost)
		clear(m.valPrefix)
	}
}

// tenth and half are the shares of qps, never below one query, so a budget of 1
// still serves.
func tenth(qps uint32) uint32 { return max(1, qps/10) }
func half(qps uint32) uint32  { return max(1, qps/2) }

// Unvalidated takes one query of a UDP source with no valid server cookie against
// the prefix share (a tenth of qps) and the unvalidated share (half of it). A
// query over either gets TC=1.
func (m *Meter) Unvalidated(now time.Time, qps uint32, src netip.Addr) Share {
	p := Prefix(src)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll(now)
	if m.unvPrefix[p] >= tenth(qps) {
		return ShareUnvalidatedPrefix
	}
	if m.unvAll >= half(qps) {
		return ShareUnvalidatedAll
	}
	m.unvPrefix[p]++
	m.unvAll++
	return ShareOK
}

// Validated takes one query of a proven source (TCP, or UDP with a valid server
// cookie) against the address share and the prefix share (a tenth each) and the
// validated share (half). A query over one gets REFUSED.
func (m *Meter) Validated(now time.Time, qps uint32, src netip.Addr) Share {
	h, p := Host(src), Prefix(src)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll(now)
	if m.valHost[h] >= tenth(qps) {
		return ShareSource
	}
	if m.valPrefix[p] >= tenth(qps) {
		return ShareValidatedPrefix
	}
	if m.valAll >= half(qps) {
		return ShareValidatedAll
	}
	m.valHost[h]++
	m.valPrefix[p]++
	m.valAll++
	return ShareOK
}

// Budget takes one query against the node-wide free_qps (point 5), whose key holds
// no address.
func (m *Meter) Budget(now time.Time, qps uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll(now)
	if m.budget >= qps {
		return false
	}
	m.budget++
	return true
}

// ---- miss cap

// MissCap bounds the free cache misses in flight on the node (free_inflight).
//
// A slot is held for the whole lookup, which a hostile authority can stretch to
// seconds, so a limit of queries per second does not bound the slots a source
// holds. The cap is therefore split the way the shares of point 4 are: misses of
// sources that may be spoofed (UDP with no valid cookie) hold at most half of the
// slots and misses of proven sources the other half, and within a class one
// prefix holds at most a tenth, and one address of a proven source at most a
// tenth. A spoofed flood cannot take the slots a real client's TCP retry needs
// (p4n-W9-r1-4).
type MissCap struct {
	mu  sync.Mutex
	max int
	n   int

	unvAll, valAll     int
	unvPrefix          map[netip.Prefix]int
	valPrefix, valHost map[netip.Prefix]int
}

// NewMissCap returns a cap of max misses.
func NewMissCap(max int) *MissCap {
	return &MissCap{max: max, unvPrefix: map[netip.Prefix]int{}, valPrefix: map[netip.Prefix]int{}, valHost: map[netip.Prefix]int{}}
}

// TryAcquire takes a slot for a miss of src, or says false when the cap, the class
// of src or the prefix or address share is full. validated is true for TCP and for
// UDP with a valid server cookie. The caller must call the returned release exactly
// once (more calls do nothing) after a true.
func (c *MissCap) TryAcquire(validated bool, src netip.Addr) (release func(), ok bool) {
	p, h := Prefix(src), Host(src)
	share := max(1, c.max/10)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n >= c.max {
		return nil, false
	}
	if validated {
		if c.valAll >= max(1, c.max/2) || c.valPrefix[p] >= share || c.valHost[h] >= share {
			return nil, false
		}
		c.valAll++
		c.valPrefix[p]++
		c.valHost[h]++
	} else {
		if c.unvAll >= max(1, c.max/2) || c.unvPrefix[p] >= share {
			return nil, false
		}
		c.unvAll++
		c.unvPrefix[p]++
	}
	c.n++
	var once sync.Once
	return func() { once.Do(func() { c.release(validated, p, h) }) }, true
}

func (c *MissCap) release(validated bool, p, h netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n--
	dec := func(m map[netip.Prefix]int, k netip.Prefix) {
		if m[k]--; m[k] <= 0 {
			delete(m, k)
		}
	}
	if validated {
		c.valAll--
		dec(c.valPrefix, p)
		dec(c.valHost, h)
	} else {
		c.unvAll--
		dec(c.unvPrefix, p)
	}
}

// InFlight is the number of slots taken.
func (c *MissCap) InFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// Tokens is the bytes a prefix may still send at once, the whole burst for a
// prefix the limit does not know. It is for tests of what counts toward the limit.
func (r *ResponseLimit) Tokens(p netip.Prefix) float64 {
	s := r.shard(p)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m.Peek(p)
	if !ok {
		return r.burst
	}
	r.refill(b, r.now())
	return b.tokens
}

// BudgetUsed is how much of the node-wide budget this second has taken.
func (m *Meter) BudgetUsed(now time.Time) uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll(now)
	return m.budget
}
