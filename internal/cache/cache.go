// Package cache is the answer cache of the DNS role. It holds only true
// answers that passed the Sanity Gate, keyed by (qname, qtype, class,
// effective CD, ECS range, route) (contract section 6). A synthesized Block or
// Redirect answer is never stored here, so one tenant's policy cannot reach
// another through it.
//
// Why the key has no tenant field, and why that is safe: what the cache holds
// is what the resolver said about a name, before any policy touched it. Every
// tenant-specific step (Pre, Post, Grant) runs on a copy after the lookup, so
// two tenants asking the same question may share one entry and never see each
// other's decision. The things that do change the true answer are the key.
//
// Two segments, never mixed. A free query (Plain DNS from a source with no
// identity, SC 5.2a) reads and writes only the Free segment, an identified one
// only the Shared segment, and an in-flight fetch is shared inside a segment
// and never across the two, so a stranger cannot learn what a tenant asked or
// slow a tenant's miss by asking for the same name (T-559).
package cache

import (
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
)

// Segment names one of the two caches.
type Segment uint8

const (
	Shared Segment = iota // identified queries
	Free                  // free queries (SC 5.2a); written by W9
	nSegments
)

func (s Segment) String() string {
	if s == Free {
		return "free"
	}
	return "shared"
}

// Default sizes (D31). They are parameters so a test can use small ones.
const (
	DefaultSharedBytes int64 = 512 << 20
	DefaultFreeBytes   int64 = 64 << 20

	// DefaultMaxTTL bounds how long any answer is kept, whatever its TTL says:
	// a day is Unbound's own default and keeps a bad TTL from pinning a name.
	DefaultMaxTTL = 24 * time.Hour

	shards = 16
)

// Key is the cache key. It has no tenant field on purpose.
type Key struct {
	QName       string // the canonical wire form of the name, as the bytes of a string
	QType       uint16
	Class       uint16
	EffectiveCD bool
	ECS         string // the masked ECS prefix, empty when the query carried none
	Route       string // the resolve route, empty for the node's default path
}

// KeyOf builds a Key from the evaluator's lookup parameters.
func KeyOf(n names.Name, qtype, class uint16, p policy.ResolveParams, route string) Key {
	k := Key{QName: string(n.Wire()), QType: qtype, Class: class, EffectiveCD: p.EffectiveCD, Route: route}
	if p.ECS.IsValid() {
		k.ECS = p.ECS.Masked().String()
	}
	return k
}

// Config sets up a Cache.
type Config struct {
	SharedBytes int64
	FreeBytes   int64
	MaxTTL      time.Duration
	// Gate is the Sanity Gate; the zero value is the gate with no allow entry.
	Gate Gate
	// Now is the clock; nil means time.Now. Tests step it.
	Now func() time.Time
}

// Stats are cumulative counters of one segment. They hold no name or address.
type Stats struct {
	Hits, Misses, Puts, Rejected, Evicted uint64
	Entries                               int
	Bytes                                 int64
}

// Errors of Put. None quotes a name or an address.
var (
	ErrNotCacheable = errors.New("cache: answer is not cacheable")
	ErrSanityGate   = errors.New("cache: Sanity Gate rejected the answer")
)

type entry struct {
	ans    policy.TrueAnswer
	stored time.Time
	ttl    uint32 // seconds the answer may be served from storage
}

type shard struct {
	mu sync.Mutex
	l  *lru.Cache[Key, *entry]
}

type segment struct {
	shards  [shards]shard
	fl      sync.Mutex
	flights map[Key]*flight
	// gen counts Purges. A fetch that started under an older generation neither
	// stores its answer nor is joined by a later query (p4n-W7-r2-3).
	gen     atomic.Uint64
	hits    atomic.Uint64
	misses  atomic.Uint64
	puts    atomic.Uint64
	reject  atomic.Uint64
	evicted atomic.Uint64
}

type flight struct {
	gen  uint64
	done chan struct{}
	ans  *policy.TrueAnswer
	err  error
}

// Cache is the two-segment answer cache.
type Cache struct {
	seg    [nSegments]*segment
	gate   Gate
	now    func() time.Time
	maxTTL uint32
}

// New builds a Cache.
func New(cfg Config) *Cache {
	if cfg.SharedBytes <= 0 {
		cfg.SharedBytes = DefaultSharedBytes
	}
	if cfg.FreeBytes <= 0 {
		cfg.FreeBytes = DefaultFreeBytes
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = DefaultMaxTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Cache{gate: cfg.Gate, now: cfg.Now, maxTTL: uint32(cfg.MaxTTL / time.Second)}
	for i, b := range [nSegments]int64{cfg.SharedBytes, cfg.FreeBytes} {
		s := &segment{flights: map[Key]*flight{}}
		for j := range s.shards {
			s.shards[j].l = lru.New[Key, *entry](b / shards)
		}
		c.seg[i] = s
	}
	return c
}

// Gate returns the Sanity Gate of this cache, for the resolver to apply to an
// answer it will hand back without storing it.
func (c *Cache) Gate() *Gate { return &c.gate }

func (s *segment) shardOf(k Key) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(k.QName))
	_, _ = h.Write([]byte{byte(k.QType >> 8), byte(k.QType), byte(k.Class >> 8), byte(k.Class)})
	if k.EffectiveCD {
		_, _ = h.Write([]byte{1})
	}
	_, _ = h.Write([]byte(k.ECS))
	_, _ = h.Write([]byte(k.Route))
	return &s.shards[h.Sum32()%shards]
}

// Get returns the stored answer with its TTLs reduced by its age, or false
// when there is none or it has expired. The result is the caller's to keep: the
// slices are copies, and the RR data is never changed by anyone.
func (c *Cache) Get(seg Segment, k Key) (*policy.TrueAnswer, bool) {
	return c.get(seg, k, true)
}

// Peek is Get that touches no hit or miss counter: a read the node makes for its
// own purpose (Grant safety at Grant creation) is no client lookup, and
// cache_hit_permille must measure what clients experienced (p4n-W7-r9-1).
func (c *Cache) Peek(seg Segment, k Key) (*policy.TrueAnswer, bool) {
	return c.get(seg, k, false)
}

func (c *Cache) get(seg Segment, k Key, count bool) (*policy.TrueAnswer, bool) {
	s := c.seg[seg]
	sh := s.shardOf(k)
	now := c.now()
	sh.mu.Lock()
	e, ok := sh.l.Get(k)
	if ok && now.Sub(e.stored) >= time.Duration(e.ttl)*time.Second {
		sh.l.Remove(k)
		ok = false
	}
	sh.mu.Unlock()
	if !ok {
		if count {
			s.misses.Add(1)
		}
		return nil, false
	}
	if count {
		s.hits.Add(1)
	}
	age := uint32(now.Sub(e.stored) / time.Second)
	return aged(&e.ans, age), true
}

func aged(a *policy.TrueAnswer, age uint32) *policy.TrueAnswer {
	out := *a
	out.Chain = append([]names.Name(nil), a.Chain...)
	out.Answer = agedRRs(a.Answer, age)
	out.Authority = agedRRs(a.Authority, age)
	return &out
}

func agedRRs(in []policy.RR, age uint32) []policy.RR {
	if in == nil {
		return nil
	}
	out := make([]policy.RR, len(in))
	copy(out, in)
	for i := range out {
		if out[i].TTL > age {
			out[i].TTL -= age
		} else {
			out[i].TTL = 0
		}
	}
	return out
}

// Put stores a true answer for the name of its question, after the Sanity Gate.
// It refuses a failed answer (SERVFAIL, timeout, no route), an answer with a
// response code other than NOERROR and NXDOMAIN, an answer whose TTL is zero,
// and anything the gate rejects. A refusal stores nothing.
func (c *Cache) Put(seg Segment, k Key, qname names.Name, a *policy.TrueAnswer) error {
	return c.put(seg, k, qname, a, c.seg[seg].gen.Load())
}

// Generation is the number of Purges of a segment so far. A fetch reads it
// before it asks the backend and stores with PutGen, so an answer from the old
// resolve configuration is dropped when a Purge happened meanwhile.
func (c *Cache) Generation(seg Segment) uint64 { return c.seg[seg].gen.Load() }

// PutGen is Put for a fetch that began under generation gen. It stores nothing
// (and returns ErrStale) when the segment was purged since.
func (c *Cache) PutGen(seg Segment, k Key, qname names.Name, a *policy.TrueAnswer, gen uint64) error {
	return c.put(seg, k, qname, a, gen)
}

// ErrStale is the refusal of PutGen for a fetch that began before a Purge.
var ErrStale = errors.New("cache: fetch began before a purge")

func (c *Cache) put(seg Segment, k Key, qname names.Name, a *policy.TrueAnswer, gen uint64) error {
	s := c.seg[seg]
	if a == nil || a.Failed || (a.RCode != policy.RCodeNoError && a.RCode != policy.RCodeNXDomain) {
		return ErrNotCacheable
	}
	if v := c.gate.Check(qname, a); !v.OK {
		s.reject.Add(1)
		return ErrSanityGate
	}
	ttl := minTTL(a)
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl == 0 {
		return ErrNotCacheable
	}
	e := &entry{ans: *a, stored: c.now(), ttl: ttl}
	e.ans.Chain = append([]names.Name(nil), a.Chain...)
	e.ans.Answer = append([]policy.RR(nil), a.Answer...)
	e.ans.Authority = append([]policy.RR(nil), a.Authority...)
	sh := s.shardOf(k)
	sh.mu.Lock()
	// Checked under the shard lock: Purge raises gen before it clears the shards,
	// so an answer that passes here is cleared by the Purge that follows.
	if s.gen.Load() != gen {
		sh.mu.Unlock()
		return ErrStale
	}
	ev := sh.l.Add(k, e, cost(k, a))
	sh.mu.Unlock()
	s.puts.Add(1)
	if ev > 0 {
		s.evicted.Add(uint64(ev))
	}
	return nil
}

// minTTL is the shortest TTL of the answer and authority sections, which is the
// time the whole answer is good for. An answer with no record at all (a bare
// NXDOMAIN from a source that sent no SOA) is not kept.
func minTTL(a *policy.TrueAnswer) uint32 {
	min, any := uint32(0xFFFFFFFF), false
	for _, sec := range [][]policy.RR{a.Answer, a.Authority} {
		for i := range sec {
			if sec[i].Type == policy.TypeRRSIG {
				continue
			}
			any = true
			if sec[i].TTL < min {
				min = sec[i].TTL
			}
		}
	}
	if !any {
		return 0
	}
	return min
}

// Sizes the byte budget is charged in. names.Name is a fixed 384-byte struct
// (255 wire bytes, 127 label offsets), so a record or a chain name costs that
// much whatever its text length. Charging the text length made the 512 MiB budget
// hold about five times that much heap (p4n-W7-r1-10). entryOverhead covers what
// the struct sizes do not: the entry and TrueAnswer headers, the LRU list element
// and its map slot, and the key's own strings.
const (
	rrSize        = int64(unsafe.Sizeof(policy.RR{}))
	nameSize      = int64(unsafe.Sizeof(names.Name{}))
	entryOverhead = 512
)

func cost(k Key, a *policy.TrueAnswer) int64 {
	n := int64(len(k.QName)+len(k.ECS)+len(k.Route)) + entryOverhead
	for _, sec := range [][]policy.RR{a.Answer, a.Authority} {
		for i := range sec {
			// Data is a separate allocation, rounded up to its size class.
			n += rrSize + (int64(len(sec[i].Data))+15)&^15
		}
	}
	n += int64(len(a.Chain)) * nameSize
	return n
}

// Do runs fetch for a miss, sharing one run between the callers that ask for
// the same key in the same segment at the same time. A caller whose cancel
// channel closes stops waiting and gets an error; the fetch goes on for the
// callers that remain, because it belongs to none of them. Segments never share
// a run (T-559).
//
// fetch must be bound by its own deadline: it runs on a goroutine of its own and
// is never cancelled by a caller.
func (c *Cache) Do(seg Segment, k Key, cancel <-chan struct{}, fetch func() (*policy.TrueAnswer, error)) (*policy.TrueAnswer, error) {
	s := c.seg[seg]
	s.fl.Lock()
	f, ok := s.flights[k]
	if ok && f.gen != s.gen.Load() {
		// Started before a Purge: its answer belongs to the old resolve
		// configuration, so this caller starts a flight of its own.
		ok = false
	}
	if !ok {
		f = &flight{gen: s.gen.Load(), done: make(chan struct{})}
		s.flights[k] = f
		go func() {
			defer func() {
				// A panic in fetch must not leave waiters hanging, nor the key
				// stuck in flight: it becomes an error for all of them.
				if recover() != nil {
					f.ans, f.err = nil, errFetch
				}
				s.fl.Lock()
				if s.flights[k] == f {
					delete(s.flights, k)
				}
				s.fl.Unlock()
				close(f.done)
			}()
			f.ans, f.err = fetch()
		}()
	}
	s.fl.Unlock()
	select {
	case <-f.done:
	case <-cancel:
		return nil, errWait
	}
	if f.err != nil {
		return nil, f.err
	}
	return aged(f.ans, 0), nil
}

var (
	errFetch = errors.New("cache: fetch failed")
	errWait  = errors.New("cache: wait cancelled")
)

// Purge empties a segment. The resolve configuration changing (a new mode, a
// new upstream list) is the reason: an answer fetched by the old route must not
// outlive it.
func (c *Cache) Purge(seg Segment) {
	// Raised first: a fetch still running keeps the old generation and its Put is
	// refused, and a query that arrives now no longer joins its flight.
	c.seg[seg].gen.Add(1)
	for i := range c.seg[seg].shards {
		sh := &c.seg[seg].shards[i]
		sh.mu.Lock()
		sh.l.Clear()
		sh.mu.Unlock()
	}
}

// Stats returns the counters of a segment.
func (c *Cache) Stats(seg Segment) Stats {
	s := c.seg[seg]
	st := Stats{Hits: s.hits.Load(), Misses: s.misses.Load(), Puts: s.puts.Load(), Rejected: s.reject.Load(), Evicted: s.evicted.Load()}
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		st.Entries += sh.l.Len()
		st.Bytes += sh.l.Used()
		sh.mu.Unlock()
	}
	return st
}
