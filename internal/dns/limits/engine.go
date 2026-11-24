package limits

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// EventKind names what a test hook sees.
type EventKind uint8

const (
	// EventQuery: a query was given to a query limit (the name-form exemption
	// keeps exempt queries from ever causing this event, which is what the
	// L13 test checks).
	EventQuery EventKind = iota + 1
	// EventStopped: a query limit stopped the query.
	EventStopped
	// EventConnRefused: a connection limit refused a new connection.
	EventConnRefused
)

// Event is what Set.SetHook delivers. It carries no address and no name, so a
// hook can never become a sink for them.
type Event struct {
	Kind      EventKind
	Entry     string
	Transport Transport
}

// Set runs a Registry. It is the only thing that counts anything for step 1.
type Set struct {
	// tables[t] holds the tables of the entries that list transport t. Counters
	// are kept per (entry, transport): "limits are kept per transport".
	queries [8][]*table
	conns   [8][]*table
	hook    atomic.Pointer[func(Event)]
	clock   func() int64
}

// NewSet validates r and builds the counters. Its clock is monotonic: a wall
// clock that steps back (chrony after boot, a wrong NTP source) would stop every
// bucket from refilling until it caught up, and keep sources limited that have
// done nothing (p4n-W6-r2-7). The reading is the time since the Set was built,
// plus one because a zero stands for a bucket that has not been used yet.
func NewSet(r Registry) (*Set, error) {
	start := time.Now()
	return newSet(r, func() int64 { return int64(time.Since(start)) + 1 })
}

func newSet(r Registry, clock func() int64) (*Set, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	s := &Set{clock: clock}
	for i := range r {
		e := r[i].clone()
		for _, t := range e.Transports {
			tb := newTable(s, e, t)
			if e.Acts == ActsQuery {
				s.queries[t] = append(s.queries[t], tb)
			} else {
				s.conns[t] = append(s.conns[t], tb)
			}
		}
	}
	return s, nil
}

func (e Entry) clone() *Entry {
	e.Transports = append([]Transport(nil), e.Transports...)
	return &e
}

// SetHook installs a function called for every event, for tests. It must be
// cheap and must not call back into the Set.
func (s *Set) SetHook(f func(Event)) {
	if f == nil {
		s.hook.Store(nil)
		return
	}
	s.hook.Store(&f)
}

func (s *Set) emit(k EventKind, tb *table) {
	if h := s.hook.Load(); h != nil {
		(*h)(Event{Kind: k, Entry: tb.e.Name, Transport: tb.t})
	}
}

// Query gives one query of transport t from src to every query limit of t and
// returns what the first one that stops it answers, or AnswerNone when the
// query passes. A limit acts on this query only: it never closes, resets or
// holds a connection (L13 (2)).
func (s *Set) Query(t Transport, src netip.Addr) Answer {
	if !t.Valid() {
		return AnswerNone
	}
	src = src.Unmap()
	var buf [8]*table
	taken := buf[:0]
	for _, tb := range s.queries[t] {
		if !tb.applies(src) {
			continue
		}
		s.emit(EventQuery, tb)
		if !tb.take(src) {
			s.emit(EventStopped, tb)
			// A query that is stopped spends nothing: the tokens of the entries
			// checked before this one go back, so a source held by one limit does
			// not drain its other buckets while it is held (p4n-W6-r2-8).
			for _, p := range taken {
				p.refund(src)
			}
			return tb.e.Answer
		}
		if tb.e.Rate > 0 {
			taken = append(taken, tb)
		}
	}
	return AnswerNone
}

// Conn is the claim of one open connection on the connection limits. It must be
// released exactly once, when the connection closes.
type Conn struct {
	held []heldSlot
	once sync.Once
}

type heldSlot struct {
	tb    *table
	key   netip.Prefix
	spent bool // a token of the bucket was taken for this connection
}

// undo gives back what a connection that was refused had already counted: its
// open counts, and the tokens it had spent.
func (c *Conn) undo() {
	c.once.Do(func() {
		for _, h := range c.held {
			h.tb.release(h.key)
			if h.spent {
				h.tb.refundKey(h.key)
			}
		}
	})
}

// Release gives the claim back. It is safe to call more than once, and on a
// nil Conn.
func (c *Conn) Release() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		for _, h := range c.held {
			h.tb.release(h.key)
		}
	})
}

// Admit gives a new connection of transport t to every connection limit of t.
// src must be a validated source: call it after a finished TCP handshake, or
// after a finished QUIC handshake or a valid Retry token, never on a SYN or an
// Initial (L13 (3)). When it returns false the connection is refused and
// nothing it counted stays counted; the caller closes it at once, it was never
// accepted.
func (s *Set) Admit(t Transport, src netip.Addr) (*Conn, bool) {
	if !t.Valid() {
		return nil, false
	}
	src = src.Unmap()
	c := &Conn{}
	for _, tb := range s.conns[t] {
		if !tb.applies(src) {
			continue
		}
		key, spent, ok := tb.acquire(src)
		if !ok {
			// Refused: the open counts and the tokens taken for this connection
			// go back (p4n-W6-r2-8).
			c.undo()
			s.emit(EventConnRefused, tb)
			return nil, false
		}
		c.held = append(c.held, heldSlot{tb, key, spent})
	}
	return c, true
}

// Open returns how many connections of transport t the Set counts as open,
// summed over the keyless count entries; it is for tests.
func (s *Set) Open(t Transport, entry string) int {
	n := 0
	for _, tb := range s.conns[t] {
		if tb.e.Name == entry {
			n += tb.openTotal()
		}
	}
	return n
}

// table is the counters of one entry on one transport, sharded so that
// unrelated sources do not contend.
type table struct {
	s      *Set
	e      *Entry
	t      Transport
	shards [nShards]shard
}

const (
	nShards = 16
	// maxKeysPerShard bounds the memory a spoofed flood of source addresses can
	// take: 16 x 16384 slots of a few dozen bytes. At the cap a new key makes room
	// an idle one, which forgets only a full bucket, never an open connection.
	maxKeysPerShard = 16384
)

type shard struct {
	mu  sync.Mutex
	m   map[netip.Prefix]*slot
	ops uint32
}

type slot struct {
	tokens float64
	at     int64 // ns of the last refill
	open   int
	// pending is the QUIC handshakes in progress under this key whose address is
	// not validated. They count against nothing: they only tell wouldRefuse how
	// much of the bucket and of the open count is already spoken for, so the
	// Retry decision can see them (p4n-W6-r5-4).
	pending int
}

func newTable(s *Set, e *Entry, t Transport) *table {
	tb := &table{s: s, e: e, t: t}
	for i := range tb.shards {
		tb.shards[i].m = map[netip.Prefix]*slot{}
	}
	return tb
}

// applies says whether the entry limits this source at all: an IPv6-only
// aggregate does not touch IPv4 sources.
func (tb *table) applies(src netip.Addr) bool {
	if tb.e.Key.Kind == KeyNone {
		return true
	}
	if src.Is4() {
		return tb.e.Key.V4Bits != 0
	}
	return tb.e.Key.V6Bits != 0
}

func (tb *table) keyOf(src netip.Addr) netip.Prefix {
	if tb.e.Key.Kind == KeyNone {
		return netip.Prefix{}
	}
	bits := int(tb.e.Key.V6Bits)
	if src.Is4() {
		bits = int(tb.e.Key.V4Bits)
	}
	p, err := src.Prefix(bits)
	if err != nil {
		// Unreachable for validated entries; fail closed to one shared key.
		return netip.Prefix{}
	}
	return p
}

func (tb *table) shardOf(k netip.Prefix) *shard {
	if !k.IsValid() {
		return &tb.shards[0]
	}
	a := k.Addr().As16()
	var h uint32 = 2166136261
	for _, b := range a {
		h = (h ^ uint32(b)) * 16777619
	}
	h = (h ^ uint32(k.Bits())) * 16777619
	return &tb.shards[h%nShards]
}

// refill brings a slot's bucket up to date. The bucket of a new slot is full.
func (tb *table) refill(sl *slot, now int64) {
	if tb.e.Rate == 0 {
		return
	}
	burst := float64(tb.e.Burst)
	if sl.at == 0 {
		sl.tokens, sl.at = burst, now
		return
	}
	if now > sl.at {
		sl.tokens += float64(now-sl.at) / 1e9 * tb.e.Rate
		if sl.tokens > burst {
			sl.tokens = burst
		}
		sl.at = now
	}
}

// slotFor finds or makes the slot of key k. The caller holds sh.mu.
func (tb *table) slotFor(sh *shard, k netip.Prefix, now int64) *slot {
	sh.ops++
	if sl, ok := sh.m[k]; ok {
		return sl
	}
	// A full sweep every sweepEvery new keys keeps the cost per query small
	// (the table has at most maxKeysPerShard entries); between sweeps a table
	// at its cap makes room by forgetting one idle slot, which is O(1). A scan
	// on every insert would let a flood of spoofed sources cost the node
	// 16384 steps per packet.
	if sh.ops%sweepEvery == 0 {
		tb.sweep(sh, now)
	}
	if len(sh.m) >= maxKeysPerShard {
		tb.makeRoom(sh)
	}
	sl := &slot{}
	sh.m[k] = sl
	return sl
}

const sweepEvery = 4096

// sweep drops slots that hold no open connection and whose bucket has
// refilled: forgetting them changes nothing.
func (tb *table) sweep(sh *shard, now int64) {
	for k, sl := range sh.m {
		if sl.open > 0 || sl.pending > 0 {
			continue
		}
		tb.refill(sl, now)
		if tb.e.Rate == 0 || sl.tokens >= float64(tb.e.Burst) {
			delete(sh.m, k)
		}
	}
}

// makeRoom forgets one slot with no open connection, looking at a few in map
// order (which Go randomises). Forgetting a bucket gives that source a full
// bucket again, which is the price of a bounded table under a flood of
// sources; a slot that holds an open connection or a handshake in progress is
// never forgotten, and when every slot looked at holds one the table grows past
// its cap by one, which the open-connection caps and RetryUnderLoad bound.
func (tb *table) makeRoom(sh *shard) {
	n := 0
	for k, sl := range sh.m {
		if sl.open == 0 && sl.pending == 0 {
			delete(sh.m, k)
			return
		}
		if n++; n >= 16 {
			return
		}
	}
}

// take spends one token of the key's bucket (a query, or a new connection).
// An entry with no rate always passes.
func (tb *table) take(src netip.Addr) bool {
	if tb.e.Rate == 0 {
		return true
	}
	k := tb.keyOf(src)
	sh := tb.shardOf(k)
	now := tb.s.clock()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sl := tb.slotFor(sh, k, now)
	tb.refill(sl, now)
	if sl.tokens < 1 {
		return false
	}
	sl.tokens--
	return true
}

// acquire counts one new connection: it spends a token when the entry has a
// rate and takes one of the open slots when it has a count, and does both or
// neither.
// It also says whether it spent a token, for the refund of a connection that a
// later entry refuses.
func (tb *table) acquire(src netip.Addr) (k netip.Prefix, spent, ok bool) {
	k = tb.keyOf(src)
	sh := tb.shardOf(k)
	now := tb.s.clock()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sl := tb.slotFor(sh, k, now)
	if tb.e.Count > 0 && sl.open >= tb.e.Count {
		return k, false, false
	}
	if tb.e.Rate > 0 {
		tb.refill(sl, now)
		if sl.tokens < 1 {
			return k, false, false
		}
		sl.tokens--
		spent = true
	}
	if tb.e.Count > 0 {
		sl.open++
	}
	return k, spent, true
}

// refund puts back the token take spent for src.
func (tb *table) refund(src netip.Addr) { tb.refundKey(tb.keyOf(src)) }

// refundKey puts one token back in the bucket of k, if the bucket is still
// held (a slot that was forgotten had a full bucket anyway).
func (tb *table) refundKey(k netip.Prefix) {
	if tb.e.Rate == 0 {
		return
	}
	sh := tb.shardOf(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sl, ok := sh.m[k]; ok {
		if sl.tokens++; sl.tokens > float64(tb.e.Burst) {
			sl.tokens = float64(tb.e.Burst)
		}
	}
}

func (tb *table) release(k netip.Prefix) {
	if tb.e.Count == 0 {
		return
	}
	sh := tb.shardOf(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sl, ok := sh.m[k]; ok && sl.open > 0 {
		sl.open--
	}
}

func (tb *table) openTotal() int {
	n := 0
	for i := range tb.shards {
		sh := &tb.shards[i]
		sh.mu.Lock()
		for _, sl := range sh.m {
			n += sl.open
		}
		sh.mu.Unlock()
	}
	return n
}

// String names the table for test failures.
func (tb *table) String() string { return fmt.Sprintf("%s/%s", tb.e.Name, tb.t) }

// WouldRefuse says whether Admit would refuse a new connection of transport t
// from src right now. It counts nothing, makes no slot and spends no token, so
// it may be asked about an address that has not been validated: a spoofed
// Initial costs a victim nothing (L13 (3)). The QUIC listeners use it to ask for
// a Retry from a source that is over a connection limit, so that the TLS
// handshake it would trigger is not run for a connection that will be refused
// (p4n-W6-r4-4).
func (s *Set) WouldRefuse(t Transport, src netip.Addr) bool {
	if !t.Valid() {
		return true
	}
	src = src.Unmap()
	for _, tb := range s.conns[t] {
		if tb.applies(src) && tb.wouldRefuse(src) {
			return true
		}
	}
	return false
}

// wouldRefuse is acquire without its effects, for one more connection on top
// of the handshakes already in progress under the key. A key with no slot has a
// full bucket and nothing in progress, so it is never refused.
func (tb *table) wouldRefuse(src netip.Addr) bool {
	k := tb.keyOf(src)
	sh := tb.shardOf(k)
	now := tb.s.clock()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sl, ok := sh.m[k]
	if !ok {
		return false
	}
	if tb.e.Count > 0 && sl.open+sl.pending >= tb.e.Count {
		return true
	}
	if tb.e.Rate > 0 {
		tokens := float64(tb.e.Burst)
		if sl.at != 0 {
			tokens = sl.tokens
			if now > sl.at {
				tokens += float64(now-sl.at) / 1e9 * tb.e.Rate
				if tokens > float64(tb.e.Burst) {
					tokens = float64(tb.e.Burst)
				}
			}
		}
		if tokens-float64(sl.pending) < 1 {
			return true
		}
	}
	return false
}

// Pending is the claim of one QUIC handshake in progress, whose address is not
// validated, on the connection limits: it counts for the Retry decision and for
// nothing else. A QUIC connection spends a token and an open slot only when its
// handshake is done (L13 (3)), but the Retry decision has to know how many
// handshakes are already running under each key, at every level of the
// aggregates, or one host with a routed IPv6 /56 starts as many handshakes as
// fit in a round trip and the TLS work is done before Admit refuses them
// (p4n-W6-r5-4). It never refuses anything and spends no token, so a spoofed
// Initial costs its victim a Retry and no more.
type Pending struct {
	held []heldSlot
	once sync.Once
}

// BeginPending records a handshake of transport t from src. End it exactly
// once, when the handshake completes or fails; End is safe to call more than
// once and on a nil Pending.
func (s *Set) BeginPending(t Transport, src netip.Addr) *Pending {
	if !t.Valid() {
		return nil
	}
	src = src.Unmap()
	p := &Pending{}
	for _, tb := range s.conns[t] {
		if !tb.applies(src) || (tb.e.Rate == 0 && tb.e.Count == 0) {
			continue
		}
		p.held = append(p.held, heldSlot{tb: tb, key: tb.addPending(src)})
	}
	return p
}

// End takes the handshake out of the counts.
func (p *Pending) End() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		for _, h := range p.held {
			h.tb.endPending(h.key)
		}
	})
}

func (tb *table) addPending(src netip.Addr) netip.Prefix {
	k := tb.keyOf(src)
	sh := tb.shardOf(k)
	now := tb.s.clock()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	tb.slotFor(sh, k, now).pending++
	return k
}

func (tb *table) endPending(k netip.Prefix) {
	sh := tb.shardOf(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sl, ok := sh.m[k]; ok && sl.pending > 0 {
		sl.pending--
	}
}
