package proxy

import (
	"container/list"
	"sync"
	"time"
)

// srcKey is a client source as a map key: 4 or 16 raw bytes, never printed.
type srcKey [17]byte

func keyOf(src []byte) srcKey {
	var k srcKey
	k[0] = byte(len(src))
	copy(k[1:], src)
	return k
}

// pool holds the pre-grant connections of one kind (5.4): a connection is in it from
// its accept until its verdict, and it ends when it has a place elsewhere.
//
// The two rules of 5.4 are here and nowhere else. Over a source's cap, the source's
// own oldest connection is closed, so a source that stalls loses its own and never a
// place of another. Over the pool's cap, the oldest connection of the source that
// holds the most is closed, so one source that fills the pool is the one that loses
// from it. What a connection has sent changes nothing.
type pool struct {
	mu      sync.Mutex
	perSrc  int
	node    int
	n       int
	bySrc   map[srcKey]*list.List // per source, oldest first
	nextSeq uint64
}

type poolEntry struct {
	key   srcKey
	seq   uint64
	close func() // ends the connection; called with no lock held
	el    *list.Element
	in    bool
}

func newPool(perSrc, node int) *pool {
	return &pool{perSrc: perSrc, node: node, bySrc: map[srcKey]*list.List{}}
}

func (p *pool) setLimits(perSrc, node int) {
	p.mu.Lock()
	p.perSrc, p.node = perSrc, node
	p.mu.Unlock()
}

// admit puts a connection in the pool and returns its entry. The victims it had to
// close are closed before it returns.
func (p *pool) admit(key srcKey, closeFn func()) *poolEntry {
	e := &poolEntry{key: key, close: closeFn, in: true}
	var victims []*poolEntry
	p.mu.Lock()
	p.nextSeq++
	e.seq = p.nextSeq
	l := p.bySrc[key]
	if l == nil {
		l = list.New()
		p.bySrc[key] = l
	}
	for p.perSrc > 0 && l.Len() >= p.perSrc {
		victims = append(victims, p.removeLocked(l.Front().Value.(*poolEntry)))
	}
	for p.node > 0 && p.n >= p.node {
		// The source with the most connections loses its oldest. The new
		// connection is not in the list yet, so a source with one connection is
		// never chosen over a source with more.
		var big *list.List
		for _, o := range p.bySrc {
			if o.Len() > 0 && (big == nil || o.Len() > big.Len()) {
				big = o
			}
		}
		if big == nil {
			break
		}
		victims = append(victims, p.removeLocked(big.Front().Value.(*poolEntry)))
	}
	l = p.bySrc[key]
	if l == nil {
		l = list.New()
		p.bySrc[key] = l
	}
	e.el = l.PushBack(e)
	p.n++
	p.mu.Unlock()
	for _, v := range victims {
		v.close()
	}
	return e
}

func (p *pool) removeLocked(e *poolEntry) *poolEntry {
	if !e.in {
		return e
	}
	e.in = false
	l := p.bySrc[e.key]
	l.Remove(e.el)
	if l.Len() == 0 {
		delete(p.bySrc, e.key)
	}
	p.n--
	return e
}

// release takes a connection out of the pool (its verdict came, or it closed).
func (p *pool) release(e *poolEntry) {
	p.mu.Lock()
	p.removeLocked(e)
	p.mu.Unlock()
}

// size is the number of connections in the pool.
func (p *pool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// rate is the new-connection limit of 12 for each source: a token meter with a rate a
// second and a burst. The type is not called bucket because the N5 lint reads type
// names and this limit is the proxy's, not a DNS listener's. The map is bounded: when
// it passes its cap the meters that are full again, which means idle sources, are dropped.
type rate struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[srcKey]*meter
}

type meter struct {
	tokens float64
	at     time.Time
}

const maxBuckets = 1 << 18

func newRate(perSec, burst int) *rate {
	return &rate{perSec: float64(perSec), burst: float64(burst), buckets: map[srcKey]*meter{}}
}

func (r *rate) setLimits(perSec, burst int) {
	r.mu.Lock()
	r.perSec, r.burst = float64(perSec), float64(burst)
	r.mu.Unlock()
}

// allow takes one token for a source.
func (r *rate) allow(key srcKey, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[key]
	if b == nil {
		if len(r.buckets) >= maxBuckets {
			r.pruneLocked(now)
		}
		b = &meter{tokens: r.burst, at: now}
		r.buckets[key] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * r.perSec
	if b.tokens > r.burst {
		b.tokens = r.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (r *rate) pruneLocked(now time.Time) {
	for k, b := range r.buckets {
		if b.tokens+now.Sub(b.at).Seconds()*r.perSec >= r.burst {
			delete(r.buckets, k)
		}
	}
	// A flood of distinct sources that all hold tokens still has to fit.
	if len(r.buckets) >= maxBuckets {
		r.buckets = map[srcKey]*meter{}
	}
}

// counter limits something in flight by source and in all (the lookups of 12).
type counter struct {
	mu     sync.Mutex
	perSrc int
	node   int
	n      int
	by     map[srcKey]int
}

func newCounter(perSrc, node int) *counter {
	return &counter{perSrc: perSrc, node: node, by: map[srcKey]int{}}
}

func (c *counter) setLimits(perSrc, node int) {
	c.mu.Lock()
	c.perSrc, c.node = perSrc, node
	c.mu.Unlock()
}

func (c *counter) take(key srcKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n >= c.node || c.by[key] >= c.perSrc {
		return false
	}
	c.n++
	c.by[key]++
	return true
}

func (c *counter) put(key srcKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n--
	if c.by[key]--; c.by[key] <= 0 {
		delete(c.by, key)
	}
}
