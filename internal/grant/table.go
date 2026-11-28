package grant

import (
	"context"
	"hash/fnv"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Verdict is what Put answers (4.2).
type Verdict uint8

const (
	// Ok: the holder is in the entry and the answer may be given.
	Ok Verdict = iota
	// Validate: the source is not validated and nothing was written; the handler
	// answers TC=1 with no records.
	Validate
	// Refused: nothing was written for this holder; Reason says why.
	Refused
)

// Reasons of a refusal (4.2). They are counter names and never carry a value.
const (
	ReasonCollision   = "collision"
	ReasonEndpointCap = "endpoint_cap"
	ReasonNodeCap     = "node_cap"
	ReasonUnsafe      = "unsafe" // judged by the caller (R9), counted here
)

// Width is the grant_width of NodeConfig (4.3).
type Width uint8

const (
	WidthExact Width = iota
	WidthPrefix24
	WidthCarrier
)

// PutReq is one Put (4.2). The caller has already judged R9 (step 1) and decided
// the outcome; the table judges steps 2 to 4.
type PutReq struct {
	Name   []byte // canonical wire
	Source netip.Addr
	// ASN of the source (GeoIP), 0 when unknown: an ASN of 0 never matches (4.3).
	ASN    uint32
	Out    Outcome
	Holder Holder // Expires and LastDecide are set by the table
	// Validated is TCP, an encrypted transport, or UDP with a valid server cookie.
	Validated bool
	// EndpointCap is grant_cap of the Endpoint's record, 0 for the default.
	EndpointCap int
	// Privileged says the source is in a claim or an authorized prefix: only such a
	// source may use the last quarter of the Endpoint's room.
	Privileged bool
	// ExpiresAt, for a forwarded Put, is the sender's expiry; it is cut to 4 h from
	// now. Zero means 4 h.
	ExpiresAt time.Time
	// Short makes the holder live this long and no longer (a forwarded Grant that
	// waits for the image to catch up, 4.5). Zero means the normal lifetime.
	Short time.Duration
	// Joins is the test of SC 10.3 with the live outcome as the offer: it says
	// whether this holder's own decision allows that outcome. It may be slow (it
	// reruns the evaluator), so it is called with no lock held. Nil means no.
	Joins func(live Outcome) bool
}

// PutResult is the answer of Put.
type PutResult struct {
	Verdict Verdict
	Reason  string
	// Alone: the peer holds no copy, so the answer leaves its address out (4.5).
	Alone bool
	// Offer: a deciding query of a holder decided here whose peer copy is missing or
	// past half its life; the caller queues a forward.
	Offer bool
	// Holder is the stored holder after the write (Ok only).
	Holder Holder
}

const nShards = 64

type bucket struct {
	ents map[*entry]struct{} // entries with at least one widenable holder
	sum  map[sumKey]int32
}

type sumKey struct {
	ep  [16]byte
	out Outcome
}

type nameSet struct {
	bySrc map[netip.Addr]*entry
	by24  map[[3]byte]*bucket
	byASN map[uint32]*bucket
}

type entry struct {
	ns      *nameSet
	name    string
	src     netip.Addr
	asn     uint32
	out     Outcome
	holders []Holder
}

type shard struct {
	mu    sync.Mutex
	names map[string]*nameSet
}

// pool is a counted room under the share rule of 5.4. Shared connections (those of
// an entry that several accounts hold) have their own part, at most half of it, in
// which a source gets one more by the same rule; they count in total too, so the
// pool never fills.
type pool struct {
	cap, total int
	by         map[[16]byte]int
	shTotal    int
	shBy       map[[16]byte]int
}

func newPool(cap int) *pool {
	return &pool{cap: cap, by: map[[16]byte]int{}, shBy: map[[16]byte]int{}}
}

// add is the share rule: an account gets one more only while what it holds is below
// an eighth of the free room of the pool. So one account holds at most a ninth of
// it and the pool never fills for the others.
func (p *pool) add(acct [16]byte) bool {
	free := p.cap - p.total
	if free <= 0 || p.by[acct]*8 >= free {
		return false
	}
	p.by[acct]++
	p.total++
	return true
}

func (p *pool) sub(acct [16]byte) {
	if p.by[acct] > 0 {
		p.by[acct]--
		if p.by[acct] == 0 {
			delete(p.by, acct)
		}
		p.total--
	}
}

func (p *pool) addShared(src [16]byte) bool {
	free := p.cap/2 - p.shTotal
	if free <= 0 || p.total >= p.cap || p.shBy[src]*8 >= free {
		return false
	}
	p.shBy[src]++
	p.shTotal++
	p.total++
	return true
}

func (p *pool) subShared(src [16]byte) {
	if p.shBy[src] > 0 {
		p.shBy[src]--
		if p.shBy[src] == 0 {
			delete(p.shBy, src)
		}
		p.shTotal--
		p.total--
	}
}

// force counts a place that already exists (a rebuilt table, a connection that moved):
// it is never refused, and may take a pool past its cap for as long as it lives.
func (p *pool) force(acct [16]byte) { p.by[acct]++; p.total++ }

func (p *pool) forceShared(src [16]byte) { p.shBy[src]++; p.shTotal++; p.total++ }

type epCount struct {
	total, fwd int
	perSrc     map[netip.Addr]int
}

// Table is the Grant table (4.1). It is safe for concurrent use.
type Table struct {
	lim Limits
	now func() time.Time

	shards [nShards]shard

	smu    sync.Mutex // counters and pools; taken after a shard's lock, never before
	node   *pool
	nodeFw *pool
	eps    map[[16]byte]*epCount
	srcN   map[any]int

	wmu      sync.Mutex
	waits    map[waitKey][]chan struct{}
	waitSrc  map[netip.Addr]int
	waitNode int

	fullAt  atomic.Int64 // Unix second of the last node_cap refusal
	sweepAt atomic.Uint32

	cmu    sync.Mutex
	counts map[string]uint64
	widths map[uint32]*[6]uint64
	last   string
}

type waitKey struct {
	name string
	src  netip.Addr
}

// NewTable makes a table. now may be nil.
func NewTable(lim Limits, now func() time.Time) *Table {
	if now == nil {
		now = time.Now
	}
	t := &Table{lim: lim, now: now, node: newPool(lim.NodeHolders), nodeFw: newPool(lim.NodeForwarded),
		eps: map[[16]byte]*epCount{}, srcN: map[any]int{}, waits: map[waitKey][]chan struct{}{}, waitSrc: map[netip.Addr]int{},
		counts: map[string]uint64{}, widths: map[uint32]*[6]uint64{}}
	for i := range t.shards {
		t.shards[i].names = map[string]*nameSet{}
	}
	return t
}

func (t *Table) shard(name []byte) *shard {
	h := fnv.New32a()
	_, _ = h.Write(name)
	return &t.shards[h.Sum32()%nShards]
}

// Count adds to a named counter (a reason, never a value).
func (t *Table) Count(name string) {
	t.cmu.Lock()
	t.counts[name]++
	t.cmu.Unlock()
}

// Full reports whether a node_cap refusal happened in the last 60 s (proxy_state.full).
func (t *Table) Full() bool {
	at := t.fullAt.Load()
	return at != 0 && t.now().Unix()-at < 60
}

// Holders is the number of holders in the table.
func (t *Table) Holders() int {
	t.smu.Lock()
	defer t.smu.Unlock()
	return t.node.total
}

// ---- entry bookkeeping (shard lock held)

func (sh *shard) set(name string, create bool) *nameSet {
	ns := sh.names[name]
	if ns == nil && create {
		ns = &nameSet{bySrc: map[netip.Addr]*entry{}, by24: map[[3]byte]*bucket{}, byASN: map[uint32]*bucket{}}
		sh.names[name] = ns
	}
	return ns
}

func prefix24(a netip.Addr) ([3]byte, bool) {
	if !a.Is4() {
		return [3]byte{}, false
	}
	b := a.As4()
	return [3]byte{b[0], b[1], b[2]}, true
}

// unindex removes the entry's contribution to the width buckets; index adds it.
// Only widenable holders count (4.3): a wildcard rule never widens.
func (e *entry) unindex() { e.reindex(-1) }
func (e *entry) index()   { e.reindex(1) }

func (e *entry) reindex(d int32) {
	wide := false
	for i := range e.holders {
		if e.holders[i].Widenable {
			wide = true
			break
		}
	}
	if !wide {
		return
	}
	touch := func(b *bucket) {
		if d > 0 {
			b.ents[e] = struct{}{}
		} else {
			delete(b.ents, e)
		}
		for i := range e.holders {
			if !e.holders[i].Widenable {
				continue
			}
			k := sumKey{e.holders[i].Endpoint, e.out}
			b.sum[k] += d
			if b.sum[k] <= 0 {
				delete(b.sum, k)
			}
		}
	}
	if p, ok := prefix24(e.src); ok {
		b := e.ns.by24[p]
		if b == nil && d > 0 {
			b = &bucket{ents: map[*entry]struct{}{}, sum: map[sumKey]int32{}}
			e.ns.by24[p] = b
		}
		if b != nil {
			touch(b)
			if len(b.ents) == 0 {
				delete(e.ns.by24, p)
			}
		}
	}
	if e.asn != 0 {
		b := e.ns.byASN[e.asn]
		if b == nil && d > 0 {
			b = &bucket{ents: map[*entry]struct{}{}, sum: map[sumKey]int32{}}
			e.ns.byASN[e.asn] = b
		}
		if b != nil {
			touch(b)
			if len(b.ents) == 0 {
				delete(e.ns.byASN, e.asn)
			}
		}
	}
}

// release gives back the counters of holder i without touching the slice.
func (t *Table) release(h *Holder, src netip.Addr) {
	t.smu.Lock()
	t.node.sub(h.Account)
	if h.forwarded() {
		t.nodeFw.sub(h.Account)
	}
	if c := t.eps[h.Endpoint]; c != nil {
		c.total--
		if h.forwarded() {
			c.fwd--
		}
		if c.perSrc[src]--; c.perSrc[src] <= 0 {
			delete(c.perSrc, src)
		}
		if c.total <= 0 {
			delete(t.eps, h.Endpoint)
		}
	}
	t.smu.Unlock()
}

// dropAt removes holder i of an entry that is NOT indexed at the moment (the
// caller unindexed it and indexes again after its changes).
func (t *Table) dropAt(e *entry, i int) {
	t.release(&e.holders[i], e.src)
	e.holders = append(e.holders[:i], e.holders[i+1:]...)
}

// retire removes an empty entry.
func (t *Table) retire(sh *shard, e *entry) {
	if len(e.holders) != 0 || e.ns.bySrc[e.src] != e {
		return
	}
	delete(e.ns.bySrc, e.src)
	if len(e.ns.bySrc) == 0 {
		delete(sh.names, e.name)
	}
	t.srcCount(e, -1)
}

// register puts a new entry with its first holder into the table.
func (t *Table) register(e *entry) {
	e.ns.bySrc[e.src] = e
	t.srcCount(e, 1)
}

// srcCount keeps the third index of 4.1: the number of entries of each source, and
// of each /24 and ASN, so the pool of a new connection is found in one lookup.
func (t *Table) srcCount(e *entry, d int) {
	t.smu.Lock()
	defer t.smu.Unlock()
	bump := func(k any) {
		t.srcN[k] += d
		if t.srcN[k] <= 0 {
			delete(t.srcN, k)
		}
	}
	bump(e.src)
	if p, ok := prefix24(e.src); ok {
		bump(p)
	}
	if e.asn != 0 {
		bump(e.asn)
	}
}

// live returns the entry of (name, src) with its expired holders removed.
func (t *Table) live(sh *shard, name string, src netip.Addr, now int64) *entry {
	ns := sh.names[name]
	if ns == nil {
		return nil
	}
	e := ns.bySrc[src]
	if e == nil {
		return nil
	}
	t.expire(sh, e, now)
	if len(e.holders) == 0 {
		return nil
	}
	return e
}

func (t *Table) expire(sh *shard, e *entry, now int64) {
	any := false
	for i := range e.holders {
		if e.holders[i].Expires <= now {
			any = true
			break
		}
	}
	if !any {
		return
	}
	e.unindex()
	for i := len(e.holders) - 1; i >= 0; i-- {
		if e.holders[i].Expires <= now {
			t.dropAt(e, i)
		}
	}
	e.index()
	t.retire(sh, e)
}

func (e *entry) find(id holderID) int {
	for i := range e.holders {
		if e.holders[i].id() == id {
			return i
		}
	}
	return -1
}

// addHolder applies the caps of 4.2 step 4 and appends. The entry is unindexed by
// the caller. It returns "" or a reason.
func (t *Table) addHolder(e *entry, h Holder, p *PutReq) string {
	n := 0
	for i := range e.holders {
		if e.holders[i].Endpoint == h.Endpoint {
			n++
		}
	}
	if len(e.holders) >= MaxHolders || n >= MaxPerEndpoint {
		return ReasonCollision
	}
	capE := p.EndpointCap
	if capE <= 0 {
		capE = t.lim.DefaultEndpointCap
	}
	t.smu.Lock()
	defer t.smu.Unlock()
	c := t.eps[h.Endpoint]
	if c == nil {
		c = &epCount{perSrc: map[netip.Addr]int{}}
	}
	switch {
	case c.total >= capE:
		return ReasonEndpointCap
	case c.perSrc[e.src] >= max(capE/4, 1):
		return ReasonEndpointCap
	case !p.Privileged && c.total >= capE-capE/4:
		return ReasonEndpointCap // the last quarter is for claims and authorized prefixes
	case h.forwarded() && c.fwd >= max(capE/t.lim.EndpointForwardDiv, 1):
		return ReasonEndpointCap
	}
	if !t.node.add(h.Account) {
		t.fullAt.Store(t.now().Unix())
		return ReasonNodeCap
	}
	if h.forwarded() && !t.nodeFw.add(h.Account) {
		t.node.sub(h.Account)
		t.fullAt.Store(t.now().Unix())
		return ReasonNodeCap
	}
	c.total++
	c.perSrc[e.src]++
	if h.forwarded() {
		c.fwd++
	}
	t.eps[h.Endpoint] = c
	e.holders = append(e.holders, h)
	return ""
}

func (t *Table) stamp(p *PutReq, now int64) Holder {
	h := p.Holder
	h.LastDecide = now
	life := HolderLife
	if !p.ExpiresAt.IsZero() {
		if d := p.ExpiresAt.Sub(time.Unix(now, 0)); d < life {
			life = d
		}
	}
	if p.Short > 0 && p.Short < life {
		life = p.Short
	}
	if life < time.Second {
		life = time.Second
	}
	h.Expires = now + int64(life/time.Second)
	return h
}

// refresh updates a stored holder from a deciding query of the same identity.
func refresh(dst *Holder, src Holder) {
	keep := *dst
	*dst = src
	// What the offer machinery learned about the peer survives a refresh.
	dst.Alone, dst.OfferAt, dst.SentAt = keep.Alone, keep.OfferAt, keep.SentAt
	if keep.forwarded() {
		dst.Alone = false
	}
}

// Put is 4.2 steps 2 to 4. See PutReq for what the caller has done before.
func (t *Table) Put(p *PutReq) PutResult {
	name := string(p.Name)
	sh := t.shard(p.Name)
	var joinFor Outcome
	var joinOK, joinKnown bool
	for {
		sh.mu.Lock()
		now := t.now().Unix()
		e := t.live(sh, name, p.Source, now)
		id := p.Holder.id()

		if !p.Validated {
			// Step 2: writes nothing, refreshes nothing, replaces nothing.
			res := PutResult{Verdict: Validate}
			if e != nil {
				if i := e.find(id); i >= 0 && e.out == p.Out && e.holders[i].Expires-now >= MaxProxyTTL {
					res = PutResult{Verdict: Ok, Alone: e.holders[i].Alone, Holder: e.holders[i]}
				}
			}
			sh.mu.Unlock()
			t.Count("put_" + map[Verdict]string{Ok: "ok", Validate: "validate"}[res.Verdict])
			return res
		}

		stamped := t.stamp(p, now)
		if e == nil {
			ns := sh.set(name, true)
			e = &entry{ns: ns, name: name, src: p.Source, asn: p.ASN, out: p.Out}
			if r := t.addHolder(e, stamped, p); r != "" {
				if len(ns.bySrc) == 0 {
					delete(sh.names, name)
				}
				sh.mu.Unlock()
				return t.refused(r)
			}
			t.register(e)
			e.index()
			return t.written(sh, e, id, now, p)
		}

		i := e.find(id)
		allMine := true
		for k := range e.holders {
			if e.holders[k].Endpoint != p.Holder.Endpoint || e.holders[k].Client != p.Holder.Client {
				allMine = false
				break
			}
		}
		switch {
		case i >= 0 && e.out == p.Out:
			e.unindex()
			refresh(&e.holders[i], stamped)
			e.index()
			return t.written(sh, e, id, now, p)
		case allMine:
			// Its own newer decision: the outcome becomes the new one (not an end of 4.6).
			e.unindex()
			old := e.out
			e.out = p.Out
			if i >= 0 {
				refresh(&e.holders[i], stamped)
			} else if r := t.addHolder(e, stamped, p); r != "" {
				e.out = old // nobody decided the new outcome, so the others keep theirs
				e.index()
				sh.mu.Unlock()
				return t.refused(r)
			}
			e.index()
			return t.written(sh, e, id, now, p)
		}

		// Another client or Endpoint holds the entry: join when this holder's own
		// decision allows the live outcome. The test reruns the evaluator, so it runs
		// with the lock released and is judged again against the live outcome.
		if !joinKnown || joinFor != e.out {
			live := e.out
			sh.mu.Unlock()
			joinOK = p.Joins != nil && p.Joins(live)
			joinKnown, joinFor = true, live
			continue
		}
		if joinOK {
			e.unindex()
			if i >= 0 {
				refresh(&e.holders[i], stamped)
			} else if r := t.addHolder(e, stamped, p); r != "" {
				e.index()
				sh.mu.Unlock()
				return t.refused(r)
			}
			e.index()
			return t.written(sh, e, id, now, p)
		}

		// No join: the holders of this (Endpoint, client) leave, and for a Put decided
		// here so do those of this account that have been silent for MaxProxyTTL,
		// because no cache holds an answer of them. Leaving closes nothing.
		e.unindex()
		for k := len(e.holders) - 1; k >= 0; k-- {
			h := &e.holders[k]
			mine := h.Endpoint == p.Holder.Endpoint && h.Client == p.Holder.Client
			stale := !p.Holder.forwarded() && h.Account == p.Holder.Account && now-h.LastDecide > MaxProxyTTL
			if mine || stale {
				t.dropAt(e, k)
			}
		}
		if len(e.holders) == 0 {
			e.out = p.Out
			if r := t.addHolder(e, stamped, p); r != "" {
				t.retire(sh, e)
				sh.mu.Unlock()
				return t.refused(r)
			}
			e.index()
			return t.written(sh, e, id, now, p)
		}
		e.index()
		sh.mu.Unlock()
		return t.refused(ReasonCollision)
	}
}

// written finishes an Ok under the shard lock and releases it.
func (t *Table) written(sh *shard, e *entry, id holderID, now int64, p *PutReq) PutResult {
	i := e.find(id)
	h := &e.holders[i]
	res := PutResult{Verdict: Ok, Alone: h.Alone}
	if !h.forwarded() && now >= h.OfferAt {
		res.Offer = true
		h.OfferAt = now + int64(UnsentRetry/time.Second)
	}
	res.Holder = *h
	src := e.src
	sh.mu.Unlock()
	t.Count("put_ok")
	t.signal(name2(p.Name), src)
	return res
}

func name2(b []byte) string { return string(b) }

func (t *Table) refused(reason string) PutResult {
	t.Count("refused_" + reason)
	t.cmu.Lock()
	t.last = reason
	t.cmu.Unlock()
	return PutResult{Verdict: Refused, Reason: reason}
}

// ---- waits (4.3 step 3)

func (t *Table) signal(name string, src netip.Addr) {
	t.wmu.Lock()
	k := waitKey{name, src}
	chs := t.waits[k]
	delete(t.waits, k)
	t.wmu.Unlock()
	for _, c := range chs {
		close(c)
	}
}

// Wait waits up to d for a Put of exactly (name, src) and reports whether one came.
// A source has at most WaitPerSource waits and the node WaitNode; over either it
// returns false at once.
func (t *Table) Wait(ctx context.Context, name []byte, src netip.Addr, d time.Duration) bool {
	t.wmu.Lock()
	if t.waitSrc[src] >= t.lim.WaitPerSource || t.waitNode >= t.lim.WaitNode {
		t.wmu.Unlock()
		t.Count("wait_refused")
		return false
	}
	c := make(chan struct{})
	k := waitKey{string(name), src}
	t.waits[k] = append(t.waits[k], c)
	t.waitSrc[src]++
	t.waitNode++
	t.wmu.Unlock()
	defer func() {
		t.wmu.Lock()
		if t.waitSrc[src]--; t.waitSrc[src] <= 0 {
			delete(t.waitSrc, src)
		}
		t.waitNode--
		// A timed-out waiter leaves its channel behind until the next Put of the key:
		// drop it now so a flood of keys that never get a Put holds nothing.
		chs := t.waits[k]
		for i := range chs {
			if chs[i] == c {
				chs = append(chs[:i], chs[i+1:]...)
				break
			}
		}
		if len(chs) == 0 {
			delete(t.waits, k)
		} else {
			t.waits[k] = chs
		}
		t.wmu.Unlock()
	}()
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-c:
		return true
	case <-tm.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// ---- lookup (4.3)

// Hit is what a lookup found. Holders are at most the 8 whose deciding query is
// newest, More says there are others.
type Hit struct {
	Name     string
	Out      Outcome
	Holders  []Holder
	More     bool
	EntrySrc netip.Addr
	Via      Width // exact, or the width that matched
	// Endpoints is the number of distinct Endpoints among the holders, Accounts of
	// accounts: charging reads them (4.3).
	Endpoints int
	Accounts  int
}

func hitOf(e *entry, via Width, widenOnly bool) Hit {
	hs := make([]Holder, 0, len(e.holders))
	for i := range e.holders {
		if widenOnly && !e.holders[i].Widenable {
			continue
		}
		hs = append(hs, e.holders[i])
	}
	sort.SliceStable(hs, func(i, j int) bool { return hs[i].LastDecide > hs[j].LastDecide })
	eps, accts := map[[16]byte]struct{}{}, map[[16]byte]struct{}{}
	for i := range hs {
		eps[hs[i].Endpoint] = struct{}{}
		accts[hs[i].Account] = struct{}{}
	}
	h := Hit{Name: e.name, Out: e.out, EntrySrc: e.src, Via: via, Endpoints: len(eps), Accounts: len(accts)}
	if len(hs) > 8 {
		hs, h.More = hs[:8], true
	}
	h.Holders = hs
	return h
}

// Lookup is 4.3 steps 1 and 2. The wait of step 3 is the caller's (Wait, then
// Lookup again), so a lookup that waits counts once.
func (t *Table) Lookup(src netip.Addr, asn uint32, name []byte, width Width) (Hit, bool) {
	sh := t.shard(name)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := t.now().Unix()
	if e := t.live(sh, string(name), src, now); e != nil {
		t.widthCount(asn, 5)
		return hitOf(e, WidthExact, false), true
	}
	ns := sh.names[string(name)]
	if ns == nil {
		t.widthCount(asn, 4)
		return Hit{}, false
	}
	var p24, car *bucket
	if p, ok := prefix24(src); ok {
		p24 = ns.by24[p]
	}
	if asn != 0 {
		car = ns.byASN[asn]
	}
	// What each width would have said, counted per client ASN (4.3).
	counted := false
	for _, w := range []struct {
		b    *bucket
		base int
	}{{p24, 0}, {car, 2}} {
		if w.b == nil {
			continue
		}
		counted = true
		if len(w.b.sum) == 1 {
			t.widthCount(asn, w.base)
		} else {
			t.widthCount(asn, w.base+1)
		}
	}
	if !counted {
		t.widthCount(asn, 4)
	}
	var b *bucket
	via := WidthExact
	switch width {
	case WidthPrefix24:
		b, via = p24, WidthPrefix24
	case WidthCarrier:
		b, via = car, WidthCarrier
	}
	if b == nil || len(b.sum) != 1 {
		return Hit{}, false // the match holds only when one Endpoint and one outcome share it
	}
	for e := range b.ents {
		t.expire(sh, e, now)
		if len(e.holders) == 0 {
			continue
		}
		h := hitOf(e, via, true)
		if len(h.Holders) == 0 {
			continue
		}
		return h, true
	}
	return Hit{}, false
}

// widthCount indexes: 0 prefix24_unique, 1 prefix24_shared, 2 carrier_unique,
// 3 carrier_shared, 4 miss, 5 exact.
func (t *Table) widthCount(asn uint32, i int) {
	t.cmu.Lock()
	c := t.widths[asn]
	if c == nil {
		// A node sees a few hundred operators; the cap keeps a spoofed flood of
		// sources from growing the map, and the stats message holds 4096 counters.
		if len(t.widths) >= 600 {
			c = t.widths[0]
			if c == nil {
				c = new([6]uint64)
				t.widths[0] = c
			}
		} else {
			c = new([6]uint64)
			t.widths[asn] = c
		}
	}
	c[i]++
	t.cmu.Unlock()
}

// Live reports the live outcome of (name, src), for the `more` test of 4.6.
func (t *Table) Live(name []byte, src netip.Addr) (Outcome, bool) {
	sh := t.shard(name)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if e := t.live(sh, string(name), src, t.now().Unix()); e != nil {
		return e.out, true
	}
	return Outcome{}, false
}

// Known reports whether a source has a live entry (exact, or by the width in
// force): it picks the pool of a new connection (5.4). It counts nothing. An entry
// whose holders have all expired but not yet been swept still counts, which only
// gives such a source the main pool for the seconds until the sweep.
func (t *Table) Known(src netip.Addr, asn uint32, width Width) bool {
	t.smu.Lock()
	defer t.smu.Unlock()
	if t.srcN[src] > 0 {
		return true
	}
	switch width {
	case WidthPrefix24:
		if p, ok := prefix24(src); ok {
			return t.srcN[p] > 0
		}
	case WidthCarrier:
		return asn != 0 && t.srcN[asn] > 0
	}
	return false
}

// ---- ends (4.6)

// Judge is asked about every holder: it reports whether the holder has ended. The
// name and outcome are those of its entry.
type Judge func(name []byte, src netip.Addr, out Outcome, h *Holder) bool

// Sweep removes every holder that judge says has ended, and the entries that are
// left with none. It returns how many holders it removed. It closes nothing:
// connections are judged by their own record (JudgeConns).
func (t *Table) Sweep(judge Judge) int {
	n := 0
	for i := range t.shards {
		n += t.sweepShard(&t.shards[i], judge)
	}
	return n
}

func (t *Table) sweepShard(sh *shard, judge Judge) int {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := t.now().Unix()
	n := 0
	for _, ns := range sh.names {
		for _, e := range ns.bySrc {
			t.expire(sh, e, now)
			if len(e.holders) == 0 {
				continue
			}
			var drop []int
			nb := []byte(e.name)
			for k := range e.holders {
				if judge(nb, e.src, e.out, &e.holders[k]) {
					drop = append(drop, k)
				}
			}
			if len(drop) == 0 {
				continue
			}
			e.unindex()
			for j := len(drop) - 1; j >= 0; j-- {
				t.dropAt(e, drop[j])
				n++
			}
			e.index()
			t.retire(sh, e)
		}
	}
	return n
}

// SweepStep expires the holders of one shard and moves on, so a full pass takes
// nShards calls: a holder that has expired is gone from every lookup at once (live
// checks it), and this only gives its memory back.
func (t *Table) SweepStep() {
	i := t.sweepAt.Add(1) % nShards
	sh := &t.shards[i]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := t.now().Unix()
	for _, ns := range sh.names {
		for _, e := range ns.bySrc {
			t.expire(sh, e, now)
		}
	}
}

// Sent records what became of a forward (4.5): "accepted" clears alone, the other
// two set it and say when the holder may be offered again.
func (t *Table) Sent(name []byte, src netip.Addr, ep, client [16]byte, result string) {
	sh := t.shard(name)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := t.live(sh, string(name), src, t.now().Unix())
	if e == nil {
		return
	}
	now := t.now().Unix()
	for i := range e.holders {
		h := &e.holders[i]
		if h.Endpoint != ep || h.Client != client || h.forwarded() {
			continue
		}
		switch result {
		case "accepted":
			h.Alone, h.SentAt = false, now
			h.OfferAt = now + int64(HolderLife/2/time.Second)
		case "refused":
			h.Alone, h.OfferAt = true, now+int64(RefusedRetry/time.Second)
		default: // unsent
			h.Alone, h.OfferAt = true, now+int64(UnsentRetry/time.Second)
		}
	}
}

// Stats is the table's counters as named values: refusals by reason, Put results
// and the width counters of 4.3 (a, <asn>, <width>). Names hold no value of a
// query.
func (t *Table) Stats() (named map[string]uint64, last string) {
	t.cmu.Lock()
	defer t.cmu.Unlock()
	named = make(map[string]uint64, len(t.counts)+len(t.widths)*6)
	for k, v := range t.counts {
		named[k] = v
	}
	for asn, c := range t.widths {
		for i, w := range [...]string{"prefix24_unique", "prefix24_shared", "carrier_unique", "carrier_shared", "miss", "exact"} {
			if c[i] != 0 {
				named["a"+itoa(asn)+"_"+w] = c[i]
			}
		}
	}
	return named, t.last
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Drop removes one holder (a forwarded Grant whose second look refused it). It
// closes nothing.
func (t *Table) Drop(name []byte, src netip.Addr, ep, client, origin [16]byte) {
	sh := t.shard(name)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := t.live(sh, string(name), src, t.now().Unix())
	if e == nil {
		return
	}
	i := e.find(holderID{ep, client, origin})
	if i < 0 {
		return
	}
	e.unindex()
	t.dropAt(e, i)
	e.index()
	t.retire(sh, e)
}
