package grant

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// This file is the connection table of 4.1 and the charging of 4.3 and 5.4. A
// connection is charged at its verdict, keeps its charge, and gives it back at its
// close; a kind 1 connection that closes (or moves on) with no byte from its target
// leaves its place counted until `dial_hold` after the dial began, because Xray
// goes on with the dial (5.5).

// DirectExit is the key of the `direct` inbound's pool.
const DirectExit = "direct"

type entryKey struct {
	name string
	src  netip.Addr
}

type epSrc struct {
	ep  [16]byte
	src netip.Addr
}

// place is what one connection holds in the pools.
type place struct {
	kind     uint8
	ep, acct [16]byte
	shared   bool
	src      netip.Addr
	entry    entryKey
	entryCap int
	exit     string // kind 1
}

// Conn is one open connection as dns knows it.
type Conn struct {
	ID       uint64
	Source   netip.Addr
	Name     string // canonical wire
	EntrySrc netip.Addr
	Out      Outcome
	// Holders are those of the entry at admission whose deciding query is newest, at
	// most 8; More says there were others (4.1).
	Holders []Holder
	More    bool
	Socks   string // current SOCKS target, empty for a block page
	Opened  time.Time

	pl      place
	charged bool
}

type hold struct {
	pl    place
	until time.Time
}

type openedAt struct {
	at   int64
	acct [16]byte
}

// Conns is the connection table. It is safe for concurrent use.
type Conns struct {
	lim Limits
	now func() time.Time
	cnt func(string)

	mu   sync.Mutex
	byID map[uint64]*Conn
	node *pool
	// exits, by exit key; exitOf maps a SOCKS address to its exit key.
	exits  map[string]*pool
	exitOf map[string]string

	opened  *pool
	openedQ []openedAt

	blockNode *pool
	epOpen    map[[16]byte]int
	epSrcN    map[epSrc]int
	srcOpen   map[netip.Addr]int
	entryOpen map[entryKey]int
	blockEp   map[[16]byte]int

	holds []hold
}

// NewConns makes the table. count receives refusal reasons (names, never values).
func NewConns(lim Limits, now func() time.Time, count func(string)) *Conns {
	if now == nil {
		now = time.Now
	}
	if count == nil {
		count = func(string) {}
	}
	return &Conns{lim: lim, now: now, cnt: count, byID: map[uint64]*Conn{},
		node: newPool(lim.NodeOpen), exits: map[string]*pool{}, exitOf: map[string]string{},
		opened: newPool(lim.OpenedLast30s), blockNode: newPool(lim.BlockNode),
		epOpen: map[[16]byte]int{}, epSrcN: map[epSrc]int{}, srcOpen: map[netip.Addr]int{},
		entryOpen: map[entryKey]int{}, blockEp: map[[16]byte]int{}}
}

// SetExits tells the table which exit each SOCKS address leaves through (the
// `locations` list). An address it does not know is its own exit.
func (c *Conns) SetExits(exitOf map[string]string) {
	c.mu.Lock()
	c.exitOf = exitOf
	c.mu.Unlock()
}

func (c *Conns) exitKey(socks string) string {
	if k, ok := c.exitOf[socks]; ok {
		return k
	}
	return "x:" + socks
}

func (c *Conns) exitPool(k string) *pool {
	p := c.exits[k]
	if p == nil {
		p = newPool(c.lim.ExitOpen)
		c.exits[k] = p
	}
	return p
}

func src16(a netip.Addr) [16]byte { return a.As16() }

// hasRoom is the share rule's test without the add.
func (p *pool) hasRoom(acct [16]byte, shared bool, src [16]byte) bool {
	if shared {
		free := p.cap/2 - p.shTotal
		return free > 0 && p.total < p.cap && p.shBy[src]*8 < free
	}
	free := p.cap - p.total
	return free > 0 && p.by[acct]*8 < free
}

func (c *Conns) tickLocked(now time.Time) {
	cut := now.Unix() - 30
	i := 0
	for i < len(c.openedQ) && c.openedQ[i].at <= cut {
		c.opened.sub(c.openedQ[i].acct)
		i++
	}
	c.openedQ = c.openedQ[i:]
	j := 0
	for _, h := range c.holds {
		if !h.until.After(now) {
			c.release(&h.pl, false)
			continue
		}
		c.holds[j] = h
		j++
	}
	c.holds = c.holds[:j]
}

// Tick gives back what has aged out: the window of connections opened lately and
// the places held after a dial (5.5). The owner calls it every second.
func (c *Conns) Tick() {
	c.mu.Lock()
	c.tickLocked(c.now())
	c.mu.Unlock()
}

// acquire charges a place. With force it never refuses (a connection that already
// exists). The reason is a counter name.
func (c *Conns) acquire(pl *place, force bool, now time.Time) string {
	s16 := src16(pl.src)
	if pl.kind == KindBlockPage {
		if !force && !pl.shared && c.blockEp[pl.ep] >= c.lim.BlockEndpoint {
			return "block_endpoint"
		}
		switch {
		case force && pl.shared:
			c.blockNode.forceShared(s16)
		case force:
			c.blockNode.force(pl.acct)
		case pl.shared && !c.blockNode.addShared(s16), !pl.shared && !c.blockNode.add(pl.acct):
			return "block_node"
		}
		if !pl.shared {
			c.blockEp[pl.ep]++
		}
		c.srcOpen[pl.src]++
		return ""
	}
	if !force {
		switch {
		case pl.entryCap > 0 && c.entryOpen[pl.entry] >= pl.entryCap:
			return "entry_open"
		case !pl.shared && c.epOpen[pl.ep] >= c.lim.EndpointOpen:
			return "endpoint_open"
		case !pl.shared && c.epSrcN[epSrc{pl.ep, pl.src}] >= c.lim.EndpointSource:
			return "source_open"
		case pl.shared && c.srcOpen[pl.src] >= c.lim.EndpointSource:
			return "source_open"
		}
	}
	ex := c.exitPool(pl.exit)
	if force {
		if pl.shared {
			c.node.forceShared(s16)
			ex.forceShared(s16)
		} else {
			c.node.force(pl.acct)
			ex.force(pl.acct)
		}
	} else if pl.shared {
		if !c.node.addShared(s16) {
			return "node_open"
		}
		if !ex.addShared(s16) {
			c.node.subShared(s16)
			return "exit_open"
		}
	} else {
		if !c.node.add(pl.acct) {
			return "node_open"
		}
		if !ex.add(pl.acct) {
			c.node.sub(pl.acct)
			return "exit_open"
		}
		if !force && !c.opened.add(pl.acct) {
			c.node.sub(pl.acct)
			ex.sub(pl.acct)
			return "opened_rate"
		}
		if !force {
			c.openedQ = append(c.openedQ, openedAt{now.Unix(), pl.acct})
		}
	}
	c.entryOpen[pl.entry]++
	if pl.shared {
		c.srcOpen[pl.src]++
	} else {
		c.epOpen[pl.ep]++
		c.epSrcN[epSrc{pl.ep, pl.src}]++
	}
	return ""
}

// release gives a place back. The opened-lately window is not given back: it ages.
func (c *Conns) release(pl *place, _ bool) {
	s16 := src16(pl.src)
	if pl.kind == KindBlockPage {
		if pl.shared {
			c.blockNode.subShared(s16)
		} else {
			c.blockNode.sub(pl.acct)
			dec(c.blockEp, pl.ep)
		}
		decAddr(c.srcOpen, pl.src)
		return
	}
	ex := c.exitPool(pl.exit)
	if pl.shared {
		c.node.subShared(s16)
		ex.subShared(s16)
		decAddr(c.srcOpen, pl.src)
	} else {
		c.node.sub(pl.acct)
		ex.sub(pl.acct)
		dec(c.epOpen, pl.ep)
		k := epSrc{pl.ep, pl.src}
		if c.epSrcN[k]--; c.epSrcN[k] <= 0 {
			delete(c.epSrcN, k)
		}
	}
	if c.entryOpen[pl.entry]--; c.entryOpen[pl.entry] <= 0 {
		delete(c.entryOpen, pl.entry)
	}
	if ex.total == 0 && len(ex.by) == 0 {
		delete(c.exits, pl.exit)
	}
}

func dec(m map[[16]byte]int, k [16]byte) {
	if m[k]--; m[k] <= 0 {
		delete(m, k)
	}
}

func decAddr(m map[netip.Addr]int, k netip.Addr) {
	if m[k]--; m[k] <= 0 {
		delete(m, k)
	}
}

func placeOf(src netip.Addr, h Hit) place {
	pl := place{src: src, entry: entryKey{h.Name, h.EntrySrc}, kind: h.Out.Kind, shared: h.Accounts > 1}
	if len(h.Holders) > 0 {
		pl.ep, pl.acct = h.Holders[0].Endpoint, h.Holders[0].Account
	}
	return pl
}

func (c *Conns) entryCap(h Hit) int { return c.lim.EntryPerEndpoint * min(max(h.Endpoints, 1), 8) }

// Admit charges a new connection that a hit gave a verdict for (kind 1 takes the
// ordered exits of its targets; the first with room is charged and every one with
// room is returned by index, so the verdict lists only those). It returns the
// counter name of the refusal, or "" and the connection.
func (c *Conns) Admit(id uint64, src netip.Addr, h Hit, exits []string, socks string) (*Conn, []int, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.tickLocked(now)
	pl := placeOf(src, h)
	pl.entryCap = c.entryCap(h)
	var rooms []int
	if h.Out.Kind == KindRedirect {
		for i, e := range exits {
			if p := c.exits[e]; p == nil || p.hasRoom(pl.acct, pl.shared, src16(src)) {
				rooms = append(rooms, i)
			}
		}
		if len(rooms) == 0 {
			c.cnt("exit_open")
			return nil, nil, "exit_open"
		}
		pl.exit = exits[rooms[0]]
	}
	if r := c.acquire(&pl, false, now); r != "" {
		c.cnt(r)
		return nil, nil, r
	}
	cn := &Conn{ID: id, Source: src, Name: h.Name, EntrySrc: h.EntrySrc, Out: h.Out, Holders: h.Holders, More: h.More,
		Socks: socks, Opened: now, pl: pl, charged: true}
	if old := c.byID[id]; old != nil {
		c.dropLocked(old)
	}
	c.byID[id] = cn
	return cn, rooms, ""
}

func (c *Conns) dropLocked(cn *Conn) {
	if cn.charged {
		c.release(&cn.pl, false)
		cn.charged = false
	}
	delete(c.byID, cn.ID)
}

// Get returns a copy of a connection.
func (c *Conns) Get(id uint64) (Conn, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cn := c.byID[id]
	if cn == nil {
		return Conn{}, false
	}
	return *cn, true
}

// Moved says connection id went on to target socks. When left is set the dial it
// left (made at startMS after the open) goes on, so its place stays counted until
// DialHold after its start and the connection takes a new place in the pool of the
// new exit; otherwise that dial has ended and the place only changes exit.
func (c *Conns) Moved(id uint64, socks string, left bool, startMS uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cn := c.byID[id]
	if cn == nil || cn.pl.kind != KindRedirect {
		return
	}
	newExit := c.exitKey(socks)
	cn.Socks = socks
	if newExit == cn.pl.exit && !left {
		return
	}
	if left {
		held := cn.pl
		c.holds = append(c.holds, hold{pl: held, until: cn.Opened.Add(time.Duration(startMS) * time.Millisecond).Add(c.lim.DialHold)})
		cn.pl.exit = newExit
		c.acquire(&cn.pl, true, c.now()) // the connection's own new place
		return
	}
	// Same node and account shares, another exit's pool.
	old := c.exitPool(cn.pl.exit)
	nw := c.exitPool(newExit)
	if cn.pl.shared {
		old.subShared(src16(cn.pl.src))
		nw.forceShared(src16(cn.pl.src))
	} else {
		old.sub(cn.pl.acct)
		nw.force(cn.pl.acct)
	}
	cn.pl.exit = newExit
}

// Pending is a connection that closed with no byte from its current target.
type Pending struct {
	ID      uint64
	StartMS uint32
}

// Closed gives back the places of closed connections. A pending one keeps its place
// as a hold until DialHold after its dial began.
func (c *Conns) Closed(ids []uint64, pending []Pending) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for _, id := range ids {
		if cn := c.byID[id]; cn != nil {
			c.dropLocked(cn)
		}
	}
	for _, p := range pending {
		cn := c.byID[p.ID]
		if cn == nil {
			continue
		}
		until := cn.Opened.Add(time.Duration(p.StartMS) * time.Millisecond).Add(c.lim.DialHold)
		if cn.charged && cn.pl.kind == KindRedirect && until.After(now) {
			c.holds = append(c.holds, hold{pl: cn.pl, until: until})
			cn.charged = false // the hold owns the place now
		}
		c.dropLocked(cn)
	}
}

// OpenItem is one connection of the proxy's `open` list.
type OpenItem struct {
	ID     uint64
	Source netip.Addr
	Socks  string
	Tag    []byte
}

// Rebuild replaces the table with the proxy's list (4.1): each connection is charged
// by its tag, never refused. Holds are forgotten; they end by themselves within
// dial_hold.
func (c *Conns) Rebuild(items []OpenItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cn := range c.byID {
		if cn.charged {
			c.release(&cn.pl, false)
		}
	}
	for _, h := range c.holds {
		c.release(&h.pl, false)
	}
	c.holds = nil
	c.byID = make(map[uint64]*Conn, len(items))
	now := c.now()
	for _, it := range items {
		cn := decodeTag(it.Tag)
		if cn == nil {
			// A tag that does not read holds no holder, so the first judgement ends it.
			cn = &Conn{}
		}
		cn.ID, cn.Source, cn.Socks, cn.Opened = it.ID, it.Source, it.Socks, now
		if cn.Out.Kind != 0 {
			cn.pl.src = it.Source
			cn.pl.entry = entryKey{cn.Name, cn.EntrySrc}
			if cn.Out.Kind == KindRedirect {
				cn.pl.exit = c.exitKey(it.Socks)
			}
			c.acquire(&cn.pl, true, now)
			cn.charged = true
		}
		c.byID[it.ID] = cn
	}
}

// JudgeConns returns the ids of the connections to end (4.6): every holder recorded
// with it has ended, and, with `more`, its (name, source) has no live holder of its
// outcome either. live is Table.Live.
func (c *Conns) JudgeConns(judge Judge, live func(name []byte, src netip.Addr) (Outcome, bool)) []uint64 {
	c.mu.Lock()
	cs := make([]*Conn, 0, len(c.byID))
	for _, cn := range c.byID {
		cs = append(cs, cn)
	}
	c.mu.Unlock()
	var end []uint64
	for _, cn := range cs {
		all := true
		nb := []byte(cn.Name)
		for i := range cn.Holders {
			if !judge(nb, cn.EntrySrc, cn.Out, &cn.Holders[i]) {
				all = false
				break
			}
		}
		if all && cn.More {
			if out, ok := live(nb, cn.EntrySrc); ok && out == cn.Out {
				all = false
			}
		}
		if all {
			end = append(end, cn.ID)
		}
	}
	sort.Slice(end, func(i, j int) bool { return end[i] < end[j] })
	return end
}

// SocksUsed lists the SOCKS addresses that open connections use.
func (c *Conns) SocksUsed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]struct{}{}
	for _, cn := range c.byID {
		if cn.Socks != "" {
			seen[cn.Socks] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Open counts the open connections of each kind.
func (c *Conns) Open() (kind1, kind2 int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cn := range c.byID {
		if cn.Out.Kind == KindBlockPage {
			kind2++
		} else {
			kind1++
		}
	}
	return
}

// Held is the number of places kept after a dial (tests and stats).
func (c *Conns) Held() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.holds)
}

// ExitOpen is how many places an exit's pool counts, held dials included.
func (c *Conns) ExitOpen(exit string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.exits[exit]; p != nil {
		return p.total
	}
	return 0
}

// NodeOpen is the node pool's count.
func (c *Conns) NodeOpen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.node.total
}

// ---- the tag (2.1): what a restart of dns needs to rebuild a connection's record

const tagVersion = 1

// Tag encodes the connection for the verdict. It fits MaxTag bytes: holders that
// do not fit are left out and `more` is set, which only makes the end of the
// connection wait for a live holder of its outcome (4.6).
func (c *Conn) Tag(max int) []byte {
	b := []byte{tagVersion, c.Out.Kind, 0, 0}
	var flags byte
	if c.pl.shared {
		flags |= 1
	}
	if c.Out.Dial != "" {
		flags |= 2
	}
	b = append(b, c.pl.ep[:]...)
	b = append(b, c.pl.acct[:]...)
	b = binary.BigEndian.AppendUint16(b, c.Out.Location)
	if c.Out.Kind == KindBlockPage {
		b = append(b, c.Out.Page[:]...)
	}
	b = append(b, byte(len(c.Name)))
	b = append(b, c.Name...)
	es := c.EntrySrc.AsSlice()
	b = append(b, byte(len(es)))
	b = append(b, es...)
	if c.Out.Dial != "" {
		b = append(b, byte(len(c.Out.Dial)))
		b = append(b, c.Out.Dial...)
	}
	n := 0
	more := c.More
	for i := range c.Holders {
		hb := encodeHolder(&c.Holders[i])
		if len(b)+len(hb) > max {
			more = true
			break
		}
		b = append(b, hb...)
		n++
	}
	if more {
		flags |= 4
	}
	b[2], b[3] = flags, byte(n)
	return b
}

func encodeHolder(h *Holder) []byte {
	var f byte
	if h.Open {
		f |= 1
	}
	if h.Client != ([16]byte{}) {
		f |= 2
	}
	if h.Origin != ([16]byte{}) {
		f |= 4
	}
	if h.Claim != ([16]byte{}) {
		f |= 8
	}
	b := []byte{f}
	b = append(b, h.Endpoint[:]...)
	b = append(b, h.Ident[:]...)
	b = append(b, h.Account[:]...)
	if f&2 != 0 {
		b = append(b, h.Client[:]...)
	}
	if f&4 != 0 {
		b = append(b, h.Origin[:]...)
	}
	if f&8 != 0 {
		b = append(b, h.Claim[:]...)
	}
	return b
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || len(r.b) < n {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func decodeTag(b []byte) *Conn {
	r := &reader{b: b}
	hd := r.take(4)
	if r.bad || hd[0] != tagVersion || (hd[1] != KindRedirect && hd[1] != KindBlockPage) {
		return nil
	}
	cn := &Conn{}
	cn.Out.Kind = hd[1]
	flags, n := hd[2], int(hd[3])
	cn.pl.kind = cn.Out.Kind
	cn.pl.shared = flags&1 != 0
	copy(cn.pl.ep[:], r.take(16))
	copy(cn.pl.acct[:], r.take(16))
	if l := r.take(2); !r.bad {
		cn.Out.Location = binary.BigEndian.Uint16(l)
	}
	if cn.Out.Kind == KindBlockPage {
		copy(cn.Out.Page[:], r.take(32))
	}
	if l := r.take(1); !r.bad {
		cn.Name = string(r.take(int(l[0])))
	}
	if l := r.take(1); !r.bad {
		if a, ok := netip.AddrFromSlice(r.take(int(l[0]))); ok {
			cn.EntrySrc = a
		} else {
			r.bad = true
		}
	}
	if flags&2 != 0 {
		if l := r.take(1); !r.bad {
			cn.Out.Dial = string(r.take(int(l[0])))
		}
	}
	cn.More = flags&4 != 0
	for i := 0; i < n && !r.bad; i++ {
		f := r.take(1)
		if r.bad {
			break
		}
		var h Holder
		copy(h.Endpoint[:], r.take(16))
		copy(h.Ident[:], r.take(16))
		copy(h.Account[:], r.take(16))
		h.Open = f[0]&1 != 0
		if f[0]&2 != 0 {
			copy(h.Client[:], r.take(16))
		}
		if f[0]&4 != 0 {
			copy(h.Origin[:], r.take(16))
		}
		if f[0]&8 != 0 {
			copy(h.Claim[:], r.take(16))
		}
		cn.Holders = append(cn.Holders, h)
	}
	if r.bad {
		return nil
	}
	return cn
}
