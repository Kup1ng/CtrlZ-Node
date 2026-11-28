package dns

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/grant"
)

// This file is the dns side of P4b's Grants (p4b-proxy 4, 5.3): the glue between the
// query path, the Grant table (internal/grant) and the proxy's link (internal/link,
// for which *Grants is the Backend). The table decides nothing about DNS; this file
// turns a decision into a Put, a lookup into a verdict, and the image into ends.

// ProxyOptions switch the proxy's Grants on. A Handler built without them is the
// node of P4: no Grant is written and the proxy has nothing to ask.
type ProxyOptions struct {
	// Limits are the numbers of 12; the zero value takes grant.DefaultLimits.
	Limits grant.Limits
	// Send queues a message for the agent (grant_res, grant_out, proxy_state). It
	// never blocks and says whether the message was queued.
	Send func(*sock.Msg) bool
	// Facts reads what the node's config says.
	Facts func() ProxyFacts
	// End tells the proxy to close connections (the link server's End).
	End func(ids []uint64, socks []string) bool
}

// ProxyFacts are the node's own facts that Grants read at each use.
type ProxyFacts struct {
	Self      [16]byte   // this node's id
	ProxyBind netip.Addr // proxy_bind_ip, the address the proxy listens on
	DNSBind   netip.Addr // dns_bind_ip
	Width     grant.Width
	// PeerDown says this node's own probe of the peer is down (SC 7).
	PeerDown func(node [16]byte) bool
}

// Grants is the Grant side of a Handler.
type Grants struct {
	h     *Handler
	o     ProxyOptions
	lim   grant.Limits
	table *grant.Table
	conns *grant.Conns
	fwd   *grant.FwdQueue
	start time.Time

	locs atomic.Pointer[locView]

	linkUp    atomic.Bool
	listening atomic.Bool // what the proxy last said, false while the link is down
	pxOpen    atomic.Uint32

	passMu   sync.Mutex
	lastPass atomic.Int64
	// kick asks for a pass of the image (at most once in 5 s, 4.6); kickNow is for a
	// revocation, which ends Grants when dns gets it.
	kick    chan struct{}
	kickNow chan struct{}

	mu       sync.Mutex
	noA      map[string]noAMark
	aWaits   map[[16]byte]int
	refused  map[string]uint64
	waiting  []waitFwd
	inSec    int64
	inN      int
	stateAt  time.Time
	stateKey string

	warm chan struct{}
	fsem chan struct{}
}

func newGrants(h *Handler, o ProxyOptions) *Grants {
	if o.Limits == (grant.Limits{}) {
		o.Limits = grant.DefaultLimits()
	}
	g := &Grants{h: h, o: o, lim: o.Limits, start: h.now(), kick: make(chan struct{}, 1), kickNow: make(chan struct{}, 1),
		noA: map[string]noAMark{}, aWaits: map[[16]byte]int{}, refused: map[string]uint64{},
		warm: make(chan struct{}, 64), fsem: make(chan struct{}, 256)}
	g.table = grant.NewTable(o.Limits, h.now)
	g.conns = grant.NewConns(o.Limits, h.now, g.table.Count)
	g.fwd = grant.NewFwdQueue(o.Limits)
	return g
}

// Grants returns the Grant side of the handler, nil for a node with no proxy.
func (h *Handler) Grants() *Grants { return h.grants }

// Table and Conns are for tests and the stats of the node.
func (g *Grants) Table() *grant.Table { return g.table }
func (g *Grants) Conns() *grant.Conns { return g.conns }

func (g *Grants) facts() ProxyFacts {
	if g.o.Facts == nil {
		return ProxyFacts{}
	}
	return g.o.Facts()
}

func (g *Grants) send(m *sock.Msg) bool { return g.o.Send != nil && g.o.Send(m) }

func (g *Grants) end(ids []uint64, socks []string) {
	if g.o.End != nil {
		g.o.End(ids, socks)
	}
}

// Listening is the proxy's state as dns knows it: false while the link is down. It
// is what the evaluator reads as ProxyDown (4.4).
func (g *Grants) Listening() bool { return g.linkUp.Load() && g.listening.Load() }

// ---- the query side: Put

func accountOf(rec *policyv1.EndpointRecord, ep [16]byte) [16]byte {
	if len(rec.GetAccountHash()) == 16 {
		return [16]byte(rec.AccountHash)
	}
	return ep
}

func identOf(rec *policyv1.EndpointRecord) (id [16]byte) {
	h := sha256.New()
	h.Write(rec.RidHash)
	h.Write(rec.DohTokenHash)
	copy(id[:], h.Sum(nil))
	return id
}

// holderFor builds the holder of a decision (4.1). The client is kept only when the
// record has a ClientRecord of it, so a device that names any label does not make a
// holder of its own.
func holderFor(st *epState, f *sharedpolicy.Final, claim [16]byte, client, origin [16]byte) grant.Holder {
	rec := st.rec
	h := grant.Holder{Endpoint: st.id, Origin: origin, Ident: identOf(rec), Claim: claim,
		Account: accountOf(rec, st.id), Open: !rec.RequireAuthorizedIps, Widenable: f.Widenable}
	if client != ([16]byte{}) {
		for _, c := range rec.Clients {
			if len(c.ClientHash) == 16 && [16]byte(c.ClientHash) == client {
				h.Client = client
				break
			}
		}
	}
	switch f.Target {
	case sharedpolicy.TargetAuto:
		h.Pick = grant.PickAuto
	case sharedpolicy.TargetRandom:
		h.Pick = grant.PickRandom
	}
	return h
}

func outcomeOf(f *sharedpolicy.Final) grant.Outcome {
	o := grant.Outcome{Kind: f.GrantKind, Dial: string(f.DialHost.Wire())}
	if f.GrantKind == grant.KindRedirect {
		o.Location = f.Location
	} else {
		o.Page = f.PageHash
	}
	return o
}

func dialName(o grant.Outcome) names.Name {
	if o.Dial == "" {
		return names.Name{}
	}
	n, _ := names.FromCanonicalWire([]byte(o.Dial))
	return n
}

// unsafe is R9 at Grant creation (4.2 step 1), for a kind 1 holder: the name to dial
// is a single label or under a private suffix, or the cache holds an A of it that is
// neither public nor injected.
func (g *Grants) unsafe(dial names.Name, p sharedpolicy.ResolveParams) bool {
	if !cache.PublicName(dial) {
		return true
	}
	if g.h.cfg.CachedA == nil {
		return false
	}
	variants := []sharedpolicy.ResolveParams{p}
	if p != (sharedpolicy.ResolveParams{}) {
		variants = append(variants, sharedpolicy.ResolveParams{})
	}
	for _, v := range variants {
		if addrs, ok := g.h.cfg.CachedA(dial, v); ok && badAddrs(addrs) {
			return true
		}
	}
	return false
}

// badAddrs: an address that is neither public nor injected (10.10.34.0/24 is what
// the national filter injects, and such a name goes to the exit, 15.2).
func badAddrs(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if c := netclass.ClassOf(a); c != netclass.Public && c != netclass.Injected {
			return true
		}
	}
	return false
}

// putCall is what a Put takes from a query.
type putCall struct {
	req    *listen.Request
	id     *ident
	qn     names.Name
	in     *sharedpolicy.Input
	stack  *sharedpolicy.Stack
	env    *sharedpolicy.Env
	final  *sharedpolicy.Final
	params sharedpolicy.ResolveParams
	sv     *Serving
}

// put is steps 7 and 9 of SC 5.2: it runs before the answer is sent and returns the
// verdict of the table.
func (g *Grants) put(ctx context.Context, c *putCall) grant.PutResult {
	src := c.req.Source.Addr().Unmap()
	f := c.final
	out := outcomeOf(f)
	if g.grantsRevoked(c.sv, c.id.st.id) {
		g.table.Count("refused_" + ReasonRevoked)
		return grant.PutResult{Verdict: grant.Refused, Reason: ReasonRevoked}
	}
	if out.Kind == grant.KindRedirect {
		dial := c.qn
		if out.Dial != "" {
			dial = dialName(out)
		}
		if g.unsafe(dial, c.params) {
			g.table.Count("refused_" + grant.ReasonUnsafe)
			return grant.PutResult{Verdict: grant.Refused, Reason: grant.ReasonUnsafe}
		}
	}
	var claim [16]byte
	if c.id.claim != nil {
		claim = c.id.claim.ID
	}
	st := c.id.st
	h := holderFor(st, f, claim, c.id.stackClient(), [16]byte{})
	req := &grant.PutReq{
		Name: c.qn.Wire(), Source: src, ASN: g.asn(src), Out: out, Holder: h, Validated: c.req.Validated,
		EndpointCap: int(st.rec.GrantCap), Privileged: c.id.claim != nil || inAny(st.authorized, src),
		Joins: g.joins(c.in, c.stack, c.env),
	}
	res := g.table.Put(req)
	if res.Verdict != grant.Ok {
		return res
	}
	if out.Kind == grant.KindRedirect {
		g.warmA(dialOrName(c.qn, out))
	}
	if res.Offer {
		// The stored outcome, not this query's own decision: a holder that joined a live
		// outcome must not hand the peer another one (4.2).
		g.offer(c.sv, st, src, &c.qn, res.Out, &res.Holder)
	}
	return res
}

// ReasonRevoked is the refusal of a Put for an Endpoint whose Grants a revocation
// ends while it is in force (4.6): no holder is written that the next pass would
// remove, so the proxy cannot admit a connection on it in between.
const ReasonRevoked = "revoked"

// grantsRevoked says an Endpoint or grants_by_endpoint revocation is in force.
func (g *Grants) grantsRevoked(sv *Serving, ep [16]byte) bool {
	applied, now := sv.img.Seq(), g.h.now()
	return g.h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, ep, applied, now) ||
		g.h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_GRANTS_BY_ENDPOINT, ep, applied, now)
}

func dialOrName(qn names.Name, o grant.Outcome) names.Name {
	if o.Dial != "" {
		return dialName(o)
	}
	return qn
}

// joins is the test of SC 10.3 with the live outcome as the offer: the holder's own
// decision, run again, must allow it.
func (g *Grants) joins(in *sharedpolicy.Input, stack *sharedpolicy.Stack, env *sharedpolicy.Env) func(grant.Outcome) bool {
	return func(live grant.Outcome) bool {
		offer := sharedpolicy.GrantOffer{Kind: live.Kind, Location: live.Location, DialHost: dialName(live)}
		f, ok := sharedpolicy.AcceptGrant(in, stack, env, g.h.cfg.Resolver, offer)
		if ok && live.Kind == grant.KindBlockPage {
			ok = f.PageHash == live.Page // a Branded block joins only the same page
		}
		return ok
	}
}

func (g *Grants) asn(a netip.Addr) uint32 {
	if g.h.cfg.Geo == nil {
		return 0
	}
	return g.h.cfg.Geo.ASN(a)
}

// warmA starts the background A lookup of a new kind 1 holder's dial name, so 5.3
// finds it in the cache. Bounded: at most 64 run at once.
func (g *Grants) warmA(n names.Name) {
	if g.h.cfg.Resolver == nil {
		return
	}
	select {
	case g.warm <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-g.warm }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = g.h.cfg.Resolver.Lookup(ctx, n, sharedpolicy.TypeA, sharedpolicy.ResolveParams{})
	}()
}

// ---- the proxy side: verdicts (5.3)

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)

const (
	putWait   = 200 * time.Millisecond // 4.3 step 3
	aWait     = 300 * time.Millisecond // 5.3
	aRetry    = 60 * time.Second
	aWaitsEp  = 64
	maxNoA    = 8192
	maxTarget = sock.MaxTargets
)

// Source is the pool question of 5.4: does the source have a live entry.
func (g *Grants) Source(src netip.Addr) bool {
	return g.table.Known(src, g.asn(src), g.facts().Width)
}

func none() *sock.LinkVerdict { return &sock.LinkVerdict{Kind: sock.VerdictNone} }

// Lookup is the verdict of one connection (4.3, 5.3).
func (g *Grants) Lookup(ctx context.Context, id uint64, src netip.Addr, wire []byte, port uint16) *sock.LinkVerdict {
	// The generation is read before anything else and ctx is checked after it: a
	// lookup of a proxy session that has been replaced either sees its ctx cancelled
	// or carries the old generation, and in both cases charges nothing into the table
	// the new session's open list built (grant.Conns.AdmitAt).
	gen := g.conns.Gen()
	width := g.facts().Width
	asn := g.asn(src)
	probe := func() (hit grant.Hit, y grant.Tally, ok bool) { return g.table.Probe(src, asn, wire, width) }
	hit, y, ok := probe()
	if !ok {
		// A Put may be a moment behind the proxy's lookup: the device asked DNS and
		// connected at once. Wait for that exact key; the wait looks once more after it
		// is registered, so a Put that landed since the miss is not lost, and again when
		// it is signalled.
		signalled := g.table.Wait(ctx, wire, src, putWait, func() bool {
			hit, y, ok = probe()
			return ok
		})
		if signalled && !ok {
			hit, y, ok = probe()
		}
	}
	// Counted once, as what the connection finally found (4.3).
	g.table.Record(asn, y)
	if !ok {
		g.table.Count("lookup_none")
		return none()
	}
	if len(hit.Holders) == 0 || ctx.Err() != nil {
		return none()
	}
	if hit.Out.Kind == grant.KindBlockPage {
		return g.blockVerdict(gen, id, src, hit)
	}
	return g.proxyVerdict(ctx, gen, id, src, wire, port, hit)
}

func (g *Grants) blockVerdict(gen, id uint64, src netip.Addr, hit grant.Hit) *sock.LinkVerdict {
	cn, _, why := g.conns.AdmitAt(gen, id, src, hit, nil, "")
	if why != "" {
		return none()
	}
	nh := hit.Holders[0]
	v := &sock.LinkVerdict{Kind: sock.VerdictBlock, Tag: cn.Tag(sock.MaxTag), Endpoint: nh.Endpoint[:], Account: nh.Account[:]}
	// After a restart a device may still hold the answer of another tenant whose Grant
	// the restart removed, so for MaxProxyTTL ctrlz-block serves our default page (4.1).
	if hit.Out.Page != ([32]byte{}) && g.h.now().Sub(g.start) >= grant.MaxProxyTTL*time.Second {
		v.PageHash = hit.Out.Page[:]
	}
	return v
}

type target struct{ socks, host, exit string }

func (g *Grants) proxyVerdict(ctx context.Context, gen, id uint64, src netip.Addr, wire []byte, port uint16, hit grant.Hit) *sock.LinkVerdict {
	name, err := names.FromCanonicalWire(wire)
	if err != nil {
		return none()
	}
	// The backend check of D42 for an old or forged Grant: step 4 of 5.2 repeats the
	// TLD rule in the other process.
	if g.h.cfg.NeverProxied(name) {
		g.table.Count("never_proxied")
		return none()
	}
	dial := dialOrName(name, hit.Out)
	if !cache.PublicName(dial) {
		g.table.Count("unsafe")
		return none()
	}
	lv := g.locs.Load()
	if !lv.usable() {
		g.table.Count("no_location")
		return none()
	}
	nh := hit.Holders[0]
	addrs, answered, gated := g.dialAddrs(ctx, dial, nh.Endpoint)
	if ctx.Err() != nil {
		return none() // the session of this lookup ended while it waited
	}
	if gated {
		// The Sanity Gate refused the answer for a class other than injected (private,
		// loopback, CGNAT): the name must not be dialled, by address or by name (R9, 5.3).
		g.table.Count("unsafe")
		return none()
	}
	if answered && badAddrs(addrs) {
		g.table.Count("unsafe")
		return none()
	}
	var cands []target
	if answered && g.h.cfg.Geo != nil {
		for _, a := range addrs {
			if g.h.cfg.Geo.Country(a) == [2]byte{'I', 'R'} {
				// The only target is the direct inbound with this numeric address, so the
				// address that was checked is the address that is dialled. Not refused.
				if lv.direct == "" {
					g.table.Count("no_location")
					return none()
				}
				cands = []target{{lv.direct, a.String(), grant.DirectExit}}
				break
			}
		}
	}
	if cands == nil {
		host := dial.String()
		if !hostRE.MatchString(host) {
			g.table.Count("bad_host")
			return none()
		}
		for _, c := range lv.targets(hit.Out.Location, nh.Pick == grant.PickRandom, nh.Endpoint, wire, g.h.now().Unix(), maxTarget) {
			cands = append(cands, target{c.socks, host, c.exit})
		}
	}
	if len(cands) == 0 {
		g.table.Count("no_location")
		return none()
	}
	exits := make([]string, len(cands))
	for i := range cands {
		exits[i] = cands[i].exit
	}
	cn, rooms, why := g.conns.AdmitAt(gen, id, src, hit, exits, cands[0].socks)
	if why != "" {
		return none()
	}
	// The connection is charged to the first target with room; it starts there.
	first := cands[rooms[0]].socks
	g.conns.Moved(id, first, false, 0)
	v := &sock.LinkVerdict{Kind: sock.VerdictProxy, Tag: cn.Tag(sock.MaxTag)}
	for _, i := range rooms {
		v.Targets = append(v.Targets, sock.Target{Socks: cands[i].socks, Host: cands[i].host, Port: port})
	}
	return v
}

// dialAddrs reads the A of the host to dial from the shared cache, or waits up to
// 300 ms for a lookup through the identified resolver. A name with no answer in that
// time goes to the location, and is asked again in 60 s at the earliest. A waits of
// one Endpoint are at most 64 (12).
//
// gated says the Sanity Gate refused the answer for a class other than injected, now
// or at the lookup 60 s ago that the name is remembered for: the verdict is none (5.3).
func (g *Grants) dialAddrs(ctx context.Context, dial names.Name, ep [16]byte) (addrs []netip.Addr, answered, gated bool) {
	p := sharedpolicy.ResolveParams{}
	if g.h.cfg.CachedA != nil {
		if a, ok := g.h.cfg.CachedA(dial, p); ok {
			return a, true, false
		}
	}
	if g.h.cfg.Resolver == nil {
		return nil, false, false
	}
	key := string(dial.Wire())
	now := g.h.now()
	g.mu.Lock()
	if m, bad := g.noA[key]; bad && now.Sub(m.at) < aRetry {
		g.mu.Unlock()
		return nil, false, m.gated
	}
	if g.aWaits[ep] >= aWaitsEp {
		g.mu.Unlock()
		return nil, false, false
	}
	g.aWaits[ep]++
	g.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, aWait)
	ans, err := g.h.cfg.Resolver.Lookup(cctx, dial, sharedpolicy.TypeA, p)
	cancel()
	g.mu.Lock()
	if g.aWaits[ep]--; g.aWaits[ep] <= 0 {
		delete(g.aWaits, ep)
	}
	if ctx.Err() != nil {
		// The caller went away, which says nothing of the name: no mark, no answer.
		g.mu.Unlock()
		return nil, false, false
	}
	failed := true
	if err == nil && ans != nil && !ans.Failed {
		failed = false
		for i := range ans.Answer {
			if a, ok := ans.Answer[i].Addr(); ok {
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 {
		if failed && g.h.cfg.GateClass != nil {
			if c, ok := g.h.cfg.GateClass(dial); ok && c != netclass.Injected {
				gated = true
			}
		}
		if len(g.noA) >= maxNoA {
			g.noA = map[string]noAMark{}
		}
		g.noA[key] = noAMark{at: now, gated: gated}
	}
	g.mu.Unlock()
	return addrs, len(addrs) > 0, gated
}

// noAMark is the 60 s memory of a name that had no A at its last lookup.
type noAMark struct {
	at    time.Time
	gated bool // the Sanity Gate refused it, for a class other than injected
}

// ---- the link's other messages

// Moved, Closed: the table of open connections follows the proxy (4.1).
func (g *Grants) Moved(m *sock.LinkMoved) {
	left := m.Left != nil
	var start uint32
	if left {
		start = m.Left.StartMS
	}
	g.conns.Moved(m.ID, m.Socks, left, start)
}

func (g *Grants) Closed(c *sock.LinkClosed) {
	p := make([]grant.Pending, len(c.Pending))
	for i, x := range c.Pending {
		p[i] = grant.Pending{ID: x.ID, StartMS: x.StartMS}
	}
	g.conns.Closed(c.IDs, p)
}

// State is the proxy's own state frame. The refusal counts are the proxy's, since
// its start.
func (g *Grants) State(s *sock.LinkState) {
	g.listening.Store(s.Listening)
	g.pxOpen.Store(s.Open)
	// A frame lists every refusal the proxy has counted since its start, so it replaces
	// the last one: a proxy that sends new names in each frame cannot grow this map.
	m := make(map[string]uint64, len(s.Refused))
	for _, r := range s.Refused {
		m[r.Reason] = r.Count
	}
	g.mu.Lock()
	g.refused = m
	g.mu.Unlock()
}

// ProxyConfig is `config` (2.1): the address to listen on and the limits of 12 that
// the proxy applies itself.
func (g *Grants) ProxyConfig() (sock.ProxyConfig, bool) {
	f := g.facts()
	if !f.ProxyBind.IsValid() {
		return sock.ProxyConfig{}, false
	}
	return sock.ProxyConfig{
		BindIP:        f.ProxyBind.String(),
		MainPerSource: 512, MainNode: 8192, MainSniffMS: 5000,
		OtherPerSource: 64, OtherNode: 2048, OtherFirstMS: 1000,
		NewRate: 200, NewBurst: 1000,
		LookupPerSource: 64, LookupNode: 8192,
		MemUnit: 1 << 30, MemSlots: 3 << 29,
		DialFirstByteMS: 5000, MaxAgeS: 24 * 3600, IdleS: 600,
	}, true
}

// LinkUp rebuilds the table of open connections from the proxy's list and judges
// it, so a connection whose Grants ended while the link was down, or before a
// restart of dns, lives no longer (4.6). The proxy gets `end` before `config`.
func (g *Grants) LinkUp(_ uint64, items []grant.OpenItem) {
	g.conns.Rebuild(items)
	g.linkUp.Store(true)
	g.listening.Store(false)
	g.pass()
	g.endStale()
}

// LinkDown: the proxy listens on nothing while there is no link, and the answers
// leave own out (4.4).
func (g *Grants) LinkDown() {
	g.linkUp.Store(false)
	g.listening.Store(false)
}

// Stats is `stats_res`: names only, never a value of a query.
func (g *Grants) Stats() *sock.LinkStatsRes {
	named, last := g.table.Stats()
	named["holders"] = uint64(g.table.Holders())
	k1, k2 := g.conns.Open()
	named["open_proxy"], named["open_block"] = uint64(k1), uint64(k2)
	q, p := g.fwd.Len()
	named["fwd_queued"], named["fwd_unanswered"] = uint64(q), uint64(p)
	g.mu.Lock()
	for r, n := range g.refused {
		named["px_"+r] = n
	}
	g.mu.Unlock()
	res := &sock.LinkStatsRes{LastRefused: last}
	for n, v := range named {
		if len(n) > 32 {
			n = n[:32]
		}
		if len(res.Counters) >= sock.MaxCounters {
			break
		}
		res.Counters = append(res.Counters, sock.Counter{Name: n, Value: v})
	}
	return res
}

// ---- locations

// OnLocations takes the agent's list: the port map and health of every config
// (6.4). The last list is kept while the agent is away.
func (g *Grants) OnLocations(l *sock.Locations) {
	v := newLocView(l)
	g.locs.Store(v)
	g.conns.SetExits(v.exitOf)
	g.endStale()
}

// endStale sends `end` for every SOCKS address that a connection uses and the last
// list does not hold (4.6): a deleted or disabled config closes its connections at
// once, a replaced generation after its drain.
func (g *Grants) endStale() {
	v := g.locs.Load()
	if v == nil || !g.linkUp.Load() {
		return
	}
	var gone []string
	for _, s := range g.conns.SocksUsed() {
		if !v.held[s] {
			gone = append(gone, s)
		}
	}
	if len(gone) > 0 {
		g.end(nil, gone)
	}
}

// ---- ends (4.6)

// passEvery is the least time between two passes that no revocation asked for (4.6:
// every served image, at most once in 5 s). A pass walks every holder under the shard
// locks that Put needs, so a burst of images must not repeat the sweep.
const passEvery = 5 * time.Second

// Revalidate asks for a pass for a served image or a catalog change. It runs at once
// when the last pass is older than 5 s; otherwise the periodic pass of Run, at most
// 5 s after the last, covers it.
func (g *Grants) Revalidate() {
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

// RevalidateNow asks for a pass at once, for a revocation: it ends Grants when dns
// gets it, and while it is in force (4.6).
func (g *Grants) RevalidateNow() {
	select {
	case g.kickNow <- struct{}{}:
	default:
	}
}

// Run is the worker of the Grants: it judges the table at each kick and at least
// every 5 s, ages what has timed out, sends the forwards and reports the state.
func (g *Grants) Run(ctx context.Context) {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.kickNow:
			g.pass()
		case <-g.kick:
			if g.h.now().Sub(time.Unix(g.lastPass.Load(), 0)) >= passEvery {
				g.pass()
			}
		case <-t.C:
		}
		g.sendForwards()
		if n++; n%50 == 0 { // once a second
			g.conns.Tick()
			g.table.SweepStep()
			g.expireForwards()
			g.reportState()
			if g.h.now().Unix()-g.lastPass.Load() >= 5 {
				g.pass()
			}
		}
	}
}

// pass is "every served image, at most once in 5 s": it removes the holders that
// have ended, then the connections whose every holder has.
func (g *Grants) pass() {
	g.passMu.Lock()
	defer g.passMu.Unlock()
	g.lastPass.Store(g.h.now().Unix())
	j := g.judger()
	g.table.Sweep(j)
	if ids := g.conns.JudgeConns(j, g.table.Live); len(ids) > 0 {
		g.end(ids, nil)
	}
	g.redecide()
}

type epJudge struct {
	have bool
	hard bool
	rec  *policyv1.EndpointRecord
	id   [16]byte
	auth []netip.Prefix
	peer [16]byte
}

func authorizedOf(rec *policyv1.EndpointRecord) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range rec.Authorized {
		if a, ok := netip.AddrFromSlice(p.GetAddr()); ok {
			if pf, err := a.Unmap().Prefix(int(p.GetBits())); err == nil {
				out = append(out, pf)
			}
		}
	}
	return out
}

// judger is ended(holder) of 4.6: one function for the holders of the table and
// those recorded with a connection, over the image served now. It is called one
// holder at a time by one goroutine (passMu), so its memo needs no lock.
func (g *Grants) judger() grant.Judge {
	sv := g.h.srv.Load()
	if sv == nil {
		return func([]byte, netip.Addr, grant.Outcome, *grant.Holder) bool { return false }
	}
	now := g.h.now()
	applied := sv.img.Seq()
	self := g.facts().Self
	claims := map[[16]byte][16]byte{}
	for _, c := range sv.img.Claims() {
		claims[c.ID] = c.EndpointID
	}
	pt := sv.img.PairTable()
	nodes := map[[16]byte]*policyv1.NodeEntry{}
	for _, n := range pt.GetNodes() {
		if len(n.NodeId) == 16 {
			nodes[[16]byte(n.NodeId)] = n
		}
	}
	memo := map[[16]byte]*epJudge{}
	never := g.h.cfg.NeverProxied
	return func(name []byte, src netip.Addr, out grant.Outcome, h *grant.Holder) bool {
		e := memo[h.Endpoint]
		if e == nil {
			e = &epJudge{}
			if ep, ok := sv.img.ByEndpointID(h.Endpoint); ok {
				rec := ep.Record
				e.have, e.rec, e.id, e.auth = true, rec, identOf(rec), authorizedOf(rec)
				e.hard = rec.AdminState != commonv1.AdminState_ADMIN_STATE_ENABLED && rec.AdminState != commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED
				if p := pairOf(pt, rec.PairId); p != nil && len(p.Primary) == 16 && len(p.Fallback) == 16 {
					switch self {
					case [16]byte(p.Primary):
						e.peer = [16]byte(p.Fallback)
					case [16]byte(p.Fallback):
						e.peer = [16]byte(p.Primary)
					}
				}
			}
			memo[h.Endpoint] = e
		}
		switch {
		case !e.have || e.hard || e.id != h.Ident:
			return true
		case g.h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, h.Endpoint, applied, now),
			g.h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_GRANTS_BY_ENDPOINT, h.Endpoint, applied, now):
			return true
		case h.Claim != ([16]byte{}):
			if claims[h.Claim] != h.Endpoint || !e.rec.LegacyDns ||
				g.h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_CLAIM, h.Claim, applied, now) {
				return true
			}
		case h.Open && e.rec.RequireAuthorizedIps && !inAny(e.auth, src):
			return true
		}
		if h.Origin != ([16]byte{}) {
			n := nodes[h.Origin]
			if n == nil || len(n.SpkiSha256) == 0 || e.peer != h.Origin {
				return true
			}
		}
		if out.Kind == grant.KindRedirect && never != nil {
			if n, err := names.FromCanonicalWire(name); err == nil && never(n) {
				return true
			}
		}
		return false
	}
}

// ---- proxy_state

// reportState tells the agent what dns knows of the proxy: every 10 s and when
// dns_bind or listening changes.
func (g *Grants) reportState() {
	f := g.facts()
	bind := ""
	if f.DNSBind.IsValid() {
		bind = f.DNSBind.String()
	}
	listening := g.Listening()
	k1, k2 := g.conns.Open()
	key := bind + "|" + map[bool]string{true: "1", false: "0"}[listening]
	now := g.h.now()
	g.mu.Lock()
	due := key != g.stateKey || now.Sub(g.stateAt) >= 10*time.Second
	if due {
		g.stateKey, g.stateAt = key, now
	}
	g.mu.Unlock()
	if !due {
		return
	}
	g.send(&sock.Msg{Type: sock.TypeProxyState, ProxyState: &sock.ProxyState{
		DNSBind: bind, Listening: listening, Open: uint32(k1 + k2), Full: g.table.Full()}})
}

// fillSelf adds what depends on the pair of an Endpoint to the node's own addresses:
// the peer's address, and whether answers may carry it (4.4). A peer is in the list
// only when the Endpoint's pair is this node's pair; it is usable when it is not
// proxy_blocked, not revoked (its SPKI empty in the applied table) and not down by
// this node's own probe. Own is left out while the proxy is not listening.
func (g *Grants) fillSelf(s *sharedpolicy.SelfAddrs, sv *Serving, rec *policyv1.EndpointRecord) {
	f := g.facts()
	s.ProxyDown = !g.Listening()
	s.PeerProxyIP, s.PeerProxyUsable = netip.Addr{}, false
	if me := sv.nodes[f.Self]; me != nil {
		s.ProxyBlocked = me.ProxyBlocked
	}
	p := pairOf(sv.img.PairTable(), rec.PairId)
	if p == nil || len(p.Primary) != 16 || len(p.Fallback) != 16 {
		return
	}
	var peer [16]byte
	switch f.Self {
	case [16]byte(p.Primary):
		peer = [16]byte(p.Fallback)
	case [16]byte(p.Fallback):
		peer = [16]byte(p.Primary)
	default:
		return
	}
	pe := sv.nodes[peer]
	if pe == nil {
		return
	}
	if a, ok := netip.AddrFromSlice(pe.ProxyIp); ok {
		s.PeerProxyIP = a.Unmap()
		s.PeerProxyUsable = !pe.ProxyBlocked && len(pe.SpkiSha256) != 0 && !(f.PeerDown != nil && f.PeerDown(peer))
	}
}

// grantSafe is R9 on the cache alone (4.2 step 1), for the tests that pin it.
func (h *Handler) grantSafe(n names.Name, p sharedpolicy.ResolveParams) bool {
	return !(&Grants{h: h}).unsafe(n, p)
}
