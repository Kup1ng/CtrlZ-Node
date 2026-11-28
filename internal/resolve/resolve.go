// Package resolve routes a cache miss to Unbound or to configured upstreams
// (recursive, upstream or hybrid mode), applies the Sanity Gate before a
// result reaches the cache (in the cache package), and tracks upstream health.
// Rule matching is the shared route package; failover and health checks are
// here (p4-nodes.md 7.7, SC 11).
package resolve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/route"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// Exchanger sends one query and returns the reply. *Upstream is one; the local
// Unbound is reached through one (as a plain upstream on loopback), and tests
// use fakes.
type Exchanger interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// Member is one upstream of the node with the interval of its health check.
type Member struct {
	ID    [16]byte
	X     Exchanger
	Every time.Duration // 0 means the default
	// Trusted says the member's DNSSEC verdict is believed: its AD bit and its
	// Extended DNS Errors reach the evaluator. Only the local Unbound and an
	// encrypted upstream the admin marked trusted are (SC 5.11); every other reply
	// is Insecure, whatever its header says.
	Trusted bool
}

// Defaults and bounds of the health check. A check passes with NOERROR or
// NXDOMAIN within probeTimeout (SC 8a.4, Resolve health).
const (
	defaultHealthEvery = 30 * time.Second
	localHealthEvery   = 5 * time.Second
	probeTimeout       = 2 * time.Second
	failsToDown        = 3
	// passesToUp is the 3-in-a-row rule of SC 8a.4 in the other direction: one
	// lucky answer must not bring a broken path back.
	passesToUp = 3
	// probeUDPSize is the EDNS0 payload of a fetch (policy.Resolver.fetch); a
	// check asks the same, so a path that loses DO or large replies fails it.
	probeUDPSize = 1232
	// kickGapSeconds is how many seconds of health_interval_s unit pass between
	// two checks that live errors or a dark verdict ask for. Without it a tenant
	// whose names time out would sample checks at probe round-trip rate, and one
	// lost probe would then hold a healthy member out of its group (p4n-W7-r9-2).
	kickGapSeconds = 5
)

// RouterConfig is what NodeConfig gives the resolve path.
type RouterConfig struct {
	Mode commonv1.ResolveMode
	// Local is the Unbound of this path on its loopback address: the identified
	// one for the shared path, the free one for the free path (SC 5.2a, SC 11).
	Local Member
	// Upstreams are NodeConfig.upstreams, in the hub's order.
	Upstreams []Member
	// Groups maps a group name to the ids of its upstreams, in group order.
	Groups map[string][][16]byte
	Rules  []route.Rule
	Geo    route.GeoSites
	// IntervalUnit stands for one second of health_interval_s; tests shorten it.
	IntervalUnit time.Duration

	// allowNoUpstream lets upstream mode start with no usable upstream: every row
	// of the config was refused. Queries then get ErrNoPath, and Refused and
	// Health still tell the hub why (p4n-W7-r7-2). Only NewRouterFromWire sets it.
	allowNoUpstream bool
}

// Health is the health of one resolve path, for Heartbeat.upstreams.
type Health struct {
	ID      [16]byte
	Healthy bool
	// LatencyMS is the round trip of the latest passed scheduled check in
	// milliseconds (rounded up, at least 1); 0 while the path is down, before its
	// first passed check, and for a refused row.
	LatencyMS uint32
}

// Refusal is an upstream the router did not take, with the sentinel why.
type Refusal struct {
	ID  [16]byte
	Err error
}

type member struct {
	Member
	// fails and passes count consecutive failed and passed scheduled checks;
	// healthy flips at 3 of either (SC 8a.4). Only the member's check loop writes
	// them, and only for scheduled checks.
	fails   atomic.Int32
	passes  atomic.Int32
	healthy atomic.Bool
	// latencyMS is the round trip of the latest passed scheduled check.
	latencyMS atomic.Uint32
	// dark says a check confirmed what the live errors suggested: the member was
	// suspect (liveFails at 3) and its check failed. Only that, not the errors
	// alone, holds a member down between two scheduled checks, so a name that
	// times out at a healthy upstream never demotes it.
	dark atomic.Bool
	// liveFails counts consecutive live transport errors. It orders candidates
	// and nothing else: Health (what F2 and the Heartbeat read) comes from the
	// checks alone (p4n-W7-r6-3), but a path that went dark between two checks
	// must not stay first for 3 x health_interval_s (p4n-W7-r7-1). Any reply
	// from the member and any passed check reset it.
	liveFails atomic.Int32
	// replies counts every reply the member has given to a live query. A live
	// error counts toward liveFails only when no reply came while the query was
	// out: a member that answers other names is not on a dark path, and a name
	// whose servers never answer (picked by any tenant) says nothing about the
	// path (p4n-W7-r8-4). A counter, not a timestamp, because the clock of the
	// build machines steps in tens of milliseconds.
	replies atomic.Uint64
	// kick asks the member's check loop for an immediate probe.
	kick chan struct{}
}

// preferred says whether the member goes ahead of the others in the order: the
// scheduled checks hold it up and no check has confirmed it dark.
func (m *member) preferred() bool {
	return m.healthy.Load() && !m.dark.Load()
}

// Router picks a path for a query and walks it in order.
type Router struct {
	mode   commonv1.ResolveMode
	local  *member
	ups    []*member
	byID   map[[16]byte]*member
	groups map[string][]*member
	rules  []route.Rule
	geo    route.GeoSites
	unit   time.Duration
	// kickGap is the least time between the end of one kicked check or recheck
	// and the start of the next one.
	kickGap time.Duration

	refused []Refusal
	owned   []interface{ Close() error }

	stop chan struct{}
	wg   sync.WaitGroup
}

// ErrNoPath is returned when every candidate failed.
var ErrNoPath = errors.New("resolve: no upstream answered")

// NewRouter builds a Router from members that already exist and starts its
// health checks. Close stops them.
func NewRouter(cfg RouterConfig) (*Router, error) {
	if cfg.Mode < commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE || cfg.Mode > commonv1.ResolveMode_RESOLVE_MODE_HYBRID {
		return nil, fmt.Errorf("resolve: bad mode %d", cfg.Mode)
	}
	if cfg.Local.X == nil && cfg.Mode != commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM {
		return nil, errors.New("resolve: a mode that uses Unbound needs it")
	}
	if len(cfg.Upstreams) == 0 && cfg.Mode == commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM && !cfg.allowNoUpstream {
		return nil, errors.New("resolve: upstream mode needs an upstream")
	}
	if cfg.IntervalUnit <= 0 {
		cfg.IntervalUnit = time.Second
	}
	r := &Router{mode: cfg.Mode, unit: cfg.IntervalUnit, kickGap: kickGapSeconds * cfg.IntervalUnit, rules: cfg.Rules, geo: cfg.Geo, byID: map[[16]byte]*member{}, groups: map[string][]*member{}, stop: make(chan struct{})}
	if cfg.Local.X != nil {
		r.local = newMember(cfg.Local)
		r.local.Trusted = true // the node's own validating resolver
		if r.local.Every == 0 {
			r.local.Every = localHealthEvery
		}
	}
	for _, m := range cfg.Upstreams {
		mm := newMember(m)
		r.ups = append(r.ups, mm)
		r.byID[m.ID] = mm
	}
	for name, ids := range cfg.Groups {
		for _, id := range ids {
			if m, ok := r.byID[id]; ok {
				r.groups[name] = append(r.groups[name], m)
			}
		}
	}
	// Only the paths the mode uses are checked and reported: a probe of an unused
	// Unbound or upstream is traffic for nothing.
	var checked []*member
	if cfg.Mode != commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE {
		checked = append(checked, r.ups...)
	}
	if r.local != nil && cfg.Mode != commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM {
		checked = append(checked, r.local)
	}
	for _, m := range checked {
		r.wg.Add(1)
		go r.check(m)
	}
	return r, nil
}

func newMember(m Member) *member {
	mm := &member{Member: m, kick: make(chan struct{}, 1)}
	mm.healthy.Store(true)
	return mm
}

// NewRouterFromWire builds the upstreams of a NodeConfig through NewUpstream
// (the only constructor, T-550) and a Router over them. An upstream NewUpstream
// refuses, a via_location one included (P4b), is left out and listed by
// Refused: one bad row must not stop every other query of the node, and the hub
// sees it as an unhealthy path. roots replaces the system roots for the TLS
// kinds (tests); nil in production.
func NewRouterFromWire(cfg *hubv1.NodeConfig, local Member, geo route.GeoSites, unit time.Duration) (*Router, error) {
	rc := RouterConfig{Mode: cfg.GetMode(), Local: local, Geo: geo, IntervalUnit: unit, Groups: map[string][][16]byte{}}
	var built []*Upstream
	var refused []Refusal
	for _, u := range cfg.GetUpstreams() {
		id, ok := to16(u.GetId())
		if !ok {
			return nil, errors.New("resolve: upstream id")
		}
		uc, err := ConfigFromWire(u)
		var up *Upstream
		if err == nil {
			up, err = NewUpstream(uc)
		}
		if err != nil {
			refused = append(refused, Refusal{ID: id, Err: err})
			continue
		}
		built = append(built, up)
		rc.Upstreams = append(rc.Upstreams, Member{ID: id, X: up, Every: time.Duration(u.GetHealthIntervalS()) * time.Second,
			// A plain udp upstream cannot be trusted whatever the row says: nothing
			// protects its AD bit on the wire (SC 5.11).
			Trusted: u.GetTrusted() && u.GetKind() != commonv1.UpstreamKind_UPSTREAM_KIND_UDP})
	}
	for _, g := range cfg.GetGroups() {
		for _, raw := range g.GetUpstreamIds() {
			if id, ok := to16(raw); ok {
				rc.Groups[g.GetName()] = append(rc.Groups[g.GetName()], id)
			}
		}
	}
	for _, rr := range cfg.GetRules() {
		pr, err := route.ParseRule(rr.GetOrder(), rr.GetMatchType(), rr.GetMatchValue(), rr.GetGroup(), rr.GetFinalDefault())
		if err != nil {
			return nil, fmt.Errorf("resolve: rule %d: %w", rr.GetOrder(), err)
		}
		rc.Rules = append(rc.Rules, pr)
	}
	// A config with upstream rows that were all refused still gets a Router, so
	// the refusals are reported; a config with no row at all is an error.
	rc.allowNoUpstream = len(refused) > 0
	r, err := NewRouter(rc)
	if err != nil {
		for _, b := range built {
			_ = b.Close()
		}
		return nil, err
	}
	r.refused = refused
	for _, b := range built {
		r.owned = append(r.owned, b)
	}
	// An upstream that was refused is unhealthy as far as the hub is concerned.
	return r, nil
}

func to16(b []byte) ([16]byte, bool) {
	var a [16]byte
	if len(b) != 16 {
		return a, false
	}
	copy(a[:], b)
	return a, true
}

// Refused lists the upstreams that were not built, with the reason.
func (r *Router) Refused() []Refusal { return r.refused }

// Mode is the node's mode.
func (r *Router) Mode() commonv1.ResolveMode { return r.mode }

// Close stops the health checks and closes the upstreams the router built. It
// does not close the Local member or any Member it was handed.
func (r *Router) Close() {
	select {
	case <-r.stop:
		return
	default:
		close(r.stop)
	}
	r.wg.Wait()
	for _, c := range r.owned {
		_ = c.Close()
	}
}

// Route names the path a query takes, for the cache key (SC 6): empty for the
// node's default path, "g:<group>" when a hybrid rule matched. A given name and
// type always has the same route, so the key is stable.
func (r *Router) Route(n *names.Name, qtype uint16) string {
	if r.mode != commonv1.ResolveMode_RESOLVE_MODE_HYBRID {
		return ""
	}
	if g, ok := route.Match(r.rules, n, qtype, r.geo); ok {
		return "g:" + g
	}
	return ""
}

// candidates is the ordered list to try for a route, and how many of its first
// members are preferred ones: the rest is a tail of members the checks or live
// queries hold down, which share one slice of the deadline between them.
func (r *Router) candidates(rt string) ([]*member, int) {
	switch r.mode {
	case commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE:
		return []*member{r.local}, 1
	case commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM:
		return healthyFirst(r.ups)
	}
	// Hybrid: the group's preferred upstreams in order, then the node's default.
	var out []*member
	if len(rt) > 2 {
		for _, m := range r.groups[rt[2:]] {
			if m.preferred() {
				out = append(out, m)
			}
		}
	}
	return append(out, r.local), len(out) + 1
}

// healthyFirst keeps the order inside each class and puts the members that are
// down by their checks, or failing live queries, last: when all of them are
// down the query is still tried, so a query is answered as soon as a path works,
// ahead of the check that marks it up. It also returns the size of the first
// class.
func healthyFirst(in []*member) ([]*member, int) {
	out := make([]*member, 0, len(in))
	for _, m := range in {
		if m.preferred() {
			out = append(out, m)
		}
	}
	np := len(out)
	for _, m := range in {
		if !m.preferred() {
			out = append(out, m)
		}
	}
	return out, np
}

// Exchange resolves req along its route. It fails over to the next candidate on
// a transport error and on SERVFAIL or REFUSED, and returns the last reply when
// none does better. The query is never changed.
func (r *Router) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	if len(req.Question) != 1 {
		return nil, "", ErrBadQuery
	}
	rt := ""
	if qn, ok := questionName(req.Question[0].Name); ok {
		rt = r.Route(&qn, req.Question[0].Qtype)
	}
	var last *dns.Msg
	cands, npref := r.candidates(rt)
	for i, m := range cands {
		if ctx.Err() != nil {
			break
		}
		// The deadline is shared among the preferred members still ahead, and the
		// tail of held-down members counts as one share: a healthy member must not
		// lose time to members the checks already call down (p4n-W7-r8-3).
		left := len(cands) - i
		if i < npref {
			left = npref - i
			if len(cands) > npref {
				left++
			}
		}
		cctx, cancel := slice(ctx, left)
		seen := m.replies.Load()
		resp, err := m.X.Exchange(cctx, req)
		cancel()
		if err != nil {
			// A caller that gave up says nothing about the member, and neither does
			// a failure while the member was answering other queries.
			if ctx.Err() == nil && m.replies.Load() == seen && m.liveFails.Add(1) >= failsToDown {
				// The path may be dark or the name may be the problem: a probe of a
				// random name tells which, so the member is not held down until the
				// next scheduled check on the word of a name a tenant picked. Every
				// error from the third on asks; the check loop runs at most one check
				// per kickGap, so asking is cheap and traffic cannot set the rate.
				select {
				case m.kick <- struct{}{}:
				default:
				}
			}
			continue
		}
		m.replies.Add(1)
		m.liveFails.Store(0)
		m.dark.Store(false)
		resp = m.vouch(resp)
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			last = resp
			continue
		}
		return resp, rt, nil
	}
	if last != nil {
		return last, rt, nil
	}
	return nil, rt, ErrNoPath
}

// questionName parses the presentation name of a question through the wire
// form, so \DDD and \. escapes mean what they say. The cache key's route is
// derived from the wire name by the caller (policy.Resolver.Lookup), and
// names.FromString does not decode escapes: a label of 20 bytes of 0x80 renders
// as more than 63 characters and would make the two routes differ, sending the
// query past its rule's group while the answer is stored under the group's key
// (p4n-W7-r3-1).
func questionName(s string) (names.Name, bool) {
	var buf [256]byte
	n, err := dns.PackDomainName(dns.Fqdn(s), buf[:], 0, nil, false)
	if err != nil {
		return names.Name{}, false
	}
	qn, err := names.FromCanonicalWire(buf[:n])
	return qn, err == nil
}

// scheduled records the result of a scheduled health check in Health, by the
// 3-in-a-row rule of SC 8a.4: a lone result changes nothing, so a lost packet
// does not withdraw a node and one lucky answer does not bring a broken path
// back. Only scheduled checks call it. A live reply is no pass (a SERVFAIL from
// an Unbound that lost its path to the authorities is a reply too, and
// serve-expired keeps cached names answering), a few live timeouts on a quiet
// node are no outage, and a kicked check must not let traffic speed up or put
// off an F2: F2 reads Health (SC 8a.4, 11; p4n-W7-r6-3).
func (m *member) scheduled(ok bool, rtt time.Duration) {
	if ok {
		m.fails.Store(0)
		m.latencyMS.Store(max(uint32((rtt+time.Millisecond-1)/time.Millisecond), 1))
		if m.passes.Add(1) >= passesToUp {
			m.healthy.Store(true)
		}
		return
	}
	m.passes.Store(0)
	if m.fails.Add(1) >= failsToDown {
		m.healthy.Store(false)
	}
}

// order records what a check, scheduled or kicked, says about the order. seen is
// the member's reply counter from before the check began. A pass ends any
// suspicion. A failure makes a suspect member (live errors at the threshold)
// dark, unless the member answered a live query while the check was out: a path
// that answers is not dark, whatever one probe said. It does nothing to a member
// that is not suspect: the failing check of a healthy-looking path is Health's
// business, not the order's.
func (m *member) order(ok bool, seen uint64) {
	if ok {
		m.liveFails.Store(0)
		m.dark.Store(false)
		return
	}
	if m.liveFails.Load() < failsToDown || m.replies.Load() != seen {
		return
	}
	// Set, then look again: a reply stores its counter before it clears dark, so
	// either this look sees the reply and undoes the set, or the reply's clear
	// comes after the set. A member that has just answered is never left dark.
	m.dark.Store(true)
	if m.replies.Load() != seen {
		m.dark.Store(false)
	}
}

// report is the member's entry of Router.Health.
func (m *member) report(id [16]byte) Health {
	h := Health{ID: id, Healthy: m.healthy.Load()}
	if h.Healthy {
		h.LatencyMS = m.latencyMS.Load()
	}
	return h
}

// Health lists the health of the local Unbound (under the reserved id) and of
// each upstream, in the order of the config.
func (r *Router) Health() []Health {
	var out []Health
	if r.local != nil && r.mode != commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM {
		out = append(out, r.local.report(wire.LocalUnboundID()))
	}
	if r.mode != commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE {
		for _, m := range r.ups {
			out = append(out, m.report(m.ID))
		}
		for _, f := range r.refused {
			out = append(out, Health{ID: f.ID, Healthy: false})
		}
	}
	return out
}

// check runs the health check of one member until Close.
func (r *Router) check(m *member) {
	defer r.wg.Done()
	base := m.Every
	if base <= 0 {
		base = defaultHealthEvery
		if m == r.local {
			base = localHealthEvery
		}
	}
	every := time.Duration(base/time.Second) * r.unit
	if every <= 0 {
		every = r.unit
	}
	// The first check is not waited for a whole interval: a path that starts
	// dead is found at once.
	t := time.NewTimer(0)
	defer t.Stop()
	// recheck brings a dark member back within kickGap of its recovery instead of
	// at the next scheduled check: a dark member gets no live replies that could
	// clear it, so without it one unlucky verdict would cost a whole interval.
	recheck := time.NewTimer(time.Hour)
	recheck.Stop()
	defer recheck.Stop()
	var nextKick time.Time
	i := 0
	for {
		// A kicked check runs between scheduled ones and touches neither the timer
		// nor Health; the loop is one goroutine, so a member never has two checks
		// out, and kicks closer than kickGap to the last check are dropped (the
		// next live error asks again).
		var sched bool
		select {
		case <-r.stop:
			return
		case <-t.C:
			sched = true
		case <-m.kick:
			if m.dark.Load() || time.Now().Before(nextKick) {
				continue
			}
		case <-recheck.C:
		}
		seen := m.replies.Load()
		ok, rtt := r.probeOnce(m, tlds[i%len(tlds)])
		i++
		verdict := ok
		if !ok && !m.dark.Load() && m.liveFails.Load() >= failsToDown && m.replies.Load() == seen {
			// A suspect member's failed check is confirmed at once by a second one,
			// so one lost packet or one slow answer cannot make a healthy member
			// dark. Dark needs both to fail.
			verdict, _ = r.probeOnce(m, tlds[i%len(tlds)])
			i++
		}
		m.order(verdict, seen)
		if sched {
			m.scheduled(ok, rtt)
			t.Reset(every) // the interval runs from the end of the scheduled check
		}
		if !sched {
			// The gap runs from the end of a kicked check or a recheck only. A
			// scheduled check, which every new Router starts with, must not delay
			// the first kick by kickGap: that made a blackholed member go dark up to
			// kickGap + 4 s after its third error (p4n-W7-r10-1). Consecutive kicks
			// stay kickGap apart, and scheduled checks add one per interval.
			nextKick = time.Now().Add(r.kickGap)
		}
		if !recheck.Stop() {
			select {
			case <-recheck.C:
			default:
			}
		}
		if m.dark.Load() {
			recheck.Reset(r.kickGap)
		}
	}
}

var tlds = [...]string{"com", "net", "org"}

// probeOnce runs one check of a member and says whether it passed and how long
// it took on the monotonic clock. A stopped router does not wait out a probe.
func (r *Router) probeOnce(m *member, tld string) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	go func() {
		select {
		case <-r.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	start := time.Now()
	ok := probe(ctx, m.X, tld)
	return ok, time.Since(start)
}

// probe asks for a name nobody has asked before, so no cache can answer it
// (SC 8a.4 Resolve health). NOERROR and NXDOMAIN pass. It asks as a fetch does,
// with DO=1 and a 1232-byte payload: a path that loses DNSSEC records or large
// replies (a middlebox dropping EDNS or fragments) must fail the check that
// confirms what live misses suggest, not pass it on a bare query.
func probe(ctx context.Context, x Exchanger, tld string) bool {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false
	}
	q := new(dns.Msg)
	q.SetQuestion(hex.EncodeToString(b[:])+"."+tld+".", dns.TypeA)
	q.SetEdns0(probeUDPSize, true)
	resp, err := x.Exchange(ctx, q)
	return err == nil && resp != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError)
}

// vouch removes the DNSSEC claims of a reply from a member whose verdict is not
// believed: the AD bit, and the Extended DNS Errors that would make the answer
// Bogus. Without it a plain or untrusted upstream could mark forged data Secure,
// which is cached without a tenant and served with AD to every client that asks
// for it. The reply is copied only when something changes, so a trusted or
// clean reply costs nothing.
func (m *member) vouch(resp *dns.Msg) *dns.Msg {
	if m.Trusted || resp == nil {
		return resp
	}
	opt := resp.IsEdns0()
	hasEDE := false
	if opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_EDE); ok {
				hasEDE = true
			}
		}
	}
	if !resp.AuthenticatedData && !hasEDE {
		return resp
	}
	c := resp.Copy()
	c.AuthenticatedData = false
	if hasEDE {
		o := c.IsEdns0()
		kept := o.Option[:0]
		for _, x := range o.Option {
			if _, ok := x.(*dns.EDNS0_EDE); !ok {
				kept = append(kept, x)
			}
		}
		o.Option = kept
	}
	return c
}

// slice limits one candidate to its share of what is left of the caller's
// deadline, so a member that stops answering (packets dropped, the usual way an
// international upstream is filtered) cannot use the whole fetch deadline and
// leave nothing for the next one (p4n-W7-r7-1). The last candidate gets all that
// is left. A context with no deadline is passed through.
func slice(ctx context.Context, left int) (context.Context, context.CancelFunc) {
	dl, ok := ctx.Deadline()
	if !ok || left <= 1 {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, time.Now().Add(time.Until(dl)/time.Duration(left)))
}
