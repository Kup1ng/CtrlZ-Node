package dns

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/sysnames"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
)

// Config is what a Handler needs from its caller.
type Config struct {
	// Resolver is the identified path's lookup: a policy.Resolver over the shared
	// cache segment and the identified Unbound. The free path has its own.
	Resolver sharedpolicy.Resolver
	Reporter Reporter
	// Profiles opens profile blobs for the Endpoints of each image.
	Profiles *policy.Profiles
	// NeverProxied is the predicate of D42 (T-524): P2's noredirect.Name over the
	// catalog rows the node holds. It is required: a node that decides without it
	// would proxy names it must never proxy.
	NeverProxied func(names.Name) bool
	Catalog      *sharedpolicy.Catalog
	Geo          sharedpolicy.GeoView
	// Self gives the node's own addresses for the PROXY_IPs of a Block or Redirect
	// answer; nil means none.
	Self   func() sharedpolicy.SelfAddrs
	Free   FreePath
	Grants GrantSink
	// CachedA gives the true A addresses the cache holds for a name, with no
	// lookup (policy.Resolver.CachedA). Optional: nil means the cache is not asked,
	// and the Grant is written (the nftables guard remains the mandatory control).
	CachedA func(names.Name, sharedpolicy.ResolveParams) ([]netip.Addr, bool)
	Now     func() time.Time
}

// Handler is the query path of SC 5.2, steps 2 to 10. It is a listen.Handler. The
// listener has done step 1.
type Handler struct {
	cfg Config
	now func() time.Time

	set atomic.Pointer[Settings]
	srv atomic.Pointer[Serving]
	zs  atomic.Pointer[ZoneState]
	rev Revocations

	verify *verifyTable
	seen   *seenFilter
	// defaultStack is the stack with no profile in force, which PostDefault is
	// (see postDefault). It is never changed, so every query shares it.
	defaultStack *sharedpolicy.Stack

	hard, auth, revoked, degraded atomic.Uint64
}

// New builds a Handler. It serves nothing until SetSettings and SetImage have
// been called; until then every query is REFUSED.
func New(cfg Config) (*Handler, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("dns: no resolver")
	}
	if cfg.NeverProxied == nil {
		return nil, errors.New("dns: no NeverProxied predicate (D42, T-524)")
	}
	if cfg.Reporter == nil {
		cfg.Reporter = nopReporter{}
	}
	h := &Handler{cfg: cfg, now: cfg.Now, verify: newVerifyTable(), seen: newSeenFilter(), defaultStack: sharedpolicy.NewStack(nil, nil, nil)}
	if h.now == nil {
		h.now = time.Now
	}
	return h, nil
}

// SetSettings swaps in the NodeConfig-derived settings.
func (h *Handler) SetSettings(s *Settings) { h.set.Store(s) }

// SetImage swaps in a new serving image, with its claims and compiled Endpoints.
func (h *Handler) SetImage(img Image) {
	h.srv.Store(NewServing(img, h.cfg.Profiles, h.srv.Load()))
}

// SetZoneState hands dns the table in use and the node's local view (the agent
// does, over the socket). Nil, which is also the state before the first call,
// means no table is in use: the zone names that need one are REFUSED (SC 8a.5).
func (h *Handler) SetZoneState(z *ZoneState) { h.zs.Store(z) }

// Revocations is the set of priority revocations in force.
func (h *Handler) Revocations() *Revocations { return &h.rev }

// Verify returns the handler of GET /v, for listen.Config.Verify.
func (h *Handler) Verify() listen.VerifyHandler { return verifyHandler{h: h} }

// Counters returns the node-local refusal counts.
func (h *Handler) Counters() Counters {
	return Counters{HardDisabled: h.hard.Load(), RequireAuth: h.auth.Load(), Revoked: h.revoked.Load(), Degraded: h.degraded.Load()}
}

// result is what a step produced. answered is true for a query the node served
// (an answer or a zone answer), false for a refusal, which creates no activity.
type result struct {
	rep      listen.Reply
	answered bool
}

func ans(m *dns.Msg) result { return result{rep: listen.Reply{Msg: m}, answered: true} }
func refuse(m *dns.Msg) result {
	return result{rep: listen.Reply{Msg: m}}
}

// ServeDNS implements listen.Handler.
func (h *Handler) ServeDNS(ctx context.Context, req *listen.Request) listen.Reply {
	set, sv := h.set.Load(), h.srv.Load()
	q := req.Msg
	if set == nil || sv == nil {
		return listen.Reply{Msg: rcodeMsg(q, dns.RcodeRefused)}
	}
	// A query that is not a plain IN question is answered with its error only
	// after identity and 4b have had their say: a DoH request that names nobody
	// is 404, a refused source gets the refusal of its transport (a silent drop on
	// Plain DNS, 403 on DoH), and the dns_ip of a node is dropped (SC 5.2a (b)),
	// whatever the shape of the message (p4n-W7-r5-3). The shape decides nothing
	// about identity, so no tenant data depends on the order.
	shape := shapeRcode(q)
	var qn names.Name
	if shape < 0 {
		var err error
		if qn, err = policy.NameFromDNS(q.Question[0].Name); err != nil {
			shape = dns.RcodeFormatError
		}
	}
	now := h.now()

	id := h.identify(req, set, sv, now)
	if id.httpStatus != 0 {
		// Before step 2: a DoH request that names nobody is 404 (SC 3.3).
		return listen.Reply{Status: id.httpStatus}
	}
	g := h.gate(&id, req, sv, now)
	if shape >= 0 {
		switch {
		case id.known() && g.refused():
			return h.refusal(req, g).rep
		case !id.known() && !id.claimNoRecord && (req.Transport == listen.UDP || req.Transport == listen.TCP) && sv.nodeIPs[req.Source.Addr().Unmap()]:
			return listen.Reply{Drop: true}
		}
		return listen.Reply{Msg: rcodeMsg(q, shape)}
	}
	h.learn(req, &id, &g, now)

	res := h.route(ctx, req, set, sv, &id, g, qn, now)
	if res.answered && id.st != nil && !g.refused() {
		h.activity(req, &id, now)
	}
	if res.rep.Msg != nil && req.Transport == listen.UDP && !res.rep.Msg.Truncated {
		res.rep.Msg = fitUDP(q, res.rep.Msg)
	}
	return res.rep
}

// shapeRcode is the error for a message that is not one IN question of opcode
// QUERY, or -1 when it is one.
func shapeRcode(q *dns.Msg) int {
	switch {
	case q.Opcode != dns.OpcodeQuery:
		return dns.RcodeNotImplemented
	case len(q.Question) != 1:
		return dns.RcodeFormatError
	case q.Question[0].Qclass != dns.ClassINET:
		return dns.RcodeRefused
	}
	return -1
}

// route is steps 2 to 10 in order.
func (h *Handler) route(ctx context.Context, req *listen.Request, set *Settings, sv *Serving, id *ident, g gateResult, qn names.Name, now time.Time) result {
	q := req.Msg
	qtype := q.Question[0].Qtype

	// Step 2: system names. Panel and admin hostnames get the true answer through
	// the identified resolver, never policy (T-040).
	if e, ok := set.matcher.Lookup(&qn, qtype, set.isolated); ok {
		if r, handled := h.stepSystem(ctx, req, set, sv, id, g, e, qn, now); handled {
			return r
		}
	}

	// Step 3: the zone. HostResolver, HostMalformed, the apex and the reserved
	// names need no identity on any transport.
	// qn.String() writes every byte outside [a-z0-9_-] as a backslash and three digits, so a ":port" in a
	// qname never reaches ParseHost's port stripping (p4n-W7-r3-2).
	host := identity.ParseHost(qn.String(), set.zones)
	if m, ok := h.answerZone(q, qn, set, sv, host); ok {
		return ans(m)
	}

	// Step 4a: verify names, before stack selection, for an identified query and
	// an unidentified one alike.
	if host.Kind == identity.HostVerify {
		return h.stepVerify(req, set, id, g, host.Label, now)
	}

	// Step 4: identity. Unknown is REFUSED, or what Plain DNS's 5.2a decides.
	// myip (SC 5.2 step 3, T-048): it answers only an identified query that 4b
	// lets through, and only with the source address, so it waits for both. The
	// free path never answers it: a source with no identity gets the drop of
	// SC 5.2a (b) or REFUSED.
	isMyIP := host.Kind == identity.HostReserved && host.Name == "myip"
	if !id.known() {
		return h.noIdentity(ctx, req, sv, id, FreeQuery{Name: qn, QType: qtype}, !isMyIP)
	}

	// Step 4b.
	if g.refused() {
		return h.refusal(req, g)
	}
	if id.claim != nil {
		if req.Transport == listen.UDP && !req.Validated {
			// An unvalidated UDP query of a claim that no validated query has
			// refreshed in the last hour is answered TC=1 with no records, so a
			// router that sends no cookie keeps the claim alive through its TCP
			// retry, and spoofed UDP cannot (p4-nodes.md 7.6).
			lv := id.claim.lastValidated.Load()
			if lv == 0 || now.Unix()-lv > 3600 {
				return refuse(listen.Truncated(q))
			}
		}
		if req.Validated {
			id.claim.lastValidated.Store(now.Unix())
		}
	}
	if isMyIP {
		return h.stepMyIP(q, id, req.Source.Addr())
	}

	in := h.input(req, id, qn, qtype, now)
	if id.st.degraded || id.st.rec.AdminState == commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED {
		// soft_disabled and the degraded mode of SC 9.7 item 7: no profile, no
		// Grant, the cache, the default resolve and the Sanity Gate stay, and the
		// answer is PostDefault.
		if id.st.degraded {
			h.degraded.Add(1)
		}
		return ans(fromAnswer(q, qn, h.postDefault(ctx, in, qtype).Answer))
	}

	// Steps 5 to 9: SelectStack, Pre, the cache and router, Post.
	stack, _ := sharedpolicy.SelectStack(id.st.view, policy.ClientHash(id.client), now.Unix())
	env := h.env()
	final, pre := sharedpolicy.DecideWithPre(ctx, in, stack, &env, h.cfg.Resolver)
	if final.WantGrant && h.cfg.Grants != nil && h.grantSafe(qn, pre.Params) {
		h.cfg.Grants.Grant(GrantRequest{Endpoint: id.st.id, Source: req.Source.Addr(), Name: qn, Final: &final})
	}
	return ans(fromAnswer(q, qn, final.Answer))
}

func (h *Handler) env() sharedpolicy.Env {
	env := sharedpolicy.Env{Cat: h.cfg.Catalog, Geo: h.cfg.Geo, NeverProxied: h.cfg.NeverProxied}
	if h.cfg.Self != nil {
		env.Self = h.cfg.Self()
	}
	return env
}

// input builds the evaluator's Input for a query.
func (h *Handler) input(req *listen.Request, id *ident, qn names.Name, qtype uint16, now time.Time) *sharedpolicy.Input {
	q := req.Msg
	in := &sharedpolicy.Input{
		Name: qn, QType: qtype, Now: now.Unix(), Src: req.Source.Addr().Unmap(),
		Protocol: evalProtocol(req.Transport),
		CD:       q.CheckingDisabled, AD: q.AuthenticatedData,
	}
	if opt := q.IsEdns0(); opt != nil {
		in.DO = opt.Do()
	}
	if id != nil && id.st != nil {
		in.EndpointID = id.st.id
	}
	if h.cfg.Geo != nil {
		in.SrcCountry = h.cfg.Geo.Country(in.Src)
	}
	return in
}

// postDefault is the answer of every path that resolves with no policy
// (SC 5.1 PostDefault): the DNSSEC shaping of 5.11 with EffectiveCD equal to the
// client's CD, the failure rule of 5.12 and the row Bypass, default, no match of
// section 7. The shared module has no PostDefault yet, so it is the evaluator's
// own Pre and Post over a stack with no profile in force, which is exactly that
// path: nothing in it can match a rule, a filter or a service.
func (h *Handler) postDefault(ctx context.Context, in *sharedpolicy.Input, qtype uint16) sharedpolicy.Final {
	var ans *sharedpolicy.TrueAnswer
	if qtype != sharedpolicy.TypeANY { // ANY is never resolved: HINFO (RFC 8482)
		var err error
		ans, err = h.cfg.Resolver.Lookup(ctx, in.Name, qtype, sharedpolicy.ResolveParams{EffectiveCD: in.CD})
		if err != nil || ans == nil {
			ans = &sharedpolicy.TrueAnswer{Failed: true, RCode: sharedpolicy.RCodeServFail}
		}
	} else {
		ans = &sharedpolicy.TrueAnswer{Chain: []names.Name{in.Name}}
	}
	st := h.defaultStack
	env := h.env()
	pre := sharedpolicy.Pre(in, st, &env)
	return sharedpolicy.Post(ctx, in, st, &env, &pre, ans, h.cfg.Resolver)
}

// stepSystem is step 2 (SC 8). handled is false when the row does not answer
// this query and the query goes on to step 3 as if no row matched.
func (h *Handler) stepSystem(ctx context.Context, req *listen.Request, set *Settings, sv *Serving, id *ident, g gateResult, e sysnames.Entry, qn names.Name, now time.Time) (result, bool) {
	q := req.Msg
	qtype := q.Question[0].Qtype
	asked := q.Question[0].Name
	switch e.Outcome {
	case sysnames.OutcomeNXDomain:
		m := newReply(q, true)
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{syntheticSOA(qn, asked, e.TTL)}
		return ans(m), true
	case sysnames.OutcomeLocal:
		m := newReply(q, true)
		for _, r := range e.Records {
			if rr := rrOf(qn, r.Type, e.TTL, r.RData); rr != nil {
				rr.Header().Name = asked
				m.Answer = append(m.Answer, rr)
			}
		}
		if len(m.Answer) == 0 {
			m.Ns = []dns.RR{syntheticSOA(qn, asked, e.TTL)}
		}
		return ans(m), true
	}

	// true_answer and isolated_synth rows.
	//
	// A source that 4b will refuse is held to what a source with no identity
	// gets, never more: a wildcard row lets it pick a name that misses every
	// cache, and the identified Unbound is the one the resolve health check
	// shares (SC 8a.9 F2), so a leaked rid or a hard_disabled Endpoint must not
	// turn into a free random-name resolver. It gets the 4b refusal for a wildcard
	// row, and an exact row only for A, AAAA and HTTPS with CD clear (p4n-W7-r3-4).
	refusedID := id.known() && g.refused()
	if refusedID && strings.HasPrefix(e.Pattern, "*") {
		return h.refusal(req, g), true
	}
	if !id.known() || refusedID {
		// A row with a wildcard lets the source pick a name that misses every cache,
		// so with no identity it is a free query on Plain DNS and REFUSED elsewhere
		// (SC 8, Queries with no identity). Shared 1.4.0 has no Entry.Wildcard, so it
		// is read from the pattern: a row that matched a name it does not list itself
		// has a star in it.
		if !refusedID && strings.HasPrefix(e.Pattern, "*") {
			return h.noIdentity(ctx, req, sv, id, h.wildcardFreeQuery(req, set, e, qn), true), true
		}
		if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeHTTPS {
			return result{}, false // as if no row matched
		}
	}
	if e.Outcome == sysnames.OutcomeSynthDNSIP {
		return ans(h.synthDNSIP(q, qn, set, e.TTL)), true
	}
	in := h.input(req, id, qn, qtype, now)
	if !id.known() || refusedID {
		in.CD = false // an unidentified lookup is made with CD clear
	}
	f := h.postDefault(ctx, in, qtype)
	if f.Answer.RCode == sharedpolicy.RCodeServFail && e.FallbackSynth {
		// Android's validation name must keep passing while the resolver is down.
		return ans(h.synthDNSIP(q, qn, set, e.TTL)), true
	}
	return ans(fromAnswer(q, qn, f.Answer)), true
}

// synthDNSIP is the answer of an isolated_synth row: A is this node's own
// DNS_IP, everything else NODATA (SC 8).
func (h *Handler) synthDNSIP(q *dns.Msg, qn names.Name, set *Settings, ttl uint32) *dns.Msg {
	m := newReply(q, true)
	qs := q.Question[0]
	if qs.Qtype == dns.TypeA && set.selfIP.Is4() {
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: qs.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: set.selfIP.AsSlice()}}
		return m
	}
	m.Ns = []dns.RR{syntheticSOA(qn, qs.Name, ttl)}
	return m
}

func syntheticSOA(qn names.Name, asked string, ttl uint32) dns.RR {
	r := sharedpolicy.SyntheticSOA(qn, ttl)
	rr, err := policy.RRToDNS(r)
	if err != nil {
		return nil
	}
	rr.Header().Name = asked
	return rr
}

// stepVerify is step 4a. A is the node's own address with TTL 0, a UDP TXT query
// gets the proof code, and every other type NODATA. The label goes into the LRU
// that GET /v reads, and a proof query is reported under the conditions of 7.6.
func (h *Handler) stepVerify(req *listen.Request, set *Settings, id *ident, g gateResult, label string, now time.Time) result {
	q := req.Msg
	qs := q.Question[0]
	zn, _ := set.zoneFor(mustName(qs.Name))

	// Only a query that has an identity and that 4b lets through may write the
	// identified table; a refused one reads as unidentified, as it would for any
	// stranger (p4n-W7-r4-2).
	if ok := id.rid != "" && !g.refused(); ok {
		h.verify.note(label, verifyEntry{rid: id.rid, client: id.client, proto: protocolOf(req.Transport), identified: true, at: now})
	} else {
		h.verify.note(label, verifyEntry{proto: protocolOf(req.Transport), at: now})
	}
	h.proof(req, id, label, qs.Qtype, now)

	if qs.Qtype == dns.TypeTXT && req.Transport == listen.UDP && set.hasProofKey() {
		code := identity.ProofCode(set.proofKey, label, req.Source.Addr().Unmap())
		m := authMsg(q)
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: qs.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{code}}}
		return ans(m)
	}
	if set.selfIP.IsValid() {
		if m, ok := addrAnswer(q, 0, set.selfIP); ok {
			return ans(m)
		}
	}
	return ans(nodataMsg(q, zn))
}

func mustName(s string) names.Name {
	n, _ := policy.NameFromDNS(s)
	return n
}

// stepMyIP answers myip.<zone> (T-048): the source address for an Endpoint with
// Expose IP, NODATA for one without. The answer is TTL 0.
func (h *Handler) stepMyIP(q *dns.Msg, id *ident, src netip.Addr) result {
	qs := q.Question[0]
	zn := mustName(qs.Name)
	if set := h.set.Load(); set != nil {
		if z, ok := set.zoneFor(zn); ok {
			zn = z
		}
	}
	if id.st.rec.ExposeIp {
		if m, ok := addrAnswer(q, 0, src); ok {
			return ans(m)
		}
	}
	return ans(nodataMsg(q, zn))
}

// refusal is the answer to a query 4b stops: Plain DNS is dropped without a
// reply, DoT and DoQ get REFUSED, DoH and DoH3 HTTP 403. Only a counter records
// it (T-047).
func (h *Handler) refusal(req *listen.Request, g gateResult) result {
	// The counter follows the order of 4b: Require Authorized IPs first, then
	// admin_state, then a revocation (p4n-W7-r2-1).
	switch {
	case g.auth:
		h.auth.Add(1)
	case g.hard:
		h.hard.Add(1)
	default:
		h.revoked.Add(1)
	}
	switch req.Transport {
	case listen.UDP, listen.TCP:
		return result{rep: listen.Reply{Drop: true}}
	case listen.DoH, listen.DoH3:
		return result{rep: listen.Reply{Status: 403}}
	}
	return refuse(rcodeMsg(req.Msg, dns.RcodeRefused))
}

// noIdentity is step 4 for a query nobody owns. Over DoT and DoQ it is REFUSED.
// On Plain DNS it is SC 5.2a: REFUSED when the claim's Endpoint record is not
// held, the silent drop when the source is the dns_ip of a node (point (b)), then
// the free path, then REFUSED. The free path is W9's, behind FreePath.
func (h *Handler) noIdentity(ctx context.Context, req *listen.Request, sv *Serving, id *ident, fq FreeQuery, allowFree bool) result {
	q := req.Msg
	if req.Transport == listen.UDP || req.Transport == listen.TCP {
		if !id.claimNoRecord {
			fc, counts := h.cfg.Free.(FreeCases)
			if sv.nodeIPs[req.Source.Addr().Unmap()] {
				if counts {
					fc.Hop(req)
				}
				return result{rep: listen.Reply{Drop: true}}
			}
			if !allowFree {
				// myip: never a free query, but the counter says which of (a) and (c) would
				// have stopped the source anyway.
				if counts {
					fc.MyIP(req)
				}
			} else if h.cfg.Free != nil {
				if rep, ok := h.cfg.Free.Serve(ctx, req, fq); ok {
					return result{rep: rep}
				}
			}
		}
	}
	return refuse(rcodeMsg(q, dns.RcodeRefused))
}

// grantSafe is R9 of SC 7, at Grant creation: when the cache already holds a true
// A for the name and any of its addresses is not public, no Grant is written. The
// answer to the client is unchanged; only the proxy permission is withheld.
//
// The cache key carries the profile's ECS prefix and the effective CD, so the
// check reads the key of the evaluator's own lookup (p) and the plain one: an
// answer the evaluator just cached under p is otherwise invisible here
// (p4n-W7-r2-2).
func (h *Handler) grantSafe(qn names.Name, p sharedpolicy.ResolveParams) bool {
	if h.cfg.CachedA == nil {
		return true
	}
	variants := []sharedpolicy.ResolveParams{p}
	if p != (sharedpolicy.ResolveParams{}) {
		variants = append(variants, sharedpolicy.ResolveParams{})
	}
	for _, v := range variants {
		addrs, ok := h.cfg.CachedA(qn, v)
		if !ok {
			continue
		}
		for _, a := range addrs {
			if !netclass.IsPublic(a) {
				return false
			}
		}
	}
	return true
}
