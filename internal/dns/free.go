package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/sysnames"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/freelimit"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// This file is the free path of SC 5.2a (p4-nodes 7.9), the FreePath the Handler
// calls at step 4 for a Plain DNS source with no identity. It runs the points of
// the order in the contract one by one and each stops the query with the answer
// the contract names; the numbers in the comments are those points.
//
// What decides whether it may run at all is split three ways, as the contract
// splits it. (b), that the source is not a node's dns_ip, is the Handler's (it has
// the table of the image). (a) and (c) are facts of the agent's run that dns reads
// over the socket (FreeEnv). Everything after is here.
//
// A free query touches only what is its own: the free segment of the cache, the
// free resolver (the free Unbound and the free connection pools, which the caller
// puts behind Config.Resolver), the budget and the shares. It is never given a
// policy, a stack or a tenant's cache entry, and no qname or address reaches a
// sink: the counters name an outcome and an rcode (No trace).

// FreeEnv is what the free path reads of the agent's run.
type FreeEnv interface {
	// Gate gives (a) and (c) of SC 5.2a: on is a free_dns value in force that is
	// enabled and at or above the off floor, caughtUp is the three facts of the
	// agent's current run. Both are false while the agent cannot be read, so a dns
	// cut off from a crashed agent does not serve on facts nothing refreshes.
	//
	// imageSeq is the seq of the image that told this query's source from a tenant's
	// device: the Handler's own Serving, not anything the Env holds. The Env stores a
	// new image before the query path has swapped to it, and a swap that fails leaves
	// the Handler on the old one for good, so (c) is judged against the image that
	// actually identified the query (p4n-MD-r3-1).
	Gate(imageSeq uint64) (on, caughtUp bool)
	// QPS is the qps of the value in force: the node-wide budget.
	QPS() uint32
	// Isolated says that no resolve path is healthy (SC 5.2a point 7).
	Isolated() bool
}

// FreeConfig builds a FreeServer.
type FreeConfig struct {
	Env FreeEnv
	// Resolver looks a free miss up: a policy.Resolver over cache.Free and the free
	// resolver. It must never be the identified one.
	Resolver sharedpolicy.Resolver
	// Cache and Route read the free segment for point 6, so a miss is known before
	// the miss cap and Isolated mode are asked. Route is the free Backend's.
	Cache *cache.Cache
	Route func(n *names.Name, qtype uint16) string
	// Count takes one counter of 5.2a (Counters). It is called with no name and no
	// address.
	Count func(p commonv1.Protocol, o telemetryv1.FreeOutcome, rcode uint32)
	// SharedEnv gives the evaluator's Env (NeverProxied and the rest), used by no
	// rule here: with no profile in force nothing can match.
	SharedEnv func() sharedpolicy.Env
	// Now is the clock of the limits. Nil means time.Now: they are rates, not hub time.
	Now func() time.Time

	// MissCap is free_inflight; 0 means 256 (provisional, D31).
	MissCap int
	// ResponseRate and ResponseBurst are the response limit in bytes; 0 means 64 KiB
	// a second and 256 KiB (7.9, D31).
	ResponseRate, ResponseBurst int
}

// DefaultMissCap is free_inflight of SC 5.2a.
const DefaultMissCap = 256

// FreeServer implements FreePath and FreeCases.
type FreeServer struct {
	cfg   FreeConfig
	now   func() time.Time
	rl    *freelimit.ResponseLimit
	meter *freelimit.Meter
	miss  *freelimit.MissCap
	stack *sharedpolicy.Stack // no profile: PostDefault
}

// NewFreeServer builds the free path. It serves nothing until the agent's facts
// say it may.
func NewFreeServer(cfg FreeConfig) (*FreeServer, error) {
	if cfg.Env == nil || cfg.Resolver == nil || cfg.Cache == nil || cfg.Route == nil {
		return nil, errors.New("dns: free path needs an env, a resolver, a cache and a route")
	}
	if cfg.MissCap <= 0 {
		cfg.MissCap = DefaultMissCap
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &FreeServer{
		cfg: cfg, now: cfg.Now,
		rl:    freelimit.NewResponseLimit(cfg.ResponseRate, cfg.ResponseBurst, cfg.Now),
		meter: freelimit.NewMeter(), miss: freelimit.NewMissCap(cfg.MissCap),
		stack: sharedpolicy.NewStack(nil, nil, nil),
	}, nil
}

// MissesInFlight is how many free misses hold a slot of the miss cap.
func (f *FreeServer) MissesInFlight() int { return f.miss.InFlight() }

func (f *FreeServer) count(p commonv1.Protocol, o telemetryv1.FreeOutcome, rcode int) {
	if f.cfg.Count != nil {
		f.cfg.Count(p, o, uint32(rcode))
	}
}

// Hop counts a query that point (b) dropped. It is the one outcome that sends no
// reply, and it is counted with rcode 0.
func (f *FreeServer) Hop(req *listen.Request) {
	f.count(protocolOf(req.Transport), telemetryv1.FreeOutcome_FREE_OUTCOME_HOP, 0)
}

// MyIP counts a myip query from a source of identity case 3 that (b) did not drop:
// the caller answers REFUSED, since myip answers only an identified Endpoint, and
// the counter says why the free path would not have taken the source either.
func (f *FreeServer) MyIP(req *listen.Request, imageSeq uint64) {
	o := telemetryv1.FreeOutcome_FREE_OUTCOME_MYIP
	if on, caught := f.cfg.Env.Gate(imageSeq); !on {
		o = telemetryv1.FreeOutcome_FREE_OUTCOME_OFF
	} else if !caught {
		o = telemetryv1.FreeOutcome_FREE_OUTCOME_NOT_CAUGHT_UP
	}
	f.count(protocolOf(req.Transport), o, dns.RcodeRefused)
}

// Serve is the order of SC 5.2a. It returns handled=true for every query it takes,
// whatever the answer, because a query of identity case 3 whose free path says no
// is REFUSED, which is also what the Handler gives for handled=false; returning it
// here lets the counter carry the rcode.
func (f *FreeServer) Serve(ctx context.Context, req *listen.Request, q FreeQuery) (listen.Reply, bool) {
	m := req.Msg
	proto := protocolOf(req.Transport)
	src := req.Source.Addr().Unmap()
	// UDP with no valid server cookie may come from a spoofed address: only its
	// replies are held to the response limit, and it has its own shares.
	unvalidated := req.Transport == listen.UDP && !req.Validated
	prefix := freelimit.Prefix(src)

	// reply ends the query with msg. counted says whether the bytes go toward the
	// response limit (step 10): every free UDP reply sent after a query passed
	// point 3 counts, the replies of points 1, 2 and 3 do not.
	reply := func(msg *dns.Msg, o telemetryv1.FreeOutcome, counted bool) (listen.Reply, bool) {
		if req.Transport == listen.UDP && !msg.Truncated {
			msg = fitUDP(m, msg) // so the bytes charged are the bytes sent
		}
		if counted && unvalidated {
			n := msg.Len()
			if hasCookie(m) {
				n += cookieOptLen // the listener adds the server cookie after this
			}
			f.rl.Charge(prefix, n)
		}
		f.count(proto, o, msg.Rcode)
		return listen.Reply{Msg: msg}, true
	}
	refused := func(o telemetryv1.FreeOutcome, counted bool) (listen.Reply, bool) {
		return reply(rcodeMsg(m, dns.RcodeRefused), o, counted)
	}
	truncated := func(o telemetryv1.FreeOutcome, counted bool) (listen.Reply, bool) {
		return reply(listen.Truncated(m), o, counted)
	}

	// Point 1: (a) and (c). (b) was judged by the Handler.
	if on, caught := f.cfg.Env.Gate(q.ImageSeq); !on {
		return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_OFF, false)
	} else if !caught {
		return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_NOT_CAUGHT_UP, false)
	}
	// Point 2: RD. A query that asks only for the cache probes what other free
	// users resolved.
	if !m.RecursionDesired {
		return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_RD0, false)
	}
	now := f.now()
	// Point 3: the response limit, for UDP with no valid cookie. TC=1 and no
	// records, the size of the query, so a reflected flood above the rate sends the
	// victim nothing worth the trouble.
	if unvalidated && f.rl.Over(prefix) {
		return truncated(telemetryv1.FreeOutcome_FREE_OUTCOME_RATE_LIMITED, false)
	}
	// Point 4: the shares. The budget is what they are shares of, so a query one of
	// them stops spends none of it.
	qps := f.cfg.Env.QPS()
	if unvalidated {
		switch f.meter.Unvalidated(now, max(qps, 1), src) {
		case freelimit.ShareUnvalidatedPrefix:
			return truncated(telemetryv1.FreeOutcome_FREE_OUTCOME_PREFIX_SHARE, true)
		case freelimit.ShareUnvalidatedAll:
			return truncated(telemetryv1.FreeOutcome_FREE_OUTCOME_UNVALIDATED_SHARE, true)
		}
	} else {
		switch f.meter.Validated(now, max(qps, 1), src) {
		case freelimit.ShareSource:
			return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_SOURCE_SHARE, false)
		case freelimit.ShareValidatedPrefix:
			return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_PREFIX_SHARE, false)
		case freelimit.ShareValidatedAll:
			return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_VALIDATED_SHARE, false)
		}
	}
	// Point 5: the budget. It counts every free query that gets here, a hit as
	// well as a miss, because a hit costs CPU and answer bytes too.
	if qps == 0 || !f.meter.Budget(now, qps) {
		return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_OVER_BUDGET, true)
	}

	// An isolated_synth row needs no lookup, so it passes points 6 and 7.
	if q.SynthAlways && q.Synth != nil {
		return reply(q.Synth(), telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, true)
	}

	// Points 6 and 7. ANY is never resolved (RFC 8482): its answer is the HINFO of
	// the default row, with no hit and no miss.
	if q.QType != sharedpolicy.TypeANY {
		key := cache.KeyOf(q.Name, q.QType, sharedpolicy.ClassIN, sharedpolicy.ResolveParams{EffectiveCD: m.CheckingDisabled}, f.cfg.Route(&q.Name, q.QType))
		if _, hit := f.cfg.Cache.Get(cache.Free, key); !hit {
			// A miss. During a cut it would only hold a slot until it timed out, and
			// the slots are for identified queries.
			if f.cfg.Env.Isolated() {
				return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_ISOLATED, true)
			}
			release, ok := f.miss.TryAcquire(!unvalidated, src)
			if !ok {
				return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_OVER_MISS_CAP, true)
			}
			defer release()
		}
	}

	// The lookup says itself whether it was turned away by a full pool: a flag of this
	// call, not a count of the node (p4n-W9-r1-3).
	var turnedAway refusalTrack
	fin := f.postDefault(ctx, req, q, &turnedAway)
	// A miss can wait up to the fetch deadline, and the gate was read before it. Free
	// DNS must stop within seconds of the admin's switch and while the agent cannot be
	// read (SC 5.2a), so a miss that started before either is not answered (p4n-W9-r2-1).
	// Its lookup was done and is cached; only the answer is withheld.
	if on, caught := f.cfg.Env.Gate(q.ImageSeq); !on {
		return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_OFF, false)
	} else if !caught {
		return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_NOT_CAUGHT_UP, false)
	}
	if fin.Answer.RCode == sharedpolicy.RCodeServFail {
		if turnedAway.seen.Load() {
			return refused(telemetryv1.FreeOutcome_FREE_OUTCOME_OVER_MISS_CAP, true)
		}
		if q.Synth != nil {
			// Android's validation name keeps passing while the resolver is down.
			return reply(q.Synth(), telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, true)
		}
	}
	return reply(fromAnswer(m, q.Name, fin.Answer), telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, true)
}

// postDefault is Handler.postDefault over the free resolver: the DNSSEC shaping of
// 5.11 with EffectiveCD equal to the client's CD, the failure rule of 5.12 and the
// row Bypass, default, no match, with no profile, no Grant and no tenant. Any ECS
// option of the client is ignored: the Input carries none, so the key has no ECS
// range and nothing goes upstream.
func (f *FreeServer) postDefault(ctx context.Context, req *listen.Request, q FreeQuery, track *refusalTrack) sharedpolicy.Final {
	res := sharedpolicy.Resolver(track.wrap(f.cfg.Resolver))
	m := req.Msg
	in := &sharedpolicy.Input{
		Name: q.Name, QType: q.QType, Now: f.now().Unix(), Src: req.Source.Addr().Unmap(),
		Protocol: evalProtocol(req.Transport),
		CD:       m.CheckingDisabled, AD: m.AuthenticatedData,
	}
	if opt := m.IsEdns0(); opt != nil {
		in.DO = opt.Do()
	}
	var ans *sharedpolicy.TrueAnswer
	if q.QType != sharedpolicy.TypeANY { // ANY is never resolved: HINFO (RFC 8482)
		var err error
		ans, err = res.Lookup(ctx, q.Name, q.QType, sharedpolicy.ResolveParams{EffectiveCD: in.CD})
		if err != nil || ans == nil {
			ans = &sharedpolicy.TrueAnswer{Failed: true, RCode: sharedpolicy.RCodeServFail}
		}
	} else {
		ans = &sharedpolicy.TrueAnswer{Chain: []names.Name{in.Name}}
	}
	var env sharedpolicy.Env
	if f.cfg.SharedEnv != nil {
		env = f.cfg.SharedEnv()
	}
	pre := sharedpolicy.Pre(in, f.stack, &env)
	return sharedpolicy.Post(ctx, in, f.stack, &env, &pre, ans, res)
}

// cookieOptLen is what the listener adds to a reply for a query that carries a
// COOKIE option: the option header and an 8-byte client cookie with a 16-byte
// server cookie.
const cookieOptLen = 4 + 8 + 16

func hasCookie(q *dns.Msg) bool {
	if opt := q.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_COOKIE); ok {
				return true
			}
		}
	}
	return false
}

var _ FreePath = (*FreeServer)(nil)
var _ FreeCases = (*FreeServer)(nil)

// wildcardFreeQuery is the FreeQuery of a wildcard system name from a source with
// no identity (SC 8, Queries with no identity). An isolated_synth row carries its
// synthesized answer along: while the node is Isolated it is the answer and needs
// no lookup (it passes points 6 and 7 of 5.2a), and otherwise it stands in for a
// SERVFAIL.
func (h *Handler) wildcardFreeQuery(req *listen.Request, set *Settings, e sysnames.Entry, qn names.Name) FreeQuery {
	q := req.Msg
	fq := FreeQuery{Name: qn, QType: q.Question[0].Qtype}
	if e.Outcome == sysnames.OutcomeSynthDNSIP || e.FallbackSynth {
		fq.Synth = func() *dns.Msg { return h.synthDNSIP(q, qn, set, e.TTL) }
		fq.SynthAlways = e.Outcome == sysnames.OutcomeSynthDNSIP
	}
	return fq
}

// refusalTrack sees the lookups of one free query. A lookup whose answer is Failed
// with RCode REFUSED was turned away by a full free pool (policy.Resolver.Refusal);
// the flag is of this query alone, whoever else shares the fetch or the node.
type refusalTrack struct{ seen atomic.Bool }

func (t *refusalTrack) wrap(r sharedpolicy.Resolver) sharedpolicy.Resolver {
	return trackedResolver{r, t}
}

type trackedResolver struct {
	sharedpolicy.Resolver
	t *refusalTrack
}

func (r trackedResolver) Lookup(ctx context.Context, n names.Name, qtype uint16, p sharedpolicy.ResolveParams) (*sharedpolicy.TrueAnswer, error) {
	a, err := r.Resolver.Lookup(ctx, n, qtype, p)
	if err == nil && a != nil && a.Failed && a.RCode == sharedpolicy.RCodeRefused {
		r.t.seen.Store(true)
	}
	return a, err
}
