package dns

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/sysnames"
	"github.com/Kup1ng/CtrlZ-Shared/vectors"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// The zone-answer group (SC 15, 8a.3, 8a.10) through the real handler: each case
// is a question to ServeDNS over UDP, and the DNS message that comes back is
// compared with the answer 8a.3 requires.

// fakeImage is an Image whose Endpoints come from the case: a resolver id and the
// pair its EndpointRecord names.
type fakeImage struct {
	eps map[string]*image.Endpoint
	tbl *zone.Table
}

func (f *fakeImage) Seq() uint64 { return 1 }
func (f *fakeImage) ByResolverID(rid string) (*image.Endpoint, bool) {
	e, ok := f.eps[rid]
	return e, ok
}
func (f *fakeImage) ByEndpointID([16]byte) (*image.Endpoint, bool) { return nil, false }
func (f *fakeImage) Claims() []image.Claim                         { return nil }
func (f *fakeImage) ProfilePath([32]byte) (string, bool)           { return "", false }
func (f *fakeImage) PairTable() *policyv1.PairTable                { return nil }
func (f *fakeImage) Zone() *zone.Table                             { return f.tbl }

type handlerZone struct{ t *testing.T }

func (z handlerZone) Answer(q *vectors.ZoneQuery) vectors.ZoneAnswerExpect {
	img := &fakeImage{eps: map[string]*image.Endpoint{}, tbl: q.Table}
	for rid, pair := range q.Endpoints {
		img.eps[rid] = &image.Endpoint{Record: &policyv1.EndpointRecord{EndpointId: make([]byte, 16), PairId: pair[:]}}
	}
	h, err := New(Config{Resolver: nopResolver{}, NeverProxied: neverIR})
	if err != nil {
		z.t.Fatal(err)
	}
	h.SetSettings(NewSettings([]names.Name{names.MustString("dns.ctrlz.test")}, nil, q.SelfIP, make([]byte, 32), false))
	h.SetImage(img)
	h.SetZoneState(&ZoneState{Table: q.Table, Local: q.Local, Acme: func(fqdn string) []string { return q.Acme[fqdn] }})

	qt, ok := dns.StringToType[q.QType]
	if !ok {
		z.t.Fatalf("type %q", q.QType)
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q.QName), qt)
	req := &listen.Request{Msg: m, Transport: listen.UDP, Source: netip.MustParseAddrPort("203.0.113.9:4000")}
	rep := h.ServeDNS(context.Background(), req)
	if rep.Msg == nil {
		z.t.Fatalf("no message for %s %s", q.QName, q.QType)
	}
	out := vectors.ZoneAnswerExpect{Rcode: dns.RcodeToString[rep.Msg.Rcode], AA: rep.Msg.Authoritative, Answer: []string{}, Authority: []string{}}
	for _, rr := range rep.Msg.Answer {
		out.Answer = append(out.Answer, strings.Join(strings.Fields(rr.String()), " "))
	}
	for _, rr := range rep.Msg.Ns {
		out.Authority = append(out.Authority, strings.Join(strings.Fields(rr.String()), " "))
	}
	sort.Strings(out.Answer)
	return out
}

type nopResolver struct{}

func (nopResolver) Lookup(context.Context, names.Name, uint16, sharedpolicy.ResolveParams) (*sharedpolicy.TrueAnswer, error) {
	return &sharedpolicy.TrueAnswer{Failed: true, RCode: sharedpolicy.RCodeServFail}, nil
}

func TestZoneAnswerVectorsThroughTheHandler(t *testing.T) {
	vectors.RunZoneAnswers(t, handlerZone{t: t})
}

// ---- the evaluator groups through the node's glue

// glueHarness runs the evaluator vector groups through what the handler does: the
// system names step (stepSystem, with its conversions to and from DNS messages),
// then SelectStack, Pre, one lookup and Post with the handler's own Env, whose
// NeverProxied is the predicate the fixture names. A node whose glue drifts from
// the shared evaluator fails here first (R45).
type glueHarness struct{}

func (glueHarness) Prepare(fx *vectors.Fixture) (vectors.Evaluator, error) {
	env, panel, err := fx.Env()
	if err != nil {
		return nil, err
	}
	return &glueEval{fx: fx, env: env, panel: panel}, nil
}

type glueEval struct {
	fx    *vectors.Fixture
	env   sharedpolicy.Env
	panel []names.Name
}

func (e *glueEval) Evaluate(ctx context.Context, r *vectors.Request) (*vectors.Outcome, error) {
	ep, ok := e.fx.Endpoints[r.Endpoint]
	if !ok {
		return nil, nil
	}
	in := r.Input
	// A case may change the node's address state and the published latency of its
	// locations (shared 1.7.0, Request.Apply); the handler reads them from its Config.
	env := r.Apply(e.env)
	h, err := New(Config{
		Resolver: r.Resolver, NeverProxied: env.NeverProxied, Catalog: env.Cat, Geo: env.Geo,
		Self: func() sharedpolicy.SelfAddrs { return env.Self },
	})
	if err != nil {
		return nil, err
	}
	set := NewSettings(nil, e.panel, e.env.Self.DNSIP, nil, r.Isolated)

	if ent, ok := set.matcher.Lookup(&in.Name, in.QType, r.Isolated); ok {
		// Through the handler's step 2, as an identified query, and back.
		m := new(dns.Msg)
		m.SetQuestion(policy.NameToDNS(in.Name), in.QType)
		m.CheckingDisabled = in.CD
		if in.DO {
			m.SetEdns0(1232, true)
		}
		m.AuthenticatedData = in.AD
		req := &listen.Request{Msg: m, Transport: listen.DoT, Source: netip.MustParseAddrPort("203.0.113.1:1")}
		id := &ident{st: &epState{id: in.EndpointID}}
		res, handled := h.stepSystem(ctx, req, set, nil, id, gateResult{}, ent, in.Name, timeZero)
		if !handled {
			return nil, nil
		}
		f := sharedpolicy.Final{Action: sharedpolicy.ActionBypass, Stage: sharedpolicy.StageSystem, Ref: sharedpolicy.Ref{Kind: sharedpolicy.RefSystem}, Widenable: true}
		f.Answer = answerOfMsg(res.rep.Msg)
		return &vectors.Outcome{Final: f}, nil
	}
	st, _ := sharedpolicy.SelectStack(ep, r.ClientHash, in.Now)
	envv := h.env()
	envv.Locs = env.Locs
	f, pre := sharedpolicy.DecideWithPre(ctx, &in, st, &envv, r.Resolver)
	// The answer goes through the message the client would get and back.
	m := new(dns.Msg)
	m.SetQuestion(policy.NameToDNS(in.Name), in.QType)
	back := answerOfMsg(fromAnswer(m, in.Name, f.Answer))
	back.ECS = f.Answer.ECS
	back.AD = f.Answer.AD
	f.Answer = back
	return &vectors.Outcome{PreDone: pre.Done, Deferred: pre.Deferred, Walk: pre.Walk, Final: f}, nil
}

// answerOfMsg is the inverse of fromAnswer for the parts the vectors compare.
func answerOfMsg(m *dns.Msg) sharedpolicy.Answer {
	a := sharedpolicy.Answer{RCode: uint16(m.Rcode), AD: m.AuthenticatedData}
	for _, rr := range m.Answer {
		if r, ok := policy.RRFromDNS(rr); ok {
			a.Answer = append(a.Answer, r)
		}
	}
	for _, rr := range m.Ns {
		if r, ok := policy.RRFromDNS(rr); ok {
			a.Authority = append(a.Authority, r)
		}
	}
	return a
}

var _ = sysnames.Version

// Every evaluator group of the shared vectors, the Iranian-name ones included
// (T-524, a vector for each stage), runs through the node's glue.
func TestGoldenVectorsThroughTheGlue(t *testing.T) {
	vectors.Run(t, glueHarness{})
}

var timeZero = time.Unix(0, 0)
