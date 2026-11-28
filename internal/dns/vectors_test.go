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
	h, err := New(Config{
		Resolver: r.Resolver, NeverProxied: e.env.NeverProxied, Catalog: e.env.Cat, Geo: e.env.Geo,
		Self: func() sharedpolicy.SelfAddrs { return e.env.Self },
	})
	if err != nil {
		return nil, err
	}
	set := NewSettings(nil, e.panel, e.env.Self.DNSIP, nil, r.Isolated)

	if r.NoPolicy {
		// The path with no profile (soft_disabled, degraded, the free path): the
		// handler's own postDefault, which the Endpoint's profile never reaches.
		f := h.postDefault(ctx, &in, in.QType)
		m := new(dns.Msg)
		m.SetQuestion(policy.NameToDNS(in.Name), in.QType)
		back := answerOfMsg(fromAnswer(m, in.Name, f.Answer))
		back.ECS = f.Answer.ECS
		back.AD = f.Answer.AD
		f.Answer = back
		return &vectors.Outcome{Final: f}, nil
	}

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
		return &vectors.Outcome{Final: f, Wildcard: ent.Wildcard}, nil
	}
	st, _ := sharedpolicy.SelectStack(ep, r.ClientHash, in.Now)
	envv := h.env()
	envv.Locs = e.env.Locs
	// The case's own node state (Self) and published latency go in through the shared
	// Request.Apply, the call every harness makes (shared vectors, reference.go), so a
	// case that changes the state of the node changes it the same way here.
	envv = r.Apply(envv)
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

// nodeGroupRuns names where the node runs each vector group that is not an
// evaluator group (an evaluator group has a fixture, and TestGoldenVectorsThroughTheGlue
// runs every one of those through the glue). N10 of the P4 spec: the node runs every
// group the reference harness runs, from this one list read against vectors.Groups(),
// so a group that is added to the shared module and that no one decided how the node
// runs fails here, and so does a name that no longer exists.
var nodeGroupRuns = map[string]string{
	// Through the node's own code.
	"zone-answer":      "TestZoneAnswerVectorsThroughTheHandler (the handler)",
	"pair-table-apply": "internal/store/apply TestPairTableApplyVectorsThroughTheTableWriter (the table writer and the applier)",
	// Shared code that the node imports unchanged: vectors.Run runs it directly, and the
	// node's glue run above includes it.
	"appleprofile": "shared code", "blob": "shared code", "gtable": "shared code", "hash": "shared code",
	"identity": "shared code", "locations-sets": "shared code", "manifest": "shared code", "names": "shared code",
	"no-redirect": "shared code", "pair-table-validate": "shared code", "quarantine": "shared code",
	"route": "shared code", "schedule-zones": "shared code", "telemetry-validate": "shared code",
	"tokens": "shared code", "upload": "shared code", "zone-failover": "shared code",
	// P4b: the Xray allow-list, the share link converter and the Grant reference model are shared
	// code that vectors.Run runs directly. The node table of Grants (p4b-proxy 4) adds its own run
	// of "grants" when it lands; this entry then names that test.
	"xray": "shared code", "sharelink": "shared code", "grants": "shared code",
}

func TestEveryVectorGroupHasANodeRun(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range vectors.Groups() {
		seen[name] = true
		g, err := vectors.ReadGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		if g.Fixture != "" {
			if _, listed := nodeGroupRuns[name]; listed {
				t.Errorf("group %q is an evaluator group and needs no entry: the glue run covers it", name)
			}
			continue
		}
		if _, ok := nodeGroupRuns[name]; !ok {
			t.Errorf("group %q has no node run: add it to nodeGroupRuns with the test that runs it", name)
		}
	}
	for name := range nodeGroupRuns {
		if !seen[name] {
			t.Errorf("nodeGroupRuns names %q, which is not a vector group", name)
		}
	}
}
