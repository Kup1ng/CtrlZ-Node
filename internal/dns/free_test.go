package dns

// Tests of the free path, SC 5.2a point by point. Each one is written so that it
// fails when the point it names is taken out of free.go: the world is the one of
// the other handler tests (a real Handler over a real image), with a FreeServer
// that has its own resolver, its own backend and its own segment of the cache.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/freelimit"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
)

const (
	stranger  = "198.51.100.7" // no claim, not a node
	stranger2 = "203.0.113.9"
	nodeSrc   = "8.8.8.8" // the dns_ip of node 0 of the table: point (b)
)

var (
	oAnswered = telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED
	oOff      = telemetryv1.FreeOutcome_FREE_OUTCOME_OFF
	oHop      = telemetryv1.FreeOutcome_FREE_OUTCOME_HOP
	oCaught   = telemetryv1.FreeOutcome_FREE_OUTCOME_NOT_CAUGHT_UP
	oRD0      = telemetryv1.FreeOutcome_FREE_OUTCOME_RD0
	oRate     = telemetryv1.FreeOutcome_FREE_OUTCOME_RATE_LIMITED
	oPrefix   = telemetryv1.FreeOutcome_FREE_OUTCOME_PREFIX_SHARE
	oUnval    = telemetryv1.FreeOutcome_FREE_OUTCOME_UNVALIDATED_SHARE
	oVal      = telemetryv1.FreeOutcome_FREE_OUTCOME_VALIDATED_SHARE
	oSource   = telemetryv1.FreeOutcome_FREE_OUTCOME_SOURCE_SHARE
	oBudget   = telemetryv1.FreeOutcome_FREE_OUTCOME_OVER_BUDGET
	oIsolated = telemetryv1.FreeOutcome_FREE_OUTCOME_ISOLATED
	oMissCap  = telemetryv1.FreeOutcome_FREE_OUTCOME_OVER_MISS_CAP
	oMyIP     = telemetryv1.FreeOutcome_FREE_OUTCOME_MYIP
)

// freeEnv is the agent's facts, set by the test.
type fakeFreeEnv struct {
	on, caught, iso atomic.Bool
	qps             atomic.Uint32
}

func (e *fakeFreeEnv) Gate() (bool, bool) { return e.on.Load(), e.caught.Load() }
func (e *fakeFreeEnv) QPS() uint32        { return e.qps.Load() }
func (e *fakeFreeEnv) Isolated() bool     { return e.iso.Load() }

type countKey struct {
	proto   commonv1.Protocol
	outcome telemetryv1.FreeOutcome
	rcode   uint32
}

type rig struct {
	w    *world
	srv  *FreeServer
	env  *fakeFreeEnv
	back *fakeBackend // the free resolver's, never the world's
	res  *policy.Resolver

	mu     sync.Mutex
	counts map[countKey]int
}

// newRig puts a FreeServer behind the world's Handler, with free DNS on, the node
// caught up and a budget of 1000 qps, and the clock frozen so a one-second window
// does not move under a test.
func newRig(t testing.TB, w *world, mut ...func(*FreeConfig)) *rig {
	t.Helper()
	w.setNow(time.Unix(1_700_000_000, 0))
	r := &rig{w: w, env: &fakeFreeEnv{}, back: newFakeBackend(), counts: map[countKey]int{}}
	r.env.on.Store(true)
	r.env.caught.Store(true)
	r.env.qps.Store(1000)
	r.res = &policy.Resolver{Cache: w.cache, Segment: cache.Free, Backend: r.back, Deadline: 2 * time.Second,
		Refusal: func(err error) bool { return errors.Is(err, errTestPoolFull) }}
	cfg := FreeConfig{
		Env: r.env, Resolver: r.res, Cache: w.cache, Route: r.back.Route,
		Now: w.now,
		Count: func(p commonv1.Protocol, o telemetryv1.FreeOutcome, rc uint32) {
			r.mu.Lock()
			r.counts[countKey{p, o, rc}]++
			r.mu.Unlock()
		},
	}
	for _, m := range mut {
		m(&cfg)
	}
	srv, err := NewFreeServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	w.h.cfg.Free = srv
	return r
}

// n is how many queries were counted with this outcome, over any protocol and rcode.
func (r *rig) n(o telemetryv1.FreeOutcome) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for k, v := range r.counts {
		if k.outcome == o {
			n += v
		}
	}
	return n
}

func (r *rig) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.counts {
		n += v
	}
	return n
}

func (r *rig) count(p commonv1.Protocol, o telemetryv1.FreeOutcome, rc int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[countKey{p, o, uint32(rc)}]
}

func freeUDP(src string) qopt       { return qopt{t: listen.UDP, src: src, validated: vptr(false)} }
func freeUDPCookie(src string) qopt { return qopt{t: listen.UDP, src: src, validated: vptr(true)} }
func freeTCP(src string) qopt       { return qopt{t: listen.TCP, src: src} }

func isTC(r listen.Reply) bool {
	return r.Msg != nil && r.Msg.Truncated && len(r.Msg.Answer) == 0 && len(r.Msg.Ns) == 0
}

func answered(r listen.Reply, ip string) bool {
	a := aAddrs(r.Msg)
	return r.Msg != nil && r.Msg.Rcode == dns.RcodeSuccess && len(a) == 1 && a[0] == ip
}

// 5.2a Identity and (a), (b), (c): the first that fails in the order (b), (a), (c)
// names the outcome, and every failure but (b) is REFUSED.
func TestFreeGateAndHopGuard(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	name := "g1.example.com"

	if rep := w.call(freeUDP(stranger), name, dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("free on, caught up: %v", rep.Msg)
	}
	if r.n(oAnswered) != 1 || r.back.total.Load() != 1 {
		t.Fatalf("answered %d, backend %d", r.n(oAnswered), r.back.total.Load())
	}

	// (b): a node's dns_ip gets a silent drop, no resolver work, counted hop with rcode 0.
	before := r.back.total.Load()
	if rep := w.call(freeTCP(nodeSrc), "g2.example.com", dns.TypeA); !rep.Drop || r.count(commonv1.Protocol_PROTOCOL_TCP, oHop, 0) != 1 || r.back.total.Load() != before {
		t.Fatalf("hop: %+v counts %v", rep, r.counts)
	}

	// (a) off, and the order (a) before (c).
	r.env.on.Store(false)
	r.env.caught.Store(false)
	rep := w.call(freeUDP(stranger), "g3.example.com", dns.TypeA)
	if rcodeOf(rep) != "REFUSED" || r.n(oOff) != 1 || r.n(oCaught) != 0 {
		t.Fatalf("off and not caught up: %v counts %v", rcodeOf(rep), r.counts)
	}
	// (c) alone.
	r.env.on.Store(true)
	rep = w.call(freeTCP(stranger), "g4.example.com", dns.TypeA)
	if rcodeOf(rep) != "REFUSED" || r.n(oCaught) != 1 {
		t.Fatalf("not caught up: %v counts %v", rcodeOf(rep), r.counts)
	}
	// And (b) first of all, even while both fail.
	r.env.on.Store(false)
	if rep := w.call(freeTCP(nodeSrc), "g5.example.com", dns.TypeA); !rep.Drop || r.n(oHop) != 2 {
		t.Fatalf("hop with the switch off: %+v counts %v", rep, r.counts)
	}
	if r.back.total.Load() != before {
		t.Fatal("a refused free query reached the resolver")
	}
}

// 5.2a (a): the free path is off while the agent cannot be read, which the Env
// reports as both facts false.
func TestFreeIsOffWhenTheAgentCannotBeRead(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	r.env.on.Store(false)
	r.env.caught.Store(false)
	for _, o := range []qopt{freeUDP(stranger), freeTCP(stranger)} {
		if rep := w.call(o, "agent-down.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" {
			t.Fatalf("%v: %v", o.t, rcodeOf(rep))
		}
	}
	if r.back.total.Load() != 0 {
		t.Fatal("resolver used while the free path was off")
	}
}

// Point 2: RD=0 is REFUSED, spends no budget and reaches no resolver.
func TestFreeRD0(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	m := mkq("rd0.example.com", dns.TypeA, qopt{})
	m.RecursionDesired = false
	rep := w.callMsg(freeUDP(stranger), m)
	if rcodeOf(rep) != "REFUSED" || r.n(oRD0) != 1 || r.back.total.Load() != 0 {
		t.Fatalf("%v counts %v", rcodeOf(rep), r.counts)
	}
	if r.srvBudgetUsed() != 0 {
		t.Fatalf("an RD=0 query spent budget: %d", r.srvBudgetUsed())
	}
	// Over TCP too.
	if rep := w.callMsg(freeTCP(stranger), m); rcodeOf(rep) != "REFUSED" || r.n(oRD0) != 2 {
		t.Fatalf("tcp: %v", rcodeOf(rep))
	}
}

func (r *rig) srvBudgetUsed() uint32 { return r.srv.meter.BudgetUsed(r.w.now()) }

// Point 3: a prefix that has used its response rate gets TC=1 with no records, and
// a validated query is neither counted nor stopped by it.
func TestFreeResponseLimit(t *testing.T) {
	w := newWorld(t)
	// 1 KB a second, a burst of 2 KB: a handful of answers.
	r := newRig(t, w, func(c *FreeConfig) { c.ResponseRate, c.ResponseBurst = 1000, 2000 })
	r.env.qps.Store(50000)
	var answers, tcs int
	for i := 0; i < 200; i++ {
		rep := w.call(freeUDP(fmt.Sprintf("192.0.2.%d", i%250+1)), fmt.Sprintf("r%d.example.com", i), dns.TypeA)
		switch {
		case isTC(rep):
			tcs++
		case answered(rep, "192.0.2.99"):
			answers++
		default:
			t.Fatalf("query %d: %v", i, rep.Msg)
		}
	}
	if answers < 10 || answers > 50 || tcs != 200-answers {
		t.Fatalf("%d answers and %d TC=1 of 200 queries with a burst of 2000 bytes", answers, tcs)
	}
	if r.n(oRate) != tcs {
		t.Fatalf("rate_limited counted %d, TC=1 sent %d", r.n(oRate), tcs)
	}
	// The same prefix over TCP, and over UDP with a valid cookie, is not stopped.
	if rep := w.call(freeTCP("192.0.2.1"), "tcp-ok.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("tcp from a limited prefix: %v", rep.Msg)
	}
	if rep := w.call(freeUDPCookie("192.0.2.1"), "cookie-ok.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("udp with a valid cookie from a limited prefix: %v", rep.Msg)
	}
	// Another prefix has its own burst.
	if rep := w.call(freeUDP("198.18.0.1"), "other-prefix.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("another prefix: %v", rep.Msg)
	}
	// Time pays the debt back.
	w.advance(10 * time.Second)
	if rep := w.call(freeUDP("192.0.2.1"), "later.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("after ten seconds: %v", rep.Msg)
	}
}

// Which replies count toward the response limit (step 10): the answer, the TC=1 of
// point 4 and the REFUSED of points 5 and 7; not the replies of points 1, 2 and 3.
func TestFreeWhatCountsTowardTheResponseLimit(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w, func(c *FreeConfig) { c.ResponseRate, c.ResponseBurst = 1, 1<<20 })
	pfx := freelimit.Prefix(netip.MustParseAddr(stranger))
	charged := func(f func()) bool {
		before := r.srv.rl.Tokens(pfx)
		f()
		return r.srv.rl.Tokens(pfx) < before-1
	}
	// Point 1 and 2 replies are not counted.
	r.env.on.Store(false)
	if charged(func() { w.call(freeUDP(stranger), "c1.example.com", dns.TypeA) }) {
		t.Fatal("the REFUSED of point 1 was charged")
	}
	r.env.on.Store(true)
	m := mkq("c2.example.com", dns.TypeA, qopt{})
	m.RecursionDesired = false
	if charged(func() { w.callMsg(freeUDP(stranger), m) }) {
		t.Fatal("the REFUSED of point 2 was charged")
	}
	// The answer is.
	if !charged(func() { w.call(freeUDP(stranger), "c3.example.com", dns.TypeA) }) {
		t.Fatal("an answer was not charged")
	}
	// The TC=1 of point 4 is: qps 10 makes a tenth of 1.
	r.env.qps.Store(1)
	if rep := w.call(freeUDP(stranger), "c4.example.com", dns.TypeA); !isTC(rep) && !answered(rep, "192.0.2.99") {
		t.Fatalf("setup: %v", rep.Msg)
	}
	if !charged(func() {
		if rep := w.call(freeUDP(stranger), "c5.example.com", dns.TypeA); !isTC(rep) || r.n(oPrefix) == 0 {
			t.Fatalf("point 4: %v counts %v", rep.Msg, r.counts)
		}
	}) {
		t.Fatal("the TC=1 of point 4 was not charged")
	}
	// The REFUSED of point 5 is (a validated TCP query spends budget 1 of 1 first).
	r.w.advance(2 * time.Second)
	r.env.qps.Store(1)
	if rep := w.call(freeTCP("198.18.1.1"), "c6.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("setup tcp: %v", rep.Msg)
	}
	if !charged(func() {
		if rep := w.call(freeUDP(stranger), "c7.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" || r.n(oBudget) == 0 {
			t.Fatalf("point 5: %v counts %v", rcodeOf(rep), r.counts)
		}
	}) {
		t.Fatal("the REFUSED of point 5 was not charged")
	}
	// The REFUSED of point 7 (Isolated) is.
	r.w.advance(2 * time.Second)
	r.env.qps.Store(1000)
	r.env.iso.Store(true)
	if !charged(func() {
		if rep := w.call(freeUDP(stranger), "c8.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" || r.n(oIsolated) == 0 {
			t.Fatalf("point 7: %v counts %v", rcodeOf(rep), r.counts)
		}
	}) {
		t.Fatal("the REFUSED of point 7 was not charged")
	}
	// The TC=1 of point 3 is not.
	r.env.iso.Store(false)
	for !r.srv.rl.Over(pfx) {
		r.srv.rl.Charge(pfx, 100_000)
	}
	if charged(func() {
		if rep := w.call(freeUDP(stranger), "c9.example.com", dns.TypeA); !isTC(rep) || r.n(oRate) != 1 {
			t.Fatalf("point 3: %v counts %v", rep.Msg, r.counts)
		}
	}) {
		t.Fatal("the TC=1 of point 3 was charged")
	}
}

// Point 4: the shares. UDP without a cookie gets TC=1, TCP and cookie UDP get REFUSED.
func TestFreeShares(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	r.env.qps.Store(20) // a tenth is 2, a half is 10
	ask := func(o qopt, i int) listen.Reply { return w.call(o, fmt.Sprintf("s%d.example.com", i), dns.TypeA) }

	// One /24 over UDP takes two, then TC=1 (prefix_share).
	for i := 0; i < 2; i++ {
		if rep := ask(freeUDP(fmt.Sprintf("192.0.2.%d", 10+i)), i); !answered(rep, "192.0.2.99") {
			t.Fatalf("%d: %v", i, rep.Msg)
		}
	}
	if rep := ask(freeUDP("192.0.2.77"), 3); !isTC(rep) || r.n(oPrefix) != 1 {
		t.Fatalf("prefix share: %v counts %v", rep.Msg, r.counts)
	}
	// Four more prefixes take 8: with the first two that is the half, 10.
	for p := 1; p <= 4; p++ {
		for i := 0; i < 2; i++ {
			if rep := ask(freeUDP(fmt.Sprintf("198.51.%d.1", p)), 10*p+i); !answered(rep, "192.0.2.99") {
				t.Fatalf("prefix %d: %v", p, rep.Msg)
			}
		}
	}
	if rep := ask(freeUDP("203.0.113.1"), 99); !isTC(rep) || r.n(oUnval) != 1 {
		t.Fatalf("unvalidated share: %v counts %v", rep.Msg, r.counts)
	}
	// Spoofed UDP cannot stop the proven sources: TCP and cookie UDP still answer, up
	// to their own shares, and the budget (20) still has the unvalidated half's room.
	if rep := ask(freeTCP("203.0.113.1"), 100); !answered(rep, "192.0.2.99") {
		t.Fatalf("tcp after a spoofed flood: %v", rep.Msg)
	}
	if rep := ask(freeUDPCookie("100.64.50.2"), 101); !answered(rep, "192.0.2.99") {
		t.Fatalf("cookie udp after a spoofed flood: %v", rep.Msg)
	}
	// Validated shares: one address takes two, then REFUSED source_share.
	if rep := ask(freeTCP("203.0.113.1"), 102); rcodeOf(rep) != "SUCCESS" && rcodeOf(rep) != "NOERROR" {
		t.Fatalf("second of the address: %v", rcodeOf(rep))
	}
	if rep := ask(freeTCP("203.0.113.1"), 103); rcodeOf(rep) != "REFUSED" || r.n(oSource) != 1 {
		t.Fatalf("source share: %v counts %v", rcodeOf(rep), r.counts)
	}
	// Another address of the same prefix: the prefix has taken its tenth already
	// (cookie UDP and TCP share the validated keys).
	if rep := ask(freeTCP("203.0.113.55"), 104); rcodeOf(rep) != "REFUSED" || r.n(telemetryv1.FreeOutcome_FREE_OUTCOME_PREFIX_SHARE) != 2 {
		t.Fatalf("validated prefix share: %v counts %v", rcodeOf(rep), r.counts)
	}
	// Five prefixes of validated sources fill the half.
	for p := 1; p <= 4; p++ { // 3 taken so far, 7 more make the half
		for i := 0; i < 2 && !(p == 4 && i == 1); i++ {
			if rep := ask(freeTCP(fmt.Sprintf("100.64.%d.1", p)), 200+10*p+i); rcodeOf(rep) != "NOERROR" {
				t.Fatalf("prefix %d: %v", p, rcodeOf(rep))
			}
		}
	}
	if rep := ask(freeTCP("100.64.9.1"), 300); rcodeOf(rep) != "REFUSED" || r.n(oVal) != 1 {
		t.Fatalf("validated share: %v counts %v", rcodeOf(rep), r.counts)
	}
}

// A query that a point stops spends no budget and no miss slot at the later points.
func TestFreeAStoppedQuerySpendsNothingLater(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	r.env.qps.Store(20)
	for i := 0; i < 2; i++ { // the prefix's tenth
		w.call(freeUDP("192.0.2.10"), fmt.Sprintf("a%d.example.com", i), dns.TypeA)
	}
	if used := r.srvBudgetUsed(); used != 2 {
		t.Fatalf("budget used %d after two answers", used)
	}
	back := r.back.total.Load()
	for i := 0; i < 50; i++ {
		if rep := w.call(freeUDP("192.0.2.11"), fmt.Sprintf("b%d.example.com", i), dns.TypeA); !isTC(rep) {
			t.Fatalf("query %d not stopped: %v", i, rep.Msg)
		}
	}
	if r.srvBudgetUsed() != 2 || r.back.total.Load() != back || r.srv.MissesInFlight() != 0 {
		t.Fatalf("a TC=1 query spent budget %d, backend %d, slots %d", r.srvBudgetUsed(), r.back.total.Load()-back, r.srv.MissesInFlight())
	}
}

// Point 5: the budget counts a hit as well as a miss, and stops what the shares let by.
func TestFreeBudget(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	r.env.qps.Store(1) // a tenth and a half are both 1, so the budget is the last stop
	if rep := w.call(freeUDP("192.0.2.1"), "bud.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("first: %v", rep.Msg)
	}
	// The name is in the cache now; a hit still takes the budget.
	rep := w.call(freeTCP("198.18.0.1"), "bud.example.com", dns.TypeA)
	if rcodeOf(rep) != "REFUSED" || r.n(oBudget) != 1 {
		t.Fatalf("a hit over the budget: %v counts %v", rcodeOf(rep), r.counts)
	}
	w.advance(time.Second)
	if rep := w.call(freeTCP("198.18.0.1"), "bud.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("next second: %v", rep.Msg)
	}
	// No identified query is counted by it or stopped by it.
	r.env.qps.Store(1)
	w.advance(time.Second)
	w.call(freeUDP("192.0.2.1"), "bud2.example.com", dns.TypeA) // uses the second's budget
	for i := 0; i < 20; i++ {
		if rep := w.plain(epA, "allow.example.com", dns.TypeA); len(aAddrs(rep.Msg)) == 0 && rcodeOf(rep) == "REFUSED" {
			t.Fatalf("identified query %d stopped by the free budget", i)
		}
	}
	if r.srvBudgetUsed() != 1 {
		t.Fatalf("identified queries took budget: %d", r.srvBudgetUsed())
	}
}

// Points 6 and 8: free queries read and write only the free segment, and the
// answer carries no tenant policy.
func TestFreeUsesOnlyItsOwnSegmentResolverAndNoPolicy(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)

	// A free user resolves a name Endpoint B's profile blocks: the true answer, since
	// a free query is given no policy.
	rep := w.call(freeTCP(stranger), "ads.example.com", dns.TypeA)
	if !answered(rep, "192.0.2.66") {
		t.Fatalf("free ads.example.com: %v", rep.Msg)
	}
	// ...and a name Endpoint A's Default Block would block.
	if rep := w.call(freeTCP(stranger2), "www.example.com", dns.TypeA); !answered(rep, "192.0.2.20") {
		t.Fatalf("free www.example.com: %v", rep.Msg)
	}
	if w.back.total.Load() != 0 {
		t.Fatal("a free query reached the identified resolver")
	}
	if st := w.cache.Stats(cache.Shared); st.Puts != 0 || st.Hits != 0 {
		t.Fatalf("the shared segment saw a free query: %+v", st)
	}
	if st := w.cache.Stats(cache.Free); st.Puts == 0 {
		t.Fatal("the free answer was not stored in the free segment")
	}
	// The second free query for the name is a hit and asks no one.
	n := r.back.total.Load()
	if rep := w.call(freeTCP("100.64.1.1"), "ads.example.com", dns.TypeA); !answered(rep, "192.0.2.66") || r.back.total.Load() != n {
		t.Fatalf("free hit: %v, backend %d -> %d", rep.Msg, n, r.back.total.Load())
	}
	// An identified query for the same name does not read the free entry: it asks its
	// own resolver and gets its own policy's answer.
	if rep = w.plain(epB, "www.example.com", dns.TypeA); !answered(rep, "192.0.2.20") || w.back.hitCount("www.example.com", dns.TypeA) != 1 {
		t.Fatalf("the identified path did not ask its own resolver: %v, %d", rep.Msg, w.back.hitCount("www.example.com", dns.TypeA))
	}
	if rep = w.plain(epB, "ads.example.com", dns.TypeA); answered(rep, "192.0.2.66") {
		t.Fatal("Endpoint B's block rule did not act: a free answer leaked into the identified path or the rule is gone")
	}
	// And the reverse: a name an identified query resolved is a miss for a free one.
	w.plain(epB, "shared.example.com", dns.TypeA)
	if rep := w.call(freeTCP(stranger), "shared.example.com", dns.TypeA); !answered(rep, "192.0.2.40") {
		t.Fatalf("free shared.example.com: %v", rep.Msg)
	}
	if r.back.hitCount("shared.example.com", dns.TypeA) != 1 {
		t.Fatal("a free query was answered from the identified segment")
	}
	// No activity, no learned IP, no proof: an unidentified query leaves no row.
	if p, l, a := w.rep.counts(); p+l != 0 || a != 0 && w.rep.acts[0].EndpointId[0] != epB {
		t.Fatalf("reports: proofs %d learned %d activity %d", p, l, a)
	}
}

// The cache key of a free query holds no ECS range: a client's ECS option changes
// nothing, reaches no resolver and is not in the answer.
func TestFreeIgnoresECS(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	withECS := func(addr string) *dns.Msg {
		m := mkq("ecs.example.com", dns.TypeA, qopt{edns: true})
		m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: netip.MustParseAddr(addr).AsSlice()})
		return m
	}
	rep := w.callMsg(freeTCP(stranger), withECS("192.0.2.0"))
	if !answered(rep, "192.0.2.99") {
		t.Fatalf("%v", rep.Msg)
	}
	for _, o := range rep.Msg.IsEdns0().Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); ok {
			t.Fatal("the answer carries an ECS option")
		}
	}
	for _, o := range r.back.last.IsEdns0().Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); ok {
			t.Fatal("an ECS option went upstream")
		}
	}
	if rep := w.callMsg(freeTCP(stranger2), withECS("198.51.100.0")); !answered(rep, "192.0.2.99") || r.back.total.Load() != 1 {
		t.Fatalf("a different ECS range missed the cache: backend %d", r.back.total.Load())
	}
}

// The client's CD is the effective CD (a separate key), ANY is HINFO and never resolved.
func TestFreeShapingAndANY(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	rep := w.call(freeTCP(stranger), "any.example.com", dns.TypeANY)
	if rep.Msg == nil || len(rep.Msg.Answer) != 1 || rep.Msg.Answer[0].Header().Rrtype != dns.TypeHINFO || r.back.total.Load() != 0 {
		t.Fatalf("ANY: %v backend %d", rep.Msg, r.back.total.Load())
	}
	w.call(freeTCP(stranger), "cd.example.com", dns.TypeA)
	w.call(freeTCP(stranger2), "cd.example.com", dns.TypeA)
	if r.back.total.Load() != 1 {
		t.Fatalf("same question, two lookups: %d", r.back.total.Load())
	}
	w.callMsg(freeTCP(stranger), mkq("cd.example.com", dns.TypeA, qopt{cd: true}))
	if r.back.total.Load() != 2 {
		t.Fatalf("CD is part of the key: %d", r.back.total.Load())
	}
	if !r.back.last.CheckingDisabled {
		t.Fatal("the client's CD did not reach the resolver")
	}
}

// Point 7: in Isolated mode a miss is REFUSED with no resolver work, a hit still answers.
func TestFreeIsolatedRefusesMissesNotHits(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	w.call(freeTCP(stranger), "iso-hit.example.com", dns.TypeA)
	r.env.iso.Store(true)
	n := r.back.total.Load()
	if rep := w.call(freeTCP(stranger2), "iso-miss.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" || r.n(oIsolated) != 1 || r.back.total.Load() != n {
		t.Fatalf("miss: %v counts %v", rcodeOf(rep), r.counts)
	}
	if rep := w.call(freeTCP(stranger2), "iso-hit.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("hit: %v", rep.Msg)
	}
}

// stallMisses starts n free misses that the backend holds, each from its own
// prefix, and waits until they hold their slots.
func stallMisses(t *testing.T, w *world, r *rig, tag string, n int, o func(i int) qopt) (wait func()) {
	t.Helper()
	var wg sync.WaitGroup
	base := r.srv.MissesInFlight()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			qo := o(i)
			w.h.ServeDNS(ctx, &listen.Request{Msg: mkq(fmt.Sprintf("%s%d.example.com", tag, i), dns.TypeA, qo), Transport: qo.t,
				Source: netip.AddrPortFrom(netip.MustParseAddr(qo.src), 4000), Validated: qo.t != listen.UDP})
		}()
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.srv.MissesInFlight() < base+n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := r.srv.MissesInFlight(); got < base+n {
		t.Fatalf("%d misses hold a slot, want %d", got, base+n)
	}
	return wg.Wait
}

// Point 7: the miss cap. Slots are held for the life of the miss and given back,
// and proven sources hold at most half of them.
func TestFreeMissCap(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w, func(c *FreeConfig) { c.MissCap = 20 })
	r.back.stall.Store(true)
	wait := stallMisses(t, w, r, "cap", 10, func(i int) qopt { return freeTCP(fmt.Sprintf("100.64.%d.1", i)) })
	if rep := w.call(freeTCP("100.64.99.1"), "cap-eleventh.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" || r.n(oMissCap) != 1 {
		t.Fatalf("eleventh validated miss: %v counts %v", rcodeOf(rep), r.counts)
	}
	wait()
	if r.srv.MissesInFlight() != 0 {
		t.Fatalf("%d slots held after the misses ended", r.srv.MissesInFlight())
	}
	r.back.stall.Store(false)
	if rep := w.call(freeTCP("100.64.9.2"), "cap-fourth.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("after the slots were free: %v", rep.Msg)
	}
	// A hit takes no slot.
	r.back.stall.Store(true)
	wait = stallMisses(t, w, r, "cap2-", 10, func(i int) qopt { return freeTCP(fmt.Sprintf("100.65.%d.1", i)) })
	if rep := w.call(freeTCP("100.64.9.3"), "cap-fourth.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("hit with the cap held: %v", rep.Msg)
	}
	wait()
}

// p4n-W9-r1-4: slow misses of spoofable sources (UDP with no valid cookie, any
// address) hold at most half the slots, and one prefix a tenth, so a real client's
// TCP retry still gets a slot while they last.
func TestFreeSpoofedSlowMissesLeaveASlotForTCP(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w, func(c *FreeConfig) { c.MissCap = 20 })
	r.back.stall.Store(true)
	udp := func(i int) qopt {
		no := false
		return qopt{t: listen.UDP, src: fmt.Sprintf("100.66.%d.1", i), validated: &no}
	}
	// Ten spoofed misses from ten prefixes take the unvalidated half.
	wait := stallMisses(t, w, r, "spoof", 10, udp)
	no := false
	if rep := w.call(qopt{t: listen.UDP, src: "100.66.200.1", validated: &no}, "spoof-more.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" || r.n(oMissCap) != 1 {
		t.Fatalf("an eleventh spoofed miss: %v counts %v", rcodeOf(rep), r.counts)
	}
	// The TCP miss of a real client gets one of the other half.
	r.back.stall.Store(false)
	if rep := w.call(freeTCP(stranger), "real-client.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("a TCP miss while spoofed misses hold their half: %v counts %v", rcodeOf(rep), r.counts)
	}
	wait()

	// One prefix holds at most a tenth (two of 20), whatever its addresses.
	r.back.stall.Store(true)
	same := func(i int) qopt { return qopt{t: listen.UDP, src: fmt.Sprintf("100.67.0.%d", i+1), validated: &no} }
	wait = stallMisses(t, w, r, "same", 2, same)
	n := r.n(oMissCap)
	if rep := w.call(qopt{t: listen.UDP, src: "100.67.0.200", validated: &no}, "same-third.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" || r.n(oMissCap) != n+1 {
		t.Fatalf("third miss of one prefix: %v counts %v", rcodeOf(rep), r.counts)
	}
	wait()
}

// A lookup that fails because every free connection of its upstream is full is
// REFUSED; any other failure is the SERVFAIL of 5.12, and neither is cached.
func TestFreePoolFullIsRefusedOtherFailureIsServfail(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	r.back.fail.Store(true)
	rep := w.call(freeTCP(stranger), "down.example.com", dns.TypeA)
	if rcodeOf(rep) != "SERVFAIL" || r.n(oAnswered) != 1 {
		t.Fatalf("backend down: %v counts %v", rcodeOf(rep), r.counts)
	}
	r.back.fail.Store(false)
	r.res.Backend = &fullBackend{fakeBackend: r.back, full: map[string]bool{"pool-full.example.com.": true}}
	rep = w.call(freeTCP(stranger2), "pool-full.example.com", dns.TypeA)
	if rcodeOf(rep) != "REFUSED" || r.n(oMissCap) != 1 {
		t.Fatalf("pool full: %v counts %v", rcodeOf(rep), r.counts)
	}
	r.res.Backend = r.back
	if rep := w.call(freeTCP(stranger2), "pool-full.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
		t.Fatalf("a failure was cached: %v", rep.Msg)
	}
}

// Which lookup was turned away is a fact of that lookup (p4n-W9-r1-3): another
// query that finds a pool full while this one is in flight does not turn its
// SERVFAIL into REFUSED.
func TestFreeUnrelatedFailureStaysServfailWhileAPoolIsFull(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	fb := &fullBackend{fakeBackend: r.back, full: map[string]bool{"turned-away.example.com.": true},
		hold: map[string]chan struct{}{"slow-fail.example.com.": make(chan struct{})}, started: make(chan string, 4)}
	r.res.Backend = fb
	done := make(chan listen.Reply, 1)
	go func() { done <- w.call(freeTCP(stranger), "slow-fail.example.com", dns.TypeA) }()
	if got := <-fb.started; got != "slow-fail.example.com." {
		t.Fatalf("started %q", got)
	}
	// While it is in flight, another miss is turned away by a full pool.
	if rep := w.call(freeTCP(stranger2), "turned-away.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" {
		t.Fatalf("turned away: %v", rcodeOf(rep))
	}
	close(fb.hold["slow-fail.example.com."])
	rep := <-done
	if rcodeOf(rep) != "SERVFAIL" {
		t.Fatalf("an unrelated failure became %v", rcodeOf(rep))
	}
	if r.n(oMissCap) != 1 || r.n(oAnswered) != 1 {
		t.Fatalf("counters: %v", r.counts)
	}
}

// p4n-W9-r2-1: the gate is read again when a slow miss returns. A miss that started
// before free DNS was switched off, or before the agent went away, is REFUSED and
// counted OFF or NOT_CAUGHT_UP, whatever its lookup found.
func TestFreeGateIsReadAgainWhenASlowMissReturns(t *testing.T) {
	for _, tc := range []struct {
		name string
		flip func(*fakeFreeEnv)
		want telemetryv1.FreeOutcome
	}{
		{"switched off", func(e *fakeFreeEnv) { e.on.Store(false) }, oOff},
		{"agent unreadable", func(e *fakeFreeEnv) { e.on.Store(false); e.caught.Store(false) }, oOff},
		{"not caught up", func(e *fakeFreeEnv) { e.caught.Store(false) }, oCaught},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := newRig(t, w)
			hb := &holdBackend{fakeBackend: r.back, release: make(chan struct{}), started: make(chan struct{}, 1)}
			r.res.Backend = hb
			done := make(chan listen.Reply, 1)
			go func() { done <- w.call(freeUDP(stranger), "slow-miss.example.com", dns.TypeA) }()
			<-hb.started
			tc.flip(r.env)
			close(hb.release)
			rep := <-done
			if rcodeOf(rep) != "REFUSED" || r.n(tc.want) != 1 || r.n(oAnswered) != 0 {
				t.Fatalf("%v counts %v", rcodeOf(rep), r.counts)
			}
			if r.srv.MissesInFlight() != 0 {
				t.Fatal("the miss kept its slot")
			}
			// Back on, the same name is answered (its lookup was cached).
			r.env.on.Store(true)
			r.env.caught.Store(true)
			if rep := w.call(freeUDP(stranger2), "slow-miss.example.com", dns.TypeA); !answered(rep, "192.0.2.99") {
				t.Fatalf("after the gate came back: %v", rep.Msg)
			}
		})
	}
}

// holdBackend answers like the fake backend once release is closed.
type holdBackend struct {
	*fakeBackend
	release chan struct{}
	started chan struct{}
}

func (b *holdBackend) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
	return b.fakeBackend.Exchange(ctx, req)
}

var errTestPoolFull = errors.New("test: every free connection is full")

// fullBackend fails the names in full as a full pool does, and the names in hold
// with a plain error once their channel closes.
type fullBackend struct {
	*fakeBackend
	full    map[string]bool
	hold    map[string]chan struct{}
	started chan string
}

func (b *fullBackend) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	name := req.Question[0].Name
	if b.full[name] {
		return nil, "", fmt.Errorf("%w: upstream", errTestPoolFull)
	}
	if ch := b.hold[name]; ch != nil {
		b.started <- name
		<-ch
		return nil, "", errors.New("upstream timeout")
	}
	return b.fakeBackend.Exchange(ctx, req)
}

// A wildcard system name from a stranger is a free query (SC 8): the same budget,
// the same segment and the same resolver, and an isolated_synth row answers with no
// lookup while the node is Isolated.
func TestFreeWildcardSystemNames(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	name := "any-label.metric.gstatic.com"
	if rep := w.call(freeTCP(stranger), name, dns.TypeA); !answered(rep, "192.0.2.99") || r.back.hitCount(name, dns.TypeA) != 1 || w.back.total.Load() != 0 {
		t.Fatalf("wildcard true_answer row: %v", rep.Msg)
	}
	if r.n(oAnswered) != 1 {
		t.Fatalf("not counted: %v", r.counts)
	}
	// Free path off: REFUSED, and the identified resolver is not asked either.
	r.env.on.Store(false)
	if rep := w.call(freeTCP(stranger), "other-label.metric.gstatic.com", dns.TypeA); rcodeOf(rep) != "REFUSED" || w.back.total.Load() != 0 || r.n(oOff) != 1 {
		t.Fatalf("free off: %v", rcodeOf(rep))
	}
	// A node's own dns_ip: dropped.
	r.env.on.Store(true)
	if rep := w.call(freeTCP(nodeSrc), "hop-label.metric.gstatic.com", dns.TypeA); !rep.Drop {
		t.Fatalf("hop: %+v", rep)
	}
	// isolated_synth: the DNS_IP answer, no lookup, while the node is Isolated.
	w.h.SetSettings(NewSettings([]names.Name{names.MustString(testZone)}, []names.Name{names.MustString("panel.example.org")}, netip.MustParseAddr(selfDNSIP), w.proof, true))
	r.env.iso.Store(true)
	n := r.back.total.Load()
	rep := w.call(freeTCP(stranger), "x-dnsotls-ds.metric.gstatic.com", dns.TypeA)
	if !answered(rep, selfDNSIP) || r.back.total.Load() != n {
		t.Fatalf("isolated_synth: %v backend %d -> %d", rep.Msg, n, r.back.total.Load())
	}
	// ...and not for a stranger the free path does not take.
	r.env.on.Store(false)
	if rep := w.call(freeTCP(stranger), "x-dnsotls-ds.metric.gstatic.com", dns.TypeA); rcodeOf(rep) != "REFUSED" {
		t.Fatalf("isolated_synth with free off: %v", rcodeOf(rep))
	}
}

// myip is never a free query: REFUSED from a stranger, counted by what stopped the
// free path or as myip when nothing did, and a hop is a hop.
func TestFreeMyIP(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	my := "myip." + testZone
	if rep := w.call(freeTCP(stranger), my, dns.TypeA); rcodeOf(rep) != "REFUSED" || r.n(oMyIP) != 1 {
		t.Fatalf("%v counts %v", rcodeOf(rep), r.counts)
	}
	r.env.caught.Store(false)
	w.call(freeTCP(stranger), my, dns.TypeA)
	r.env.on.Store(false)
	w.call(freeTCP(stranger), my, dns.TypeA)
	if r.n(oCaught) != 1 || r.n(oOff) != 1 {
		t.Fatalf("counts %v", r.counts)
	}
	if rep := w.call(freeTCP(nodeSrc), my, dns.TypeA); !rep.Drop || r.n(oHop) != 1 {
		t.Fatalf("hop: %+v", rep)
	}
	if r.back.total.Load() != 0 {
		t.Fatal("myip reached a resolver")
	}
}

// What the free path counts and what it does not (SC 5.2a, Counters): nothing from
// an identified source, a source whose claim a revocation or the admin state
// decides (identity cases 1 and 4), or an encrypted transport.
func TestFreeCountsOnlyIdentityCase3(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	w.plain(epA, "allow.example.com", dns.TypeA)                                                      // identified
	w.call(qopt{t: listen.UDP, src: "127.0.0.4", validated: vptr(false)}, "x.example.com", dns.TypeA) // epC: hard_disabled claim, silent drop
	w.dot(epA, "allow.example.com", dns.TypeA)
	w.call(qopt{t: listen.DoT, sni: "unknown." + testZone}, "x.example.com", dns.TypeA)
	w.call(qopt{t: listen.DoH, sni: "x." + testZone, http: dohInfo("/"+tok(9), "a."+testZone)}, "x.example.com", dns.TypeA)
	if r.total() != 0 || r.back.total.Load() != 0 {
		t.Fatalf("counted %v", r.counts)
	}
	// And a stranger on Plain DNS is counted once by transport.
	w.call(freeUDP(stranger), "y.example.com", dns.TypeA)
	w.call(freeTCP(stranger), "y.example.com", dns.TypeA)
	if r.count(commonv1.Protocol_PROTOCOL_UDP, oAnswered, 0) != 1 || r.count(commonv1.Protocol_PROTOCOL_TCP, oAnswered, 0) != 1 {
		t.Fatalf("%v", r.counts)
	}
}

// Under a spoofed flood the bytes that go to a victim are bounded: after the burst
// every reply is TC=1 and no larger than the query.
func TestFreeReflectionIsBounded(t *testing.T) {
	w := newWorld(t)
	r := newRig(t, w)
	r.env.qps.Store(50000)
	var qBytes, rBytes, tc, full int
	victim := func(i int) string { return fmt.Sprintf("203.0.113.%d", i%250+1) } // one /24, many hosts
	for i := 0; i < 3000; i++ {
		// 60 A records in a 1 KB answer: a 20x amplifier with no limit.
		m := mkq("big.example.com", dns.TypeA, qopt{edns: true})
		q, _ := m.Pack()
		qBytes += len(q)
		rep := w.callMsg(freeUDP(victim(i)), m)
		if rep.Msg == nil {
			t.Fatalf("query %d dropped", i)
		}
		b, err := rep.Msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		rBytes += len(b)
		if isTC(rep) {
			tc++
			if len(b) > len(q)+12 {
				t.Fatalf("a TC=1 reply of %d bytes to a query of %d", len(b), len(q))
			}
		} else {
			full++
		}
	}
	if tc == 0 {
		t.Fatal("a flood from one prefix was never limited")
	}
	// The unlimited ratio is about 20; the burst of 256 KiB over 150 KB of queries plus
	// one-for-one TC=1 replies keeps it under 4.
	if rBytes > 4*qBytes {
		t.Fatalf("%d reply bytes for %d query bytes (%d answers, %d TC=1)", rBytes, qBytes, full, tc)
	}
	if rBytes > freelimit.DefaultBurstBytes+freelimit.DefaultRateBytes*2+qBytes+3000*12 {
		t.Fatalf("%d reply bytes for one prefix, the limit is a burst of %d", rBytes, freelimit.DefaultBurstBytes)
	}
}

// The free path never takes an identified query, and a handler with no free path
// answers REFUSED.
func TestFreeNilPathIsRefused(t *testing.T) {
	w := newWorld(t)
	if rep := w.call(freeTCP(stranger), "n.example.com", dns.TypeA); rcodeOf(rep) != "REFUSED" {
		t.Fatalf("%v", rcodeOf(rep))
	}
}
