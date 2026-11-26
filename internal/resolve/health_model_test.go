package resolve

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/route"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// Tests of the upstream health and failover model (p4-nodes.md 7.7, after review
// round 8): 3-in-a-row both ways, kicked checks, dark, the check's EDNS0,
// latency, and which paths are checked.

func isCheckName(qn string) bool { return len(strings.SplitN(qn, ".", 2)[0]) == 32 }

// stepFake answers a check only when the test releases it, so the test decides
// how many scheduled checks have run. entered is told each time a check begins.
type stepFake struct {
	step    chan struct{}
	entered chan struct{}
	good    atomic.Bool
}

func newStepFake() *stepFake {
	return &stepFake{step: make(chan struct{}), entered: make(chan struct{}, 100)}
}

func (f *stepFake) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	select {
	case <-f.step:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if !f.good.Load() {
		return nil, errors.New("down")
	}
	m := new(dns.Msg)
	m.SetReply(req)
	return m, nil
}

func (f *stepFake) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the next check did not begin")
	}
}

func TestHealthComesBackOnlyAfterThreeScheduledPasses(t *testing.T) {
	f := newStepFake()
	lid := wire.LocalUnboundID()
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: f, Every: time.Second}})
	// Three failed checks take it down. After each release, the next check begins
	// only once the loop has recorded the result.
	for i := 0; i < failsToDown; i++ {
		f.waitEntered(t)
		f.step <- struct{}{}
	}
	f.waitEntered(t)
	if healthOf(r, lid) {
		t.Fatal("three failed checks did not take the path down")
	}
	f.good.Store(true)
	f.step <- struct{}{} // pass 1
	f.waitEntered(t)
	if healthOf(r, lid) {
		t.Fatal("one passed check brought the path back")
	}
	f.step <- struct{}{} // pass 2
	f.waitEntered(t)
	if healthOf(r, lid) {
		t.Fatal("two passed checks brought the path back")
	}
	f.step <- struct{}{} // pass 3
	f.waitEntered(t)
	if !healthOf(r, lid) {
		t.Fatal("three passed checks did not bring the path back")
	}
	// A lone failure in between does not count as progress: passes start again.
	f.good.Store(false)
	f.step <- struct{}{}
	f.waitEntered(t)
	if !healthOf(r, lid) {
		t.Fatal("one failed check took a healthy path down")
	}
}

// liveFake answers live queries at will and checks as the test says.
type liveFake struct {
	liveErr atomic.Bool
	probeOK atomic.Bool
	probes  atomic.Int64
}

func (f *liveFake) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if isCheckName(req.Question[0].Name) {
		f.probes.Add(1)
		if !f.probeOK.Load() {
			return nil, errors.New("dark")
		}
	} else if f.liveErr.Load() {
		return nil, errors.New("down")
	}
	m := new(dns.Msg)
	m.SetReply(req)
	return m, nil
}

func TestKickedChecksDoNotMoveHealth(t *testing.T) {
	f := &liveFake{}
	f.probeOK.Store(true)
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: f, Every: 3600 * time.Second}})
	lid := wire.LocalUnboundID()
	waitFor(t, func() bool { return f.probes.Load() >= 1 }, "the first scheduled check")
	f.probeOK.Store(false)
	for ep := 1; ep <= 3; ep++ {
		f.liveErr.Store(true)
		// Errors go on until the check runs: a kick that falls inside kickGap of the
		// last check is dropped, and the next error asks again.
		want := int64(1 + ep)
		waitFor(t, func() bool { who(t, r, "a.example.com", dns.TypeA); return f.probes.Load() >= want }, "the kicked check")
		f.liveErr.Store(false)
		// the kicked check ends before the live reply that clears the suspicion
		time.Sleep(30 * time.Millisecond)
		if got := who(t, r, "a.example.com", dns.TypeA); got == "error" {
			t.Fatal("no live reply")
		}
	}
	if !healthOf(r, lid) {
		t.Fatal("kicked checks moved Health")
	}
}

func TestSuspectMemberStaysPreferredWhileItsCheckRuns(t *testing.T) {
	rule, err := route.ParseRule(10, "suffix", "test", "g", false)
	if err != nil {
		t.Fatal(err)
	}
	u1, local := &nameFake{name: "u1", stallUnder: ".y.test.", probeDelay: 300 * time.Millisecond}, &nameFake{name: "local"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
		Local:     Member{X: local, Every: 3600 * time.Second},
		Upstreams: []Member{{ID: id(1), X: u1, Every: 3600 * time.Second}},
		Groups:    map[string][][16]byte{"g": {id(1)}}, Rules: []route.Rule{rule}})
	waitFor(t, func() bool { return u1.probes.Load() >= 1 && local.probes.Load() >= 1 }, "the first checks")
	// the first scheduled check takes 300 ms; wait it out so the kick is the next
	time.Sleep(350 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q := new(dns.Msg)
			q.SetQuestion("n"+string(rune('a'+i))+".y.test.", dns.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			_, _, _ = r.Exchange(ctx, q)
		}(i)
	}
	waitFor(t, func() bool { return r.ups[0].liveFails.Load() >= failsToDown }, "the member to be suspect")
	if got := who(t, r, "x.test", dns.TypeA); got != "u1" {
		t.Fatalf("x.test answered by %s while the suspect member's check was out", got)
	}
	wg.Wait()
}

func TestDarkOnlyAfterItsCheckFails(t *testing.T) {
	rule, err := route.ParseRule(10, "suffix", "test", "g", false)
	if err != nil {
		t.Fatal(err)
	}
	u1, local := &fake{name: "u1"}, &fake{name: "local"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
		Local:     Member{X: local, Every: 3600 * time.Second},
		Upstreams: []Member{{ID: id(1), X: u1, Every: 3600 * time.Second}},
		Groups:    map[string][][16]byte{"g": {id(1)}}, Rules: []route.Rule{rule}})
	waitFor(t, func() bool { return u1.hits.Load() >= 1 && local.hits.Load() >= 1 }, "the first checks")
	time.Sleep(20 * time.Millisecond)
	u1.stall.Store(true) // live queries and checks both run to their deadline
	q := new(dns.Msg)
	q.SetQuestion("x.test.", dns.TypeA)
	for i := 0; i < failsToDown; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		r.Exchange(ctx, q) // u1 gets half, then local answers
		cancel()
	}
	if !r.ups[0].preferred() {
		t.Fatal("three live errors alone held the member down")
	}
	start := time.Now()
	waitWithin(t, 3*probeTimeout+time.Second, func() bool { return !r.ups[0].preferred() }, "the failed checks to make the member dark")
	if d := time.Since(start); d > 2*probeTimeout+time.Second {
		t.Fatalf("the check took %v", d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, _, err := r.Exchange(ctx, q)
	if err != nil || resp.Answer[0].(*dns.TXT).Txt[0] != "local" {
		t.Fatalf("the group's name was not answered by local once u1 was dark: %v", err)
	}
	if !healthOf(r, id(1)) {
		t.Fatal("a dark member is not a down member: Health follows scheduled checks")
	}
}

// doFake loses every query that asks for DNSSEC records, as a middlebox that
// drops EDNS or large replies does, and answers bare queries.
type doFake struct {
	withDO  atomic.Int64
	without atomic.Int64
}

func (f *doFake) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if o := req.IsEdns0(); o != nil && o.Do() {
		f.withDO.Add(1)
		return nil, errors.New("dropped")
	}
	f.without.Add(1)
	m := new(dns.Msg)
	m.SetReply(req)
	return m, nil
}

func TestCheckAsksWithDO(t *testing.T) {
	f := &doFake{}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: f, Every: time.Second}})
	waitFor(t, func() bool { return !healthOf(r, wire.LocalUnboundID()) }, "checks that ask with DO to fail")
	if f.withDO.Load() < failsToDown {
		t.Fatalf("%d DO checks", f.withDO.Load())
	}
}

type delayFake struct {
	delay time.Duration
	down  atomic.Bool
}

func (f *delayFake) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if f.down.Load() {
		return nil, errors.New("down")
	}
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	m := new(dns.Msg)
	m.SetReply(req)
	return m, nil
}

func latencyOf(r *Router, id [16]byte) (uint32, bool) {
	for _, h := range r.Health() {
		if h.ID == id {
			return h.LatencyMS, true
		}
	}
	return 0, false
}

func TestHealthCarriesCheckLatency(t *testing.T) {
	f := &delayFake{delay: 40 * time.Millisecond}
	lid := wire.LocalUnboundID()
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, Local: Member{X: f, Every: time.Second}})
	waitFor(t, func() bool { l, _ := latencyOf(r, lid); return l >= 30 }, "the latency of a passed check")
	f.down.Store(true)
	waitFor(t, func() bool { return !healthOf(r, lid) }, "the path to go down")
	if l, _ := latencyOf(r, lid); l != 0 {
		t.Fatalf("a down path reports %d ms", l)
	}

	// A refused row is unhealthy with no latency.
	loc := &hubv1.Upstream{Id: idb(2), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "127.0.0.1:53", TimeoutMs: 1000, ViaLocation: 7}
	rr, err := NewRouterFromWire(&hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, Upstreams: []*hubv1.Upstream{loc}}, Member{}, nil, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer rr.Close()
	if l, ok := latencyOf(rr, id(2)); !ok || l != 0 || healthOf(rr, id(2)) {
		t.Fatalf("refused row: latency %d present %v", l, ok)
	}
}

func TestOnlyUsedPathsAreChecked(t *testing.T) {
	// 50 intervals of 5 ms: the used path is probed over and over, the unused one never.
	run := func(t *testing.T, mode commonv1.ResolveMode, used, unused *fake) {
		cfg := RouterConfig{Mode: mode}
		if mode == commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE {
			cfg.Local = Member{X: used, Every: time.Second}
			cfg.Upstreams = []Member{{ID: id(1), X: unused, Every: time.Second}}
		} else {
			cfg.Local = Member{X: unused, Every: time.Second}
			cfg.Upstreams = []Member{{ID: id(1), X: used, Every: time.Second}}
		}
		newTestRouter(t, cfg)
		time.Sleep(250 * time.Millisecond)
		if used.hits.Load() < 3 {
			t.Fatalf("the used path was probed %d times", used.hits.Load())
		}
		if n := unused.hits.Load(); n != 0 {
			t.Fatalf("the unused path was probed %d times", n)
		}
	}
	t.Run("recursive", func(t *testing.T) {
		run(t, commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, &fake{name: "local"}, &fake{name: "up"})
	})
	t.Run("upstream", func(t *testing.T) {
		run(t, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, &fake{name: "up"}, &fake{name: "local"})
	})
	t.Run("hybrid checks both", func(t *testing.T) {
		a, b := &fake{name: "local"}, &fake{name: "up"}
		newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID, Local: Member{X: a, Every: time.Second}, Upstreams: []Member{{ID: id(1), X: b, Every: time.Second}}})
		waitFor(t, func() bool { return a.hits.Load() >= 2 && b.hits.Load() >= 2 }, "both paths to be checked")
	})
}
