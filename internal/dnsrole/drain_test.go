package dnsrole

import (
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

type fakeTarget struct {
	mu      sync.Mutex
	plans   []listen.DrainPlan
	cancels int
}

func (f *fakeTarget) Drain(p listen.DrainPlan) {
	f.mu.Lock()
	f.plans = append(f.plans, p)
	f.mu.Unlock()
}
func (f *fakeTarget) CancelDrain() { f.mu.Lock(); f.cancels++; f.mu.Unlock() }
func (f *fakeTarget) state() ([]listen.DrainPlan, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]listen.DrainPlan(nil), f.plans...), f.cancels
}

func tableMsg(since int64, withdrawn ...int) *sock.Msg {
	pt := storetest.Table(3, 70, withdrawn...)
	mem := mustMarshal(pt)
	m := &sock.Table{Member: mem, Version: 70, InUse: true, Self: storetest.NodeID(0), DrainSince: since}
	for _, w := range withdrawn {
		m.Flags = append(m.Flags, sock.Flag{Node: storetest.NodeID(w), Withdrawn: true})
	}
	return &sock.Msg{Type: sock.TypeTable, Table: m}
}

// SC 8a.6: the plan starts 60 s after the apply, spread to the 360 s less the wait;
// a dns that learns of it later gets what is left; a table that makes the node
// advertised again cancels it.
func TestDrainFollowsTheAgentsDrainSince(t *testing.T) {
	e := newEnv()
	now := time.Unix(10_000, 0)
	e.now = func() time.Time { return now }
	ctl := newDrainCtl(e)
	ft := &fakeTarget{}

	// A table message before the listeners exist is kept for attach.
	e.apply(tableMsg(now.Unix()-10, 0), "", func(string) {}, nil)
	ctl.sync()
	if p, c := ft.state(); len(p) != 0 || c != 0 {
		t.Fatal("a controller with no listeners acted")
	}
	ctl.attach(ft)
	plans, _ := ft.state()
	if len(plans) != 1 {
		t.Fatalf("plans after attach: %d", len(plans))
	}
	in := zone.Inputs()
	p := plans[0]
	// 10 s of the 60 s have passed; the window ends Wait before 360 s.
	if p.Start != in.DrainFrom-10*time.Second || p.Start+p.Window != in.DrainDone-drainWait-10*time.Second || p.Wait != drainWait || p.Still == nil {
		t.Fatalf("plan %+v for an apply 10 s ago", p)
	}

	// The same drain_since again (the agent repeats the table every second): nothing.
	e.apply(tableMsg(now.Unix()-10, 0), "", func(string) {}, nil)
	ctl.sync()
	if got, _ := ft.state(); len(got) != 1 {
		t.Fatalf("a repeated drain_since made another plan: %d", len(got))
	}

	// Still: the node is not advertised by the table in use, so a close may go on.
	if !p.Still() {
		t.Fatal("Still false for a withdrawn node that drains")
	}

	// A re-advertisement: the agent sends drain_since 0, and the plan is cancelled.
	e.apply(tableMsg(0), "", func(string) {}, nil)
	ctl.sync()
	if _, c := ft.state(); c != 1 {
		t.Fatalf("cancels = %d", c)
	}
	if p.Still() {
		t.Fatal("Still true after the agent ended the drain")
	}

	// Late: a dns that starts 200 s after the apply gets a window from now.
	e.apply(tableMsg(now.Unix()-200, 0), "", func(string) {}, nil)
	ctl.sync()
	plans, _ = ft.state()
	late := plans[len(plans)-1]
	if late.Start != 0 || late.Start+late.Window != in.DrainDone-drainWait-200*time.Second {
		t.Fatalf("late plan %+v", late)
	}

	// Past the rule's time nothing is closed: a client that comes now uses the node by address.
	e.apply(tableMsg(now.Unix()-400, 0), "", func(string) {}, nil)
	ctl.sync()
	got, c := ft.state()
	if len(got) != len(plans) || c != 2 {
		t.Fatalf("a drain 400 s old: plans %d cancels %d", len(got), c)
	}
}

// Before each close the table in use is asked: a node that the table advertises is
// not closed, whatever drain_since says.
func TestDrainStillAsksTheTable(t *testing.T) {
	e := newEnv()
	ctl := newDrainCtl(e)
	e.apply(tableMsg(e.now().Unix(), 0), "", func(string) {}, nil)
	if !ctl.still() {
		t.Fatal("node 0 is withdrawn and not advertised: it drains")
	}
	// A table that has the node advertised again but a drain_since not yet cleared
	// (the agent's next table is a second away).
	e.apply(tableMsg(e.now().Unix()), "", func(string) {}, nil)
	if ctl.still() {
		t.Fatal("an advertised node was closed")
	}
	// No table in use: only drain_since decides.
	e.apply(&sock.Msg{Type: sock.TypeTable, Table: &sock.Table{Self: storetest.NodeID(0), DrainSince: e.now().Unix()}}, "", func(string) {}, nil)
	if !ctl.still() {
		t.Fatal("no table in use but a drain_since")
	}
}

// An agent that restarts sends drain_since 0 for a node that is still withdrawn (it
// never saw the node advertised): that is no re-advertisement, and the plan goes on.
// The close-time check still holds, and a table that advertises the node ends it
// (p4n-W8-r1-8).
func TestDrainSurvivesAnAgentThatForgotIt(t *testing.T) {
	e := newEnv()
	ctl := newDrainCtl(e)
	ft := &fakeTarget{}
	ctl.attach(ft)
	e.apply(tableMsg(e.now().Unix()-5, 0), "", func(string) {}, nil)
	ctl.sync()
	plans, _ := ft.state()
	if len(plans) != 1 {
		t.Fatalf("plans = %d", len(plans))
	}
	// The restarted agent: the same withdrawn table, drain_since 0.
	e.apply(tableMsg(0, 0), "", func(string) {}, nil)
	ctl.sync()
	if got, c := ft.state(); len(got) != 1 || c != 0 {
		t.Fatalf("the plan was touched by drain_since 0 for a withdrawn node: plans %d cancels %d", len(got), c)
	}
	if !plans[0].Still() {
		t.Fatal("Still false for a node the table in use still withdraws")
	}
	// A later table that advertises it again ends the plan.
	e.apply(tableMsg(0), "", func(string) {}, nil)
	ctl.sync()
	if _, c := ft.state(); c != 1 {
		t.Fatalf("cancels = %d after the node was advertised again", c)
	}
	if plans[0].Still() {
		t.Fatal("Still true for an advertised node")
	}
}

// Two syncs that race (attach, and the handler of a table message) end with the plan
// of the newest state, however their reads interleave: the read is inside the lock
// (p4n-W8-r1-7).
func TestDrainSyncReadsTheTableInsideItsLock(t *testing.T) {
	e := newEnv()
	ctl := newDrainCtl(e)
	ft := &fakeTarget{}
	old := e.Tables() // DrainSince 0
	first := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ctl.tables = func() TableState {
		var held bool
		once.Do(func() { held = true })
		if held {
			close(first)
			<-release // attach's read is slow and returns the state it read before the message
			return old
		}
		return e.Tables()
	}
	attached := make(chan struct{})
	go func() { ctl.attach(ft); close(attached) }()
	<-first
	e.apply(tableMsg(e.now().Unix()-5, 0), "", func(string) {}, nil)
	handled := make(chan struct{})
	go func() { ctl.sync(); close(handled) }() // the handler of the message
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-attached
	<-handled
	plans, cancels := ft.state()
	if len(plans) != 1 || cancels != 0 {
		t.Fatalf("plans %d cancels %d: the stale read of attach replaced the newer plan", len(plans), cancels)
	}
	if ctl.since == 0 {
		t.Fatal("the controller ended with no plan")
	}
}

// A plan that starts late keeps every close inside the rule: with 15 s left the wait
// cannot be the full 30 s, and the closes are spread over the time left, not bunched
// at one instant (p4n-W8-r2-1).
func TestDrainThatStartsLateEndsBeforeTheRulesTime(t *testing.T) {
	in := zone.Inputs()
	for _, elapsed := range []time.Duration{299 * time.Second, 329 * time.Second, 335 * time.Second, 345 * time.Second, 359 * time.Second} {
		e := newEnv()
		now := time.Unix(10_000, 0)
		e.now = func() time.Time { return now }
		ctl := newDrainCtl(e)
		ft := &fakeTarget{}
		ctl.attach(ft)
		e.apply(tableMsg(now.Unix()-int64(elapsed/time.Second), 0), "", func(string) {}, nil)
		ctl.sync()
		plans, _ := ft.state()
		if len(plans) != 1 {
			t.Fatalf("elapsed %v: plans = %d", elapsed, len(plans))
		}
		p := plans[0]
		left := in.DrainDone - elapsed
		if p.Start+p.Window+p.Wait > left {
			t.Fatalf("elapsed %v: the last close can end %v after the plan began, past the %v left", elapsed, p.Start+p.Window+p.Wait, left)
		}
		if p.Wait > drainWait {
			t.Fatalf("elapsed %v: wait %v over the handler timeout", elapsed, p.Wait)
		}
		if elapsed <= 345*time.Second && elapsed >= 335*time.Second && p.Window < time.Second {
			t.Fatalf("elapsed %v: window %v bunches every close", elapsed, p.Window)
		}
	}
}
