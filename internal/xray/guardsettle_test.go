package xray

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lateGuard is the guard of a restarted agent: it says off until the agent has applied
// its table once, which is the moment Settled closes, and counts how often it was read
// before that.
type lateGuard struct {
	on      atomic.Bool
	early   atomic.Int32
	settled chan struct{}
	once    sync.Once
	ch      chan bool
}

func newLateGuard() *lateGuard {
	return &lateGuard{settled: make(chan struct{}), ch: make(chan bool, 4)}
}

func (g *lateGuard) Check() bool {
	select {
	case <-g.settled:
	default:
		g.early.Add(1)
	}
	return g.on.Load()
}
func (g *lateGuard) Changed() <-chan bool     { return g.ch }
func (g *lateGuard) Settled() <-chan struct{} { return g.settled }
func (g *lateGuard) apply(ok bool)            { g.on.Store(ok); g.once.Do(func() { close(g.settled) }) }

// INT2-r2-2: an agent that restarts finds its slots running and the table in the
// kernel. The manager must read the guard only after the agent has applied the table,
// so the slots are adopted and not stopped.
func TestManagerWaitsForTheGuardsFirstApplyAndAdoptsTheSlots(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.GuardSettle = 10 * time.Second })
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.stop()

	g := newLateGuard()
	r.opts.Guard = g
	r.m = New(r.opts)
	r.start()
	time.Sleep(150 * time.Millisecond) // the agent has not applied its table yet
	if a := r.units.get("a"); !a.active || a.stops != 0 {
		t.Fatalf("a slot was stopped before the guard knew its table: %+v", a)
	}
	g.apply(true)
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("the list comes back", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && l.Configs[0].Healthy
	})
	if a := r.units.get("a"); !a.active || a.stops != 0 || a.starts != 1 {
		t.Errorf("the running slot was not adopted: %+v", a)
	}
	if n := g.early.Load(); n != 0 {
		t.Errorf("the guard was read %d times before the first apply", n)
	}
}

// A table that was never applied (nft refused, or the apply never came) ends the wait
// at its bound, and the guard then stays off: the slots stop, as before.
func TestManagerStopsTheSlotsWhenTheGuardNeverSettles(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.GuardSettle = 100 * time.Millisecond })
	_ = r.units.Start(t.Context(), "a")
	_ = r.units.Start(t.Context(), "b")
	g := newLateGuard()
	r.opts.Guard = g
	r.m = New(r.opts)
	r.start()
	r.eventually("both slots stopped after the bound", func() bool {
		return !r.units.get("a").active && !r.units.get("b").active
	})
}

// INT2-r2-2: a trial cut by the restart of the agent is marked crashed also when the
// guard needed the first apply to be on: the verdict is not lost to the wait.
func TestTrialCutByAnAgentRestartIsStillMarkedCrashedWithTheRealGuardFlow(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.GuardSettle = 10 * time.Second })
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.stop()

	rec := r.runningRec(hexID(1))
	if rec == nil {
		t.Fatal("no running record")
	}
	p := r.persisted()
	p.Trial = &trialRec{Rec: *rec, Boot: "boot-1", PID: 999999} // a process that is not the slot's now
	b, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.m.statePath("state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	g := newLateGuard()
	r.opts.Guard = g
	r.m = New(r.opts)
	r.start()
	time.Sleep(100 * time.Millisecond)
	g.apply(true)
	r.eventually("the trial's config is marked", func() bool { return r.persisted().Crashed[hexID(1)] != "" })
}
