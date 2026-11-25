package freefacts

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) adv(d time.Duration) { c.t = c.t.Add(d) }
func newFacts() (*Facts, *clock) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	return New(c.now), c
}

func TestEverythingStartsOff(t *testing.T) {
	f, _ := newFacts()
	s := f.State()
	if s.ServerTimeSeen || s.CaughtUpOnce || s.Ready() || s.OffFloor != 0 {
		t.Fatalf("a fresh run is not off: %+v", s)
	}
	if !s.LagOK {
		t.Error("with no head learned nothing is lagging")
	}
}

func TestReadyNeedsAllThree(t *testing.T) {
	f, _ := newFacts()
	f.Applied(5)
	f.LearnHead(5) // first head learned: applied is already there
	if s := f.State(); !s.CaughtUpOnce || s.Ready() {
		t.Fatalf("no ServerTime yet: %+v", s)
	}
	f.ServerTime()
	if !f.State().Ready() {
		t.Fatal("all three hold")
	}
}

func TestCaughtUpOnceWaitsForFirstHeadAndNeverClears(t *testing.T) {
	f, c := newFacts()
	f.ServerTime()
	f.Applied(10)
	f.LearnHead(50)
	if f.State().CaughtUpOnce {
		t.Fatal("applied 10 is below the first head 50")
	}
	f.Applied(49)
	if f.State().CaughtUpOnce {
		t.Fatal("49 is below 50")
	}
	f.Applied(50)
	if !f.State().CaughtUpOnce {
		t.Fatal("50 reaches the first head")
	}
	// a later, higher head does not clear it while the node applies it
	f.LearnHead(80)
	c.adv(10 * time.Second)
	if s := f.State(); !s.CaughtUpOnce || !s.Ready() {
		t.Fatalf("a new entry turned the free path off: %+v", s)
	}
}

func TestLagRule(t *testing.T) {
	f, c := newFacts()
	f.ServerTime()
	f.Applied(100)
	f.LearnHead(100)
	f.LearnHead(120) // learned now
	c.adv(299 * time.Second)
	if !f.State().Ready() {
		t.Fatal("a head younger than 300 s may still be applied")
	}
	c.adv(2 * time.Second)
	if s := f.State(); s.LagOK || s.Ready() {
		t.Fatalf("a head older than 300 s that is not applied must turn the path off: %+v", s)
	}
	if !f.State().CaughtUpOnce {
		t.Error("lag must not clear caught_up_once")
	}
	f.Applied(120)
	if !f.State().Ready() {
		t.Error("applying it turns the path back on")
	}
}

func TestLowerHeadsNeverLoosenTheRule(t *testing.T) {
	f, c := newFacts()
	f.Applied(10)
	f.LearnHead(10)
	f.LearnHead(30)
	c.adv(10 * time.Second)
	f.LearnHead(20) // below an older, higher head
	c.adv(295 * time.Second)
	if f.State().LagOK {
		t.Fatal("head 30 is 305 s old and not applied")
	}
	f.Applied(29)
	if f.State().LagOK {
		t.Fatal("29 is below 30")
	}
	f.Applied(30)
	if !f.State().LagOK {
		t.Fatal("30 applied")
	}
}

func TestOffFloorOnlyRises(t *testing.T) {
	f, _ := newFacts()
	if f.FreeDNSOff(0) {
		t.Error("version 0 accepted")
	}
	f.FreeDNSOff(500)
	f.FreeDNSOff(300)
	if f.State().OffFloor != 500 {
		t.Errorf("floor = %d", f.State().OffFloor)
	}
	f.FreeDNSOff(900)
	if f.State().OffFloor != 900 {
		t.Error("floor did not rise")
	}
}

func TestHeadListIsBounded(t *testing.T) {
	f, c := newFacts()
	for i := uint64(1); i <= 3*maxHeads; i++ {
		f.LearnHead(i)
		c.adv(time.Millisecond)
	}
	f.mu.Lock()
	n := len(f.heads)
	f.mu.Unlock()
	if n > maxHeads {
		t.Fatalf("heads = %d", n)
	}
	// folding makes the rule stricter, never looser: head maxHeads*2 was folded
	// or is held, so a node at 0 is behind once the grace passes
	c.adv(LagGrace + time.Second)
	if f.State().LagOK {
		t.Error("lag rule lost heads")
	}
}

func TestStateNamesTheAppliedSeqTheFactsWereJudgedAt(t *testing.T) {
	f, _ := newFacts()
	if s := f.State(); s.Applied != 0 {
		t.Fatalf("a fresh run has applied nothing: %+v", s)
	}
	f.Applied(7)
	if s := f.State(); s.Applied != 7 {
		t.Fatalf("applied %d, want 7", s.Applied)
	}
}
