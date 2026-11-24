// Package freefacts holds the facts of the agent's current run that decide the
// free DNS path (SC 5.2a (a) and (c), Plan T-555 and T-556): the first
// ServerTime of the run, caught_up_once, the heads learned and the off floor.
//
// They live in memory only, on purpose. Every start of the agent clears them,
// and that is the safety: a node that starts while the hub cannot be reached, or
// whose off entry is held back, cannot tell a stranger from a tenant's device,
// so it refuses free queries until it has heard the hub again.
package freefacts

import (
	"sync"
	"time"
)

// LagGrace is how old a head must be before the node must have applied it
// (SC 5.2a (c), third fact): longer than the 30 s of `fit`, because an Apply
// includes the blob fetch. Provisional (D31).
const LagGrace = 300 * time.Second

// maxHeads bounds the list of learned heads. When it is full the oldest head is
// folded into the aged maximum, which can only make the lag rule stricter, never
// looser.
const maxHeads = 4096

// State is what the agent hands to dns.
type State struct {
	// ServerTimeSeen: a Control stream has delivered its first ServerTime this run.
	ServerTimeSeen bool
	// CaughtUpOnce: applied_seq reached the first head seq learned this run.
	CaughtUpOnce bool
	// LagOK: applied_seq is at or above every head learned more than LagGrace ago.
	LagOK bool
	// OffFloor is the highest FreeDnsOff version of this run, 0 when none came.
	OffFloor uint64
}

// Ready is (c): all three facts hold.
func (s State) Ready() bool { return s.ServerTimeSeen && s.CaughtUpOnce && s.LagOK }

type head struct {
	seq uint64
	at  time.Time
}

// Facts is the fact keeper. The zero value is not usable; use New.
type Facts struct {
	now func() time.Time

	mu           sync.Mutex
	serverTime   bool
	caught       bool
	firstHead    uint64
	firstHeadSet bool
	heads        []head // strictly increasing in seq and in time
	aged         uint64 // highest seq folded out of heads
	applied      uint64
	floor        uint64
}

// New returns Facts reading the time from now (nil means time.Now).
func New(now func() time.Time) *Facts {
	if now == nil {
		now = time.Now
	}
	return &Facts{now: now}
}

// ServerTime records that a Control stream delivered a ServerTime. Only the first
// matters; later calls change nothing.
func (f *Facts) ServerTime() {
	f.mu.Lock()
	f.serverTime = true
	f.mu.Unlock()
}

// LearnHead records a head seq learned from a HeadNotice or GetHead. The first
// one of the run fixes the target of caught_up_once.
func (f *Facts) LearnHead(seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.firstHeadSet {
		f.firstHead, f.firstHeadSet = seq, true
		f.checkCaught()
	}
	// A head that is not above the last kept one adds nothing: the older, higher
	// head already binds the node for longer.
	if n := len(f.heads); n > 0 && seq <= f.heads[n-1].seq {
		return
	}
	if seq <= f.aged {
		return
	}
	f.heads = append(f.heads, head{seq: seq, at: f.now()})
	if len(f.heads) > maxHeads {
		f.aged = max(f.aged, f.heads[0].seq)
		f.heads = f.heads[1:]
	}
}

// Applied records the applied seq after every Apply.
func (f *Facts) Applied(seq uint64) {
	f.mu.Lock()
	f.applied = seq
	f.checkCaught()
	f.mu.Unlock()
}

func (f *Facts) checkCaught() {
	if f.firstHeadSet && f.applied >= f.firstHead {
		f.caught = true
	}
}

// FreeDNSOff raises the off floor (FreeDnsOff). A version of 0 is refused, as
// the contract says; nothing else lowers the floor during the run.
func (f *Facts) FreeDNSOff(version uint64) bool {
	if version == 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if version > f.floor {
		f.floor = version
	}
	return true
}

// State returns the facts at the current time.
func (f *Facts) State() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	need := f.aged
	keep := f.heads[:0]
	for _, h := range f.heads {
		if now.Sub(h.at) > LagGrace {
			need = max(need, h.seq)
			continue
		}
		keep = append(keep, h)
	}
	f.heads = keep
	f.aged = need
	return State{ServerTimeSeen: f.serverTime, CaughtUpOnce: f.caught, LagOK: f.applied >= need, OffFloor: f.floor}
}
