package dnsrole

import (
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// The drain rule of SC 8a.6 on the dns side. The agent decides it (zone.Drain over
// every table the node applies) and sends drain_since with each table message; this
// file turns that into a plan for the listeners and ends the plan when the agent
// says the node is advertised again. It decides nothing about pairs itself, except
// that it asks again before each close, as the rule says, so a table that arrived
// since the plan began is honoured.

// drainTarget is what the controller drives: the listeners' Server.
type drainTarget interface {
	Drain(listen.DrainPlan)
	CancelDrain()
}

// drainWait is the longest a close waits for a query in flight: the handler
// timeout of the listeners (30 s, limits.Listeners). The window of the closes ends
// that long before the 360 s of the rule, so the last close, even one that waited
// the whole time, is done by then.
const drainWait = 30 * time.Second

// DrainTimes are the rule's numbers (zone.Inputs), held apart so a test can shorten
// them.
type DrainTimes struct {
	From time.Duration // the earliest close, from the apply
	Done time.Duration // every close is done by
	Wait time.Duration
}

func defaultDrainTimes() DrainTimes {
	in := zone.Inputs()
	return DrainTimes{From: in.DrainFrom, Done: in.DrainDone, Wait: drainWait}
}

type drainCtl struct {
	env   *Env
	times DrainTimes
	// tables reads the table state; env.Tables, replaced by a test that needs to hold
	// a read.
	tables func() TableState

	mu     sync.Mutex
	target drainTarget
	since  int64 // the DrainSince the target runs a plan for, 0 for none
}

func newDrainCtl(env *Env) *drainCtl {
	return &drainCtl{env: env, times: defaultDrainTimes(), tables: env.Tables}
}

// attach gives the controller the listeners, once they are up, and applies the
// table the agent has already sent.
func (d *drainCtl) attach(t drainTarget) {
	d.mu.Lock()
	d.target = t
	d.mu.Unlock()
	d.sync()
}

// advertised reports that the table in use makes this node the advertised node of a
// pair, which is the one thing that ends a drain.
func advertised(st TableState) bool {
	return st.Table != nil && zone.Advertised(st.Table, nil, st.Local.Self)
}

// still is the check before each close: the table in use does not make this node the
// advertised node of a pair. It does not read drain_since: an agent that restarted
// knows nothing of the drain and sends 0 for a node that is still withdrawn, and the
// plan must go on (p4n-W8-r1-8). A plan exists only because a drain_since was
// non-zero, and the table in use is what ends it.
func (d *drainCtl) still() bool { return !advertised(d.tables()) }

// sync follows the agent's drain_since. It is called after every table message, on
// the socket's receive goroutine, and does no waiting. The table state is read under
// the lock, so of two syncs that race (the one at attach and the one of a message) the
// last to lock acts on the newest state and a stale read cannot replace a newer plan
// (p4n-W8-r1-7).
func (d *drainCtl) sync() {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.tables()
	if d.target == nil || st.DrainSince == d.since {
		return
	}
	if st.DrainSince == 0 {
		// The agent says the node does not drain. That is a re-advertisement only when
		// the table in use agrees; a restarted agent sends 0 for a withdrawn node, and
		// the plan then goes on.
		if advertised(st) {
			d.since = 0
			d.target.CancelDrain()
		}
		return
	}
	d.since = st.DrainSince
	// The apply happened at DrainSince on the node's clock, so what has passed is read
	// from it once, here. The plan then runs on timers, which a step of the wall clock
	// does not move.
	elapsed := d.env.now().Sub(time.Unix(st.DrainSince, 0))
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed >= d.times.Done {
		// The rule's time is over (a dns that restarted late): a client that comes now is
		// one that uses the node by address, and is served.
		d.target.CancelDrain()
		return
	}
	// remaining is what is left of the rule's time. A plan that starts when less than
	// Wait is left cannot keep the full Wait: a close that waited that long would run
	// past Done, and a window squeezed to a millisecond would close every connection
	// at one instant. So the wait takes at most half of what is left and the window
	// gets the rest, which keeps the moments spread and the last close inside the rule
	// (p4n-W8-r2-1).
	remaining := d.times.Done - elapsed
	wait := d.times.Wait
	if wait > remaining/2 {
		wait = remaining / 2
	}
	start := d.times.From - elapsed
	if start < 0 {
		start = 0
	}
	window := remaining - wait - start
	if window < time.Millisecond {
		window = time.Millisecond
	}
	d.target.Drain(listen.DrainPlan{Start: start, Window: window, Wait: wait, Still: d.still})
}
