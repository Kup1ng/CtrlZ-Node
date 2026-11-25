package listen

import (
	"context"
	"crypto/tls"
	"math/rand/v2"
	"sync"
	"time"
)

// The drain rule of SC 8a.6 as the listeners carry it out. A node that is no
// longer the advertised node of any pair in use keeps serving, and from 60 s
// after the apply closes its DoH, DoH3, DoT and DoQ connections gracefully,
// each at a moment with no query in flight, at a random moment over the rest of
// the window. This file knows nothing about pairs or tables: the caller says
// when the window opens (Drain), whether the node is still not advertised
// (DrainPlan.Still) and when a re-advertisement cancels it (CancelDrain). Plain
// DNS (UDP and TCP 53) never registers here, so it is never touched.
//
// Why the closes are spread: every client of the node reconnects when its
// connection is closed, so closing all at once would hand the node that now
// answers the hostname one thundering herd of handshakes.

// DrainPlan is one drain.
type DrainPlan struct {
	// Start is how long from now the earliest close may come (60 s after the apply,
	// less what has passed). Zero closes from now on.
	Start time.Duration
	// Window is the time over which the closes begin, from Start. A connection
	// gets its moment at random in [Start, Start+Window); one that opens while the
	// plan runs gets a moment in what is left of the window. A connection that opens
	// after the window is served and never drained: it is a client that uses the node
	// by address (SC 8a.6).
	Window time.Duration
	// Wait is the longest a close waits for a query in flight to be answered. It is
	// the handler timeout, so a reply that can still come is not cut off.
	Wait time.Duration
	// Still is asked before each close: false means the node is advertised again (or
	// the drain no longer applies), and the whole plan ends without closing that
	// connection. Nil means always true.
	Still func() bool
}

// drainer holds the connections that can be drained and the plan in force.
type drainer struct {
	mu    sync.Mutex
	items map[*drainItem]struct{}
	plan  *drainRun
	// rnd draws a number in [0, n); replaced by a test.
	rnd func(n int64) int64
}

type drainRun struct {
	DrainPlan
	began time.Time
}

type drainItem struct {
	// quiet reports that no query is in flight on the connection; nil means the
	// close itself waits (a shard of the DoH server shuts down gracefully).
	quiet func() bool
	// close ends the connection gracefully.
	close func()
	// closeWait, when not nil, replaces close in a drain and is given the plan's Wait:
	// a DoH shard shuts down by waiting for its requests, and that wait must be the
	// plan's (shortened for a late plan), not the 30 s handler timeout, or its last
	// close comes after the rule's 360 s (p4n-W8-r3-1).
	closeWait func(wait time.Duration)
	// refuse, when not nil, is called with true at the connection's moment and says
	// the connection must take no new query from then on; the queries it already
	// holds are finished, and it is closed once none is left. Without it a busy
	// connection (a home router sending a household's lookups over one DoQ
	// connection) is never quiet, and the close at the bound cuts every reply in
	// flight (p4n-W8-r1-6). It is called with false when the plan ends before the
	// close, so a connection of a node that is advertised again takes queries again.
	//
	// With false it reports whether the connection could go back to normal. A
	// connection that has already dropped a query cannot (the client has a query
	// with no answer and only a close tells it to retry): the drainer then closes it
	// once quiet even though the plan ended (p4n-W8-r2-2).
	refuse func(on bool) bool
	// wait is the plan's Wait, kept for such a close.
	wait  time.Duration
	timer *time.Timer
	run   *drainRun // the plan the timer belongs to
	// refusing and done are guarded by drainer.mu: refuse(true) is in force, and the
	// close has been decided (the connection stays refusing for good).
	refusing, done bool
}

func newDrainer() *drainer {
	return &drainer{items: map[*drainItem]struct{}{}, rnd: func(n int64) int64 { return rand.Int64N(n) }}
}

// attach registers a connection. It returns the function that takes it out again,
// which the connection's goroutine calls when the connection ends. A nil drainer
// attaches nothing.
func (d *drainer) attach(it *drainItem) func() {
	if d == nil {
		return func() {}
	}
	d.mu.Lock()
	d.items[it] = struct{}{}
	// A replacement DoH shard is an item like any other: the clients that arrive in
	// the window go to it as often as to an original shard, and each must be closed
	// in what is left of the window (p4n-W8-r1-1). The cascade ends because each
	// moment lies inside the rest of the window, and nothing is scheduled after it.
	if d.plan != nil {
		d.schedule(it, true)
	}
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		delete(d.items, it)
		if it.timer != nil {
			it.timer.Stop()
			it.timer = nil
		}
		d.mu.Unlock()
	}
}

// schedule gives the item its random moment in what is left of the window. The
// caller holds d.mu. A connection that joins (opens while the plan runs) after the window is over is not
// scheduled, but one that was open when the plan began always is, even when
// the window is already over by the time the plan gets to it: a plan that began 340 s
// after the apply has a window of a millisecond, and every connection of the node must
// still be closed by 360 s.
func (d *drainer) schedule(it *drainItem, joining bool) {
	p := d.plan
	if it.done {
		return // its close is decided and under way (finishClose)
	}
	end := p.began.Add(p.Start + p.Window)
	e := time.Since(p.began)
	if joining && !time.Now().Before(end) {
		return // a client that uses the node by address
	}
	lo := p.Start - e
	if lo < 0 {
		lo = 0
	}
	hi := p.Start + p.Window - e
	delay := lo
	if hi > lo {
		delay += time.Duration(d.rnd(int64(hi - lo)))
	}
	it.run = p
	it.timer = time.AfterFunc(delay, func() { d.fire(it, p) })
}

// begin starts a plan, replacing the one in force.
func (d *drainer) begin(p DrainPlan) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	d.plan = &drainRun{DrainPlan: p, began: time.Now()}
	for it := range d.items {
		d.schedule(it, false)
	}
}

// cancel ends the plan in force. A connection already closed stays closed.
func (d *drainer) cancel() {
	d.mu.Lock()
	d.stopLocked()
	d.mu.Unlock()
}

func (d *drainer) stopLocked() {
	d.plan = nil
	for it := range d.items {
		if it.timer != nil {
			it.timer.Stop()
			it.timer = nil
		}
		it.run = nil
		// A connection told to take no new query goes back to normal, unless its
		// close is decided: that one is going away and stays refusing. One that has
		// dropped a query cannot go back either: it is closed once quiet, so the
		// client is told to retry what it never got an answer to.
		if it.refusing && !it.done {
			if it.refuse(false) {
				it.refusing = false
			} else {
				it.done = true
				go d.finishClose(it)
			}
		}
	}
}

// draining reports whether a plan is in force and its window has not closed.
func (d *drainer) draining() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.plan
	return p != nil && time.Now().Before(p.began.Add(p.Start+p.Window))
}

// live reports whether it still belongs to plan p.
func (d *drainer) live(it *drainItem, p *drainRun) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, in := d.items[it]
	return in && d.plan == p && it.run == p
}

// pollEvery is how often a close that waits for a quiet connection looks again.
const pollEvery = 10 * time.Millisecond

// fire is the moment of one connection. It checks that the node is still not
// advertised, tells the connection to take no new query, waits until the queries it
// holds are answered and written (a moment with no query in flight), checks again and
// closes. The wait is bounded by Wait, the handler timeout, so a handler that never
// ends does not keep the connection past the rule's time.
func (d *drainer) fire(it *drainItem, p *drainRun) {
	if !d.live(it, p) {
		return
	}
	if !d.still(p) {
		d.cancelRun(p)
		return
	}
	if it.quiet != nil {
		if it.refuse != nil && !d.refuse(it, p) {
			return
		}
		deadline := time.Now().Add(p.Wait)
		for !it.quiet() && time.Now().Before(deadline) {
			time.Sleep(pollEvery)
			if !d.live(it, p) {
				return
			}
		}
		// The wait can be long: ask again, so a re-advertisement in it is honoured.
		if !d.live(it, p) {
			return
		}
		if !d.still(p) {
			d.cancelRun(p)
			return
		}
	}
	// The close is decided here, under the lock, so a cancel cannot slip in between
	// the check and the mark and then reset a connection that is being closed.
	d.mu.Lock()
	_, in := d.items[it]
	ok := in && d.plan == p && it.run == p
	if ok {
		it.done = true
	}
	d.mu.Unlock()
	if !ok {
		return
	}
	if it.closeWait != nil {
		it.closeWait(p.Wait)
		return
	}
	it.close()
}

// pendingClose reports that the item has a moment still to come and the window of
// the plan has ended: its timer is late, or its close is under way. A DoH shard in
// that state is about to be shut down, so a connection that opens now must not be
// given to it, or it would be drained although it opened after the window (SC 8a.6,
// p4n-W8-r3-3). Without this, the replacement shards' moments bunch at the window's
// end and a few run late.
func (d *drainer) pendingClose(it *drainItem) bool {
	if d == nil || it == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.plan
	if p == nil || time.Now().Before(p.began.Add(p.Start+p.Window)) {
		return false
	}
	// done: the moment came and the shard is on its way out (the timer is already
	// cleared by detach, and the replacement is not yet in the shard list).
	return it.done || (it.timer != nil && it.run == p)
}

// refuse puts the connection in the state of taking no new query, when it still
// belongs to plan p. The callback is a flag store, so it runs under the lock: a
// cancel then cannot reset the flag before it is set.
func (d *drainer) refuse(it *drainItem, p *drainRun) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, in := d.items[it]; !in || d.plan != p || it.run != p {
		return false
	}
	it.refusing = true
	it.wait = p.Wait
	it.refuse(true)
	return true
}

// finishClose closes a connection whose close was decided by a dropped query when its
// plan ended: it waits, bounded by the plan's Wait, for the queries it holds, then
// closes. It does not ask Still again; the refusal cannot be undone.
func (d *drainer) finishClose(it *drainItem) {
	attached := func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		_, in := d.items[it]
		return in
	}
	deadline := time.Now().Add(it.wait)
	for it.quiet != nil && !it.quiet() && time.Now().Before(deadline) {
		time.Sleep(pollEvery)
		if !attached() {
			return
		}
	}
	if attached() {
		it.close()
	}
}

func (d *drainer) still(p *drainRun) bool { return p.Still == nil || p.Still() }

// cancelRun ends plan p when it is still the one in force.
func (d *drainer) cancelRun(p *drainRun) {
	d.mu.Lock()
	if d.plan == p {
		d.stopLocked()
	}
	d.mu.Unlock()
}

// Drain starts the drain of SC 8a.6: every DoT, DoH, DoH3 and DoQ connection, those
// open now and those that open during the window, is closed gracefully at a random
// moment of the plan's window, never with a query in flight and never after Still
// says the node is advertised again. It replaces a plan in force. Plain DNS is not
// touched.
func (s *Server) Drain(p DrainPlan) { s.dr.begin(p) }

// CancelDrain ends the plan in force (a table made the node advertised again).
func (s *Server) CancelDrain() { s.dr.cancel() }

// Draining reports whether a plan is in force and its window is still open.
func (s *Server) Draining() bool { return s.dr.draining() }

// The states of a DoT connection under a drain. A connection that has dropped one
// frame can no longer go back to normal: the client has a query with no answer, and
// only the close tells it to retry (DoQ and DoH3 answer a refused stream with a
// reset, so they have no such state).
const (
	drainOpen    int32 = iota // takes queries
	drainRefuse               // takes no new query; nothing dropped yet
	drainDecided              // dropped a query, or closing: the close must come
)

// refuse is drainItem.refuse. Turning it off reports false when a frame was dropped
// meanwhile, and the drainer then closes the connection instead of reopening it.
func (c *sconn) refuse(on bool) bool {
	if on {
		c.drainState.CompareAndSwap(drainOpen, drainRefuse)
		return true
	}
	return c.drainState.CompareAndSwap(drainRefuse, drainOpen) || c.drainState.Load() == drainOpen
}

// admit says whether a frame just read is served. A refused frame moves the state to
// drainDecided in one step, so a cancel cannot lift the refusal between the check and
// the drop and leave that frame unanswered on a connection that goes on.
func (c *sconn) admit() bool {
	for {
		switch c.drainState.Load() {
		case drainOpen:
			return true
		case drainDecided:
			return false
		default:
			if c.drainState.CompareAndSwap(drainRefuse, drainDecided) {
				return false
			}
		}
	}
}

// drainLinger is how long a DoT connection that was sent its close_notify may take
// to go away by itself before the server closes the socket.
const drainLinger = 2 * time.Second

// drainClose ends a DoT connection gracefully: the TLS close_notify goes out after
// every reply written so far, the client sees the end and reconnects, and the
// socket closes when the client has closed its side, or after drainLinger.
func (c *sconn) drainClose() {
	c.drainState.Store(drainDecided)
	c.reason.CompareAndSwap(0, uint32(CloseDrain))
	if tc, ok := c.conn.(*tls.Conn); ok {
		_ = tc.CloseWrite()
		time.AfterFunc(drainLinger, func() { c.fail(CloseDrain) })
		return
	}
	c.fail(CloseDrain)
}

// shutdownWithin shuts a DoH shard down gracefully (HTTP/2 GOAWAY, and an idle
// HTTP/1.1 connection closed at once or after its response) and, when a request
// is still in flight after wait, closes what is left.
func (sh *dohShard) shutdownWithin(wait time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if sh.srv.Shutdown(ctx) != nil {
		_ = sh.srv.Close()
	}
}
