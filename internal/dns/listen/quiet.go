package listen

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// quiet tracks one connection's state for the two deadlines that L13 (2) allows
// on an accepted connection: the idle deadline and the write-stall deadline.
//
// An item is a query under way: a frame or stream or request that has been
// accepted and is not yet answered. A write is a reply (or a raw write to the
// socket) that the peer has not yet taken completely.
//
//   - idle is armed while there is no item, no queued reply and no write, so it
//     can never fire while a query is unread or unanswered, however slow the
//     answer is;
//   - stall closes the connection when the oldest write in progress has run for
//     stallAfter, that is, a reply the peer has not read for that long. The
//     time is counted from the start of that write, so a peer that keeps
//     sending queries cannot move it. Only an item that was open when the write
//     began holds it off (such a query waits, and L13 (2) says no deadline
//     fires while one does); the hold ends when those items are answered, and
//     the stall then has a fresh stallAfter. An item that arrives later does
//     not hold it: a peer that does not read would otherwise defeat the
//     deadline by sending one query in each window (p4n-W6-r1-1, -5).
type quiet struct {
	mu  sync.Mutex
	now func() time.Time

	next    uint64               // the id of the next item or write
	open    int                  // items begun and neither answered nor aborted
	waiting int                  // answered, with the write not started (a queue)
	active  map[uint64]time.Time // writes in progress, by id, with their start

	// The hold-off. Items with an id below epoch were open when the write that
	// is now the oldest began; oldOpen of them still are. releasedAt is when the
	// last of them was answered.
	epoch      uint64
	oldOpen    int
	releasedAt time.Time

	idleAfter, stallAfter time.Duration
	idle, stall           alarm // either may be nil
	idleOn, stallOn       bool
	stallAt               time.Time // when the armed stall alarm fires
}

// alarm is something that can be armed for a duration or disarmed.
type alarm interface {
	arm(d time.Duration)
	disarm()
}

func newQuiet(idleAfter, stallAfter time.Duration, idle, stall alarm) *quiet {
	q := &quiet{
		now: time.Now, active: map[uint64]time.Time{},
		idleAfter: idleAfter, stallAfter: stallAfter, idle: idle, stall: stall,
	}
	q.mu.Lock()
	q.update()
	q.mu.Unlock()
	return q
}

// update arms and disarms. The caller holds q.mu. Each alarm is touched only
// when the wish changes, so an alarm is armed afresh each time the connection
// becomes quiet and not on every packet.
func (q *quiet) update() {
	wantIdle := q.open == 0 && q.waiting == 0 && len(q.active) == 0 && q.idleAfter > 0
	if wantIdle != q.idleOn {
		q.idleOn = wantIdle
		if q.idle != nil {
			if wantIdle {
				q.idle.arm(q.idleAfter)
			} else {
				q.idle.disarm()
			}
		}
	}

	wantStall := len(q.active) > 0 && q.oldOpen == 0 && q.stallAfter > 0
	if !wantStall {
		if q.stallOn {
			q.stallOn = false
			if q.stall != nil {
				q.stall.disarm()
			}
		}
		return
	}
	at := q.oldest()
	if at.Before(q.releasedAt) {
		at = q.releasedAt
	}
	at = at.Add(q.stallAfter)
	if q.stallOn && at.Equal(q.stallAt) {
		return // the armed alarm is already right: no timer churn per packet
	}
	q.stallOn, q.stallAt = true, at
	if q.stall != nil {
		d := at.Sub(q.now())
		if d < 0 {
			d = 0
		}
		q.stall.arm(d)
	}
}

// oldest is the start of the write that has been running longest. The caller
// holds q.mu. A connection has at most a few hundred writes in progress (the
// stream cap), so a scan per event is cheap.
func (q *quiet) oldest() time.Time {
	var at time.Time
	for _, t := range q.active {
		if at.IsZero() || t.Before(at) {
			at = t
		}
	}
	return at
}

func (q *quiet) with(f func()) {
	q.mu.Lock()
	f()
	q.update()
	q.mu.Unlock()
}

// resetEpoch starts the hold-off afresh for the write that is now the oldest:
// the items open now are the ones that hold it off. The caller holds q.mu.
func (q *quiet) resetEpoch() {
	q.epoch, q.oldOpen, q.releasedAt = q.next, q.open, time.Time{}
}

// endItem takes an item out of the open ones. The caller holds q.mu.
func (q *quiet) endItem(id uint64) {
	q.open--
	if id < q.epoch && q.oldOpen > 0 {
		if q.oldOpen--; q.oldOpen == 0 {
			q.releasedAt = q.now()
		}
	}
}

// startWrite registers a write. The caller holds q.mu.
func (q *quiet) startWrite(id uint64) {
	if len(q.active) == 0 {
		q.resetEpoch()
	}
	q.active[id] = q.now()
}

// begin starts an item: a frame whose first byte has arrived, an accepted
// stream, a request. It returns the id the item is ended with.
func (q *quiet) begin() uint64 {
	var id uint64
	q.with(func() { id = q.next; q.next++; q.open++ })
	return id
}

// abort ends an item that gets no reply.
func (q *quiet) abort(id uint64) { q.with(func() { q.endItem(id) }) }

// reply ends an item and starts writing its reply, in one step so the
// connection is never seen quiet in between.
func (q *quiet) reply(id uint64) {
	q.with(func() { q.endItem(id); q.startWrite(id) })
}

// queue ends an item whose reply waits for the single writer of the
// connection; writeBegin starts that write.
func (q *quiet) queue(id uint64) {
	q.with(func() { q.endItem(id); q.waiting++ })
}

// writeBegin starts the write of a queued reply.
func (q *quiet) writeBegin(id uint64) {
	q.with(func() { q.waiting--; q.startWrite(id) })
}

// rawWrite registers a write that no item owns (a socket write of net/http).
func (q *quiet) rawWrite() uint64 {
	var id uint64
	q.with(func() { id = q.next; q.next++; q.startWrite(id) })
	return id
}

// writeEnd ends a write, whether it finished or failed.
func (q *quiet) writeEnd(id uint64) {
	q.with(func() {
		at, ok := q.active[id]
		if !ok {
			return
		}
		wasOldest := at.Equal(q.oldest())
		delete(q.active, id)
		// The oldest write is done, so the peer reads, and the next one is
		// counted from its own start with its own hold-off.
		if wasOldest && len(q.active) > 0 {
			q.resetEpoch()
		}
	})
}

// isQuiet reports that nothing is unread, unanswered or being written. The drain
// closes a connection only at such a moment, so no query is lost to it.
func (q *quiet) isQuiet() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.open == 0 && q.waiting == 0 && len(q.active) == 0
}

// idleArmed reports whether the idle deadline is armed now. A reader whose
// read ended with a timeout asks it, because the deadline may have been
// disarmed an instant before the timeout was delivered.
func (q *quiet) idleArmed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.idleOn
}

// connAlarm arms a net.Conn deadline. Disarming clears it.
type connAlarm struct {
	set func(time.Time) error
}

func (a connAlarm) arm(d time.Duration) { _ = a.set(time.Now().Add(d)) }
func (a connAlarm) disarm()             { _ = a.set(time.Time{}) }

// timerAlarm calls fire once d after the last arm, unless disarmed or armed
// again first. The generation makes a timer that fires just as it is disarmed
// do nothing.
type timerAlarm struct {
	mu   sync.Mutex
	t    *time.Timer
	gen  uint64
	fire func()
}

func (a *timerAlarm) arm(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gen++
	g := a.gen
	if a.t != nil {
		a.t.Stop()
	}
	a.t = time.AfterFunc(d, func() {
		a.mu.Lock()
		ok := a.gen == g
		a.mu.Unlock()
		if ok {
			a.fire()
		}
	})
}

func (a *timerAlarm) disarm() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gen++
	if a.t != nil {
		a.t.Stop()
		a.t = nil
	}
}

// guardedConn is a net.Conn that releases its claim on the connection limits
// when it closes, and tells quiet about each write, so the write-stall
// deadline can be armed for the time a write is blocked. net/http (DoH) and the
// TCP and DoT loops all get their connections through it.
type guardedConn struct {
	net.Conn
	// peerGone is set when a read ends with the peer closing or resetting the
	// connection, so a close that follows is the peer's and not ours.
	peerGone atomic.Bool
	release  func()
	q        *quiet // nil when the loop tracks writes itself
	held     *held  // reply bytes this connection holds; nil for the stream transports
	once     sync.Once
	onClose  func()
}

func (c *guardedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && !isTimeout(err) {
		c.peerGone.Store(true)
	}
	return n, err
}

func (c *guardedConn) Write(p []byte) (int, error) {
	if c.q != nil {
		defer c.q.writeEnd(c.q.rawWrite())
	}
	return c.Conn.Write(p)
}

func (c *guardedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.release != nil {
			c.release()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

// stop disarms both alarms for good, when the connection is over.
func (q *quiet) stop() {
	q.mu.Lock()
	q.idleAfter, q.stallAfter = 0, 0
	q.update()
	q.mu.Unlock()
}
