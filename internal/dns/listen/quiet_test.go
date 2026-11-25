package listen

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// recAlarm records whether it is armed.
type recAlarm struct {
	mu    sync.Mutex
	armed bool
	arms  int
	d     time.Duration
}

func (a *recAlarm) arm(d time.Duration) {
	a.mu.Lock()
	a.armed, a.d = true, d
	a.arms++
	a.mu.Unlock()
}
func (a *recAlarm) disarm() { a.mu.Lock(); a.armed = false; a.mu.Unlock() }
func (a *recAlarm) on() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.armed
}

// fakeQuiet is a quiet with a clock the test moves.
func fakeQuiet(idleAfter, stallAfter time.Duration) (q *quiet, idle, stall *recAlarm, advance func(time.Duration)) {
	idle, stall = &recAlarm{}, &recAlarm{}
	now := time.Unix(1000, 0)
	q = newQuiet(idleAfter, stallAfter, idle, stall)
	q.mu.Lock()
	q.now = func() time.Time { return now }
	q.mu.Unlock()
	return q, idle, stall, func(d time.Duration) { q.mu.Lock(); now = now.Add(d); q.mu.Unlock() }
}

// The state machine behind L13 (2): the idle deadline is armed only while every
// query is answered and nothing is unread or being written, so it cannot fire
// while a query waits.
func TestQuietIdleOnlyWhenNothingIsOpen(t *testing.T) {
	q, idle, stall, _ := fakeQuiet(10*time.Second, 30*time.Second)
	if !idle.on() || stall.on() {
		t.Fatal("a fresh connection is idle: idle armed, stall not")
	}
	if idle.d != 10*time.Second {
		t.Fatalf("idle duration %v", idle.d)
	}
	a := q.begin()
	if idle.on() {
		t.Fatal("a query under way must disarm the idle deadline")
	}
	b := q.begin()
	q.reply(a)
	if idle.on() {
		t.Fatal("idle armed while a query waits and a reply is written")
	}
	q.reply(b)
	q.writeEnd(a)
	if idle.on() {
		t.Fatal("idle armed while a reply is still being written")
	}
	arms := idle.arms
	q.writeEnd(b)
	if !idle.on() || idle.arms != arms+1 {
		t.Fatal("idle must be armed afresh when the connection becomes quiet")
	}
	// A queued reply (TCP) also keeps the connection from being idle.
	c := q.begin()
	q.queue(c)
	if idle.on() {
		t.Fatal("idle armed with a reply queued")
	}
	q.writeBegin(c)
	q.writeEnd(c)
	if !idle.on() {
		t.Fatal("idle not armed after the queued reply was written")
	}
	d := q.begin()
	q.abort(d)
	if !idle.on() {
		t.Fatal("idle not armed after the frame was dropped")
	}
	q.stop()
	if idle.on() || stall.on() {
		t.Fatal("stop must disarm both")
	}
}

// The stall is counted from the start of the oldest write. A peer that never
// reads and sends a query in every window does not move it, and a query that
// was open when the write began holds it off until it is answered.
func TestQuietStallIsAnchoredToTheOldestWrite(t *testing.T) {
	q, _, stall, advance := fakeQuiet(10*time.Second, 30*time.Second)

	a := q.begin()
	q.reply(a) // the write of a blocks: no query waits
	if !stall.on() || stall.d != 30*time.Second {
		t.Fatalf("stall %v after %v", stall.on(), stall.d)
	}
	advance(20 * time.Second)
	// The peer sends another query, which is answered: the clock does not move.
	b := q.begin()
	if !stall.on() {
		t.Fatal("a new query disarmed the write deadline")
	}
	arms := stall.arms
	q.reply(b)
	if !stall.on() || stall.arms != arms || q.stallAt != time.Unix(1030, 0) {
		t.Fatalf("the deadline moved: armed %v, %d arms, fires at %v, want the first write plus 30s", stall.on(), stall.arms-arms, q.stallAt)
	}
	// Ending the younger write changes nothing; ending the oldest starts the
	// next one's own clock from its own start.
	q.writeEnd(b)
	if !stall.on() || q.stallAt != time.Unix(1030, 0) {
		t.Fatal("a younger write ended and the deadline moved")
	}
	q.writeEnd(a)
	if stall.on() {
		t.Fatal("no write left but the stall is armed")
	}
}

func TestQuietHoldOffIsOnlyForQueriesThatWereOpenFirst(t *testing.T) {
	q, _, stall, advance := fakeQuiet(10*time.Second, 30*time.Second)

	slow := q.begin() // waits for its answer
	a := q.begin()
	q.reply(a) // blocked write, with slow still open
	if stall.on() {
		t.Fatal("the write deadline ran while a query read before it waited")
	}
	// Queries that come later do not hold it off, and nor do they matter.
	later := q.begin()
	advance(40 * time.Second)
	q.reply(slow) // the old query is answered: a fresh 30 s starts now
	if !stall.on() || stall.d != 30*time.Second {
		t.Fatalf("after the hold-off: armed %v for %v, want a fresh 30s", stall.on(), stall.d)
	}
	_ = later // still open, and it holds nothing off
	q.stop()
}

func TestQuietLateQueriesNeverHoldOff(t *testing.T) {
	q, _, stall, _ := fakeQuiet(10*time.Second, 30*time.Second)
	a := q.begin()
	q.reply(a)
	if !stall.on() {
		t.Fatal("not armed")
	}
	for i := 0; i < 5; i++ {
		x := q.begin() // a partial frame, a stream, a request, left open
		_ = x
		if !stall.on() {
			t.Fatalf("query %d disarmed the stall", i)
		}
	}
}

// A timer alarm that is disarmed, or armed again, does not fire the old timer.
func TestTimerAlarmGeneration(t *testing.T) {
	var mu sync.Mutex
	fired := 0
	a := &timerAlarm{fire: func() { mu.Lock(); fired++; mu.Unlock() }}
	a.arm(30 * time.Millisecond)
	a.disarm()
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	if fired != 0 {
		t.Fatal("a disarmed alarm fired")
	}
	mu.Unlock()
	a.arm(20 * time.Millisecond)
	a.arm(300 * time.Millisecond) // the first timer is stale now
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	if fired != 0 {
		t.Fatal("a stale timer fired")
	}
	mu.Unlock()
	a.disarm()
}

// QUIC Retry only under load: the node asks for a Retry only when more than
// limits.RetryUnderLoad handshakes without a validated address are running,
// and a handshake stops counting when it completes, fails, or is validated.
func TestRetryOnlyUnderLoad(t *testing.T) {
	h := &handshakes{}
	if h.verify(nil, nil) {
		t.Fatal("Retry asked on an idle node")
	}
	ctxs := make([]context.CancelFunc, 0, 1100)
	states := make([]*connState, 0, 1100)
	for i := 0; i < 1000; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		ctxs = append(ctxs, cancel)
		c, err := h.connContext(ctx, &quic.ClientInfo{AddrVerified: false}, nil)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, c.Value(connStateKey{}).(*connState))
	}
	if h.pending.Load() != 1000 {
		t.Fatalf("pending %d", h.pending.Load())
	}
	if h.verify(nil, nil) {
		t.Fatal("Retry asked at exactly 1000: the rule is more than 1000")
	}
	// A validated address (a Retry token) is not a handshake without one.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := h.connContext(ctx, &quic.ClientInfo{AddrVerified: true}, nil); err != nil {
		t.Fatal(err)
	}
	if h.pending.Load() != 1000 {
		t.Fatal("a validated handshake was counted")
	}
	c, _ := h.connContext(context.Background(), &quic.ClientInfo{AddrVerified: false}, nil)
	extra := c.Value(connStateKey{}).(*connState)
	if !h.verify(nil, nil) {
		t.Fatal("no Retry over 1000 handshakes in progress")
	}
	// A completed handshake (Accept) stops counting; so does a cancelled one.
	extra.uncount()
	extra.uncount() // once
	if h.pending.Load() != 1000 || h.verify(nil, nil) {
		t.Fatalf("pending %d after one completed", h.pending.Load())
	}
	for _, c := range ctxs[:500] {
		c() // a failed or closed connection cancels its context
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.pending.Load() != 500 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.pending.Load() != 500 {
		t.Fatalf("cancelled handshakes still counted: %d", h.pending.Load())
	}
	for _, s := range states {
		s.uncount()
	}
	if h.pending.Load() != 0 {
		t.Fatalf("pending %d", h.pending.Load())
	}
	if !(&handshakes{forceRetry: true}).verify(nil, nil) {
		t.Fatal("forceRetry does not ask for a Retry")
	}
}
