package upload

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/telem"
)

type conn struct {
	hub    *fakehub.Hub
	mu     sync.Mutex
	cc     *grpc.ClientConn
	resets atomic.Int32
}

func (c *conn) Client() hubv1.NodeHubClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc == nil {
		cc, err := c.hub.Dial()
		if err != nil {
			panic(err)
		}
		c.cc = cc
	}
	return hubv1.NewNodeHubClient(c.cc)
}

func (c *conn) Reset() {
	c.resets.Add(1)
	c.mu.Lock()
	cc := c.cc
	c.cc = nil
	c.mu.Unlock()
	if cc != nil {
		go cc.Close()
	}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 800; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// a clock the test moves
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) adv(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestCountersAreSentAcknowledgedAndRepeatedUntilDurable(t *testing.T) {
	h := fakehub.New()
	var nAcks atomic.Int32
	h.AckCounters = func(b *telemetryv1.CountersBatch) *telemetryv1.Ack {
		switch nAcks.Add(1) {
		case 1:
			return nil // lost ack
		case 2:
			return &telemetryv1.Ack{BatchId: b.BatchId} // not durable
		}
		return &telemetryv1.Ack{BatchId: b.BatchId, Durable: true}
	}
	h.Start()
	t.Cleanup(h.Stop)
	c := &conn{hub: h}
	clk := &clock{t: time.Unix(2_000_100, 0)}
	fc := telem.NewFreeCounters(clk.now, nil)
	fc.ResendAfter = 200 * time.Millisecond
	key := telem.FreeKey{Proto: commonv1.Protocol_PROTOCOL_UDP, Outcome: telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED}
	fc.Add(key, 5)
	clk.adv(300 * time.Second) // the bucket ends
	u := New(Config{Conn: c, Counters: fc, CountersPoll: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	// The time of the test's clock does not move by itself; the 2 s gap and the
	// resend wait are judged on it, so move it in steps while the loop polls.
	eventually(t, "three sends of one batch", func() bool {
		clk.adv(3 * time.Second)
		return len(h.Counters()) >= 3
	})
	got := h.Counters()
	for _, b := range got {
		if b.BatchId != got[0].BatchId || len(b.Free) != 1 || b.Free[0].Count != 5 {
			t.Fatalf("a resend changed the batch: %v", b)
		}
	}
	eventually(t, "the queue to empty", func() bool { clk.adv(3 * time.Second); return fc.Stats().Queued == 0 })
	n := len(h.Counters())
	time.Sleep(150 * time.Millisecond)
	if len(h.Counters()) != n {
		t.Error("an acknowledged batch was sent again")
	}
	if err := wire.ValidateTelemetryMessage(got[0], clk.now().Unix()); err != nil {
		t.Errorf("the hub's door refuses what the node sends: %v", err)
	}
}

func TestStreamFailureResendsOnANewStream(t *testing.T) {
	h := fakehub.New()
	var first atomic.Bool
	h.AckCounters = func(b *telemetryv1.CountersBatch) *telemetryv1.Ack {
		if first.CompareAndSwap(false, true) {
			h.Stop() // the hub dies without acknowledging
			return nil
		}
		return &telemetryv1.Ack{BatchId: b.BatchId, Durable: true}
	}
	h.Start()
	c := &conn{hub: h}
	clk := &clock{t: time.Unix(2_000_100, 0)}
	fc := telem.NewFreeCounters(clk.now, nil)
	fc.Add(telem.FreeKey{Proto: commonv1.Protocol_PROTOCOL_TCP, Outcome: telemetryv1.FreeOutcome_FREE_OUTCOME_RD0}, 1)
	clk.adv(300 * time.Second)
	u := New(Config{Conn: c, Counters: fc, CountersPoll: 20 * time.Millisecond, BackoffMin: 20 * time.Millisecond, BackoffMax: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, "the first send", func() bool { clk.adv(3 * time.Second); return len(h.Counters()) >= 1 })
	// the hub is gone: the node keeps the batch queued and does not crash
	time.Sleep(200 * time.Millisecond)
	if fc.Stats().Queued != 1 {
		t.Errorf("queued %d: a batch that was never acknowledged must stay", fc.Stats().Queued)
	}
}

func TestActivityIsSentEveryPeriodAndRequeuedWithoutAnAck(t *testing.T) {
	h := fakehub.New()
	var mode atomic.Int32 // 0 ack, 1 no ack
	h.AckActivity = func(b *telemetryv1.ActivityBatch) *telemetryv1.Ack {
		if mode.Load() == 1 {
			return nil
		}
		return &telemetryv1.Ack{BatchId: b.BatchId, Durable: true}
	}
	h.Start()
	t.Cleanup(h.Stop)
	c := &conn{hub: h}
	now := time.Unix(2_000_100, 0)
	var ep [16]byte
	ep[0] = 1
	rec := recs{ep: {Clients: map[[16]byte]struct{}{identity.ClientHash("default"): {}}, Cap: 1}}
	act := telem.NewActivity(rec, func() time.Time { return now }, nil)
	add := func(label string) {
		act.Add(telem.Report{EndpointID: ep, ClientLabel: label, Protocol: commonv1.Protocol_PROTOCOL_DOH, At: now})
	}
	u := New(Config{Conn: c, Activity: act, ActivityEvery: 50 * time.Millisecond, AckWait: 150 * time.Millisecond, BackoffMin: 10 * time.Millisecond, BackoffMax: 30 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	add("default")
	eventually(t, "the first batch", func() bool { return len(h.Activity()) == 1 })
	if e := h.Activity()[0].Entries; len(e) != 1 || e[0].ClientLabel != "default" {
		t.Fatalf("entries %v", e)
	}
	// nothing new: nothing sent
	time.Sleep(200 * time.Millisecond)
	if len(h.Activity()) != 1 {
		t.Error("an empty period sent a batch")
	}
	// no ack: the entries are queued again and go out once the hub answers
	mode.Store(1)
	now = now.Add(300 * time.Second)
	add("default")
	eventually(t, "a batch that is not acknowledged", func() bool { return len(h.Activity()) >= 2 })
	mode.Store(0)
	eventually(t, "the same entry again", func() bool {
		n := 0
		for _, b := range h.Activity()[1:] {
			for _, e := range b.Entries {
				if e.LastSeenBucket == 2_000_400 {
					n++
				}
			}
		}
		return n >= 2
	})
}

type recs map[[16]byte]telem.EndpointInfo

func (r recs) Lookup(eps [][16]byte) map[[16]byte]telem.EndpointInfo {
	out := map[[16]byte]telem.EndpointInfo{}
	for _, e := range eps {
		if i, ok := r[e]; ok {
			out[e] = i
		}
	}
	return out
}

// ---- p4n-W5b-r5-2: a Send the hub never reads ends the stream

// stuckClient opens streams whose Send blocks until the stream's context ends, as
// one does when the hub holds the flow-control window shut and still answers pings.
type stuckClient struct {
	hubv1.NodeHubClient
	opened atomic.Int32
}

type stuckStream[Req, Res any] struct {
	grpc.ClientStream
	ctx context.Context
}

func (s *stuckStream[Req, Res]) Send(*Req) error     { <-s.ctx.Done(); return s.ctx.Err() }
func (s *stuckStream[Req, Res]) Recv() (*Res, error) { <-s.ctx.Done(); return nil, s.ctx.Err() }

func (c *stuckClient) UploadCounters(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[telemetryv1.CountersBatch, telemetryv1.Ack], error) {
	c.opened.Add(1)
	return &stuckStream[telemetryv1.CountersBatch, telemetryv1.Ack]{ctx: ctx}, nil
}

func (c *stuckClient) ReportActivity(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[telemetryv1.ActivityBatch, telemetryv1.Ack], error) {
	c.opened.Add(1)
	return &stuckStream[telemetryv1.ActivityBatch, telemetryv1.Ack]{ctx: ctx}, nil
}

type stuckConn struct {
	cl     *stuckClient
	resets atomic.Int32
}

func (c *stuckConn) Client() hubv1.NodeHubClient { return c.cl }
func (c *stuckConn) Reset()                      { c.resets.Add(1) }

func TestASendTheHubNeverReadsEndsTheStreamAndResetsTheConnection(t *testing.T) {
	c := &stuckConn{cl: &stuckClient{}}
	clk := &clock{t: time.Unix(2_000_100, 0)}
	fc := telem.NewFreeCounters(clk.now, nil)
	fc.Add(telem.FreeKey{Proto: commonv1.Protocol_PROTOCOL_UDP, Outcome: telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED}, 1)
	clk.adv(300 * time.Second)
	var ep [16]byte
	ep[0] = 1
	rec := recs{ep: {Clients: map[[16]byte]struct{}{identity.ClientHash("default"): {}}, Cap: 1}}
	act := telem.NewActivity(rec, clk.now, nil)
	act.Add(telem.Report{EndpointID: ep, ClientLabel: "default", Protocol: commonv1.Protocol_PROTOCOL_DOH, At: clk.now()})
	u := New(Config{Conn: c, Counters: fc, Activity: act, CountersPoll: 10 * time.Millisecond, ActivityEvery: 20 * time.Millisecond,
		SendTimeout: 100 * time.Millisecond, BackoffMin: 10 * time.Millisecond, BackoffMax: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	// Both goroutines must come back and open a second stream: each Send gave up.
	eventually(t, "both streams reopened after a stuck Send", func() bool {
		clk.adv(3 * time.Second)
		return c.cl.opened.Load() >= 4 && c.resets.Load() >= 2
	})
	if fc.Stats().Queued != 1 {
		t.Errorf("the counters batch left the queue (%d) though it was never acknowledged", fc.Stats().Queued)
	}
}
