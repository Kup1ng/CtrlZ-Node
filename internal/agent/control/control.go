// Package control is the agent's end of the hub's Control stream (p4-nodes 7.3,
// SC 12, SC 8a.11 L10 and L11, p4-nodes 5.8).
//
// What the rules ask of it, and where each is kept:
//
//   - A Heartbeat is the first NodeMessage of every stream and goes before every
//     other message whenever it is due (session writer loop). It is built by a
//     callback that reads atomics only, never under a lock that Apply holds.
//   - What an outside party can cause (ProofObservation, LearnedIP,
//     BlockUnblockRequest) waits in a queue of 256 that drops a new message when
//     full, paced to 20 a second, with a repeat inside 60 s dropped (sender.go).
//     The node's own reports (ApplyResult and the like) have a queue of their own.
//   - The receive loop only reads. It takes ServerTime, HeadNotice and
//     FreeDnsOff itself, as a few instructions on memory, and offers every other
//     message to a bounded queue that never blocks it. Each kind of work has its
//     own queue and goroutine, so a stall in one holds back that kind alone.
//   - A pushed PairTable goes to the table writer's queue (the push worker), a
//     HeadNotice only raises the highest head seq that the log worker fetches to
//     (the callback), so one that arrives while that worker is busy is not lost.
//   - The stream is cut and opened again when no ServerTime has come for 30 s,
//     and when a send has not finished in SendTimeout: a hub that holds the
//     stream open and says nothing is not a hub the node can wait for.
//
// Uploads and transfers are not here: they go on their own gRPC connections
// (packages upload and transfer), never on the one that carries Control (L6,
// L10).
package control

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// Callbacks are what the agent plugs into the stream. The first group runs on the
// receive loop and must be a few instructions on memory: no lock that Apply or a
// fetch holds, no I/O, no channel send that can block. The second group runs on a
// goroutine of its own per kind.
type Callbacks struct {
	// ServerTime: a valid ServerTime arrived (now in Unix seconds).
	ServerTime func(now int64)
	// HeadNotice: raise the highest head seq to fetch to and wake the log worker.
	HeadNotice func(seq uint64, release bool)
	// FreeDNSOff: a valid FreeDnsOff arrived.
	FreeDNSOff func(version uint64)
	// StreamState is called with true when a stream is open (its first Heartbeat
	// sent) and false when it ends.
	StreamState func(up bool)

	// Push is the table writer: it applies one pushed PairTable envelope.
	Push       func(ctx context.Context, env *signv1.Envelope)
	Revocation func(ctx context.Context, r *policyv1.Revocation)
	NodeConfig func(ctx context.Context, c *hubv1.NodeConfig)
	CertBundle func(ctx context.Context, c *hubv1.CertBundle)
	Acme       func(ctx context.Context, c *hubv1.AcmeChallenge)
}

// Config is what a Client needs. Zero durations take the production values; tests
// shorten them.
type Config struct {
	// Hub is the hub client; HubFn, when set, is asked for it at the start of every
	// stream, so a connection that failed to dial is dialled again.
	Hub   hubv1.NodeHubClient
	HubFn func() hubv1.NodeHubClient
	// Heartbeat builds the Heartbeat that is due. It must not wait on Apply.
	Heartbeat func() *hubv1.Heartbeat
	CB        Callbacks
	Now       func() time.Time

	HeartbeatEvery    time.Duration // 5 s
	ServerTimeTimeout time.Duration // 30 s without a ServerTime ends the stream
	SendTimeout       time.Duration // 20 s for one Send
	BackoffMin        time.Duration // 1 s
	BackoffMax        time.Duration // 30 s

	// Trace, when set, sees every NodeMessage in the order it is handed to the
	// stream. It is the hook of the L10 test.
	Trace func(*hubv1.NodeMessage)
}

// Client runs the Control stream.
type Client struct {
	cfg Config
	snd *sender

	pushQ *queue[*signv1.Envelope]
	revQ  *queue[*policyv1.Revocation]
	cfgQ  *queue[*hubv1.NodeConfig]
	certQ *queue[*hubv1.CertBundle]
	acmeQ *queue[*hubv1.AcmeChallenge]

	lastST   atomic.Int64 // unix nanos of the last ServerTime of this stream, 0 before one
	streams  atomic.Uint64
	ignored  atomic.Uint64
	sendFail atomic.Uint64
	up       atomic.Bool
}

// New returns a Client.
func New(cfg Config) *Client {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	d := func(v *time.Duration, def time.Duration) {
		if *v == 0 {
			*v = def
		}
	}
	d(&cfg.HeartbeatEvery, 5*time.Second)
	d(&cfg.ServerTimeTimeout, 30*time.Second)
	d(&cfg.SendTimeout, 20*time.Second)
	d(&cfg.BackoffMin, time.Second)
	d(&cfg.BackoffMax, 30*time.Second)
	return &Client{
		cfg:   cfg,
		snd:   newSender(cfg.Now),
		pushQ: newQueue[*signv1.Envelope](4, true),
		revQ:  newRevQueue(),
		cfgQ:  newQueue[*hubv1.NodeConfig](1, true),
		certQ: newQueue[*hubv1.CertBundle](16, true),
		acmeQ: newQueue[*hubv1.AcmeChallenge](64, true),
	}
}

// Report queues one of the node's own messages for the hub.
func (c *Client) Report(m *hubv1.NodeMessage) { c.snd.Report(m) }

// Outside queues a ProofObservation, LearnedIP or BlockUnblockRequest.
func (c *Client) Outside(m *hubv1.NodeMessage) bool { return c.snd.Outside(m) }

// Up reports whether a stream is open.
func (c *Client) Up() bool { return c.up.Load() }

// Stats are counters for tests and for the agent's own report.
type Stats struct {
	Streams         uint64
	Ignored         uint64
	SendFailures    uint64
	OutsideDropped  uint64
	OutsideRepeats  uint64
	OutsideTooOld   uint64
	ReportsDropped  uint64
	PushesDropped   uint64
	ConfigsDropped  uint64
	RevocationsLost uint64
}

// Stats returns the counters.
func (c *Client) Stats() Stats {
	c.snd.mu.Lock()
	rep, old, full := c.snd.repeats, c.snd.tooOld, c.snd.fullSeen
	c.snd.mu.Unlock()
	return Stats{
		Streams: c.streams.Load(), Ignored: c.ignored.Load(), SendFailures: c.sendFail.Load(),
		OutsideDropped: c.snd.outside.dropped.Load() + full, OutsideRepeats: rep, OutsideTooOld: old,
		ReportsDropped: c.snd.reports.dropped.Load(), PushesDropped: c.pushQ.dropped.Load(),
		ConfigsDropped: c.cfgQ.dropped.Load(), RevocationsLost: c.revQ.dropped.Load(),
	}
}

// Run opens Control streams until ctx ends, with backoff between them, and runs
// the workers behind the queues.
func (c *Client) Run(ctx context.Context) {
	var wg sync.WaitGroup
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	if f := c.cfg.CB.Push; f != nil {
		start(func() { c.pushQ.run(ctx, f) })
	}
	if f := c.cfg.CB.Revocation; f != nil {
		start(func() { c.revQ.run(ctx, f) })
	}
	if f := c.cfg.CB.NodeConfig; f != nil {
		start(func() { c.cfgQ.run(ctx, f) })
	}
	if f := c.cfg.CB.CertBundle; f != nil {
		start(func() { c.certQ.run(ctx, f) })
	}
	if f := c.cfg.CB.Acme; f != nil {
		start(func() { c.acmeQ.run(ctx, f) })
	}
	defer wg.Wait()

	backoff := c.cfg.BackoffMin
	for ctx.Err() == nil {
		began := c.cfg.Now()
		gotTime := c.session(ctx)
		if gotTime || c.cfg.Now().Sub(began) > c.cfg.ServerTimeTimeout {
			backoff = c.cfg.BackoffMin
		}
		// Jitter, so the nodes of an install do not reconnect in step after a hub
		// restart.
		wait := backoff/2 + time.Duration(rand.Int63n(int64(backoff)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > c.cfg.BackoffMax {
			backoff = c.cfg.BackoffMax
		}
	}
}

func (c *Client) heartbeat() (hb *hubv1.Heartbeat) {
	defer func() {
		if recover() != nil {
			hb = nil
		}
	}()
	return c.cfg.Heartbeat()
}

// session is one stream. It reports whether a ServerTime arrived on it.
func (c *Client) session(ctx context.Context) (gotServerTime bool) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hub := c.cfg.Hub
	if c.cfg.HubFn != nil {
		hub = c.cfg.HubFn()
	}
	stream, err := hub.Control(sctx)
	if err != nil {
		return false
	}
	c.lastST.Store(0)
	send := func(m *hubv1.NodeMessage) error {
		// A Send that does not finish (the hub reads nothing, or a relay holds the
		// stream) ends the stream; nothing else waits on this goroutine but the
		// next message.
		t := time.AfterFunc(c.cfg.SendTimeout, cancel)
		defer t.Stop()
		if c.cfg.Trace != nil {
			c.cfg.Trace(m)
		}
		return stream.Send(m)
	}

	// The Heartbeat is first, before the reader or anything queued.
	hb := c.heartbeat()
	if hb == nil {
		return false
	}
	if err := send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: hb}}); err != nil {
		c.sendFail.Add(1)
		return false
	}
	hbDue := c.cfg.Now().Add(c.cfg.HeartbeatEvery)
	c.streams.Add(1)
	c.up.Store(true)
	if f := c.cfg.CB.StreamState; f != nil {
		f(true)
	}
	defer func() {
		c.up.Store(false)
		if f := c.cfg.CB.StreamState; f != nil {
			f(false)
		}
	}()

	// The receive loop only reads.
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		defer cancel()
		for {
			m, err := stream.Recv()
			if err != nil {
				return
			}
			c.dispatch(m)
		}
	}()

	began := c.cfg.Now()
	for {
		// A due Heartbeat goes before anything queued.
		now := c.cfg.Now()
		if !now.Before(hbDue) {
			if hb := c.heartbeat(); hb != nil {
				if err := send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: hb}}); err != nil {
					c.sendFail.Add(1)
					break
				}
			}
			hbDue = c.cfg.Now().Add(c.cfg.HeartbeatEvery)
			continue
		}
		// No ServerTime for ServerTimeTimeout: the hub cannot decide or something
		// holds the stream. Open another.
		last := time.Unix(0, c.lastST.Load())
		if c.lastST.Load() == 0 {
			last = began
		}
		if now.Sub(last) >= c.cfg.ServerTimeTimeout {
			break
		}
		m, wait := c.snd.next()
		if m != nil {
			if err := send(m); err != nil {
				c.snd.unsent(m)
				c.sendFail.Add(1)
				break
			}
			continue
		}
		sleep := hbDue.Sub(now)
		if d := last.Add(c.cfg.ServerTimeTimeout).Sub(now); d < sleep {
			sleep = d
		}
		if wait > 0 && wait < sleep {
			sleep = wait
		}
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		t := time.NewTimer(sleep)
		select {
		case <-sctx.Done():
			t.Stop()
			cancel()
			<-recvDone
			return c.lastST.Load() != 0
		case <-recvDone:
			t.Stop()
			return c.lastST.Load() != 0
		case <-c.snd.wake:
		case <-c.snd.reports.wake:
		case <-c.snd.outside.wake:
		case <-t.C:
		}
		t.Stop()
	}
	cancel()
	<-recvDone
	return c.lastST.Load() != 0
}

// validServerTime refuses a clock that is not a date of this century.
func validServerTime(now int64) bool { return now > 1_600_000_000 && now < 4_000_000_000 }

// dispatch handles one HubMessage on the receive loop. Nothing in it waits.
func (c *Client) dispatch(m *hubv1.HubMessage) {
	// A callback that panics costs the message, never the loop.
	defer func() {
		if recover() != nil {
			c.ignored.Add(1)
		}
	}()
	switch b := m.GetBody().(type) {
	case *hubv1.HubMessage_ServerTime:
		now := b.ServerTime.GetNow()
		if !validServerTime(now) {
			c.ignored.Add(1)
			return
		}
		c.lastST.Store(c.cfg.Now().UnixNano())
		if f := c.cfg.CB.ServerTime; f != nil {
			f(now)
		}
	case *hubv1.HubMessage_HeadNotice:
		if b.HeadNotice == nil || b.HeadNotice.Seq == 0 {
			c.ignored.Add(1)
			return
		}
		if f := c.cfg.CB.HeadNotice; f != nil {
			f(b.HeadNotice.Seq, b.HeadNotice.Release)
		}
	case *hubv1.HubMessage_FreeDnsOff:
		if wire.ValidateFreeDnsOff(b.FreeDnsOff) != nil {
			c.ignored.Add(1)
			return
		}
		if f := c.cfg.CB.FreeDNSOff; f != nil {
			f(b.FreeDnsOff.Version)
		}
	case *hubv1.HubMessage_PairTable:
		if b.PairTable == nil {
			c.ignored.Add(1)
			return
		}
		c.pushQ.push(b.PairTable)
	case *hubv1.HubMessage_Revocation:
		if b.Revocation == nil || wire.ValidateRevocation(b.Revocation) != nil {
			c.ignored.Add(1)
			return
		}
		c.revQ.push(b.Revocation)
	case *hubv1.HubMessage_NodeConfig:
		if b.NodeConfig == nil {
			c.ignored.Add(1)
			return
		}
		c.cfgQ.push(b.NodeConfig)
	case *hubv1.HubMessage_CertBundle:
		if b.CertBundle == nil {
			c.ignored.Add(1)
			return
		}
		c.certQ.push(b.CertBundle)
	case *hubv1.HubMessage_AcmeChallenge:
		if b.AcmeChallenge == nil {
			c.ignored.Add(1)
			return
		}
		c.acmeQ.push(b.AcmeChallenge)
	default:
		c.ignored.Add(1)
	}
}
