// Package upload sends the node's counters and activity to the hub on the
// agent's upload connection (SC 8a.11 L10, p4-nodes 5.4, SC 5.2a Counters).
//
// The upload streams share one gRPC connection that is neither the Control
// connection nor the transfer connection, so a slow or stalled upload holds no
// Heartbeat back and a transfer cannot starve an upload. Both are best effort:
// free counters are re-sent until acknowledged or dropped (telem.FreeCounters),
// activity is re-queued when a send fails, and nothing is spooled to disk.
package upload

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/telem"
)

// Conn is the upload connection.
type Conn interface {
	Client() hubv1.NodeHubClient
	Reset()
}

// Config is what an Uploader needs.
type Config struct {
	Conn     Conn
	Counters *telem.FreeCounters
	Activity *telem.Activity

	// CountersPoll is how often the counters queue is looked at (250 ms).
	CountersPoll time.Duration
	// ActivityEvery is the activity period (60 s).
	ActivityEvery time.Duration
	// AckWait is how long an activity batch waits for its Ack (10 s).
	AckWait time.Duration
	// SendTimeout is how long one Send may take (20 s, as on the Control stream).
	SendTimeout time.Duration
	// BackoffMin and BackoffMax bound the wait after a broken stream.
	BackoffMin, BackoffMax time.Duration
}

// Uploader runs the two upload streams.
type Uploader struct{ cfg Config }

// New returns an Uploader.
func New(cfg Config) *Uploader {
	if cfg.CountersPoll == 0 {
		cfg.CountersPoll = 250 * time.Millisecond
	}
	if cfg.ActivityEvery == 0 {
		cfg.ActivityEvery = telem.ActivityEvery
	}
	if cfg.AckWait == 0 {
		cfg.AckWait = 10 * time.Second
	}
	if cfg.SendTimeout == 0 {
		cfg.SendTimeout = 20 * time.Second
	}
	if cfg.BackoffMin == 0 {
		cfg.BackoffMin = time.Second
	}
	if cfg.BackoffMax == 0 {
		cfg.BackoffMax = 30 * time.Second
	}
	return &Uploader{cfg: cfg}
}

// Run runs both streams until ctx ends.
func (u *Uploader) Run(ctx context.Context) {
	var wg sync.WaitGroup
	if u.cfg.Counters != nil {
		wg.Add(1)
		go func() { defer wg.Done(); u.loop(ctx, u.counters) }()
	}
	if u.cfg.Activity != nil {
		wg.Add(1)
		go func() { defer wg.Done(); u.loop(ctx, u.activity) }()
	}
	wg.Wait()
}

// loop runs one stream function again after it fails, with backoff, and
// replaces the upload connection when a stream broke.
func (u *Uploader) loop(ctx context.Context, f func(context.Context) error) {
	backoff := u.cfg.BackoffMin
	for ctx.Err() == nil {
		began := time.Now()
		err := f(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && time.Since(began) < 5*time.Second {
			if backoff *= 2; backoff > u.cfg.BackoffMax {
				backoff = u.cfg.BackoffMax
			}
		} else {
			backoff = u.cfg.BackoffMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// counters keeps one UploadCounters stream: one batch at a time, the next only
// after the Ack of the last and at least 2 s after it (FreeCounters.Next paces
// it), the same batch_id again until acknowledged.
func (u *Uploader) counters(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := u.cfg.Conn.Client().UploadCounters(sctx)
	if err != nil {
		return err
	}
	u.cfg.Counters.Reset()
	acks := make(chan error, 1)
	go func() {
		for {
			a, err := st.Recv()
			if err != nil {
				acks <- err
				return
			}
			u.cfg.Counters.Ack(a.BatchId, a.Durable)
		}
	}()
	t := time.NewTicker(u.cfg.CountersPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-acks:
			return err
		case <-t.C:
			if b := u.cfg.Counters.Next(); b != nil {
				if err := u.send(cancel, func() error { return st.Send(b) }); err != nil {
					return err
				}
			}
		}
	}
}

// activity sends one batch each period on a ReportActivity stream and waits for
// its Ack. A batch that gets no Ack, or whose send failed, goes back into the
// aggregator.
func (u *Uploader) activity(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := u.cfg.Conn.Client().ReportActivity(sctx)
	if err != nil {
		return err
	}
	acks := make(chan *telemetryv1.Ack, 4)
	rerr := make(chan error, 1)
	go func() {
		for {
			a, err := st.Recv()
			if err != nil {
				rerr <- err
				return
			}
			select {
			case acks <- a:
			default:
			}
		}
	}()
	t := time.NewTicker(u.cfg.ActivityEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-rerr:
			return err
		case <-t.C:
		}
		// Flush may wait behind an Apply (it reads the applied state), so it runs
		// here and nowhere that Control or dns waits on.
		// One batch a period: a window larger than one batch goes out over several
		// periods, which the hub's own pace of one batch per 30 s allows.
		if b := u.cfg.Activity.Flush(); b != nil {
			if err := u.send(cancel, func() error { return st.Send(b) }); err != nil {
				u.cfg.Activity.Requeue(b)
				return err
			}
			if !u.waitAck(ctx, b.BatchId, acks, rerr) {
				u.cfg.Activity.Requeue(b)
				u.cfg.Conn.Reset()
				return context.DeadlineExceeded
			}
		}
	}
}

func (u *Uploader) waitAck(ctx context.Context, id uint64, acks chan *telemetryv1.Ack, rerr chan error) bool {
	timer := time.NewTimer(u.cfg.AckWait)
	defer timer.Stop()
	for {
		select {
		case a := <-acks:
			if a.BatchId == id && a.Durable {
				return true
			}
		case <-timer.C:
			return false
		case <-rerr:
			return false
		case <-ctx.Done():
			return true
		}
	}
}

// send runs one Send under SendTimeout. A hub that keeps answering HTTP/2 pings but
// stops reading the stream (its flow-control window full) blocks Send for good, and
// keepalive does not see it, so a Send that has not finished in time cancels the
// stream and replaces the connection, as the Control stream does. Without this the
// goroutine would sit here until the process ended and its queue would only grow.
func (u *Uploader) send(cancel context.CancelFunc, f func() error) error {
	var fired atomic.Bool
	t := time.AfterFunc(u.cfg.SendTimeout, func() { fired.Store(true); cancel() })
	err := f()
	t.Stop()
	if fired.Load() {
		u.cfg.Conn.Reset()
		if err == nil {
			err = context.DeadlineExceeded
		}
	}
	return err
}
