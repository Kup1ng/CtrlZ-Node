// Package transfer is the agent's use of the hub's transfer RPCs: FetchEntries,
// GetHead, FetchBlob and GetSnapshot (p4-nodes 5.8, SC 12, SC 8a.11 L6).
//
// They go on a gRPC connection of their own, never on the one that carries
// Control, so a slow or stalled transfer at either end holds none of the node's
// ServerTime or pushes back. A transfer that receives no item for 30 s is
// cancelled and the connection is replaced, because whatever stalled it may be
// the connection (a relay holding it). The caller backs off between attempts
// (Backoff).
//
// The package implements the two seams of the store: blobfetch.Source (OpenBlob)
// and apply.SnapshotSource (GetSnapshot), plus the signed head the Applier holds
// snapshots against.
package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
)

// Limits.
const (
	// IdleTimeout is how long a transfer RPC may go without an item.
	IdleTimeout = 30 * time.Second
	// MaxSnapshotBytes bounds a snapshot read into memory. A snapshot holds
	// records, not blobs; the cap is generous and finite.
	MaxSnapshotBytes = 256 << 20
	// MaxEntriesPerFetch is the most entries one FetchEntries call asks for.
	MaxEntriesPerFetch = 200
	// MaxBytesPerFetch bounds the entry bytes one FetchEntries call holds in memory.
	// The call returns what it has when it reaches it (at most one entry past it).
	MaxBytesPerFetch = 64 << 20
)

// ErrStalled is returned when a transfer got no item for the idle time. The
// connection has been replaced.
var ErrStalled = errors.New("transfer: no item from the hub for too long")

// Conn is the transfer connection, which the agent can replace.
type Conn interface {
	Client() hubv1.NodeHubClient
	// Reset drops the connection so the next Client call dials a new one.
	Reset()
}

// RootFunc returns the trusted root.
type RootFunc func() (*signv1.Root, error)

// Config is what a Client needs.
type Config struct {
	Conn Conn
	Root RootFunc
	// HubNow is the node's clock plus the offset from the latest ServerTime
	// (8a.4 Clock), in Unix seconds, for judging the head's signature validity.
	HubNow func() int64
	// Idle replaces IdleTimeout, for tests.
	Idle time.Duration
	// MaxBytes replaces MaxBytesPerFetch, for tests.
	MaxBytes int
	// Batch replaces MaxEntriesPerFetch, for tests.
	Batch int
}

// Client is the transfer client.
type Client struct{ cfg Config }

// New returns a Client.
func New(cfg Config) *Client {
	if cfg.Batch == 0 {
		cfg.Batch = MaxEntriesPerFetch
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = MaxBytesPerFetch
	}
	if cfg.Idle == 0 {
		cfg.Idle = IdleTimeout
	}
	return &Client{cfg: cfg}
}

// watch runs an idle timer over one RPC. kick is called on every item; when the
// timer fires first the RPC's context is cancelled, the connection is replaced
// and stalled becomes true.
type watch struct {
	t       *time.Timer
	idle    time.Duration
	mu      sync.Mutex
	stalled bool
}

func (c *Client) watch(cancel context.CancelFunc) *watch {
	w := &watch{idle: c.cfg.Idle}
	w.t = time.AfterFunc(w.idle, func() {
		w.mu.Lock()
		w.stalled = true
		w.mu.Unlock()
		c.cfg.Conn.Reset()
		cancel()
	})
	return w
}

func (w *watch) kick() { w.t.Reset(w.idle) }
func (w *watch) stop() { w.t.Stop() }
func (w *watch) wasStalled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stalled
}

// fail maps an error of an RPC that the watchdog cancelled to ErrStalled.
func (w *watch) fail(err error) error {
	if w.wasStalled() {
		return ErrStalled
	}
	return err
}

// ErrLogGap is what FetchEntries returns when the hub's first entry is above the
// one asked for. It is the node's cue to ask for a snapshot rather than to retry.
var ErrLogGap = errors.New("transfer: the hub's log has no entry at the seq asked for")

// FetchEntries returns up to limit stored entries after seq `after`, in order.
// The hub's entry_hash field is not trusted and not used: Apply checks the
// chain over the stored bytes (prev_hash), which is what the signed head
// vouches for.
func (c *Client) FetchEntries(ctx context.Context, after uint64, limit uint32) ([]apply.Stored, error) {
	if limit == 0 || limit > uint32(c.cfg.Batch) {
		limit = uint32(c.cfg.Batch)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := c.watch(cancel)
	defer w.stop()
	st, err := c.cfg.Conn.Client().FetchEntries(ctx, &hubv1.FetchEntriesRequest{AfterSeq: after, Limit: limit})
	if err != nil {
		return nil, w.fail(err)
	}
	var out []apply.Stored
	total := 0
	for {
		e, err := st.Recv()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, w.fail(err)
		}
		w.kick()
		if len(out) == 0 && e.Seq > after+1 {
			// The hub starts above what the node asked for: the log below its oldest
			// kept entry is gone, so only a snapshot bridges the node (p4-nodes 6.5).
			return nil, ErrLogGap
		}
		if e.Seq != after+uint64(len(out))+1 || len(out) >= int(limit) {
			return out, errors.New("transfer: entries out of order or more than asked")
		}
		if len(e.EntryBytes) == 0 || len(e.EntryBytes) > wire.MaxEntrySize {
			return out, errors.New("transfer: an entry of an impossible size")
		}
		out = append(out, apply.Stored{Seq: e.Seq, Bytes: e.EntryBytes})
		// The count is bounded and each entry is, but together they are 200 times
		// wire.MaxEntrySize: stop at the byte cap and let the caller ask again from
		// the last seq. Cancelling the stream (the deferred cancel) ends the rest.
		if total += len(e.EntryBytes); total >= c.cfg.MaxBytes {
			return out, nil
		}
	}
}

// Head returns the signed head: GetHead, verified against the root by the policy
// role at hubNow, never taken on the hub's word.
func (c *Client) Head(ctx context.Context) (seq uint64, hash [32]byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Idle)
	defer cancel()
	env, err := c.cfg.Conn.Client().GetHead(ctx, &hubv1.GetHeadRequest{})
	if err != nil {
		// gRPC's deadline timer and the context's are two timers, so the error can
		// arrive a moment before ctx.Err() is set: the status code says it too.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
			c.cfg.Conn.Reset()
			return 0, hash, ErrStalled
		}
		return 0, hash, fmt.Errorf("transfer: GetHead: %w", err)
	}
	root, err := c.cfg.Root()
	if err != nil {
		return 0, hash, fmt.Errorf("transfer: root: %w", err)
	}
	payload, err := manifest.Verify(env, root, signv1.Role_ROLE_POLICY, manifest.TypeHead, c.cfg.HubNow())
	if err != nil {
		return 0, hash, fmt.Errorf("transfer: signed head: %w", err)
	}
	var h signv1.SignedHead
	if err := proto.Unmarshal(payload, &h); err != nil || len(h.EntryHash) != 32 || h.Seq == 0 {
		return 0, hash, errors.New("transfer: malformed signed head")
	}
	copy(hash[:], h.EntryHash)
	return h.Seq, hash, nil
}

// chunkReader is a stream of BlobChunks as an io.Reader with an idle watchdog,
// a cap and an offset check.
type chunkReader struct {
	st interface {
		Recv() (*hubv1.BlobChunk, error)
	}
	cancel context.CancelFunc
	w      *watch
	buf    []byte
	off    uint64
	limit  int64
	read   int64
	last   bool
	err    error
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.limit > 0 && r.read >= r.limit {
		return 0, io.EOF
	}
	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.last || (r.limit > 0 && r.read >= r.limit) {
			return 0, io.EOF
		}
		ch, err := r.st.Recv()
		if err == io.EOF {
			r.err = io.EOF
			continue
		}
		if err != nil {
			r.err = r.w.fail(err)
			continue
		}
		r.w.kick()
		if ch.Offset != r.off {
			r.err = errors.New("transfer: chunk at an unexpected offset")
			continue
		}
		r.buf, r.off, r.last = ch.Data, r.off+uint64(len(ch.Data)), ch.Last
	}
	n := copy(p, r.buf)
	if r.limit > 0 && r.read+int64(n) > r.limit {
		n = int(r.limit - r.read)
	}
	r.buf = r.buf[n:]
	r.read += int64(n)
	return n, nil
}

func (r *chunkReader) Close() error {
	r.w.stop()
	r.cancel()
	return nil
}

// OpenBlob implements blobfetch.Source: FetchBlob as a stream of the blob's
// bytes. limit is the most the caller will read; the reader stops there.
func (c *Client) OpenBlob(ctx context.Context, hash [32]byte, _ policyv1.BlobKind, limit int64) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	w := c.watch(cancel)
	st, err := c.cfg.Conn.Client().FetchBlob(ctx, &hubv1.FetchBlobRequest{Hash: hash[:]})
	if err != nil {
		w.stop()
		cancel()
		return nil, w.fail(err)
	}
	return &chunkReader{st: st, cancel: cancel, w: w, limit: limit}, nil
}

// GetSnapshot implements apply.SnapshotSource. The snapshot is untrusted until
// ApplySnapshot validated it and the chain from it reaches the signed head.
func (c *Client) GetSnapshot(ctx context.Context, atLeast uint64) (*signv1.Snapshot, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := c.watch(cancel)
	defer w.stop()
	st, err := c.cfg.Conn.Client().GetSnapshot(ctx, &hubv1.GetSnapshotRequest{AtLeastSeq: atLeast})
	if err != nil {
		return nil, w.fail(err)
	}
	var buf []byte
	var off uint64
	for {
		ch, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, w.fail(err)
		}
		w.kick()
		if ch.Offset != off {
			return nil, errors.New("transfer: snapshot chunk at an unexpected offset")
		}
		if int64(len(buf))+int64(len(ch.Data)) > MaxSnapshotBytes {
			return nil, errors.New("transfer: snapshot over the cap")
		}
		buf = append(buf, ch.Data...)
		off += uint64(len(ch.Data))
		if ch.Last {
			break
		}
	}
	snap := &signv1.Snapshot{}
	if err := proto.Unmarshal(buf, snap); err != nil {
		return nil, errors.New("transfer: snapshot does not decode")
	}
	if snap.Seq < atLeast {
		return nil, errors.New("transfer: the hub's snapshot is older than asked")
	}
	return snap, nil
}

// Backoff is the retry delay after the n-th failure in a row, from 1 s to 30 s,
// with jitter (5.8).
func Backoff(n int) time.Duration {
	d := time.Second
	for i := 0; i < n && d < 30*time.Second; i++ {
		d *= 2
	}
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d/2 + time.Duration(rand.Int63n(int64(d)/2+1))
}

// Batch is the most entries one FetchEntries call returns.
func (c *Client) Batch() uint32 { return uint32(c.cfg.Batch) }
