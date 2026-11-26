// Package fakehub is a hub for tests, built from the shared proto and nothing
// else. It is not imported by any non-test code of the node.
//
// It speaks real gRPC over an in-memory listener, so the node's real clients run
// against it, each gRPC connection is a distinct connection that the hub can
// name (the test of L6 and L10 needs to know on which connection each RPC
// arrived), and a test can stall, flood or poison any part of it: a Control
// session that the test drives by hand, transfer streams with hooks, upload
// streams with an acknowledgement policy.
package fakehub

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/test/bufconn"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
)

// RPC is one RPC the hub saw and the connection it came on.
type RPC struct {
	Method string
	Conn   uint64
}

type connKey struct{}
type rpcKey struct{}

// Hub is the fake. Fields set before Start are its script.
type Hub struct {
	hubv1.UnimplementedNodeHubServer

	// Transfers.
	Entries     []*hubv1.StoredEntry // served by FetchEntries, in seq order
	Head        *signv1.Envelope     // GetHead
	Blobs       map[[32]byte][]byte  // FetchBlob
	Snapshot    []byte               // GetSnapshot, marshalled signv1.Snapshot
	ChunkSize   int                  // 0 means 32 KiB
	EntriesHook func(ctx context.Context, req *hubv1.FetchEntriesRequest) error
	BlobHook    func(ctx context.Context, hash [32]byte) error
	GetHeadHook func(ctx context.Context) error

	// Uploads: AckCounters decides the Ack for a counters batch; nil acks durably.
	AckCounters func(b *telemetryv1.CountersBatch) *telemetryv1.Ack
	AckActivity func(b *telemetryv1.ActivityBatch) *telemetryv1.Ack

	// RenewCert answers RenewCert; nil is Unimplemented.
	Renew func(*hubv1.RenewCertRequest) (*hubv1.RenewCertResponse, error)

	lis *bufconn.Listener
	srv *grpc.Server

	mu       sync.Mutex
	rpcs     []RPC
	sessions chan *Session
	counters []*telemetryv1.CountersBatch
	activity []*telemetryv1.ActivityBatch
	connSeq  atomic.Uint64
	rpcSeq   atomic.Uint64
}

// Script changes the scripted fields while the hub runs. The handlers read them
// under the same lock, so a test that edits Entries, Head, a hook or an ack
// policy mid-run does not race with the RPCs in flight.
func (h *Hub) Script(f func(h *Hub)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f(h)
}

// New returns a Hub with empty scripts.
func New() *Hub {
	return &Hub{Blobs: map[[32]byte][]byte{}, sessions: make(chan *Session, 64)}
}

// Start begins serving. Options are added to the gRPC server (a test can add TLS
// credentials, but the in-memory listener needs none).
func (h *Hub) Start(opts ...grpc.ServerOption) {
	h.lis = bufconn.Listen(1 << 20)
	opts = append(opts, grpc.StatsHandler(h))
	h.srv = grpc.NewServer(opts...)
	hubv1.RegisterNodeHubServer(h.srv, h)
	go func() { _ = h.srv.Serve(h.lis) }()
}

// Stop ends the hub: every stream is cancelled.
func (h *Hub) Stop() { h.srv.Stop() }

// Dial returns a new client connection to the hub. Each call is a new HTTP/2
// connection, as each of the node's three connections is.
func (h *Hub) Dial(opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append([]grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return h.lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, opts...)
	return grpc.NewClient("passthrough:///fakehub", opts...)
}

// ---- stats.Handler: names connections and records RPCs.

func (h *Hub) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return context.WithValue(ctx, connKey{}, h.connSeq.Add(1))
}
func (h *Hub) HandleConn(context.Context, stats.ConnStats) {}
func (h *Hub) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	id, _ := ctx.Value(connKey{}).(uint64)
	h.mu.Lock()
	h.rpcs = append(h.rpcs, RPC{Method: info.FullMethodName, Conn: id})
	h.mu.Unlock()
	return context.WithValue(ctx, rpcKey{}, id)
}
func (h *Hub) HandleRPC(context.Context, stats.RPCStats) {}

func connOf(ctx context.Context) uint64 {
	id, _ := ctx.Value(rpcKey{}).(uint64)
	return id
}

// RPCs returns every RPC seen so far, in order.
func (h *Hub) RPCs() []RPC {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]RPC(nil), h.rpcs...)
}

// ConnsOf returns the set of connections that carried a method.
func (h *Hub) ConnsOf(method string) map[uint64]bool {
	out := map[uint64]bool{}
	for _, r := range h.RPCs() {
		if r.Method == method {
			out[r.Conn] = true
		}
	}
	return out
}

// ---- Control

// Session is one Control stream, driven by the test.
type Session struct {
	Conn uint64

	srv    grpc.BidiStreamingServer[hubv1.NodeMessage, hubv1.HubMessage]
	ctx    context.Context
	mu     sync.Mutex
	in     []*hubv1.NodeMessage
	times  []time.Time
	notify chan struct{}
	done   chan struct{}
	end    chan struct{}
	endOne sync.Once
	sendMu sync.Mutex
}

// Control implements the RPC: it hands the stream to the test through Next and
// keeps it open until the test ends it or the node does.
func (h *Hub) Control(srv grpc.BidiStreamingServer[hubv1.NodeMessage, hubv1.HubMessage]) error {
	s := &Session{Conn: connOf(srv.Context()), srv: srv, ctx: srv.Context(), notify: make(chan struct{}, 1), done: make(chan struct{}), end: make(chan struct{})}
	select {
	case h.sessions <- s:
	default:
	}
	go func() {
		defer close(s.done)
		for {
			m, err := srv.Recv()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.in = append(s.in, m)
			s.times = append(s.times, time.Now())
			s.mu.Unlock()
			select {
			case s.notify <- struct{}{}:
			default:
			}
		}
	}()
	select {
	case <-s.ctx.Done():
	case <-s.end:
	}
	return s.ctx.Err()
}

// End closes the stream from the hub's side.
func (s *Session) End() { s.endOne.Do(func() { close(s.end) }) }

// NextSession waits for the node to open a Control stream.
func (h *Hub) NextSession(timeout time.Duration) (*Session, error) {
	select {
	case s := <-h.sessions:
		return s, nil
	case <-time.After(timeout):
		return nil, errors.New("fakehub: no Control stream")
	}
}

// Send writes a HubMessage. It blocks as a real hub's write would when the node
// does not read; use SendAsync from a test that must not wait.
func (s *Session) Send(m *hubv1.HubMessage) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.srv.Send(m)
}

// Messages returns the NodeMessages received so far.
func (s *Session) Messages() []*hubv1.NodeMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*hubv1.NodeMessage(nil), s.in...)
}

// Times returns the receive time of each message of Messages.
func (s *Session) Times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.times...)
}

// Wait blocks until a received message satisfies pred, and returns it.
func (s *Session) Wait(timeout time.Duration, pred func(*hubv1.NodeMessage) bool) (*hubv1.NodeMessage, error) {
	deadline := time.After(timeout)
	seen := 0
	for {
		s.mu.Lock()
		msgs := s.in[seen:]
		seen = len(s.in)
		s.mu.Unlock()
		for _, m := range msgs {
			if pred(m) {
				return m, nil
			}
		}
		select {
		case <-s.notify:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			return nil, errors.New("fakehub: timed out waiting for a NodeMessage")
		case <-s.done:
			// one last look
			s.mu.Lock()
			for _, m := range s.in[seen:] {
				if pred(m) {
					s.mu.Unlock()
					return m, nil
				}
			}
			s.mu.Unlock()
			return nil, io.EOF
		}
	}
}

// Done is closed when the node ended the stream.
func (s *Session) Done() <-chan struct{} { return s.done }

// ---- transfers

func (h *Hub) chunk() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ChunkSize > 0 {
		return h.ChunkSize
	}
	return 32 << 10
}

// FetchEntries serves the scripted entries after a seq.
func (h *Hub) FetchEntries(req *hubv1.FetchEntriesRequest, srv grpc.ServerStreamingServer[hubv1.StoredEntry]) error {
	h.mu.Lock()
	hook, all := h.EntriesHook, append([]*hubv1.StoredEntry(nil), h.Entries...)
	h.mu.Unlock()
	if hook != nil {
		if err := hook(srv.Context(), req); err != nil {
			return err
		}
	}
	n := uint32(0)
	for _, e := range all {
		if e.Seq <= req.AfterSeq {
			continue
		}
		if req.Limit != 0 && n >= req.Limit {
			break
		}
		if err := srv.Send(e); err != nil {
			return err
		}
		n++
	}
	return nil
}

// GetHead returns the scripted signed head.
func (h *Hub) GetHead(ctx context.Context, _ *hubv1.GetHeadRequest) (*signv1.Envelope, error) {
	h.mu.Lock()
	hook, head := h.GetHeadHook, h.Head
	h.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return nil, err
		}
	}
	if head == nil {
		return nil, errors.New("no head")
	}
	return head, nil
}

func (h *Hub) sendChunks(data []byte, off uint64, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	if off > uint64(len(data)) {
		return errors.New("offset beyond the end")
	}
	data = data[off:]
	for {
		n := min(len(data), h.chunk())
		last := n == len(data)
		if err := srv.Send(&hubv1.BlobChunk{Offset: off, Data: data[:n], Last: last}); err != nil {
			return err
		}
		off += uint64(n)
		data = data[n:]
		if last {
			return nil
		}
	}
}

// FetchBlob serves a scripted blob.
func (h *Hub) FetchBlob(req *hubv1.FetchBlobRequest, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	var k [32]byte
	copy(k[:], req.Hash)
	h.mu.Lock()
	hook := h.BlobHook
	d, ok := h.Blobs[k]
	h.mu.Unlock()
	if hook != nil {
		if err := hook(srv.Context(), k); err != nil {
			return err
		}
	}
	if !ok {
		return errors.New("no such blob")
	}
	return h.sendChunks(d, req.Offset, srv)
}

// SetBlob adds a blob while the hub runs.
func (h *Hub) SetBlob(k [32]byte, d []byte) {
	h.mu.Lock()
	h.Blobs[k] = d
	h.mu.Unlock()
}

// GetSnapshot serves the scripted snapshot.
func (h *Hub) GetSnapshot(_ *hubv1.GetSnapshotRequest, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	h.mu.Lock()
	snap := h.Snapshot
	h.mu.Unlock()
	if snap == nil {
		return errors.New("no snapshot")
	}
	return h.sendChunks(snap, 0, srv)
}

// RenewCert answers through the Renew script.
func (h *Hub) RenewCert(_ context.Context, r *hubv1.RenewCertRequest) (*hubv1.RenewCertResponse, error) {
	h.mu.Lock()
	renew := h.Renew
	h.mu.Unlock()
	if renew == nil {
		return nil, errors.New("not scripted")
	}
	return renew(r)
}

// ---- uploads

// UploadCounters records batches and acknowledges them.
func (h *Hub) UploadCounters(srv grpc.BidiStreamingServer[telemetryv1.CountersBatch, telemetryv1.Ack]) error {
	for {
		b, err := srv.Recv()
		if err != nil {
			return nil
		}
		h.mu.Lock()
		h.counters = append(h.counters, b)
		h.mu.Unlock()
		ack := &telemetryv1.Ack{BatchId: b.BatchId, Durable: true}
		h.mu.Lock()
		policy := h.AckCounters
		h.mu.Unlock()
		if policy != nil {
			ack = policy(b)
		}
		if ack != nil {
			if err := srv.Send(ack); err != nil {
				return err
			}
		}
	}
}

// ReportActivity records batches and acknowledges them.
func (h *Hub) ReportActivity(srv grpc.BidiStreamingServer[telemetryv1.ActivityBatch, telemetryv1.Ack]) error {
	for {
		b, err := srv.Recv()
		if err != nil {
			return nil
		}
		h.mu.Lock()
		h.activity = append(h.activity, b)
		h.mu.Unlock()
		ack := &telemetryv1.Ack{BatchId: b.BatchId, Durable: true}
		h.mu.Lock()
		policy := h.AckActivity
		h.mu.Unlock()
		if policy != nil {
			ack = policy(b)
		}
		if ack != nil {
			if err := srv.Send(ack); err != nil {
				return err
			}
		}
	}
}

// Counters returns the counters batches received, in order, repeats included.
func (h *Hub) Counters() []*telemetryv1.CountersBatch {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*telemetryv1.CountersBatch(nil), h.counters...)
}

// Activity returns the activity batches received.
func (h *Hub) Activity() []*telemetryv1.ActivityBatch {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*telemetryv1.ActivityBatch(nil), h.activity...)
}
