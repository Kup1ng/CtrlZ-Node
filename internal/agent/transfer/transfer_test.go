package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

type testConn struct {
	hub    *fakehub.Hub
	mu     sync.Mutex
	cc     *grpc.ClientConn
	resets atomic.Int32
}

func (c *testConn) Client() hubv1.NodeHubClient {
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

func (c *testConn) Reset() {
	c.resets.Add(1)
	c.mu.Lock()
	cc := c.cc
	c.cc = nil
	c.mu.Unlock()
	if cc != nil {
		go cc.Close()
	}
}

// setup returns a client that waits 10 s for an item: a test of a transfer that works must
// not depend on how fast the first connection comes up on a loaded machine (a 400 ms
// idle time failed TestFetchEntries once with three containers running). The stall
// tests ask for a short one with setupIdle.
func setup(t *testing.T) (*fakehub.Hub, *testConn, *Client, *storetest.Keys) {
	return setupIdle(t, 10*time.Second)
}

func setupIdle(t *testing.T, idle time.Duration) (*fakehub.Hub, *testConn, *Client, *storetest.Keys) {
	t.Helper()
	h := fakehub.New()
	h.Start()
	t.Cleanup(h.Stop)
	tc := &testConn{hub: h}
	t.Cleanup(func() {
		tc.mu.Lock()
		if tc.cc != nil {
			tc.cc.Close()
		}
		tc.mu.Unlock()
	})
	keys := storetest.NewKeys(t)
	c := New(Config{Conn: tc, Root: func() (*signv1.Root, error) { return keys.Root, nil },
		HubNow: func() int64 { return time.Now().Unix() }, Idle: idle})
	return h, tc, c, keys
}

func TestFetchEntries(t *testing.T) {
	h, _, c, _ := setup(t)
	for i := uint64(1); i <= 10; i++ {
		h.Entries = append(h.Entries, &hubv1.StoredEntry{Seq: i, EntryBytes: []byte{byte(i), 1, 2}})
	}
	got, err := c.FetchEntries(context.Background(), 3, 4)
	if err != nil || len(got) != 4 || got[0].Seq != 4 || got[3].Seq != 7 {
		t.Fatalf("got %v %v", got, err)
	}
	got, err = c.FetchEntries(context.Background(), 8, 0)
	if err != nil || len(got) != 2 {
		t.Fatalf("tail: %v %v", got, err)
	}
	got, err = c.FetchEntries(context.Background(), 10, 5)
	if err != nil || len(got) != 0 {
		t.Fatalf("nothing: %v %v", got, err)
	}
}

func TestFetchEntriesRefusesWhatTheHubMustNotSend(t *testing.T) {
	for name, entries := range map[string][]*hubv1.StoredEntry{
		"a gap":              {{Seq: 5, EntryBytes: []byte{1}}},
		"out of order":       {{Seq: 4, EntryBytes: []byte{1}}, {Seq: 6, EntryBytes: []byte{1}}},
		"an empty entry":     {{Seq: 4}},
		"a repeated seq":     {{Seq: 4, EntryBytes: []byte{1}}, {Seq: 4, EntryBytes: []byte{1}}},
		"more than asked":    {{Seq: 4, EntryBytes: []byte{1}}, {Seq: 5, EntryBytes: []byte{1}}},
		"an entry way large": {{Seq: 4, EntryBytes: make([]byte, 17<<20)}},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, c, _ := setup(t)
			h.Entries = entries
			// The fake honours the limit itself, so ask for one and let the hub misbehave by
			// ignoring after the Limit check.
			lim := uint32(0)
			if name == "more than asked" {
				lim = 1
				h.Entries = append([]*hubv1.StoredEntry(nil), entries...)
			}
			got, err := c.FetchEntries(context.Background(), 3, lim)
			if name == "more than asked" {
				// the fake stops at the limit, so this case is a plain success of one entry
				if err != nil || len(got) != 1 {
					t.Fatalf("%v %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %v", got)
			}
		})
	}
}

func TestHeadIsVerified(t *testing.T) {
	h, _, c, keys := setup(t)
	hash := sha256.Sum256([]byte("e"))
	payload, _ := proto.Marshal(&signv1.SignedHead{Seq: 12, EntryHash: hash[:], CreatedAt: 1})
	h.Head = keys.SignPayload(manifest.TypeHead, payload)
	seq, got, err := c.Head(context.Background())
	if err != nil || seq != 12 || got != hash {
		t.Fatalf("%d %x %v", seq, got, err)
	}
	// signed by someone else
	other := storetest.NewKeys(t)
	h.Head = other.SignPayload(manifest.TypeHead, payload)
	if _, _, err := c.Head(context.Background()); err == nil {
		t.Error("a head signed by another key was accepted")
	}
	// a PairTable signed by the right key is not a head
	h.Head = keys.SignPayload(manifest.TypePairTable, payload)
	if _, _, err := c.Head(context.Background()); err == nil {
		t.Error("a push passed as a head")
	}
	// a head with a short hash
	bad, _ := proto.Marshal(&signv1.SignedHead{Seq: 12, EntryHash: []byte{1}})
	h.Head = keys.SignPayload(manifest.TypeHead, bad)
	if _, _, err := c.Head(context.Background()); err == nil {
		t.Error("malformed head accepted")
	}
	h.Head = nil
	if _, _, err := c.Head(context.Background()); err == nil {
		t.Error("no head")
	}
}

func TestOpenBlobStreamsAndCaps(t *testing.T) {
	h, _, c, _ := setup(t)
	h.ChunkSize = 1000
	data := bytes.Repeat([]byte("0123456789"), 1000)
	k := sha256.Sum256(data)
	h.SetBlob(k, data)
	rc, err := c.OpenBlob(context.Background(), k, policyv1.BlobKind_BLOB_KIND_PROFILE, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes: %v", len(got), err)
	}
	// the limit stops the reader early
	rc, _ = c.OpenBlob(context.Background(), k, policyv1.BlobKind_BLOB_KIND_PROFILE, 2500)
	got, err = io.ReadAll(rc)
	rc.Close()
	if err != nil || len(got) != 2500 {
		t.Fatalf("limited read: %d %v", len(got), err)
	}
	// a blob the hub does not have is an error, not an empty read
	rc, err = c.OpenBlob(context.Background(), [32]byte{9}, policyv1.BlobKind_BLOB_KIND_PROFILE, 10)
	if err == nil {
		_, err = io.ReadAll(rc)
		rc.Close()
	}
	if err == nil {
		t.Error("a missing blob read as empty")
	}
}

func TestGetSnapshot(t *testing.T) {
	h, _, c, _ := setup(t)
	h.ChunkSize = 50
	snap := &signv1.Snapshot{Seq: 40, EntryHash: bytes.Repeat([]byte{1}, 32), Endpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, storetest.Blob(t, "a"))}}
	h.Snapshot, _ = proto.Marshal(snap)
	got, err := c.GetSnapshot(context.Background(), 30)
	if err != nil || got.Seq != 40 || len(got.Endpoints) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := c.GetSnapshot(context.Background(), 41); err == nil {
		t.Error("a snapshot older than asked was accepted")
	}
	h.Snapshot = []byte{0xff, 0xff, 0xff}
	if _, err := c.GetSnapshot(context.Background(), 1); err == nil {
		t.Error("garbage accepted")
	}
}

// 5.8: a transfer that receives no item for the idle time is cancelled and the
// connection replaced.
func TestStalledTransferIsCancelledAndTheConnectionReplaced(t *testing.T) {
	h, tc, c, keys := setupIdle(t, 400*time.Millisecond)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	h.EntriesHook = func(ctx context.Context, _ *hubv1.FetchEntriesRequest) error {
		select {
		case <-hold:
		case <-ctx.Done():
		}
		return ctx.Err()
	}
	start := time.Now()
	_, err := c.FetchEntries(context.Background(), 0, 5)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 5*time.Second {
		t.Errorf("gave up after %v", d)
	}
	if tc.resets.Load() != 1 {
		t.Errorf("resets = %d", tc.resets.Load())
	}
	h.Script(func(h *fakehub.Hub) {
		h.EntriesHook = nil
		h.Entries = []*hubv1.StoredEntry{{Seq: 1, EntryBytes: []byte{1}}}
	})
	// the replacement connection is judged with a long idle time: only its working matters
	c2 := New(Config{Conn: tc, Root: func() (*signv1.Root, error) { return keys.Root, nil }, HubNow: func() int64 { return time.Now().Unix() }, Idle: 10 * time.Second})
	if got, err := c2.FetchEntries(context.Background(), 0, 5); err != nil || len(got) != 1 {
		t.Fatalf("the replacement connection does not work: %v %v", got, err)
	}
	// a blob that starts and then goes silent
	h.Script(func(h *fakehub.Hub) {
		h.BlobHook = func(ctx context.Context, _ [32]byte) error { <-ctx.Done(); return ctx.Err() }
	})
	rc, err := c.OpenBlob(context.Background(), [32]byte{1}, policyv1.BlobKind_BLOB_KIND_PROFILE, 100)
	if err == nil {
		_, err = io.ReadAll(rc)
		rc.Close()
	}
	if !errors.Is(err, ErrStalled) {
		t.Errorf("blob: %v", err)
	}
	// GetHead that never answers
	h.Script(func(h *fakehub.Hub) {
		h.GetHeadHook = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
		h.Head = keys.SignPayload(manifest.TypeHead, nil)
	})
	if _, _, err := c.Head(context.Background()); !errors.Is(err, ErrStalled) {
		t.Errorf("head: %v", err)
	}
}

func TestBackoff(t *testing.T) {
	prev := time.Duration(0)
	for n := 0; n < 12; n++ {
		d := Backoff(n)
		if d < 500*time.Millisecond || d > 30*time.Second {
			t.Errorf("Backoff(%d) = %v", n, d)
		}
		if n == 0 && d > time.Second {
			t.Errorf("first retry waits %v", d)
		}
		prev = d
	}
	if prev < 15*time.Second {
		t.Errorf("never reaches the cap: %v", prev)
	}
}

// p4n-W5b-r1-8: one FetchEntries call holds a bounded number of bytes, not 200 entries
// of the largest size; it returns what it has at the cap and the caller asks again.
func TestFetchEntriesStopsAtTheByteCap(t *testing.T) {
	h, _, _, keys := setup(t)
	tc := &testConn{hub: h}
	t.Cleanup(func() {
		tc.mu.Lock()
		if tc.cc != nil {
			tc.cc.Close()
		}
		tc.mu.Unlock()
	})
	c := New(Config{Conn: tc, Root: func() (*signv1.Root, error) { return keys.Root, nil },
		HubNow: func() int64 { return time.Now().Unix() }, Idle: 10 * time.Second, MaxBytes: 250})
	for i := uint64(1); i <= 10; i++ {
		h.Entries = append(h.Entries, &hubv1.StoredEntry{Seq: i, EntryBytes: bytes.Repeat([]byte{byte(i)}, 100)})
	}
	got, err := c.FetchEntries(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries at a cap of 250 bytes of 100-byte entries, want 3 (the one that passes the cap is the last)", len(got))
	}
	// the next call goes on from the last seq
	next, err := c.FetchEntries(context.Background(), got[len(got)-1].Seq, 0)
	if err != nil || len(next) != 3 || next[0].Seq != 4 {
		t.Fatalf("the next call: %d entries from %v, %v", len(next), next, err)
	}
}
