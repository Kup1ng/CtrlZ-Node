package blobfetch_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/blobfetch"
)

const (
	profile = policyv1.BlobKind_BLOB_KIND_PROFILE
	page    = policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE
)

type fn func(ctx context.Context, h [32]byte, kind policyv1.BlobKind, limit int64) (io.ReadCloser, error)

func (f fn) OpenBlob(ctx context.Context, h [32]byte, k policyv1.BlobKind, l int64) (io.ReadCloser, error) {
	return f(ctx, h, k, l)
}

// endless is a body that never ends and counts what was read from it.
type endless struct{ n *atomic.Int64 }

func (e endless) Read(p []byte) (int, error) {
	e.n.Add(int64(len(p)))
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
func (endless) Close() error { return nil }

func TestCapForSizeZeroIsTheKindsMaximum(t *testing.T) {
	if blobfetch.Cap(profile, 0) != wire.MaxProfileBlob || blobfetch.Cap(page, 0) != wire.MaxBlockPageBlob {
		t.Fatal("size 0")
	}
	if blobfetch.Cap(profile, 1000) != 1000 {
		t.Fatal("a known size caps the read at that size")
	}
	// A size above the kind's maximum is not trusted.
	if blobfetch.Cap(page, wire.MaxBlockPageBlob+1) != wire.MaxBlockPageBlob || blobfetch.Cap(profile, 1<<40) != wire.MaxProfileBlob {
		t.Fatal("a size above the maximum")
	}
}

// A hub that streams without end is read up to the cap plus one byte and no more,
// for size 0 and for a known size, for both kinds.
func TestAnEndlessStreamIsReadOnlyToTheCap(t *testing.T) {
	for _, c := range []struct {
		kind policyv1.BlobKind
		size uint64
		want int
	}{
		{profile, 0, wire.MaxProfileBlob + 1},
		{page, 0, wire.MaxBlockPageBlob + 1},
		{profile, 5000, 5001},
		{page, wire.MaxBlockPageBlob + 99, wire.MaxBlockPageBlob + 1},
	} {
		var read atomic.Int64
		f := blobfetch.New(fn(func(_ context.Context, _ [32]byte, _ policyv1.BlobKind, _ int64) (io.ReadCloser, error) {
			return endless{&read}, nil
		}))
		data, ok := f.Fetch([32]byte{1}, c.kind, c.size)
		if !ok || len(data) != c.want {
			t.Fatalf("%v size %d: ok=%v len=%d, want %d", c.kind, c.size, ok, len(data), c.want)
		}
		// The source was asked for the cap and was not drained far beyond it.
		if read.Load() > int64(c.want)+64<<10 {
			t.Fatalf("%v size %d: %d bytes read for a cap of %d", c.kind, c.size, read.Load(), c.want)
		}
	}
}

func TestAShortOrExactBlobIsReturnedAsIs(t *testing.T) {
	body := bytes.Repeat([]byte{7}, 4096)
	f := blobfetch.New(fn(func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}))
	for _, size := range []uint64{0, 4096} {
		if got, ok := f.Fetch([32]byte{}, profile, size); !ok || !bytes.Equal(got, body) {
			t.Fatalf("size %d: %v %d", size, ok, len(got))
		}
	}
}

func TestErrorsAndPanicsAreNotAvailable(t *testing.T) {
	cases := map[string]fn{
		"open error": func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) {
			return nil, errors.New("boom")
		},
		"panic in open": func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) { panic("hostile") },
		"read error": func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) {
			return io.NopCloser(errReader{}), nil
		},
		"panic in read": func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) {
			return io.NopCloser(panicReader{}), nil
		},
		"nil reader": func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) { return nil, nil },
	}
	for name, src := range cases {
		f := blobfetch.New(src)
		if data, ok := f.Fetch([32]byte{}, profile, 0); ok || data != nil {
			t.Errorf("%s: ok=%v", name, ok)
		}
		// The fetcher still works afterwards: no slot was lost.
		for i := 0; i < 2*blobfetch.MaxConcurrent; i++ {
			f.Fetch([32]byte{}, profile, 0)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("reset") }

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("hostile reader") }

// A stalled blob is given up at the timeout, and the caller is released then.
func TestAStalledBlobTimesOut(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	f := blobfetch.New(fn(func(ctx context.Context, _ [32]byte, _ policyv1.BlobKind, _ int64) (io.ReadCloser, error) {
		// A source that ignores its context, the worst case.
		<-block
		return nil, errors.New("late")
	}), blobfetch.WithTimeout(150*time.Millisecond))
	start := time.Now()
	if _, ok := f.Fetch([32]byte{}, profile, 0); ok {
		t.Fatal("ok")
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
}

// A body that stalls mid-stream, and watches its context, ends at the timeout.
func TestAStalledBodyEndsAtTheTimeout(t *testing.T) {
	f := blobfetch.New(fn(func(ctx context.Context, _ [32]byte, _ policyv1.BlobKind, _ int64) (io.ReadCloser, error) {
		return io.NopCloser(stall{ctx}), nil
	}), blobfetch.WithTimeout(150*time.Millisecond))
	start := time.Now()
	if _, ok := f.Fetch([32]byte{}, profile, 0); ok {
		t.Fatal("ok")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("slow")
	}
}

type stall struct{ ctx context.Context }

func (s stall) Read([]byte) (int, error) { <-s.ctx.Done(); return 0, s.ctx.Err() }

// At most four fetches run at once, across all callers, and the rest wait.
func TestAtMostFourFetchesAtOnce(t *testing.T) {
	var cur, peak atomic.Int64
	release := make(chan struct{})
	f := blobfetch.New(fn(func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		cur.Add(-1)
		return io.NopCloser(bytes.NewReader([]byte("x"))), nil
	}))
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, good := f.Fetch([32]byte{}, profile, 0); good {
				ok.Add(1)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	if p := peak.Load(); p != blobfetch.MaxConcurrent {
		t.Fatalf("peak %d while waiting, want %d", p, blobfetch.MaxConcurrent)
	}
	close(release)
	wg.Wait()
	if peak.Load() != blobfetch.MaxConcurrent || ok.Load() != 20 {
		t.Fatalf("peak %d ok %d", peak.Load(), ok.Load())
	}
}

// Four sources that ignore the timeout keep their slots: the real number running
// never goes above four, and a fifth fetch gives up at its own timeout.
func TestStuckSourcesKeepTheirSlots(t *testing.T) {
	block := make(chan struct{})
	var running atomic.Int64
	f := blobfetch.New(fn(func(context.Context, [32]byte, policyv1.BlobKind, int64) (io.ReadCloser, error) {
		running.Add(1)
		<-block
		running.Add(-1)
		return nil, errors.New("late")
	}), blobfetch.WithTimeout(100*time.Millisecond))
	var wg sync.WaitGroup
	for i := 0; i < blobfetch.MaxConcurrent+3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.Fetch([32]byte{}, profile, 0) }()
	}
	wg.Wait() // every caller has given up
	if running.Load() != blobfetch.MaxConcurrent {
		t.Fatalf("%d sources running, want %d", running.Load(), blobfetch.MaxConcurrent)
	}
	close(block)
}

func TestCallerContextEndsAFetch(t *testing.T) {
	f := blobfetch.New(fn(func(ctx context.Context, _ [32]byte, _ policyv1.BlobKind, _ int64) (io.ReadCloser, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, ok := f.FetchContext(ctx, [32]byte{}, profile, 0); ok {
		t.Fatal("ok")
	}
}
