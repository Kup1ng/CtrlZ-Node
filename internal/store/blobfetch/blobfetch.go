// Package blobfetch is the node's quarantine.Fetcher: it reads blobs from the hub
// with the limits of spec p4-nodes 7.2 and SC 9.7 item 2 (T-533, D31).
//
// Why the limits live here: quarantine.Apply checks size and SHA-256 only after
// the Fetcher has returned the bytes, and blob.Open runs later still. A hub that
// streams without end, or a ref whose size is 0 (only the hash is known), would
// otherwise fill the node's memory before any check could refuse it. So:
//
//   - the read is capped by the kind's maximum (wire.MaxProfileBlob 64 MiB,
//     wire.MaxBlockPageBlob 2 MiB) when the size is 0 or above the maximum, and by
//     the ref's size otherwise; one byte more than the cap is read so an overlong
//     stream is seen as a size mismatch by Apply (reported as hash_mismatch, kept
//     wanted) rather than as a clean shorter blob;
//   - a fetch takes at most 60 s from the moment it asks for a slot;
//   - at most 4 fetches run at once, across every caller (Apply, Retry, a
//     snapshot), the slot held until the source returns even when the 60 s have
//     passed, so a source that ignores its context cannot raise the real count;
//   - a panic in the source, or a source that returns an error, is a blob that is
//     not available now: ok=false, which Apply files as missing and tries again.
package blobfetch

import (
	"context"
	"errors"
	"io"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// Limits of D31.
const (
	Timeout       = 60 * time.Second
	MaxConcurrent = 4
)

// Source is the hub's FetchBlob as the node sees it. The agent's Control end
// implements it over a gRPC stream on the transfer connection (L6).
type Source interface {
	// OpenBlob starts a transfer of the blob and returns its bytes as a stream.
	// limit is the most the caller will read; a source may use it to stop early.
	// ctx ends the transfer: the Fetcher cancels it at its deadline.
	OpenBlob(ctx context.Context, hash [32]byte, kind policyv1.BlobKind, limit int64) (io.ReadCloser, error)
}

// Fetcher implements quarantine.Fetcher.
type Fetcher struct {
	src     Source
	timeout time.Duration
	slots   chan struct{}
}

// Option changes a Fetcher, for tests.
type Option func(*Fetcher)

// WithTimeout replaces the 60 s limit.
func WithTimeout(d time.Duration) Option { return func(f *Fetcher) { f.timeout = d } }

// New returns a Fetcher over src.
func New(src Source, opts ...Option) *Fetcher {
	f := &Fetcher{src: src, timeout: Timeout, slots: make(chan struct{}, MaxConcurrent)}
	for _, o := range opts {
		o(f)
	}
	return f
}

// Max is the largest blob of a kind.
func Max(kind policyv1.BlobKind) int64 {
	if kind == policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE {
		return wire.MaxBlockPageBlob
	}
	return wire.MaxProfileBlob
}

// Cap is the most bytes a fetch of this blob may deliver: the ref's size when it
// is known and within the kind's maximum, the maximum otherwise.
func Cap(kind policyv1.BlobKind, size uint64) int64 {
	m := Max(kind)
	if size != 0 && size <= uint64(m) {
		return int64(size)
	}
	return m
}

type result struct {
	data []byte
	err  error
}

// Fetch implements quarantine.Fetcher. It returns the bytes the source gave, at
// most Cap+1 of them, or ok=false when the blob is not available now.
func (f *Fetcher) Fetch(hash [32]byte, kind policyv1.BlobKind, size uint64) (data []byte, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	return f.FetchContext(ctx, hash, kind, size)
}

// FetchContext is Fetch under the caller's context as well as the 60 s limit.
func (f *Fetcher) FetchContext(ctx context.Context, hash [32]byte, kind policyv1.BlobKind, size uint64) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	// The wait for a slot counts against the 60 s: a fetch that cannot start does
	// not hold Apply for ever behind four stuck ones.
	select {
	case f.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	done := make(chan result, 1)
	go func() {
		// The slot is released when the source returns, not when the caller gives up.
		defer func() { <-f.slots }()
		done <- f.read(ctx, hash, kind, Cap(kind, size))
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, false
		}
		return r.data, true
	case <-ctx.Done():
		return nil, false
	}
}

// read runs in its own goroutine and recovers from a source that panics.
func (f *Fetcher) read(ctx context.Context, hash [32]byte, kind policyv1.BlobKind, limit int64) (r result) {
	defer func() {
		if p := recover(); p != nil {
			r = result{err: errors.New("blobfetch: source panicked")}
		}
	}()
	rc, err := f.src.OpenBlob(ctx, hash, kind, limit)
	if err != nil {
		return result{err: err}
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(&ctxReader{ctx: ctx, r: rc}, limit+1))
	if err != nil {
		return result{err: err}
	}
	return result{data: b}
}

// ctxReader stops reading when the context ends, for a source whose stream does
// not watch it.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
