package apply

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// recorder wraps the real Fetcher for one Apply, Retry or snapshot. Two jobs.
//
// It keeps a hostile or broken hub from filling memory. quarantine.Apply keeps
// every byte slice it is given until it has judged the blob, and a hub that
// serves many wrong blobs would make one Apply hold them all. The recorder checks
// each fetch against the hash and size it was asked for and, when they differ,
// hands Apply an empty slice instead: Apply then reports the same hash_mismatch
// it would have, keeps the blob wanted (9.7 item 3), and the bad bytes are freed
// at once.
//
// It stages what is right. A fetch whose bytes are what the panel named is
// written to quarantine/incoming/ and not held in memory. After Apply has decided
// what each blob is, persist promotes a profile or a block page into blobs/, sets
// aside bytes that hash right but do not open, and drops the rest. Nothing is
// visible to dns until the state that names it is committed.
//
// It also carries the call's context. quarantine.Fetcher has no context, and the
// apply mutex is held for as long as an Apply, Retry or snapshot runs (a
// hard_disable behind it waits, SC 9.7 item 2), so the recorder is where a call is
// made to end: once the context is done a fetch is not
// started and counts as not available now, and a fetch in flight is cancelled when
// the inner Fetcher takes a context (blobfetch does).
type recorder struct {
	root   *store.Root
	inner  quarantine.Fetcher
	ctx    context.Context
	staged map[[32]byte]struct{}
	// stopped is set when a fetch was refused or cut because the call had to end,
	// and lastDone is the last hash whose fetch ran to its end (found or not).
	// Retry uses them to put the wanted cursor back to where the work really
	// stopped.
	stopped  bool
	lastDone [32]byte
	done     bool
	// budget, when not zero, is how long the fetches of this call may spend failing
	// (a stall that ran to its timeout, a blob the hub does not have) before the
	// rest are refused. It is for the calls of the entry stream: quarantine.Apply
	// walks up to MaxWantedPerApply wanted blobs after the entry's own, and a hub
	// that stalls would otherwise hold a hard_disable for that many timeouts.
	// Fetches that succeed do not count, so a slow link that works is not cut.
	budget    time.Duration
	failedFor time.Duration
	// refused counts the fetches this recorder turned away, so a test can tell a
	// loop that kept walking after the budget was spent from one that stopped.
	refused int
	// held is the set of blobs the node still has on disk under the image it
	// serves. A fetch for one of them is answered from the file when it hashes to
	// its name and has the size asked for, and goes to the hub only when it does
	// not (a rotted or missing file).
	held map[[32]byte]struct{}
}

// fromHeld returns the bytes of a held blob. Nothing is staged: the file is in
// blobs/ already, and persist leaves it there.
func (r *recorder) fromHeld(h [32]byte, size uint64) ([]byte, bool) {
	if _, ok := r.held[h]; !ok {
		return nil, false
	}
	data, err := r.root.ReadBlob(h) // checks the hash
	if err != nil || (size != 0 && uint64(len(data)) != size) {
		return nil, false
	}
	return data, true
}

// contextFetcher is what blobfetch.Fetcher offers beyond quarantine.Fetcher.
type contextFetcher interface {
	FetchContext(ctx context.Context, hash [32]byte, kind policyv1.BlobKind, size uint64) ([]byte, bool)
}

func newRecorder(ctx context.Context, root *store.Root, inner quarantine.Fetcher, budget time.Duration) *recorder {
	return &recorder{root: root, inner: inner, ctx: ctx, budget: budget, staged: map[[32]byte]struct{}{}}
}

// Fetch implements quarantine.Fetcher.
func (r *recorder) Fetch(h [32]byte, kind policyv1.BlobKind, size uint64) ([]byte, bool) {
	if r.exhausted() {
		r.stopped = true
		r.refused++
		return nil, false
	}
	if data, ok := r.fromHeld(h, size); ok {
		r.lastDone, r.done = h, true
		return data, true
	}
	start := time.Now()
	var (
		data []byte
		ok   bool
	)
	if cf, isCtx := r.inner.(contextFetcher); isCtx {
		data, ok = cf.FetchContext(r.ctx, h, kind, size)
	} else {
		data, ok = r.inner.Fetch(h, kind, size)
	}
	if r.ctx.Err() == nil {
		r.lastDone, r.done = h, true
	}
	if !ok {
		r.failedFor += time.Since(start)
		if r.ctx.Err() != nil {
			r.stopped = true
		}
		return nil, false
	}
	if (size != 0 && uint64(len(data)) != size) || sha256.Sum256(data) != h {
		// A transfer that ended in wrong bytes failed all the same, and a slow hub
		// that answers late with garbage must use the budget as one that answers
		// nothing does (r4-1).
		r.failedFor += time.Since(start)
		return []byte{}, true
	}
	if err := r.root.StageBlob(h, data); err != nil {
		// A node that cannot write is not served a blob it could not keep: the
		// blob counts as not available now and is tried again.
		return nil, false
	}
	r.staged[h] = struct{}{}
	return data, true
}

// persist settles every staged blob against the state Apply produced. A blob that
// is in the new state's profiles or block pages goes into blobs/; one that is
// newly quarantined goes to quarantine/; any other is deleted. A staged blob whose
// file is already in blobs/ and hashes to its name is deleted, not renamed over it.
// A file that is there but rotted is replaced by the fresh bytes (an atomic
// rename); otherwise the sweep would keep the rotted one for as long as an image
// names it (review round 3, r3-6).
func (r *recorder) persist(old, work *quarantine.State) error {
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for h := range r.staged {
		_, isProfile := work.Profiles[h]
		isPage := work.BlockPages[h]
		_, bad := work.Quarantined[h]
		_, wasBad := old.Quarantined[h]
		switch {
		case (isProfile || isPage) && !r.root.BlobIntact(h):
			note(r.root.PromoteBlob(h))
		case bad && !wasBad:
			if err := r.root.SetAsideStaged(h); err != nil && !errors.Is(err, fs.ErrNotExist) {
				note(err)
			}
		default:
			r.root.DropStaged(h)
		}
		delete(r.staged, h)
	}
	return firstErr
}

// cleanup deletes what is still staged. Safe to call twice.
func (r *recorder) cleanup() {
	for h := range r.staged {
		r.root.DropStaged(h)
		delete(r.staged, h)
	}
}

// exhausted reports that the call can fetch no more: its context is done or the
// failing fetches have used the budget. Loops that only exist to fetch check it,
// so they end instead of walking a list of refusals (r4-2).
func (r *recorder) exhausted() bool {
	return r.ctx.Err() != nil || (r.budget > 0 && r.failedFor >= r.budget)
}
