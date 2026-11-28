// Package apply is the node's apply core: quarantine.Apply per stored entry,
// serially, with the persistence, the zone table and the serving image around it
// (spec p4-nodes 7.2 and 7.3, SC 9.7, Plan T-074 and T-533).
//
// # One entry, in order
//
//  1. Decode the entry and, when it carries a PairTable, check that a zone table
//     builds from it with the flag map as it is (item 1). A failure refuses the
//     entry: nothing advances, nothing is fetched.
//  2. quarantine.Apply on a copy of the state, with a Fetcher that stages each
//     verified blob on disk (so one Apply holds one blob in memory, not all of
//     them). The copy is the rollback: Apply replaces the maps it was given
//     instead of editing them.
//  3. SetMembership on the table writer: the table in use is built from this
//     entry's membership and the flag map as it is now, and swapped (item 4). It
//     is the last memory step and the only one that can still refuse the entry,
//     so it comes before any disk write that would have to be undone.
//  4. Disk, none of it visible to a reader yet: blobs promoted into blobs/, bytes
//     that hash right but do not open set aside in quarantine/, the entry stored
//     in log/, the image built in image/<name>/.
//  5. The state file is written. This is the commit point: a restart before it
//     sees the state before the entry, after it the state after.
//  6. image/current is renamed to the new image. The image is what dns serves
//     from, so it changes last, only for a state that is already durable.
//
// A failure of steps 4 or 5 undoes step 3 and leaves the old state in memory and
// on disk; the agent retries the entry. A failure of step 6 (the state is
// committed) keeps the new state and marks the image stale, and the next call
// rebuilds it, so the node never reports an entry as applied that a restart
// would not find.
//
// Retry (the wanted list, no entry) and ApplySnapshot (a node that is new or
// behind the log) go through the same commit.
//
// Everything here is serialised by one mutex: Apply is serial by contract (a
// hard_disable or a claim delete waits behind it), and so is Retry. What an entry
// waits for is bounded: every call takes a context that ends its fetches, an entry
// or snapshot stops fetching once its failing fetches have used
// Config.FailedFetchBudget, and a Retry is cancelled by the next entry that
// arrives (beginEntry).
package apply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/push"
)

// DefaultLogKeep is how many stored entries the log keeps behind applied_seq. The
// hub snapshots every 1000 entries (D31), so the log "from the latest snapshot on"
// (7.2) is at most about 1000 long; twice that leaves room for a snapshot that is
// late. Provisional.
const DefaultLogKeep = 2000

// DefaultFailedFetchBudget bounds what failing fetches may cost one call of the
// entry stream. With the 60 s limit of one fetch (D31) an Apply is held for at most
// about two minutes by a hub that stalls, instead of MaxWantedPerApply timeouts in
// a row. Provisional until the P4 load test.
const DefaultFailedFetchBudget = 60 * time.Second

// ErrGap is returned when an entry is beyond applied_seq+1 and no snapshot source
// can bridge it.
var ErrGap = errors.New("apply: gap in the log and no snapshot source")

// ErrStaleSnapshot is returned for a snapshot at or below applied_seq.
var ErrStaleSnapshot = errors.New("apply: snapshot is not ahead of applied_seq")

// SnapshotSource is the hub's GetSnapshot as the node sees it; the agent's Control
// end implements it over the transfer connection (L6). The returned snapshot is
// untrusted bytes until ApplySnapshot has validated it. The chain from it to the
// signed head is checked by Apply on each later entry (prev_hash); that the snapshot
// is not beyond the signed head is checked by ApplyEntries against Config.Head, or by
// the source itself when Head is nil.
type SnapshotSource interface {
	GetSnapshot(ctx context.Context, atLeastSeq uint64) (*signv1.Snapshot, error)
}

// Tables is the table writer as the apply core uses it. *push.Writer is the
// production implementation; the interface exists so a test can make the build
// of item 4 fail after item 1 passed (L11).
type Tables interface {
	Load(member *policyv1.PairTable, now int64) push.LoadResult
	CheckMembership(pt *policyv1.PairTable) error
	SetMembership(pt *policyv1.PairTable) (undo func(), err error)
}

var _ Tables = (*push.Writer)(nil)

// Config is what an Applier needs.
type Config struct {
	Root      *store.Root
	Fetcher   quarantine.Fetcher // the blobfetch.Fetcher in production
	Tables    Tables
	Snapshots SnapshotSource // optional: without it a gap is ErrGap
	// Head, when set, returns the seq and entry hash of the head the agent has verified
	// (GetHead and its signature). ApplyEntries refuses a snapshot that is above it, or
	// at its seq with another hash, before applying it. Nil leaves that check to the
	// SnapshotSource.
	Head    func(ctx context.Context) (seq uint64, entryHash [32]byte, err error)
	LogKeep uint64 // 0 means DefaultLogKeep
	// FailedFetchBudget is how long one ApplyEntry or ApplySnapshot may spend on
	// fetches that fail before it stops fetching (0 means DefaultFailedFetchBudget).
	FailedFetchBudget time.Duration
	// Now is the node's clock in Unix seconds, for push.Writer.Load; nil means the system clock.
	Now func() int64
}

// Applier owns the applied state of the node.
type Applier struct {
	cfg Config

	mu         sync.Mutex
	cur        *store.Applied
	imageStale bool
	// floor is the seq of an image that image/current serves while the state is behind
	// it (a lost or rolled-back state file); floorBlobs are the blobs that image lists.
	// While the state is below floor nothing built from it is served (see Open).
	floor      atomic.Uint64
	floorBlobs [][32]byte
	// floorSet is floorBlobs as a set. The blobs are on disk, verified by their hash
	// when read, and a call that needs one takes it from there before asking the hub.
	floorSet   map[[32]byte]struct{}
	deferredGC map[[32]byte]struct{}

	// pm guards the two fields below. It is never held across work, so an entry can
	// always reach it while a Retry holds mu.
	pm          sync.Mutex
	entriesWait int    // ApplyEntry and ApplySnapshot calls that are running or waiting for mu
	retryCancel func() // cancels the Retry that holds mu, nil when none

	// Readable without the lock, so a Heartbeat is never built under one that
	// Apply holds (L11).
	appliedSeq atomic.Uint64
}

// OpenReport says what Open did beyond loading the files.
type OpenReport struct {
	Load  store.LoadReport
	Push  push.LoadResult
	Image ImageAtStart
	// Swept is how many blob files that nothing names were deleted.
	Swept int
}

// ImageAtStart is what Open found about image/current.
type ImageAtStart uint8

const (
	ImageOK ImageAtStart = iota + 1
	ImageRebuilt
	ImageNone // nothing applied yet, so no image to build
)

// Open loads the state, repairs what a crash or rot left, loads the table
// writer from the state's membership and makes image/current match the state.
func Open(cfg Config) (*Applier, OpenReport, error) {
	if cfg.Root == nil || cfg.Fetcher == nil || cfg.Tables == nil {
		return nil, OpenReport{}, errors.New("apply: Root, Fetcher and Tables are required")
	}
	if cfg.LogKeep == 0 {
		cfg.LogKeep = DefaultLogKeep
	}
	if cfg.FailedFetchBudget == 0 {
		cfg.FailedFetchBudget = DefaultFailedFetchBudget
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	a := &Applier{cfg: cfg, deferredGC: map[[32]byte]struct{}{}}
	var rep OpenReport
	cur, lrep, err := cfg.Root.LoadApplied()
	if err != nil {
		return nil, rep, err
	}
	rep.Load, a.cur = lrep, cur
	a.adoptServedImage()
	a.appliedSeq.Store(cur.Q.AppliedSeq)
	if len(lrep.Lost) > 0 {
		// The state in memory is the repaired one; persist it so the wanted list
		// and the degraded Endpoints survive another restart.
		if err := cfg.Root.SaveApplied(cur); err != nil {
			return nil, rep, fmt.Errorf("apply: save repaired state: %w", err)
		}
	}
	rep.Push = cfg.Tables.Load(cur.Member, cfg.Now())
	rep.Image = ImageNone
	if a.floor.Load() > 0 {
		// The image is ahead of the state and stays (see adoptServedImage).
		rep.Image = ImageOK
	} else if cur.Q.AppliedSeq > 0 {
		ok, err := a.imageMatches()
		if err != nil {
			return nil, rep, err
		}
		rep.Image = ImageOK
		if !ok {
			if _, err := a.publishImage(a.cur); err != nil {
				return nil, rep, fmt.Errorf("apply: build the image at start: %w", err)
			}
			rep.Image = ImageRebuilt
		}
	}
	// An image that a cut left behind (built, never made current) is of no use.
	if cn, err := image.CurrentName(cfg.Root.Path(store.DirImage)); err == nil {
		_ = image.Prune(cfg.Root.Path(store.DirImage), cn)
	}
	rep.Swept = a.sweepBlobs()
	a.trimQuarantine()
	return a, rep, nil
}

// adoptServedImage handles an image/current that is ahead of the state: the state
// file was lost, damaged or restored from an older copy while dns kept serving the
// image. The image is the newest policy this node has served, and a hard_disable or
// a claim delete that it holds must stay in effect, so the node never serves
// anything older: its seq becomes the floor. Until the state has caught up to the
// floor, commits persist the state but build and swap no image, and the zone
// table and free DNS value of the image stay in use (instead of the node running
// with no table until the hub answers). The image itself is the durable record of
// the floor, so a restart finds the same situation. The state stays where it is,
// so the agent asks for a snapshot at or above the floor (ApplyEntries).
func (a *Applier) adoptServedImage() {
	im, err := image.OpenCurrent(a.cfg.Root.Path(store.DirImage))
	if err != nil || im.Seq() <= a.cur.Q.AppliedSeq {
		return
	}
	a.floor.Store(im.Seq())
	a.floorBlobs = im.Blobs()
	a.floorSet = make(map[[32]byte]struct{}, len(a.floorBlobs))
	for _, h := range a.floorBlobs {
		a.floorSet[h] = struct{}{}
	}
	a.cur.Member = im.PairTable()
	a.cur.FreeDNS = nil
	if enabled, qps, version, ok := im.FreeDNS(); ok {
		a.cur.FreeDNS = &policyv1.FreeDns{Enabled: enabled, Qps: qps, Version: version}
	}
}

// newRec makes the recorder of one call. While there is a floor, the blobs of the
// served image are given to it as held: after a lost state every one of them is
// named again by the snapshot or the entries, and fetching them from the hub
// would cost a full download while a stale image is served and the apply lock is
// held (review round 3, r3-5).
func (a *Applier) newRec(ctx context.Context, budget time.Duration) *recorder {
	r := newRecorder(ctx, a.cfg.Root, a.cfg.Fetcher, budget)
	r.held = a.floorSet
	return r
}

// Floor is the seq of the image being served while the state is behind it, 0 when
// the state is at or ahead of what is served. It never blocks.
func (a *Applier) Floor() uint64 { return a.floor.Load() }

// AppliedSeq is the seq of the last applied entry. It never blocks.
func (a *Applier) AppliedSeq() uint64 { return a.appliedSeq.Load() }

// Inspect runs fn on the applied state under the lock. fn must not keep or edit
// anything it is given; it is for reports and tests.
func (a *Applier) Inspect(fn func(*store.Applied)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a.cur)
}

// Result is the outcome of one call.
type Result struct {
	// Report is the shared apply report. Report.Advanced says whether applied_seq
	// moved; Report.Entry is set when the entry itself was refused (the agent
	// sends QuarantineReport{scope=entry}).
	Report quarantine.Report
	// Skipped is true for an entry at or below applied_seq, which changes nothing.
	Skipped bool
	// Err is a failure of the node's own disk or of a panic inside the apply. The
	// state is unchanged and the agent retries.
	Err error
	// ImageErr is a failure to publish the image after the state was committed.
	// The state is advanced; the next call rebuilds the image.
	ImageErr error
	// Image is the directory name of the current image after the call.
	Image string
}

func entryFailure(seq uint64, err error) *quarantine.Failure {
	f := &quarantine.Failure{Scope: quarantine.ScopeEntry, Seq: seq, Reason: reason.Panic, Section: "pair_table"}
	var be *zone.BuildError
	if errors.As(err, &be) {
		f.Reason = reason.BadSection
	}
	return f
}

// ApplyEntry applies one stored entry (the exact bytes the chain hashed).
func (a *Applier) ApplyEntry(ctx context.Context, stored []byte) (res Result) {
	defer a.beginEntry()()
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			res = Result{Err: errors.New("apply: panic while applying an entry")}
		}
	}()
	a.fixImage(&res)

	entry, derr := wire.DecodeEntry(stored)
	if derr == nil && entry.Seq <= a.cur.Q.AppliedSeq {
		// A resend after a reconnect. Left to quarantine.Apply it would come back as
		// an entry failure (index_range), and the agent would report a fault that
		// two nodes could raise together for nothing (r3-2).
		res.Skipped = true
		return res
	}
	if derr == nil && entry.Seq == a.cur.Q.AppliedSeq+1 && entry.PairTable != nil {
		// Item 1: the table builds from this entry's PairTable.
		if err := a.cfg.Tables.CheckMembership(entry.PairTable); err != nil {
			res.Report = quarantine.Report{Seq: entry.Seq, Entry: entryFailure(entry.Seq, err)}
			return res
		}
	}
	work := a.cur.Clone()
	rec := a.newRec(ctx, a.cfg.FailedFetchBudget)
	defer rec.cleanup()
	rep := quarantine.Apply(work.Q, stored, rec)
	if !rep.Advanced {
		res.Report = rep
		return res
	}
	reconcileDegraded(work.Q)
	if entry.PairTable != nil {
		work.Member = entry.PairTable
	}
	if entry.FreeDns != nil {
		work.FreeDNS = entry.FreeDns
	}
	return a.commit(commitArgs{work: work, rep: rep, rec: rec, stored: stored, seq: entry.Seq, pt: entry.PairTable, res: res})
}

type commitArgs struct {
	work   *store.Applied
	rep    quarantine.Report
	rec    *recorder
	stored []byte              // the entry to store in log/, nil for Retry and snapshots
	seq    uint64              // log seq of stored
	pt     *policyv1.PairTable // membership to put in use, nil to leave it
	// resetLogTo, when non-zero, deletes the stored entries below it (a snapshot).
	resetLogTo uint64
	res        Result
}

// commit is steps 3 to 6 of the package comment, for an Apply, a Retry or a
// snapshot whose in-memory work is done.
func (a *Applier) commit(c commitArgs) Result {
	old, work, res := a.cur, c.work, c.res
	// Endpoints that share a rid_hash are not served by resolver id (the image
	// refuses the lookup, so neither tenant gets the other's policy). The state is
	// still committed, because refusing the entry would stall every node behind one
	// bad record, and the collision is reported as a record failure so the hub
	// hears of it (r4-3).
	for i, id := range image.RIDCollisions(work.Q.Endpoints) {
		if i == 64 { // a report is a sample, not the list
			break
		}
		c.rep.Quarantined = append(c.rep.Quarantined, quarantine.Failure{
			Scope: quarantine.ScopeRecord, Seq: c.rep.Seq, Item: append([]byte(nil), id[:]...),
			Reason: reason.BadSection, Section: "rid_hash"})
	}
	// Below the floor the node holds a state that is older than the image it serves
	// (adoptServedImage). The state is kept so the node catches up, but nothing of it
	// is served: no table swap, no image, and membership and free DNS stay those of
	// the served image, so a hard_disable or a deleted claim that the image holds is
	// not undone by an older entry on its way past.
	below := a.floor.Load() > work.Q.AppliedSeq
	if below {
		work.Member, work.FreeDNS, c.pt = old.Member, old.FreeDNS, nil
	}
	fail := func(err error, undo func()) Result {
		if undo != nil {
			undo()
		}
		c.rec.cleanup()
		res.Report = quarantine.Report{Seq: c.rep.Seq}
		res.Err = err
		return res
	}
	var undo func()
	if c.pt != nil {
		u, err := a.cfg.Tables.SetMembership(c.pt)
		if err != nil {
			// Item 4: the table that item 1 checked does not build with the flags
			// of now (a push changed them meanwhile). Nothing of the entry is
			// swapped in and it is handled as a failure of item 1.
			c.rec.cleanup()
			res.Report = quarantine.Report{Seq: c.rep.Seq, Entry: entryFailure(c.rep.Seq, err)}
			return res
		}
		undo = u
	}
	if err := c.rec.persist(old.Q, work.Q); err != nil {
		return fail(fmt.Errorf("apply: persist blobs: %w", err), undo)
	}
	if c.stored != nil {
		if err := a.cfg.Root.AppendEntry(c.seq, c.stored); err != nil {
			return fail(fmt.Errorf("apply: store entry: %w", err), undo)
		}
	}
	stateBytes, err := store.EncodeApplied(work)
	if err != nil {
		return fail(fmt.Errorf("apply: encode state: %w", err), undo)
	}
	var imgName string
	if !below {
		imgName, err = image.Build(a.cfg.Root.W, a.cfg.Root.Path(store.DirImage), inputOf(work, tagOf(stateBytes)))
		if err != nil {
			return fail(fmt.Errorf("apply: build image: %w", err), undo)
		}
	}
	if err := a.cfg.Root.WriteApplied(stateBytes); err != nil {
		if imgName != "" {
			_ = os.RemoveAll(a.cfg.Root.Path(store.DirImage, imgName))
		}
		return fail(fmt.Errorf("apply: write state: %w", err), undo)
	}
	// Committed.
	a.cur = work
	a.appliedSeq.Store(work.Q.AppliedSeq)
	res.Report = c.rep
	if below {
		res.Image, _ = image.CurrentName(a.cfg.Root.Path(store.DirImage))
		a.after(old, work, c.resetLogTo, a.floorBlobs)
		return res
	}
	var floorBlobs [][32]byte
	if a.floor.Load() != 0 {
		// The state has reached the image that was being served: from here the image
		// is built from the state again, and the old image's blobs are released.
		a.floor.Store(0)
		floorBlobs, a.floorBlobs, a.floorSet = a.floorBlobs, nil, nil
	}
	if err := a.swapImage(imgName); err != nil {
		a.imageStale = true
		res.ImageErr = err
	} else {
		a.imageStale = false
		res.Image = imgName
	}
	a.after(old, work, c.resetLogTo, nil)
	if res.ImageErr == nil {
		for _, h := range floorBlobs {
			a.deferredGC[h] = struct{}{}
		}
	}
	return res
}

// after is the cleanup that follows a commit. None of it can change what the
// node serves, so a failure is ignored: the next Open sweeps again. keep lists
// blobs that a served image still holds although the state does not name them.
func (a *Applier) after(old, work *store.Applied, resetLogTo uint64, keep [][32]byte) {
	if resetLogTo != 0 {
		_, _ = a.cfg.Root.PruneLog(resetLogTo)
	} else if k := a.cfg.LogKeep; work.Q.AppliedSeq > k {
		_, _ = a.cfg.Root.PruneLog(work.Q.AppliedSeq - k)
	}
	// A blob that left the state is deleted one commit later: the image before this
	// one is still on disk and dns may still read it, so its files stay until that
	// image is pruned too.
	now := map[[32]byte]struct{}{}
	collect := func(q *quarantine.State, into map[[32]byte]struct{}) {
		for h := range q.Profiles {
			into[h] = struct{}{}
		}
		for h, ok := range q.BlockPages {
			if ok {
				into[h] = struct{}{}
			}
		}
	}
	// Set-aside bytes are evidence for a verdict that lives in the state. They go when
	// the verdict does (a snapshot that no longer names the hash) and, past a size
	// cap, oldest first, so a hub that keeps sending bad blobs cannot fill the disk
	// the state is written to (r4-4). Nothing reads them but an admin, so there is
	// no need to wait a commit as with blobs.
	if quarantineChanged(old.Q, work.Q) {
		a.trimQuarantine()
	}
	collect(work.Q, now)
	for _, h := range keep {
		now[h] = struct{}{}
	}
	oldSet := map[[32]byte]struct{}{}
	collect(old.Q, oldSet)
	for h := range a.deferredGC {
		if _, inNew := now[h]; inNew {
			continue
		}
		if _, inOld := oldSet[h]; inOld {
			continue
		}
		_ = a.cfg.Root.DeleteBlob(h)
	}
	a.deferredGC = map[[32]byte]struct{}{}
	for h := range oldSet {
		if _, ok := now[h]; !ok {
			a.deferredGC[h] = struct{}{}
		}
	}
}

func tagOf(stateBytes []byte) string {
	s := sha256.Sum256(stateBytes)
	return hex.EncodeToString(s[:])
}

func inputOf(w *store.Applied, tag string) image.Input {
	q := w.Q
	in := image.Input{
		Seq: q.AppliedSeq, Head: q.Head, Endpoints: q.Endpoints, Claims: q.Claims, Degraded: q.Degraded,
		Profiles: make(map[[32]byte]bool, len(q.Profiles)), BlockPages: q.BlockPages,
		Member: w.Member, FreeDNS: w.FreeDNS, Tag: tag,
	}
	for h := range q.Profiles {
		in.Profiles[h] = true
	}
	return in
}

// swapImage makes name current and prunes all but it and the one it replaced.
func (a *Applier) swapImage(name string) error {
	dir := a.cfg.Root.Path(store.DirImage)
	prev, _ := image.CurrentName(dir)
	if err := image.SetCurrent(a.cfg.Root.W, dir, name); err != nil {
		return err
	}
	keep := []string{name}
	if prev != "" {
		keep = append(keep, prev)
	}
	_ = image.Prune(dir, keep...)
	return nil
}

// publishImage builds an image from a state and makes it current.
func (a *Applier) publishImage(w *store.Applied) (string, error) {
	sb, err := store.EncodeApplied(w)
	if err != nil {
		return "", err
	}
	name, err := image.Build(a.cfg.Root.W, a.cfg.Root.Path(store.DirImage), inputOf(w, tagOf(sb)))
	if err != nil {
		return "", err
	}
	if err := a.swapImage(name); err != nil {
		return "", err
	}
	return name, nil
}

// imageMatches reports whether image/current opens and was built from the state
// file on disk. An image a cut left behind, or one built before blobs were lost
// at load, does not match and is rebuilt.
func (a *Applier) imageMatches() (bool, error) {
	im, err := image.OpenCurrent(a.cfg.Root.Path(store.DirImage))
	if err != nil {
		return false, nil
	}
	sb, err := store.EncodeApplied(a.cur)
	if err != nil {
		return false, err
	}
	return im.Meta().Tag == tagOf(sb) && im.Seq() == a.cur.Q.AppliedSeq, nil
}

// fixImage rebuilds the image after an earlier swap failed. A failure is
// reported on res and does not stop the call: the state itself is fine.
func (a *Applier) fixImage(res *Result) {
	if !a.imageStale || a.floor.Load() != 0 {
		return
	}
	name, err := a.publishImage(a.cur)
	if err != nil {
		res.ImageErr = err
		return
	}
	a.imageStale = false
	res.Image = name
}

// sweepBlobs deletes blob files that the state does not name and the current image
// does not list: what a crash left between promoting a blob and committing the
// state that names it, and what the deferred deletion above did not get to. The
// image counts because a state that was lost or damaged is fresh and names nothing
// while image/current still serves; sweeping by the state alone would delete every
// file under the image dns is reading.
func (a *Applier) sweepBlobs() int {
	files, err := a.cfg.Root.ListBlobs()
	if err != nil {
		return 0
	}
	keep := map[[32]byte]bool{}
	for h := range a.cur.Q.Profiles {
		keep[h] = true
	}
	for h, ok := range a.cur.Q.BlockPages {
		if ok {
			keep[h] = true
		}
	}
	if im, err := image.OpenCurrent(a.cfg.Root.Path(store.DirImage)); err == nil {
		for _, h := range im.Blobs() {
			keep[h] = true
		}
	}
	n := 0
	for _, h := range files {
		if !keep[h] {
			if a.cfg.Root.DeleteBlob(h) == nil {
				n++
			}
		}
	}
	return n
}

// beginEntry marks that an entry (or a snapshot, which is part of the entry stream)
// is coming and cancels the Retry that holds the mutex, if any. The returned func
// ends the mark. Retry is off the entry stream and may be long (up to
// quarantine.MaxWantedPerRetry fetches of 60 s each), while a hard_disable, a
// rotation or a claim delete in the stream must not wait for it: the Revocation
// that covers them expires in minutes (p4-nodes 5.5). A cancelled Retry keeps what
// it already fetched and the next one goes on from there.
func (a *Applier) beginEntry() (end func()) {
	a.pm.Lock()
	a.entriesWait++
	if a.retryCancel != nil {
		a.retryCancel()
	}
	a.pm.Unlock()
	return func() {
		a.pm.Lock()
		a.entriesWait--
		a.pm.Unlock()
	}
}

// retryContext is ctx for a Retry that already holds mu: cancelled by beginEntry,
// also when the entry arrived before the Retry got the mutex.
func (a *Applier) retryContext(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	a.pm.Lock()
	a.retryCancel = cancel
	if a.entriesWait > 0 {
		cancel()
	}
	a.pm.Unlock()
	return ctx, func() {
		a.pm.Lock()
		a.retryCancel = nil
		a.pm.Unlock()
		cancel()
	}
}

// Retry gives the wanted blobs another chance without an entry (SC 9.7 item 2,
// T-533). quarantine.Retry has no recover of its own, so it runs under one here:
// a decoder that panics on hostile bytes costs this call, not the node.
func (a *Applier) Retry(ctx context.Context) (res Result) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			res = Result{Err: errors.New("apply: panic during retry")}
		}
	}()
	a.fixImage(&res)
	if len(a.cur.Q.Wanted) == 0 && len(a.cur.Q.Pending) == 0 {
		return res
	}
	ctx, done := a.retryContext(ctx)
	defer done()
	work := a.cur.Clone()
	rec := a.newRec(ctx, 0)
	defer rec.cleanup()
	var rep quarantine.Report
	if !recovered(func() { rep = quarantine.Retry(work.Q, rec) }) {
		return Result{Err: errors.New("apply: panic inside retry"), Image: res.Image}
	}
	if rec.stopped {
		// The walk went on past the point where fetching stopped and moved the
		// cursor over hashes that were never asked for, or whose fetch was cut. Put it
		// back to the last one that finished, or those hashes wait a whole lap of the
		// list.
		if rec.done {
			work.Q.WantedCursor = rec.lastDone
		} else {
			work.Q.WantedCursor = a.cur.Q.WantedCursor
		}
	}
	reconcileDegraded(work.Q)
	if !changed(a.cur.Q, work.Q, rep) {
		res.Report = rep
		return res
	}
	rep.Advanced = false // a Retry never moves applied_seq
	return a.commit(commitArgs{work: work, rep: rep, rec: rec, seq: rep.Seq, res: res})
}

// reconcileDegraded lifts the degraded mark from an Endpoint whose record binds
// only profiles that are open now. quarantine promotes an Endpoint when its newer
// record becomes usable, but not when its current record does: an Endpoint that
// lost its profile at load (state.repairLost) and waits for a newer record too
// would otherwise stay degraded after the lost profile came back, while the newer
// one is still missing. The map is copied before it is edited, because it may be
// shared with the state a rollback keeps.
func reconcileDegraded(q *quarantine.State) {
	var next map[[16]byte]bool
	for id, deg := range q.Degraded {
		ep := q.Endpoints[id]
		if !deg || ep == nil || !bindsOnly(ep, q.Profiles) {
			continue
		}
		if next == nil {
			next = make(map[[16]byte]bool, len(q.Degraded))
			for k, v := range q.Degraded {
				next[k] = v
			}
		}
		delete(next, id)
	}
	if next != nil {
		q.Degraded = next
	}
}

// recovered runs fn and reports whether it returned without panicking.
func recovered(fn func()) (ok bool) {
	defer func() {
		if p := recover(); p != nil {
			ok = false
		}
	}()
	fn()
	return true
}

// changed reports whether a Retry changed anything that must be saved: the cursor
// moves on every pass over a non-empty list, so it counts too, or a restart would
// start the walk again from the beginning.
func changed(old, work *quarantine.State, rep quarantine.Report) bool {
	return len(rep.Promoted) > 0 || len(rep.Quarantined) > 0 ||
		len(work.Profiles) != len(old.Profiles) || len(work.BlockPages) != len(old.BlockPages) ||
		len(work.Quarantined) != len(old.Quarantined) || len(work.Wanted) != len(old.Wanted) ||
		len(work.Pending) != len(old.Pending) || len(work.Degraded) != len(old.Degraded) || work.WantedCursor != old.WantedCursor
}

// Stored is one entry as the hub's FetchEntries gives it.
type Stored struct {
	Seq   uint64
	Bytes []byte
}

// ErrSnapshotAheadOfHead is returned when the snapshot source gives a snapshot
// that the signed head does not vouch for: a seq above the head's, or the head's
// seq with another entry hash (SC 8a.11 L12: the hub serves neither).
var ErrSnapshotAheadOfHead = errors.New("apply: snapshot does not match the signed head")

// ApplyEntries applies entries in order. An entry at or below applied_seq is
// skipped. An entry beyond applied_seq+1 is a gap: the node asks the snapshot
// source for a snapshot at or above seq-1 (the log below the hub's oldest kept
// entry is gone), applies it, and goes on. While the state is behind the image
// being served (Floor), it tries once per call for a snapshot at or above that
// seq, so it can catch up in one step. That is only a shortcut: the floor is
// near the hub's head and the hub keeps few snapshots, so it often has none that
// recent, and then the entries are applied one by one, which changes nothing that
// is served until the floor is reached. A failed shortcut must never hold back
// the entries (a hard_disable among them), so it is dropped, not returned. It
// stops at the first entry that is refused, because the entries after it chain
// from it.
func (a *Applier) ApplyEntries(ctx context.Context, entries []Stored) ([]Result, error) {
	var out []Result
	shortcutTried := false
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		applied := a.AppliedSeq()
		if e.Seq <= applied {
			out = append(out, Result{Skipped: true})
			continue
		}
		if e.Seq > applied+1 {
			// A real gap: the log below the hub's oldest kept entry is gone.
			if a.cfg.Snapshots == nil {
				return out, ErrGap
			}
			snap, err := a.cfg.Snapshots.GetSnapshot(ctx, e.Seq-1)
			if err != nil {
				return out, fmt.Errorf("apply: get snapshot: %w", err)
			}
			if err := a.checkHead(ctx, snap); err != nil {
				return out, err
			}
			r := a.ApplySnapshot(ctx, snap)
			out = append(out, r)
			if r.Err != nil {
				return out, r.Err
			}
			if applied = a.AppliedSeq(); e.Seq <= applied {
				out = append(out, Result{Skipped: true})
				continue
			}
			if e.Seq != applied+1 {
				return out, ErrGap
			}
		} else if fl := a.floor.Load(); fl > applied && a.cfg.Snapshots != nil && !shortcutTried {
			shortcutTried = true
			if r, ok := a.floorShortcut(ctx, fl); ok {
				out = append(out, r)
				if applied = a.AppliedSeq(); e.Seq <= applied {
					out = append(out, Result{Skipped: true})
					continue
				}
			}
		}
		r := a.ApplyEntry(ctx, e.Bytes)
		out = append(out, r)
		if r.Err != nil {
			return out, r.Err
		}
		if !r.Report.Advanced {
			return out, nil
		}
	}
	return out, nil
}

// floorShortcut asks the snapshot source for a snapshot at or above the floor and
// applies it. ok is false when anything about it fails (no snapshot that recent,
// not vouched for by the signed head, older than the state, refused): the caller
// then applies the entries instead, and the entries carry their own checks.
func (a *Applier) floorShortcut(ctx context.Context, floor uint64) (Result, bool) {
	snap, err := a.cfg.Snapshots.GetSnapshot(ctx, floor)
	if err != nil || a.checkHead(ctx, snap) != nil {
		return Result{}, false
	}
	r := a.ApplySnapshot(ctx, snap)
	if r.Err != nil || !r.Report.Advanced {
		return Result{}, false
	}
	return r, true
}

// checkHead holds a snapshot against the signed head when Config.Head is set.
func (a *Applier) checkHead(ctx context.Context, snap *signv1.Snapshot) error {
	if a.cfg.Head == nil || snap == nil {
		return nil
	}
	seq, hash, err := a.cfg.Head(ctx)
	if err != nil {
		return fmt.Errorf("apply: signed head: %w", err)
	}
	if snap.Seq > seq || (snap.Seq == seq && !bytes.Equal(snap.EntryHash, hash[:])) {
		return ErrSnapshotAheadOfHead
	}
	return nil
}

// ApplySnapshot replaces the applied state with a snapshot, for a node that is new
// or has fallen behind the hub's oldest kept entry. The snapshot's records are
// validated like an entry's. Blobs the node already holds are carried over, and
// an Endpoint binds at once, keeps its previous binding while a new one waits, or
// is degraded when it has neither (fromSnapshot). Retry passes fetch the blobs until the list is
// empty, nothing new arrives, or ctx ends; what is still missing stays wanted and
// the Endpoints that wait for it stay degraded until a later Retry. The snapshot's
// CatalogRef is not applied here (the catalog is not the store's).
func (a *Applier) ApplySnapshot(ctx context.Context, snap *signv1.Snapshot) (res Result) {
	defer a.beginEntry()()
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			res = Result{Err: errors.New("apply: panic while applying a snapshot")}
		}
	}()
	if err := validateSnapshot(snap); err != nil {
		res.Report = quarantine.Report{Seq: snap.GetSeq(), Entry: &quarantine.Failure{Scope: quarantine.ScopeEntry, Seq: snap.GetSeq(), Reason: reason.BadSection, Section: "snapshot"}}
		res.Err = err
		return res
	}
	if snap.Seq <= a.cur.Q.AppliedSeq {
		res.Err = ErrStaleSnapshot
		return res
	}
	if snap.PairTable != nil {
		if err := a.cfg.Tables.CheckMembership(snap.PairTable); err != nil {
			res.Report = quarantine.Report{Seq: snap.Seq, Entry: entryFailure(snap.Seq, err)}
			return res
		}
	}
	work := fromSnapshot(snap, a.cur)
	if snap.PairTable == nil {
		// An entry without a PairTable leaves the membership as it is, and so does a
		// snapshot without one. Taking nil here would leave the running table (still
		// the old membership, since pt is nil below) and the state file (no
		// membership) disagreeing, and a restart would serve no table at all.
		work.Member = a.cur.Member
	}
	rec := a.newRec(ctx, a.cfg.FailedFetchBudget)
	defer rec.cleanup()

	rep := quarantine.Report{Seq: snap.Seq}
	if !settleWanted(ctx, work.Q, rec, &rep) {
		res.Err = errors.New("apply: panic inside retry")
		return res
	}
	rep.Advanced = true
	reconcileDegraded(work.Q)
	for k, ok := range work.Q.Degraded {
		if ok {
			rep.Degraded = append(rep.Degraded, k)
		}
	}
	return a.commit(commitArgs{work: work, rep: rep, rec: rec, seq: snap.Seq, pt: snap.PairTable, resetLogTo: snap.Seq + 1, res: res})
}

func validateSnapshot(s *signv1.Snapshot) error {
	if s == nil || s.Seq == 0 || len(s.EntryHash) != 32 {
		return errors.New("apply: snapshot without a seq or an entry hash")
	}
	if len(s.Blobs)+len(s.Endpoints)+len(s.Claims) > 4*wire.MaxRecordsPerEntry {
		return errors.New("apply: snapshot over the record cap")
	}
	seen := map[string]bool{}
	for _, b := range s.Blobs {
		if err := wire.ValidateBlobRef(b); err != nil {
			return err
		}
		if seen[string(b.Hash)] {
			return errors.New("apply: snapshot lists a blob twice")
		}
		seen[string(b.Hash)] = true
	}
	seen = map[string]bool{}
	for _, e := range s.Endpoints {
		if err := wire.ValidateEndpoint(e); err != nil {
			return err
		}
		if seen[string(e.EndpointId)] {
			return errors.New("apply: snapshot lists an endpoint twice")
		}
		seen[string(e.EndpointId)] = true
	}
	seen = map[string]bool{}
	for _, c := range s.Claims {
		if err := wire.ValidateClaim(c); err != nil {
			return err
		}
		if seen[string(c.ClaimId)] {
			return errors.New("apply: snapshot lists a claim twice")
		}
		seen[string(c.ClaimId)] = true
	}
	if err := wire.ValidatePairTable(s.PairTable); err != nil {
		return err
	}
	return wire.ValidateFreeDns(s.FreeDns)
}

// fromSnapshot is the state a snapshot describes before any blob is fetched. The
// node keeps what it already holds: a blob the snapshot names that is open in cur
// (the state before) is carried over, so it is neither fetched again nor missing
// while the others are. An Endpoint whose blobs are all held is bound at once. One
// that waits for a blob keeps its previous binding when that is still usable, as
// quarantine.Apply does for a put (KeptPrevious, 9.7 item 4), and is degraded only
// when it has none (items 2 and 7). Only what the snapshot names is carried:
// anything else leaves the state, and its file is deleted one commit later.
func fromSnapshot(s *signv1.Snapshot, cur *store.Applied) *store.Applied {
	w := store.NewApplied()
	q := w.Q
	q.AppliedSeq = s.Seq
	copy(q.Head[:], s.EntryHash)

	carry := func(h [32]byte, kind policyv1.BlobKind) {
		if kind == policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE {
			if cur.Q.BlockPages[h] {
				q.BlockPages[h] = true
			}
		} else if p, ok := cur.Q.Profiles[h]; ok {
			q.Profiles[h] = p
		}
		// The same bytes always give the same verdict, so a quarantined hash stays so.
		if why, bad := cur.Q.Quarantined[h]; bad {
			q.Quarantined[h] = why
		}
	}
	settled := func(h [32]byte) bool {
		_, p := q.Profiles[h]
		_, bad := q.Quarantined[h]
		return p || q.BlockPages[h] || bad
	}
	refs := map[[32]byte]*policyv1.BlobRef{}
	for _, b := range s.Blobs {
		h := [32]byte(b.Hash)
		refs[h] = b
		carry(h, b.Kind)
		if !settled(h) {
			q.Wanted[h] = b
		}
	}
	for _, e := range s.Endpoints {
		id := [16]byte(e.EndpointId)
		wants := map[[32]byte]*policyv1.BlobRef{}
		bad := false
		for _, hb := range bindingHashes(e) {
			h := [32]byte(hb)
			ref := refs[h]
			if ref == nil {
				ref = &policyv1.BlobRef{Hash: hb, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
				carry(h, ref.Kind)
			}
			if _, ok := q.Profiles[h]; ok {
				continue
			}
			if _, isBad := q.Quarantined[h]; isBad {
				bad = true
				continue
			}
			wants[h] = ref
			if q.Wanted[h] == nil {
				q.Wanted[h] = ref
			}
		}
		if len(wants) == 0 && !bad {
			q.Endpoints[id] = e
			continue
		}
		if prev, ok := cur.Q.Endpoints[id]; ok && !cur.Q.Degraded[id] && bindsOnly(prev, cur.Q.Profiles) {
			merged := proto.Clone(e).(*policyv1.EndpointRecord)
			merged.Base, merged.Schedule, merged.Clients = prev.Base, prev.Schedule, prev.Clients
			for _, hb := range bindingHashes(prev) {
				carry([32]byte(hb), policyv1.BlobKind_BLOB_KIND_PROFILE)
			}
			q.Endpoints[id] = merged
		} else {
			q.Endpoints[id] = e
			q.Degraded[id] = true
		}
		// A quarantined hash can never arrive, so there is nothing to wait for.
		if len(wants) > 0 && !bad {
			q.Pending[id] = &quarantine.Pending{Record: e, Wants: wants}
		}
	}
	for _, c := range s.Claims {
		q.Claims[[16]byte(c.ClaimId)] = c
	}
	capWanted(q)
	w.Member = s.PairTable
	w.FreeDNS = s.FreeDns
	return w
}

// bindsOnly reports whether every profile an Endpoint record binds is open in profiles.
func bindsOnly(ep *policyv1.EndpointRecord, profiles map[[32]byte]*blob.Profile) bool {
	for _, hb := range bindingHashes(ep) {
		if _, ok := profiles[[32]byte(hb)]; !ok {
			return false
		}
	}
	return true
}

func bindingHashes(ep *policyv1.EndpointRecord) [][]byte {
	var out [][]byte
	add := func(s *policyv1.StackRecord) {
		if s == nil {
			return
		}
		out = append(out, s.Profile1Hash)
		if len(s.Profile2Hash) != 0 {
			out = append(out, s.Profile2Hash)
		}
	}
	add(ep.Base)
	if ep.Schedule != nil {
		for _, w := range ep.Schedule.Windows {
			add(w.Stack)
		}
	}
	for _, c := range ep.Clients {
		add(c.Stack)
	}
	return out
}

// capWanted keeps len(q.Wanted) within quarantine.MaxWanted (SC 9.7 item 2) by
// dropping the hashes that no Endpoint binds and no pending record waits for:
// profiles first, then block pages, each in hash order. The shared package does
// this for an entry and a Retry but keeps the function unexported, and a snapshot
// can name up to 4*wire.MaxRecordsPerEntry blobs. A hash that a pending Endpoint
// waits for is never dropped. A dropped hash is fetched again when a later entry
// names it.
func capWanted(q *quarantine.State) {
	excess := len(q.Wanted) - quarantine.MaxWanted
	if excess <= 0 {
		return
	}
	needed := map[[32]byte]bool{}
	for _, ep := range q.Endpoints {
		for _, hb := range bindingHashes(ep) {
			needed[[32]byte(hb)] = true
		}
	}
	for _, p := range q.Pending {
		for h := range p.Wants {
			needed[h] = true
		}
	}
	var profiles, pages [][32]byte
	for h, ref := range q.Wanted {
		switch {
		case needed[h]:
		case ref.Kind == policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE:
			pages = append(pages, h)
		default:
			profiles = append(profiles, h)
		}
	}
	byHash := func(s [][32]byte) {
		sort.Slice(s, func(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 })
	}
	byHash(profiles)
	byHash(pages)
	for _, h := range append(profiles, pages...) {
		if excess == 0 {
			return
		}
		delete(q.Wanted, h)
		excess--
	}
}

// settleWanted runs Retry passes over a snapshot's wanted list until every hash
// has been tried, the context ends or the fetch budget is spent. It reports false
// when a pass panicked.
//
// A pass walks at most MaxWantedPerRetry hashes from where the last one stopped,
// so enough passes in a row that settle nothing have walked the whole list: what
// is left is not available now, and a later Retry tries again. Once the recorder
// is exhausted every further fetch is refused at once, so more passes would only
// copy the state's maps for nothing, under the apply mutex (r4-2).
func settleWanted(ctx context.Context, q *quarantine.State, rec *recorder, rep *quarantine.Report) bool {
	settled := func() int { return len(q.Profiles) + len(q.BlockPages) + len(q.Quarantined) }
	idle := 0
	for ctx.Err() == nil && len(q.Wanted) > 0 {
		before := settled()
		var r quarantine.Report
		if !recovered(func() { r = quarantine.Retry(q, rec) }) {
			return false
		}
		rep.Promoted = append(rep.Promoted, r.Promoted...)
		rep.Quarantined = append(rep.Quarantined, r.Quarantined...)
		rep.Failed, rep.Missing = r.Failed, r.Missing
		if rec.exhausted() {
			break
		}
		if settled() == before {
			idle++
			if idle*quarantine.MaxWantedPerRetry >= len(q.Wanted)+quarantine.MaxWantedPerRetry {
				break
			}
		} else {
			idle = 0
		}
	}
	return true
}

// quarantineChanged reports whether the set of quarantined hashes differs.
func quarantineChanged(old, work *quarantine.State) bool {
	if len(old.Quarantined) != len(work.Quarantined) {
		return true
	}
	for h := range work.Quarantined {
		if _, ok := old.Quarantined[h]; !ok {
			return true
		}
	}
	return false
}

// trimQuarantine keeps quarantine/ to the files the state still lists, within the
// size cap.
func (a *Applier) trimQuarantine() {
	a.cfg.Root.TrimQuarantine(func(h [32]byte) bool {
		_, ok := a.cur.Q.Quarantined[h]
		return ok
	}, store.MaxQuarantineBytes)
}
