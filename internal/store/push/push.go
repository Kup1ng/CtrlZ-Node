// Package push is the node's table writer: the one place that changes the flag
// map and builds and swaps the zone table the node serves its Endpoint hostnames
// from (SC 8a.4 Node apply, SC 8a.11 L11, Plan T-545).
//
// # One writer
//
// Two things change the table in use: a pushed flag map (the hub's withdrawals)
// and an applied log entry (the membership: nodes, addresses, slots, revocations).
// Each builds from the other's latest state, so if both built on their own a push
// applied during an Apply could be lost under the Apply's swap, or an entry's
// membership under the push's (L11, rounds 43 to 45). Writer serialises them with
// one mutex: every method locks it, builds under recover from the state as it
// is when the build starts, and swaps before it unlocks. The agent's table-writer
// goroutine (W5b) is the only caller, so a push never waits for more than one
// build of at most four nodes, and no build waits on a fetch or on disk (the
// disk write of a push comes after its swap, and Apply's own disk work happens
// before it calls SetMembership, which is the last memory step it takes).
//
// What a Heartbeat reads (Status, Flags, Member, Table) never waits on that mutex
// (L11): the two fsynced writes of a push happen while it is held, and a disk that
// stalls for seconds must not make the node's Heartbeats late, so the hub would
// call it stale while its table is already swapped. The report fields live in a
// copy behind their own small mutex, which is only ever held for a copy. The
// writer publishes the copy after the swap and before the disk write.
//
// # What is on disk (push/)
//
//	used   sealed (CZPU) JSON: highest version used, the version of the flags in
//	       use, the flag map. Written first.
//	push   sealed (CZPE) Envelope of the latest accepted push, kept as evidence:
//	       Load checks it again before it trusts the flags. Written second.
//
// A cut between the two writes leaves newer flags beside an older push, which
// Load accepts (the push is evidence, not the source of the map: the map is the
// merge of every accepted push, so no one push can rebuild it).
//
// # Start
//
// Load rebuilds the table from the applied membership and the persisted flags.
// It checks the persisted push by manifest.Verify (which judges no expiry for the
// policy role), wire.ValidatePairTablePush and the build, and never by
// expires_at, by version or by the node's clock: the push was accepted once, and
// its expiry only sets PanelStale. If a check fails or the build panics, the flags
// and the push are deleted and the node runs with no flags, so a push that crashes
// the build cannot crash the node on every restart. The highest version used is
// kept even then, so a replay of an older push is still refused.
package push

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
)

const (
	usedFile  = "used"
	pushFile  = "push"
	usedMagic = "CZPU"
	pushMagic = "CZPE"
)

// RootFunc returns the trusted root (keys/root.json). A function, so a rotation
// is seen by the next push without restarting.
type RootFunc func() (*signv1.Root, error)

// Config is what a Writer needs.
type Config struct {
	Dir  string // the push/ directory
	W    *fsx.Writer
	Root RootFunc
}

// Writer is the table writer. Create it with New and call Load once at start.
type Writer struct {
	cfg Config

	mu        sync.Mutex
	member    *policyv1.PairTable // membership of the last applied entry with a table
	flags     zone.FlagMap
	version   uint64 // version of the flags in use, 0 before any push
	highest   uint64 // highest version ever used; persisted; never goes down
	expiresAt int64  // expires_at of the push in use
	envelope  []byte // the marshalled envelope of the push in use

	table atomic.Pointer[zone.Table]

	// rm guards v, the copy that Status, Flags, Member and TableInUse read. It is
	// never held across work. v.flags is replaced and never edited in place.
	rm sync.Mutex
	v  view

	// started is the node clock at Load, for TableInUse.
	started int64

	// Report state, for PeerView and for PanelStale (8a.4 Node apply step 5, 8a.5).
	acceptedSinceStart bool
	refusals           uint64
	lastRefusal        hubv1.PushRefusal
	latestRefusal      hubv1.PushRefusal // refusal of the latest push received, 0 when it was accepted
}

// view is the part of the writer's state that a report reads.
type view struct {
	member                     *policyv1.PairTable
	flags                      zone.FlagMap
	version, highest           uint64
	expiresAt                  int64
	started                    int64
	acceptedSinceStart         bool
	refusals                   uint64
	lastRefusal, latestRefusal hubv1.PushRefusal
}

// publish copies the report state for the readers. Called with mu held, after the
// memory step it reports and before any disk write.
func (w *Writer) publish() {
	v := view{member: w.member, flags: w.flags, version: w.version, highest: w.highest, expiresAt: w.expiresAt,
		started: w.started, acceptedSinceStart: w.acceptedSinceStart, refusals: w.refusals,
		lastRefusal: w.lastRefusal, latestRefusal: w.latestRefusal}
	w.rm.Lock()
	w.v = v
	w.rm.Unlock()
}

func (w *Writer) view() view {
	w.rm.Lock()
	defer w.rm.Unlock()
	return w.v
}

// New returns a Writer with no table and no flags.
func New(cfg Config) *Writer {
	if cfg.W == nil {
		cfg.W = &fsx.Writer{}
	}
	return &Writer{cfg: cfg, flags: zone.FlagMap{}}
}

// Table is the zone table that is built, or nil when no applied entry has carried
// a PairTable. Built is not the same as in use: SC 8a.5 (Table in use) gives a
// node no table to serve from until it has accepted a push since it started or
// 30 s have passed, and a table loaded at start must not be served before that, or
// a primary that has just rebooted pulls clients back before the hub has decided.
// Serve from TableInUse. Table is safe to call from any goroutine and never blocks
// on the writer: a built Table is never changed.
func (w *Writer) Table() *zone.Table { return w.table.Load() }

// InUseDelay is how many seconds after start a node that has accepted no push puts
// its persisted table in use (SC 8a.5).
const InUseDelay = 30

// TableInUse is the table the node may answer Endpoint hostnames and name-server
// names from at now (Unix seconds): the built table once a push was accepted in
// this run or InUseDelay seconds have passed since Load, otherwise nil, which the
// zone code answers with REFUSED. It never blocks on the writer.
func (w *Writer) TableInUse(now int64) *zone.Table {
	t := w.table.Load()
	if t == nil {
		return nil
	}
	v := w.view()
	if v.acceptedSinceStart || now-v.started >= InUseDelay {
		return t
	}
	return nil
}

// Member returns the membership the table was built from, or nil. It never blocks
// on the writer.
func (w *Writer) Member() *policyv1.PairTable { return w.view().member }

// Status is what the agent reports and what local mode reads.
type Status struct {
	// Version is the version of the flags in use, 0 before any push (PeerView.pair_table_version).
	Version uint64
	// Highest is the highest version used.
	Highest uint64
	// ExpiresAt is the push in use's expires_at, 0 when none.
	ExpiresAt int64
	// AcceptedSinceStart is true once a push, a redelivery included, was accepted in this run.
	AcceptedSinceStart bool
	// Refusals counts refused pushes since the process started, and LastRefusal is the
	// last one's reason (PeerView.refusals, last_refusal).
	Refusals    uint64
	LastRefusal hubv1.PushRefusal
	// LatestRefusal is the refusal of the latest push received, UNSPECIFIED when it was
	// accepted. SC 8a.5: PanelStale holds while it is anything but LOWER_VERSION.
	LatestRefusal hubv1.PushRefusal
}

// Status returns the current report state.
// It never blocks on the writer (L11).
func (w *Writer) Status() Status {
	v := w.view()
	return Status{Version: v.version, Highest: v.highest, ExpiresAt: v.expiresAt, AcceptedSinceStart: v.acceptedSinceStart,
		Refusals: v.refusals, LastRefusal: v.lastRefusal, LatestRefusal: v.latestRefusal}
}

// Flags returns a copy of the flag map in use. It never blocks on the writer.
func (w *Writer) Flags() zone.FlagMap {
	flags := w.view().flags
	out := make(zone.FlagMap, len(flags))
	for k, v := range flags {
		out[k] = v
	}
	return out
}

// buildTable builds the table of a membership with a flag map, under recover.
// It never panics, whatever the input.
func buildTable(member *policyv1.PairTable, version uint64, flags zone.FlagMap) (t *zone.Table, err error) {
	defer func() {
		if r := recover(); r != nil {
			t, err = nil, errors.New("push: zone build panicked")
		}
	}()
	return zone.Build(zone.WithFlags(wire.ZoneInput(member), version, flags))
}

// CheckMembership is the check of SC 9.7 item 1: a zone table builds from the
// entry's PairTable with the flag map as it is now. It swaps nothing. The build
// that item 4 puts in use is SetMembership, from the flag map as it is then.
func (w *Writer) CheckMembership(pt *policyv1.PairTable) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := buildTable(pt, w.version, w.flags)
	return err
}

// SetMembership is item 4 for an entry that carries a PairTable: it builds the
// table from this membership and the flag map as it is now, and swaps it in. When
// the build fails or panics nothing changes and the error says so. The undo it
// returns puts the previous membership back (rebuilt with the flags as they are
// then, so a push applied meanwhile is kept); the apply code calls it when a
// later disk step of the same Apply fails.
func (w *Writer) SetMembership(pt *policyv1.PairTable) (undo func(), err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	t, err := buildTable(pt, w.version, w.flags)
	if err != nil {
		return nil, err
	}
	old := w.member
	w.member = pt
	w.table.Store(t)
	w.publish()
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.member = old
		defer w.publish()
		if old == nil {
			w.table.Store(nil)
			return
		}
		if t, err := buildTable(old, w.version, w.flags); err == nil {
			w.table.Store(t)
		}
	}, nil
}

// Result is the outcome of one push.
type Result struct {
	// Accepted is true for a push that was taken, a redelivery included.
	Accepted bool
	// Redelivery is true when the push repeated the version in use (step 2).
	Redelivery bool
	// Refusal is the reason of a refused push, UNSPECIFIED when accepted.
	Refusal hubv1.PushRefusal
	// Err carries the detail of a refusal for the agent's log. It holds no
	// payload bytes.
	Err error
	// PersistErr is set when the push was accepted and swapped in but could not be
	// written to disk. The node serves correctly; after a restart it runs on the
	// flags it had before, until the next push, which arrives within a round trip.
	PersistErr error
}

// ApplyPush is SC 8a.4 Node apply, steps 1 to 5. hubNow is the node's clock plus
// the offset from the latest ServerTime (8a.4, Clock). It never panics: a push is
// bytes from the network.
func (w *Writer) ApplyPush(env *signv1.Envelope, hubNow int64) (res Result) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			res = Result{Refusal: hubv1.PushRefusal_PUSH_REFUSAL_BUILD, Err: errors.New("push: panic while applying")}
		}
		w.record(&res)
		w.publish()
	}()
	return w.apply(env, hubNow)
}

// markAccepted records an accepted push and publishes it. It is called at the swap,
// before the disk write, so the report and TableInUse do not wait for the fsyncs.
func (w *Writer) markAccepted() {
	w.acceptedSinceStart = true
	w.latestRefusal = hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED
	w.publish()
}

// record updates the report state. Called with the lock held.
func (w *Writer) record(res *Result) {
	if res.Accepted {
		w.acceptedSinceStart = true
		w.latestRefusal = hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED
		return
	}
	w.refusals++
	w.lastRefusal = res.Refusal
	w.latestRefusal = res.Refusal
}

func refuse(r hubv1.PushRefusal, format string, a ...any) Result {
	return Result{Refusal: r, Err: fmt.Errorf(format, a...)}
}

func (w *Writer) apply(env *signv1.Envelope, hubNow int64) Result {
	// 1. Empty, or the signature does not verify.
	if env == nil || len(env.Payload) == 0 {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE, "push: empty envelope or payload")
	}
	if w.cfg.Root == nil {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE, "push: no trust root")
	}
	root, err := w.cfg.Root()
	if err != nil || root == nil {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE, "push: trust root unavailable")
	}
	payload, err := manifest.Verify(env, root, signv1.Role_ROLE_POLICY, manifest.TypePairTable, hubNow)
	if err != nil {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE, "push: %v", err)
	}
	// Past this line the bytes are the hub's. They are still validated: a bug
	// or a stolen policy key must not crash a node (T-545).
	pt := &policyv1.PairTable{}
	if err := proto.Unmarshal(payload, pt); err != nil {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_INVALID, "push: payload is not a PairTable")
	}
	if err := wire.ValidatePairTablePush(pt); err != nil {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_INVALID, "push: %v", err)
	}
	// The hub signs max(last+1, now in ms), never 0, and a version of 0 means "no
	// push yet" in PeerView, so a signed 0 is not a push.
	if pt.Version == 0 {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_INVALID, "push: version 0")
	}
	if pt.ExpiresAt <= hubNow {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_EXPIRED, "push: expired")
	}
	if pt.Version < w.highest {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION, "push: version %d below %d", pt.Version, w.highest)
	}

	pushed := wire.PushFlags(pt)
	envBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(env)
	if err != nil {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_INVALID, "push: envelope")
	}

	// 2. The version in use again: a redelivery, or a conflict. A version that
	// equals the highest but not the version in use is the state Load leaves
	// after it dropped a bad persisted push; the flags are gone, so it applies
	// like a higher one instead of being taken as a redelivery of nothing.
	if w.version != 0 && pt.Version == w.version {
		if !w.flags.Redelivery(pushed) {
			return refuse(hubv1.PushRefusal_PUSH_REFUSAL_FLAG_CONFLICT, "push: version %d with other flags", pt.Version)
		}
		w.markAccepted()
		res := Result{Accepted: true, Redelivery: true}
		if pt.ExpiresAt > w.expiresAt {
			w.expiresAt, w.envelope = pt.ExpiresAt, envBytes
			w.publish()
			res.PersistErr = w.persistPush()
		}
		return res
	}

	// 3 and 4. A higher version: take the flags the push names, build, swap.
	next := w.flags.Take(pushed, memberIDs(w.member))
	var t *zone.Table
	if w.member != nil {
		t, err = buildTable(w.member, pt.Version, next)
		if err != nil {
			return refuse(hubv1.PushRefusal_PUSH_REFUSAL_BUILD, "push: %v", err)
		}
	}
	w.flags, w.version, w.expiresAt, w.envelope = next, pt.Version, pt.ExpiresAt, envBytes
	if pt.Version > w.highest {
		w.highest = pt.Version
	}
	if t != nil {
		w.table.Store(t)
	}
	w.markAccepted()
	// Only after the swap is anything written (step 4).
	res := Result{Accepted: true}
	if err := w.persistUsed(); err != nil {
		res.PersistErr = err
	} else if err := w.persistPush(); err != nil {
		res.PersistErr = err
	}
	return res
}

func memberIDs(pt *policyv1.PairTable) []zone.NodeID {
	var ids []zone.NodeID
	for _, n := range pt.GetNodes() {
		if len(n.GetNodeId()) == 16 {
			ids = append(ids, zone.NodeID(n.GetNodeId()))
		}
	}
	return ids
}

// ---- persistence ----

type usedJSON struct {
	Highest uint64          `json:"highest"`
	Version uint64          `json:"version"`
	Flags   map[string]bool `json:"flags"`
}

func (w *Writer) persistUsed() error {
	u := usedJSON{Highest: w.highest, Version: w.version, Flags: make(map[string]bool, len(w.flags))}
	for id, f := range w.flags {
		u.Flags[hex.EncodeToString(id[:])] = f
	}
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return w.cfg.W.WriteFile(filepath.Join(w.cfg.Dir, usedFile), fsx.Seal(usedMagic, b), 0o600)
}

func (w *Writer) persistPush() error {
	if w.envelope == nil {
		return nil
	}
	return w.cfg.W.WriteFile(filepath.Join(w.cfg.Dir, pushFile), fsx.Seal(pushMagic, w.envelope), 0o600)
}

// LoadResult says what Load found.
type LoadResult struct {
	// Dropped is non-nil when the persisted push or its flags failed a check and
	// were deleted: the node runs with no flags (8a.4, At start).
	Dropped error
	// Version is the version of the flags now in use, 0 when none.
	Version uint64
}

// Load rebuilds the writer's state at start, from the applied membership (nil
// when no applied entry has carried a table) and the files in push/. now is the
// node's own clock, used only to call manifest.Verify, which judges no expiry for
// the policy role.
func (w *Writer) Load(member *policyv1.PairTable, now int64) LoadResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer w.publish()
	w.started = now
	w.member = member
	w.flags, w.version, w.highest, w.expiresAt, w.envelope = zone.FlagMap{}, 0, 0, 0, nil
	w.table.Store(nil)

	var res LoadResult
	flags, version, highest, usedErr := w.readUsed()
	w.highest = highest // kept whatever else fails: anti-rollback outlives the flags
	if usedErr != nil {
		res.Dropped = usedErr
		// The used file is the floor, and it is what failed. The push next to it is
		// signed and carries the version of the last push this node accepted, so
		// when it still verifies that version is the floor, and dropFiles writes it
		// back. Without it a node would accept an older push after the damage.
		var envBytes []byte
		var expires int64
		var pushVersion uint64
		if w.checkPersistedPush(now, &envBytes, &expires, &pushVersion) == nil && pushVersion > w.highest {
			w.highest = pushVersion
		}
		w.dropFiles()
		w.rebuild()
		return res
	}
	var envBytes []byte
	var expires int64
	var pushVersion uint64
	if err := w.checkPersistedPush(now, &envBytes, &expires, &pushVersion); err != nil {
		res.Dropped = err
		w.dropFiles()
		w.rebuild()
		return res
	}
	// Flags in memory only now: the table is built from them, and a failure
	// drops them, as a failed check does.
	w.flags, w.version, w.envelope, w.expiresAt = flags, version, envBytes, expires
	if pushVersion > w.highest {
		// The used file is written before the push, so a crash never leaves a
		// verified push above it; only a deleted or lost used file does. The push
		// is signed and carries the version of the last one accepted, so it is the
		// floor, and the file is written back (review round 3, r3-3).
		w.highest = pushVersion
		_ = w.persistUsed()
	}
	if member != nil {
		t, err := buildTable(member, version, flags)
		if err != nil {
			res.Dropped = err
			w.flags, w.version, w.envelope, w.expiresAt = zone.FlagMap{}, 0, nil, 0
			w.dropFiles()
			w.rebuild()
			return res
		}
		w.table.Store(t)
	}
	res.Version = w.version
	return res
}

// rebuild puts a table with no flags in use. Called with the lock held, after the
// flags were dropped.
func (w *Writer) rebuild() {
	if w.member == nil {
		return
	}
	if t, err := buildTable(w.member, 0, zone.FlagMap{}); err == nil {
		w.table.Store(t)
	}
}

// dropFiles deletes the push and writes the used file with no flags and the
// highest version kept.
func (w *Writer) dropFiles() {
	_ = os.Remove(filepath.Join(w.cfg.Dir, pushFile))
	_ = os.Remove(filepath.Join(w.cfg.Dir, usedFile))
	if w.highest > 0 {
		w.flags, w.version = zone.FlagMap{}, 0
		_ = w.persistUsed()
	}
}

func (w *Writer) readUsed() (flags zone.FlagMap, version, highest uint64, err error) {
	flags = zone.FlagMap{}
	raw, err := os.ReadFile(filepath.Join(w.cfg.Dir, usedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return flags, 0, 0, nil
	}
	if err != nil {
		return nil, 0, 0, err
	}
	body, err := fsx.Unseal(usedMagic, raw)
	if err != nil {
		return nil, 0, 0, err
	}
	var u usedJSON
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, 0, 0, fmt.Errorf("push: used file: %w", err)
	}
	for k, f := range u.Flags {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != 16 {
			return nil, 0, 0, errors.New("push: used file: bad node id")
		}
		flags[zone.NodeID(b)] = f
	}
	if u.Version > u.Highest {
		return nil, 0, 0, errors.New("push: used file: version above highest")
	}
	return flags, u.Version, u.Highest, nil
}

// checkPersistedPush is the start-time check of the persisted push: signature,
// validity, build. It judges neither expiry, version nor clock. A missing push
// file passes: the flags may be the product of a cut between the two writes.
func (w *Writer) checkPersistedPush(now int64, envBytes *[]byte, expires *int64, version *uint64) error {
	raw, err := os.ReadFile(filepath.Join(w.cfg.Dir, pushFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	body, err := fsx.Unseal(pushMagic, raw)
	if err != nil {
		return err
	}
	env := &signv1.Envelope{}
	if err := proto.Unmarshal(body, env); err != nil {
		return errors.New("push: persisted push is not an envelope")
	}
	if w.cfg.Root == nil {
		return errors.New("push: no trust root")
	}
	root, err := w.cfg.Root()
	if err != nil || root == nil {
		return errors.New("push: trust root unavailable")
	}
	payload, err := manifest.Verify(env, root, signv1.Role_ROLE_POLICY, manifest.TypePairTable, now)
	if err != nil {
		return fmt.Errorf("push: persisted push: %w", err)
	}
	pt := &policyv1.PairTable{}
	if err := proto.Unmarshal(payload, pt); err != nil {
		return errors.New("push: persisted payload is not a PairTable")
	}
	if err := wire.ValidatePairTablePush(pt); err != nil {
		return fmt.Errorf("push: persisted push: %w", err)
	}
	*envBytes, *expires, *version = body, pt.ExpiresAt, pt.Version
	return nil
}
