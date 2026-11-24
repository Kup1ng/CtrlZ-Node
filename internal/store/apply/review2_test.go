package apply_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// servedAtSeq2 puts a node at seq 2: entry 1 makes Endpoint 1 and claim 3 for it,
// entry 2 hard-disables the Endpoint and deletes the claim. It returns both stored
// entries so a test can resend them, and a hub snapshot of seq 2.
func servedAtSeq2(t *testing.T, e *env) (entry1, entry2 []byte, snap *signv1.Snapshot) {
	t.Helper()
	a := e.blob("a.example.com")
	var c storetest.Chain
	ent1 := putEntry([][]byte{a}, storetest.Endpoint(1, a))
	ent1.PutClaims = []*policyv1.ClaimRecord{storetest.Claim(3, 1)}
	ent1.PairTable = storetest.Table(3, 0)
	entry1 = c.Marshal(t, ent1)
	if r := e.a.ApplyEntry(context.Background(), entry1); !r.Report.Advanced || r.Err != nil {
		t.Fatalf("%+v", r)
	}
	c.Advance(entry1)
	disabled := storetest.Endpoint(1, a)
	disabled.AdminState = commonv1.AdminState_ADMIN_STATE_HARD_DISABLED
	ent2 := &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{disabled}, DelClaims: [][]byte{bytes.Repeat([]byte{3}, 16)}}
	entry2 = c.Marshal(t, ent2)
	if r := e.a.ApplyEntry(context.Background(), entry2); !r.Report.Advanced || r.Err != nil {
		t.Fatalf("%+v", r)
	}
	c.Advance(entry2)
	snap = &signv1.Snapshot{Seq: 2, EntryHash: c.Head[:],
		Blobs: []*policyv1.BlobRef{storetest.Ref(a)}, Endpoints: []*policyv1.EndpointRecord{disabled}, PairTable: storetest.Table(3, 0)}
	return entry1, entry2, snap
}

func damageState(t *testing.T, e *env) {
	t.Helper()
	p := e.root.Path(store.DirState, "state.bin")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	data[50] ^= 0xff
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// served asserts what dns would read: the image seq, whether the claim is there
// and whether the Endpoint is hard disabled.
func served(t *testing.T, e *env, seq uint64, claim, hardDisabled bool) {
	t.Helper()
	im := e.current()
	ep, ok := im.ByEndpointID(key16(1))
	if im.Seq() != seq || (len(im.Claims()) == 1) != claim || !ok ||
		(ep.Record.AdminState == commonv1.AdminState_ADMIN_STATE_HARD_DISABLED) != hardDisabled {
		t.Fatalf("served image: seq %d (want %d), claims %d (want claim %v), endpoint %+v (want hard disabled %v)",
			im.Seq(), seq, len(im.Claims()), claim, ep, hardDisabled)
	}
}

// A lost state file must not make the node serve a policy older than the image it
// was serving: a hard_disable and a claim delete that were applied stay in effect
// while older entries are applied on the way up (review round 2, r2-5).
func TestLostStateNeverRewindsTheServedPolicy(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	entry1, entry2, _ := servedAtSeq2(t, e)
	served(t, e, 2, false, true)
	damageState(t, e)
	e.noSnap = true
	e.reopen()
	if e.a.Floor() != 2 || e.a.AppliedSeq() != 0 {
		t.Fatalf("floor %d applied %d", e.a.Floor(), e.a.AppliedSeq())
	}
	served(t, e, 2, false, true)

	// The hub resends from its oldest kept entry.
	res, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 1, Bytes: entry1}})
	if err != nil || len(res) != 1 || !res[0].Report.Advanced || e.a.AppliedSeq() != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	served(t, e, 2, false, true)
	// A restart in the middle finds the same floor and the same image.
	e.reopen()
	if e.a.Floor() != 2 || e.a.AppliedSeq() != 1 {
		t.Fatalf("after restart: floor %d applied %d", e.a.Floor(), e.a.AppliedSeq())
	}
	served(t, e, 2, false, true)
	// Reaching the floor builds the image from the state again.
	res, err = e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 2, Bytes: entry2}})
	if err != nil || len(res) != 1 || !res[0].Report.Advanced {
		t.Fatalf("%v %+v", err, res)
	}
	if e.a.Floor() != 0 || e.a.AppliedSeq() != 2 {
		t.Fatalf("floor %d applied %d", e.a.Floor(), e.a.AppliedSeq())
	}
	served(t, e, 2, false, true)
	e.reopen()
	if e.rep.Image != apply.ImageOK {
		t.Fatalf("image at start: %v", e.rep.Image)
	}
}

// With a snapshot source the node does not climb entry by entry: it asks for a
// snapshot at or above the floor and the entry below it is skipped.
func TestLostStateAsksForASnapshotAtTheFloor(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	entry1, _, snap := servedAtSeq2(t, e)
	damageState(t, e)
	e.reopen()
	e.hub.Snapshot = snap
	res, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 1, Bytes: entry1}})
	if err != nil || e.hub.Snaps != 1 {
		t.Fatalf("%v snapshots %d %+v", err, e.hub.Snaps, res)
	}
	if e.a.AppliedSeq() != 2 || e.a.Floor() != 0 {
		t.Fatalf("applied %d floor %d", e.a.AppliedSeq(), e.a.Floor())
	}
	served(t, e, 2, false, true)
	// The blob under the image is still there after the floor was lifted.
	if im := e.current(); len(im.Blobs()) != 1 {
		t.Fatal("blob lost")
	}
}

// A snapshot below the floor is kept as state but serves nothing.
func TestSnapshotBelowTheFloorServesNothing(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	servedAtSeq2(t, e)
	damageState(t, e)
	e.reopen()
	low := &signv1.Snapshot{Seq: 1, EntryHash: bytes.Repeat([]byte{1}, 32)}
	a := e.blob("a.example.com")
	low.Blobs = []*policyv1.BlobRef{storetest.Ref(a)}
	low.Endpoints = []*policyv1.EndpointRecord{storetest.Endpoint(1, a)}
	low.Claims = []*policyv1.ClaimRecord{storetest.Claim(3, 1)}
	low.PairTable = storetest.Table(3, 0)
	r := e.a.ApplySnapshot(context.Background(), low)
	if r.Err != nil || e.a.AppliedSeq() != 1 || e.a.Floor() != 2 {
		t.Fatalf("%+v", r)
	}
	served(t, e, 2, false, true)
}

// SC 9.7 item 2: a snapshot that names more blobs than MaxWanted keeps the list
// within it, and the hash an Endpoint binds is never the one dropped (r2-3).
func TestSnapshotWantedListIsBounded(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a := e.blob("a.example.com")
	ha := storetest.Hash(a)
	snap := &signv1.Snapshot{Seq: 5, EntryHash: bytes.Repeat([]byte{5}, 32), PairTable: storetest.Table(3, 0)}
	snap.Blobs = append(snap.Blobs, storetest.Ref(a))
	snap.Endpoints = []*policyv1.EndpointRecord{storetest.Endpoint(1, a)}
	const extra = quarantine.MaxWanted + 500
	for i := 0; i < extra; i++ {
		var h [32]byte
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		h[31] = 1
		snap.Blobs = append(snap.Blobs, &policyv1.BlobRef{Hash: h[:], Kind: policyv1.BlobKind_BLOB_KIND_PROFILE, Size: 10})
	}
	// The context is already over, so nothing is fetched and everything stays wanted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := e.a.ApplySnapshot(ctx, snap)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	e.a.Inspect(func(s *store.Applied) {
		if len(s.Q.Wanted) > quarantine.MaxWanted {
			t.Fatalf("%d wanted", len(s.Q.Wanted))
		}
		if _, ok := s.Q.Wanted[ha]; !ok {
			t.Fatal("the hash an Endpoint binds was dropped")
		}
	})
}

// A snapshot with no PairTable leaves the membership as an entry with none does,
// so the running table and the state file agree (review round 2, r2-7).
func TestSnapshotWithoutAPairTableKeepsTheMembership(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a := e.blob("a.example.com")
	ent := putEntry([][]byte{a}, storetest.Endpoint(1, a))
	ent.PairTable = storetest.Table(3, 0)
	e.mustApply(ent)
	snap := &signv1.Snapshot{Seq: 9, EntryHash: bytes.Repeat([]byte{9}, 32),
		Blobs: []*policyv1.BlobRef{storetest.Ref(a)}, Endpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, a)}}
	if r := e.a.ApplySnapshot(context.Background(), snap); r.Err != nil || !r.Report.Advanced {
		t.Fatalf("%+v", r)
	}
	if e.push.Table() == nil {
		t.Fatal("the running table was dropped")
	}
	e.reopen()
	if e.push.Table() == nil || e.current().PairTable() == nil {
		t.Fatal("after a restart the membership is gone: memory and disk disagree")
	}
}

// ApplyEntries holds a snapshot against the verified head before it applies it
// (review round 2, r2-8).
func TestSnapshotIsCheckedAgainstTheSignedHead(t *testing.T) {
	skipWindows(t)
	for _, tc := range []struct {
		name string
		head func(snapHash [32]byte) (uint64, [32]byte, error)
		ok   bool
	}{
		{"snapshot ahead of the head", func([32]byte) (uint64, [32]byte, error) { return 49, [32]byte{}, nil }, false},
		{"same seq, other hash", func([32]byte) (uint64, [32]byte, error) { return 50, [32]byte{1}, nil }, false},
		{"the head cannot be read", func([32]byte) (uint64, [32]byte, error) { return 0, [32]byte{}, errors.New("down") }, false},
		{"same seq and hash", func(h [32]byte) (uint64, [32]byte, error) { return 50, h, nil }, true},
		{"head ahead", func([32]byte) (uint64, [32]byte, error) { return 60, [32]byte{}, nil }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.blob("a.example.com"), e.blob("b.example.com")
			_, hash := snapshotAt50(e, a, b)
			e.headFn = func(context.Context) (uint64, [32]byte, error) { return tc.head(hash) }
			e.reopen()
			chain := storetest.Chain{Seq: 50, Head: hash}
			entry51 := chain.Next(t, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(3, a)}})
			_, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 51, Bytes: entry51}})
			if tc.ok && (err != nil || e.a.AppliedSeq() != 51) {
				t.Fatalf("%v applied %d", err, e.a.AppliedSeq())
			}
			if !tc.ok && (err == nil || e.a.AppliedSeq() != 0) {
				t.Fatalf("%v applied %d", err, e.a.AppliedSeq())
			}
		})
	}
}
