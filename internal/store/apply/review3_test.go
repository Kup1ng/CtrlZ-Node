package apply_test

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
)

// The floor snapshot is a shortcut. A hub whose newest snapshot is older than the
// floor (the normal case: the floor is near its head) must not hold back the
// entries, a hard_disable among them (review round 3, r3-4).
func TestFloorSnapshotThatTheHubCannotGiveDoesNotBlockTheEntries(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	entry1, entry2, _ := servedAtSeq2(t, e)
	damageState(t, e)
	e.reopen()
	e.hub.Snapshot = nil // "no snapshot that recent"
	res, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 1, Bytes: entry1}, {Seq: 2, Bytes: entry2}})
	if err != nil || len(res) != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	if e.a.AppliedSeq() != 2 || e.a.Floor() != 0 {
		t.Fatalf("applied %d floor %d", e.a.AppliedSeq(), e.a.Floor())
	}
	// The shortcut is tried once per call, not once per entry.
	if e.hub.Snaps != 1 {
		t.Fatalf("snapshot requests %d", e.hub.Snaps)
	}
	served(t, e, 2, false, true)
}

// A blob that the floor image holds on disk is not fetched again after a lost
// state (r3-5), by the snapshot or by an entry.
func TestLostStateDoesNotFetchBlobsItStillHolds(t *testing.T) {
	skipWindows(t)
	t.Run("snapshot", func(t *testing.T) {
		e := newEnv(t)
		entry1, _, snap := servedAtSeq2(t, e)
		damageState(t, e)
		e.reopen()
		e.hub.Snapshot = snap
		e.hub.Opens = 0
		if _, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 1, Bytes: entry1}}); err != nil {
			t.Fatal(err)
		}
		if e.hub.Opens != 0 {
			t.Fatalf("%d blob fetches for a blob that is on disk", e.hub.Opens)
		}
		e.a.Inspect(func(a *store.Applied) {
			if len(a.Q.Degraded) != 0 || len(a.Q.Wanted) != 0 || len(a.Q.Profiles) != 1 {
				t.Fatalf("degraded %d wanted %d profiles %d", len(a.Q.Degraded), len(a.Q.Wanted), len(a.Q.Profiles))
			}
		})
	})
	t.Run("entry", func(t *testing.T) {
		e := newEnv(t)
		entry1, _, _ := servedAtSeq2(t, e)
		damageState(t, e)
		e.noSnap = true
		e.reopen()
		e.hub.Opens = 0
		if _, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 1, Bytes: entry1}}); err != nil {
			t.Fatal(err)
		}
		if e.hub.Opens != 0 || e.a.AppliedSeq() != 1 {
			t.Fatalf("%d blob fetches, applied %d", e.hub.Opens, e.a.AppliedSeq())
		}
		e.a.Inspect(func(a *store.Applied) {
			if len(a.Q.Degraded) != 0 || len(a.Q.Profiles) != 1 {
				t.Fatalf("degraded %d profiles %d", len(a.Q.Degraded), len(a.Q.Profiles))
			}
		})
	})
}

// A held blob that rotted is fetched again, and the good bytes replace the rotted
// file, or the image would name a rotted file once the floor is reached (r3-6).
func TestRottedBlobUnderTheFloorIsReplacedByTheFetch(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	entry1, _, _ := servedAtSeq2(t, e)
	data := e.blob("a.example.com")
	h := sha256.Sum256(data)
	damageState(t, e)
	e.noSnap = true
	e.reopen()
	if err := os.WriteFile(e.root.BlobPath(h), []byte("rotted"), 0o640); err != nil {
		t.Fatal(err)
	}
	e.hub.Opens = 0
	if _, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 1, Bytes: entry1}}); err != nil {
		t.Fatal(err)
	}
	if e.hub.Opens != 1 {
		t.Fatalf("blob fetches %d", e.hub.Opens)
	}
	if _, err := e.root.ReadBlob(h); err != nil {
		t.Fatalf("the rotted file was kept: %v", err)
	}
}

// A resend of an entry the node has applied is skipped, not reported as a fault
// (r3-2).
func TestApplyEntryOfAnAppliedSeqIsSkipped(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	entry1, _, _ := servedAtSeq2(t, e)
	res := e.a.ApplyEntry(context.Background(), entry1)
	if !res.Skipped || res.Err != nil || res.Report.Advanced || res.Report.Entry != nil || e.a.AppliedSeq() != 2 {
		t.Fatalf("%+v", res)
	}
}
