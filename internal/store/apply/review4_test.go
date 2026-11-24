package apply_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// A hub that answers late with bytes that do not hash to the name used no budget,
// so the 60 s per fetch was the only bound and an apply could hold the mutex for
// as many minutes as there were wanted blobs (review round 4, r4-1).
func TestSlowWrongBytesAreChargedToTheFetchBudget(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.timeout = 5 * time.Second
	e.budget = 500 * time.Millisecond
	e.reopen()
	var blobs [][]byte
	var eps []*policyv1.EndpointRecord
	for i := 0; i < 6; i++ {
		d := storetest.Blob(t, string(rune('a'+i))+".example.com") // not on the hub yet
		blobs = append(blobs, d)
		eps = append(eps, storetest.Endpoint(byte(i+1), d))
	}
	e.mustApply(putEntry(blobs, eps...))
	var opens atomic.Int32
	e.hub.OpenHook = func(ctx context.Context, _ [32]byte) (io.ReadCloser, error, bool) {
		opens.Add(1)
		select {
		case <-time.After(400 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err(), true
		}
		return io.NopCloser(bytes.NewReader([]byte("wrong bytes"))), nil, true
	}
	res := e.apply(&policyv1.ConfigEntry{})
	if !res.Report.Advanced || res.Err != nil {
		t.Fatalf("%+v", res)
	}
	if n := opens.Load(); n != 2 {
		t.Fatalf("%d fetches started, the budget allows 2 of 400 ms", n)
	}
	e.a.Inspect(func(a *store.Applied) {
		if len(a.Q.Wanted) != 6 || len(a.Q.Quarantined) != 0 {
			t.Fatalf("wanted %d quarantined %d: wrong bytes judge the transfer, not the hash", len(a.Q.Wanted), len(a.Q.Quarantined))
		}
	})
}

// Two tenants' Endpoints that arrive with one rid_hash are both refused by
// resolver id, in the image and so for dns, and the collision is reported
// (r4-3). Tenant 3's Endpoint is untouched.
func TestCollidingRIDHashesServeNeitherTenant(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a, b, c := e.blob("a.example.com"), e.blob("b.example.com"), e.blob("c.example.com")
	epA, epB, epC := storetest.Endpoint(1, a), storetest.Endpoint(2, b), storetest.Endpoint(3, c)
	shared := identity.RIDHash("shared")
	epA.RidHash, epB.RidHash = shared[:], shared[:]
	rc := identity.RIDHash("tenant-c")
	epC.RidHash = rc[:]
	res := e.mustApply(putEntry([][]byte{a, b, c}, epA, epB, epC))
	reported := map[byte]bool{}
	for _, f := range res.Report.Quarantined {
		if f.Section == "rid_hash" {
			reported[f.Item[0]] = true
		}
	}
	if len(reported) != 2 || !reported[1] || !reported[2] {
		t.Fatalf("collision report %+v", res.Report.Quarantined)
	}
	im := e.current()
	if ep, ok := im.ByResolverID("shared"); ok {
		t.Fatalf("a colliding resolver id resolved to endpoint %d", ep.Record.EndpointId[0])
	}
	if ep, ok := im.ByResolverID("tenant-c"); !ok || ep.Record.EndpointId[0] != 3 {
		t.Fatal("tenant C lost its Endpoint")
	}
	if _, ok := im.ByEndpointID(key16(1)); !ok {
		t.Fatal("endpoint A is gone from the image by id")
	}
}

// Set-aside bytes go when their hash leaves the state, and an old stray file goes
// at the next start; a file of the state stays (r4-4).
func TestQuarantineDirectoryDoesNotOutliveTheState(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	bad := []byte("not a blob")
	bh := e.hub.Add(bad)
	good := e.blob("a.example.com")
	ent := putEntry([][]byte{good}, storetest.Endpoint(1, good), storetest.Endpoint(4, bad))
	ent.PutBlobs = append(ent.PutBlobs, &policyv1.BlobRef{Hash: bh[:], Size: uint64(len(bad)), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE})
	e.mustApply(ent)
	qpath := e.root.QuarantinePath(bh)
	if _, err := os.Stat(qpath); err != nil {
		t.Fatalf("the bad blob was not set aside: %v", err)
	}
	// A stray from a crash, and the file that is not ours.
	stray := [32]byte{0x77}
	if err := os.WriteFile(e.root.QuarantinePath(stray), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(e.root.Path(store.DirQuarantine), "state.bin.corrupt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if _, err := os.Stat(e.root.QuarantinePath(stray)); err == nil {
		t.Fatal("a stray quarantine file survived the start")
	}
	if _, err := os.Stat(qpath); err != nil {
		t.Fatalf("the file of a quarantined hash was swept: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("a file that is not a hash was deleted")
	}
	// A snapshot that no longer names the hash drops the verdict and the bytes.
	snap, _ := snapshotAt50(e, good, e.blob("b.example.com"))
	if r := e.a.ApplySnapshot(context.Background(), snap); r.Err != nil || !r.Report.Advanced {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(qpath); err == nil {
		t.Fatal("the bytes of a hash the state dropped are still on disk")
	}
}

// The directory is capped: the oldest files go first.
func TestTrimQuarantineKeepsTheNewestWithinTheCap(t *testing.T) {
	dir := t.TempDir()
	r, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var hs [][32]byte
	for i := 0; i < 4; i++ {
		h := [32]byte{byte(i + 1)}
		hs = append(hs, h)
		p := r.QuarantinePath(h)
		if err := os.WriteFile(p, bytes.Repeat([]byte{1}, 100), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, now, now.Add(time.Duration(i)*time.Minute))
	}
	if n := r.TrimQuarantine(func([32]byte) bool { return true }, 250); n != 2 {
		t.Fatalf("deleted %d", n)
	}
	for i, h := range hs {
		_, err := os.Stat(r.QuarantinePath(h))
		if (i < 2) == (err == nil) {
			t.Fatalf("file %d present=%v", i, err == nil)
		}
	}
}
