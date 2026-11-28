package store_test

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func open(t *testing.T, dir string, w *fsx.Writer) *store.Root {
	t.Helper()
	r, err := store.Open(dir, w)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLayoutAndModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are Linux")
	}
	dir := filepath.Join(t.TempDir(), "ctrlz")
	r := open(t, dir, nil)
	want := map[string]os.FileMode{
		"": 0o750, store.DirState: 0o700, store.DirLog: 0o700, store.DirBlobs: 0o750, store.DirQuarantine: 0o700,
		store.DirImage: 0o750, store.DirPush: 0o700, store.DirKeys: 0o700, store.DirConfig: 0o750,
	}
	for name, mode := range want {
		st, err := os.Stat(r.Path(name))
		if err != nil || !st.IsDir() || st.Mode().Perm() != mode {
			t.Errorf("%q: %v %v", name, st, err)
		}
	}
	// A directory made by an older run with a looser mode is tightened.
	if err := os.Chmod(r.Path(store.DirKeys), 0o755); err != nil {
		t.Fatal(err)
	}
	r = open(t, dir, nil)
	if st, _ := os.Stat(r.Path(store.DirKeys)); st.Mode().Perm() != 0o700 {
		t.Errorf("keys mode %v", st.Mode().Perm())
	}
	// Blobs are group-readable, set-aside bytes and staged files are not.
	d := storetest.Blob(t, "a.example.com")
	h := storetest.Hash(d)
	if err := r.PutBlob(h, d); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(r.BlobPath(h)); st.Mode().Perm() != 0o640 {
		t.Errorf("blob mode %v", st.Mode().Perm())
	}
	if err := r.AppendEntry(1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(r.Path(store.DirLog, "00000000000000000001.entry")); st.Mode().Perm() != 0o600 {
		t.Errorf("log mode %v", st.Mode().Perm())
	}
}

func TestOpenRemovesLeftoversOfACrash(t *testing.T) {
	dir := t.TempDir()
	w := &fsx.Writer{Hook: func(_ string, s fsx.Step) error {
		if s == fsx.StepRename {
			return fsx.ErrInjected
		}
		return nil
	}}
	r := open(t, dir, w)
	if err := r.AppendEntry(1, []byte("x")); !errors.Is(err, fsx.ErrInjected) {
		t.Fatal(err)
	}
	if err := r.StageBlob([32]byte{1}, []byte("x")); !errors.Is(err, fsx.ErrInjected) {
		t.Fatal(err)
	}
	r = open(t, dir, nil)
	for _, d := range []string{store.DirLog, "quarantine/incoming"} {
		ents, _ := os.ReadDir(r.Path(d))
		if len(ents) != 0 {
			t.Errorf("%s holds %d files after a start", d, len(ents))
		}
	}
}

func TestBlobIsCheckedAgainstItsName(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	d := storetest.Blob(t, "a.example.com")
	h := storetest.Hash(d)
	if err := r.PutBlob([32]byte{9}, d); err == nil {
		t.Fatal("bytes that do not hash to the name were stored")
	}
	if err := r.PutBlob(h, d); err != nil {
		t.Fatal(err)
	}
	if got, err := r.ReadBlob(h); err != nil || string(got) != string(d) {
		t.Fatal(err)
	}
	// Rot on disk is found at read.
	if err := os.WriteFile(r.BlobPath(h), append([]byte("X"), d[1:]...), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadBlob(h); err == nil {
		t.Fatal("a rotted blob was returned")
	}
	if hs, _ := r.ListBlobs(); len(hs) != 1 || hs[0] != h {
		t.Fatalf("list %v", hs)
	}
	if err := r.DeleteBlob(h); err != nil || r.DeleteBlob(h) != nil {
		t.Fatal("delete must be idempotent")
	}
}

func TestStagedBlobsArePromotedOrSetAsideOrDropped(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	a, b, c := [32]byte{1}, [32]byte{2}, [32]byte{3}
	for _, h := range [][32]byte{a, b, c} {
		if err := r.StageBlob(h, []byte{h[0]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.PromoteBlob(a); err != nil {
		t.Fatal(err)
	}
	if err := r.SetAsideStaged(b); err != nil {
		t.Fatal(err)
	}
	r.DropStaged(c)
	r.DropStaged(c) // idempotent
	if _, err := os.Stat(r.BlobPath(a)); err != nil {
		t.Error("promoted blob missing")
	}
	if _, err := os.Stat(r.QuarantinePath(b)); err != nil {
		t.Error("set-aside blob missing")
	}
	ents, _ := os.ReadDir(r.IncomingDir())
	if len(ents) != 0 {
		t.Errorf("incoming not empty: %d", len(ents))
	}
}

func TestLogKeepsExactBytesAndPrunes(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	for s := uint64(1); s <= 5; s++ {
		if err := r.AppendEntry(s, []byte{byte(s), 0xff, 0}); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := r.ReadEntry(3); err != nil || string(b) != "\x03\xff\x00" {
		t.Fatalf("%q %v", b, err)
	}
	if n, err := r.PruneLog(4); err != nil || n != 3 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if s, _ := r.LogSeqs(); len(s) != 2 || s[0] != 4 || s[1] != 5 {
		t.Fatalf("seqs %v", s)
	}
}

// fullState builds a state with every kind of record in it.
func fullState(t *testing.T, r *store.Root) (*store.Applied, [][32]byte) {
	t.Helper()
	d1, d2 := storetest.Blob(t, "a.example.com"), storetest.Blob(t, "b.example.com")
	h1, h2 := storetest.Hash(d1), storetest.Hash(d2)
	for _, p := range []struct {
		h [32]byte
		d []byte
	}{{h1, d1}, {h2, d2}} {
		if err := r.PutBlob(p.h, p.d); err != nil {
			t.Fatal(err)
		}
	}
	a := store.NewApplied()
	q := a.Q
	q.AppliedSeq, q.Head, q.WantedCursor = 7, [32]byte{7}, [32]byte{3}
	var err error
	if q.Profiles[h1], err = blob.Open(d1); err != nil {
		t.Fatal(err)
	}
	if q.Profiles[h2], err = blob.Open(d2); err != nil {
		t.Fatal(err)
	}
	e1, e2 := storetest.Endpoint(1, d1), storetest.Endpoint(2, d2)
	q.Endpoints[[16]byte(e1.EndpointId)], q.Endpoints[[16]byte(e2.EndpointId)] = e1, e2
	q.Claims[[16]byte(storetest.Claim(5, 1).ClaimId)] = storetest.Claim(5, 1)
	q.Quarantined[[32]byte{0xee}] = reason.BadMagic
	missing := storetest.Blob(t, "c.example.com")
	mh := storetest.Hash(missing)
	ref := &policyv1.BlobRef{Hash: mh[:], Size: uint64(len(missing)), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
	q.Wanted[mh] = ref
	e3 := storetest.Endpoint(3, missing)
	q.Endpoints[[16]byte(e3.EndpointId)] = e3
	q.Degraded[[16]byte(e3.EndpointId)] = true
	a.FreeDNS = &policyv1.FreeDns{Enabled: true, Qps: 50, Version: 4}
	a.Member = storetest.Table(2, 0)
	return a, [][32]byte{h1, h2, mh}
}

func TestStateRoundTrip(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	a, _ := fullState(t, r)
	if err := r.SaveApplied(a); err != nil {
		t.Fatal(err)
	}
	b1, _ := store.EncodeApplied(a)
	got, rep, err := r.LoadApplied()
	if err != nil || rep.Fresh || rep.Corrupt != nil || len(rep.Lost) != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	b2, _ := store.EncodeApplied(got)
	if string(b1) != string(b2) {
		t.Fatal("the loaded state encodes differently from the saved one")
	}
	if got.Q.AppliedSeq != 7 || got.FreeDNS.GetQps() != 50 || len(got.Member.Nodes) != 2 || len(got.Q.Profiles) != 2 {
		t.Fatalf("%+v", got.Q)
	}
}

func TestNoStateIsAFreshNode(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	a, rep, err := r.LoadApplied()
	if err != nil || !rep.Fresh || a.Q.AppliedSeq != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
}

// A damaged state file is set aside and the node starts fresh: it must not refuse
// to start.
func TestCorruptStateIsSetAside(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	a, _ := fullState(t, r)
	if err := r.SaveApplied(a); err != nil {
		t.Fatal(err)
	}
	p := r.Path(store.DirState, "state.bin")
	b, _ := os.ReadFile(p)
	for _, bad := range [][]byte{b[:len(b)/2], append(append([]byte(nil), b[:100]...), b[101:]...), {}} {
		if err := os.WriteFile(p, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		got, rep, err := r.LoadApplied()
		if err != nil || !rep.Fresh || rep.Corrupt == nil || got.Q.AppliedSeq != 0 {
			t.Fatalf("%v %+v", err, rep)
		}
		if _, err := os.Stat(p); err == nil {
			t.Fatal("the damaged file is still in place")
		}
		if _, err := os.Stat(r.Path(store.DirQuarantine, "state.bin.corrupt")); err != nil {
			t.Fatal("the damaged file was not kept for a person to look at")
		}
	}
}

// Truncating a valid state at every length is either refused or, never, a panic.
func TestTruncatedStateNeverPanics(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	a, _ := fullState(t, r)
	good, _ := store.EncodeApplied(a)
	p := r.Path(store.DirState, "state.bin")
	for n := 0; n < len(good); n += 7 {
		if err := os.WriteFile(p, good[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		_, rep, err := r.LoadApplied()
		if err != nil || !rep.Fresh {
			t.Fatalf("length %d: %v %+v", n, err, rep)
		}
	}
}

// A blob that is gone or rotted at load goes back on the wanted list, and the
// Endpoint that binds it is degraded and pending (9.7 items 2 and 7).
func TestLostBlobIsWantedAgain(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	a, hs := fullState(t, r)
	if err := r.SaveApplied(a); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.BlobPath(hs[0])); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.BlobPath(hs[1]), []byte("rot"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, rep, err := r.LoadApplied()
	if err != nil || len(rep.Lost) != 2 {
		t.Fatalf("%v %+v", err, rep)
	}
	q := got.Q
	if len(q.Profiles) != 0 || q.Wanted[hs[0]] == nil || q.Wanted[hs[1]] == nil {
		t.Fatalf("profiles %d wanted %d", len(q.Profiles), len(q.Wanted))
	}
	for _, id := range []byte{1, 2, 3} {
		k := [16]byte{}
		for i := range k {
			k[i] = id
		}
		if !q.Degraded[k] || q.Pending[k] == nil {
			t.Errorf("endpoint %d is not degraded and pending", id)
		}
	}
}

func TestStateHashChangesWithTheState(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	a, _ := fullState(t, r)
	_ = r.SaveApplied(a)
	h1, _ := r.StateHash()
	a.Q.AppliedSeq++
	_ = r.SaveApplied(a)
	h2, _ := r.StateHash()
	if h1 == h2 || h1 == (sha256.Sum256(nil)) {
		t.Fatal("hash did not change")
	}
}

func TestKeysAreAgentOnly(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	if err := r.WriteKey("node.key", []byte("key bytes")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(r.KeyPath("node.key")); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
	for _, bad := range []string{"", ".", "..", "../x", "a/b"} {
		if err := r.WriteKey(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// PeekMember reads the table of the state and, unlike LoadApplied, leaves a damaged
// file where it is.
func TestPeekMemberReadsAndChangesNothing(t *testing.T) {
	r := open(t, t.TempDir(), nil)
	if r.PeekMember() != nil {
		t.Fatal("a table from no state")
	}
	a, _ := fullState(t, r)
	if err := r.SaveApplied(a); err != nil {
		t.Fatal(err)
	}
	if m := r.PeekMember(); m == nil || len(m.Nodes) != 2 {
		t.Fatalf("member %v", m)
	}
	p := r.Path(store.DirState, "state.bin")
	if err := os.WriteFile(p, []byte("not a state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r.PeekMember() != nil {
		t.Fatal("a table from a damaged file")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("PeekMember moved the damaged file")
	}
	if _, err := os.Stat(r.Path(store.DirQuarantine, "state.bin.corrupt")); err == nil {
		t.Fatal("PeekMember quarantined the file")
	}
}

// PeekMemberAt reads the same table with no Open of its own.
func TestPeekMemberAtReadsTheOpenStore(t *testing.T) {
	dir := t.TempDir()
	r := open(t, dir, nil)
	if store.PeekMemberAt(dir) != nil {
		t.Fatal("a table from no state")
	}
	a, _ := fullState(t, r)
	if err := r.SaveApplied(a); err != nil {
		t.Fatal(err)
	}
	if m := store.PeekMemberAt(dir); m == nil || len(m.Nodes) != 2 {
		t.Fatalf("member %v", m)
	}
}
