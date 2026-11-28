package apply_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"crypto/sha256"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// snapshotAt50 is the hub's snapshot: two Endpoints, a claim, a table, a free value.
func snapshotAt50(e *env, a, b []byte) (*signv1.Snapshot, [32]byte) {
	var head [32]byte
	head[0] = 0x50
	snap := &signv1.Snapshot{Seq: 50, EntryHash: head[:]}
	snap.Blobs = []*policyv1.BlobRef{storetest.Ref(a), storetest.Ref(b)}
	snap.Endpoints = []*policyv1.EndpointRecord{storetest.Endpoint(1, a), storetest.Endpoint(2, b)}
	snap.Claims = []*policyv1.ClaimRecord{storetest.Claim(3, 1)}
	snap.PairTable = storetest.Table(3, 0)
	snap.FreeDns = &policyv1.FreeDns{Enabled: true, Qps: 10, Version: 7}
	e.hub.Snapshot = snap
	return snap, head
}

// A node that is new, shown an entry far ahead of it, asks for a snapshot, applies
// it and then the entry, which chains from the snapshot's hash.
func TestAGapIsBridgedBySnapshot(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a, b := e.blob("a.example.com"), e.blob("b.example.com")
	_, head := snapshotAt50(e, a, b)
	chain := storetest.Chain{Seq: 50, Head: head}
	entry51 := chain.Next(t, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(3, a)}})
	// A log entry from before the snapshot, to see it dropped.
	if err := e.root.AppendEntry(7, []byte("old")); err != nil {
		t.Fatal(err)
	}

	results, err := e.a.ApplyEntries(context.Background(), []apply.Stored{
		{Seq: 51, Bytes: entry51},
		{Seq: 51, Bytes: entry51}, // a resend is skipped
	})
	if err != nil || len(results) != 3 || !results[len(results)-1].Skipped {
		t.Fatalf("%v %+v", err, results)
	}
	if e.hub.Snaps != 1 || e.a.AppliedSeq() != 51 {
		t.Fatalf("snapshots asked %d, applied %d", e.hub.Snaps, e.a.AppliedSeq())
	}
	im := e.current()
	if im.Seq() != 51 || im.EndpointCount() != 3 || len(im.Claims()) != 1 || im.Zone() == nil {
		t.Fatalf("%+v", im.Meta())
	}
	if en, qps, v, ok := im.FreeDNS(); !ok || !en || qps != 10 || v != 7 {
		t.Fatal("free dns value of the snapshot")
	}
	for _, id := range []byte{1, 2, 3} {
		if ep, ok := im.ByEndpointID(key16(id)); !ok || ep.Degraded {
			t.Fatalf("endpoint %d degraded or missing", id)
		}
	}
	if len(e.push.Table().Nodes) != 3 {
		t.Fatal("the table of the snapshot is not in use")
	}
	if seqs, _ := e.root.LogSeqs(); len(seqs) != 1 || seqs[0] != 51 {
		t.Fatalf("log after a snapshot: %v", seqs)
	}
	// The result survives a restart.
	e.reopen()
	if e.a.AppliedSeq() != 51 || e.rep.Image != apply.ImageOK {
		t.Fatalf("%+v", e.rep)
	}
	// A snapshot that is not ahead of applied_seq is refused.
	if r := e.a.ApplySnapshot(context.Background(), e.hub.Snapshot); !errors.Is(r.Err, apply.ErrStaleSnapshot) {
		t.Fatalf("%+v", r)
	}
}

func TestAGapWithNoSnapshotSourceChangesNothing(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.noSnap = true
	e.reopen()
	chain := storetest.Chain{Seq: 5}
	ent := chain.Next(t, &policyv1.ConfigEntry{})
	_, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 6, Bytes: ent}})
	if !errors.Is(err, apply.ErrGap) || e.a.AppliedSeq() != 0 {
		t.Fatalf("%v", err)
	}
	// And a hub that has no snapshot recent enough is an error, not a state change.
	e.noSnap = false
	e.reopen()
	if _, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 6, Bytes: ent}}); err == nil || e.a.AppliedSeq() != 0 {
		t.Fatalf("%v", err)
	}
}

// Entries stop at the first one that is refused: those after it chain from it.
func TestApplyEntriesStopsAtARefusedEntry(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	c := e.chain
	good1 := c.Next(t, &policyv1.ConfigEntry{})
	bad := []byte("broken")
	good2 := c.Next(t, &policyv1.ConfigEntry{})
	results, err := e.a.ApplyEntries(context.Background(), []apply.Stored{{Seq: 1, Bytes: good1}, {Seq: 2, Bytes: bad}, {Seq: 3, Bytes: good2}})
	if err != nil || len(results) != 2 || !results[0].Report.Advanced || results[1].Report.Advanced || results[1].Report.Entry == nil {
		t.Fatalf("%v %+v", err, results)
	}
	if e.a.AppliedSeq() != 1 {
		t.Fatal("applied")
	}
}

// A snapshot with a blob the hub does not have: the Endpoints wait, degraded, and
// a Retry later finishes the job. A snapshot with a blob that hashes right and
// does not open: quarantined.
func TestSnapshotWithMissingAndBadBlobs(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a := e.blob("a.example.com")
	b := storetest.Blob(t, "b.example.com") // not on the hub
	snap, _ := snapshotAt50(e, a, b)
	bad := []byte("not a blob")
	bh := e.hub.Add(bad)
	snap.Blobs = append(snap.Blobs, &policyv1.BlobRef{Hash: bh[:], Size: uint64(len(bad)), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE})
	snap.Endpoints = append(snap.Endpoints, storetest.Endpoint(4, bad))

	res := e.a.ApplySnapshot(context.Background(), snap)
	if res.Err != nil || !res.Report.Advanced || len(res.Report.Quarantined) != 1 {
		t.Fatalf("%+v", res)
	}
	im := e.current()
	if ep, _ := im.ByEndpointID(key16(1)); ep.Degraded {
		t.Fatal("endpoint 1 has its blob")
	}
	if ep, _ := im.ByEndpointID(key16(2)); !ep.Degraded {
		t.Fatal("endpoint 2 waits for a blob")
	}
	if ep, _ := im.ByEndpointID(key16(4)); !ep.Degraded {
		t.Fatal("endpoint 4 has only a quarantined blob")
	}
	e.hub.Add(b)
	r := e.a.Retry(context.Background())
	if r.Err != nil || len(r.Report.Promoted) != 1 {
		t.Fatalf("%+v", r)
	}
	if ep, _ := e.current().ByEndpointID(key16(2)); ep.Degraded {
		t.Fatal("not promoted")
	}
}

func TestBadSnapshotsAreRefused(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a, b := e.blob("a.example.com"), e.blob("b.example.com")
	mk := func(mut func(*signv1.Snapshot)) *signv1.Snapshot {
		s, _ := snapshotAt50(e, a, b)
		c := proto.Clone(s).(*signv1.Snapshot)
		mut(c)
		return c
	}
	for name, s := range map[string]*signv1.Snapshot{
		"nil":          nil,
		"seq 0":        mk(func(s *signv1.Snapshot) { s.Seq = 0 }),
		"short hash":   mk(func(s *signv1.Snapshot) { s.EntryHash = []byte{1} }),
		"dup endpoint": mk(func(s *signv1.Snapshot) { s.Endpoints = append(s.Endpoints, s.Endpoints[0]) }),
		"bad table": mk(func(s *signv1.Snapshot) {
			s.PairTable = storetest.Table(2, 0)
			s.PairTable.Pairs[0].Primary = []byte{1}
		}),
		"bad free value": mk(func(s *signv1.Snapshot) { s.FreeDns = &policyv1.FreeDns{Enabled: true, Qps: 0, Version: 1} }),
		"bad endpoint":   mk(func(s *signv1.Snapshot) { s.Endpoints = []*policyv1.EndpointRecord{{EndpointId: []byte{1}}} }),
	} {
		res := e.a.ApplySnapshot(context.Background(), s)
		if res.Err == nil && res.Report.Entry == nil {
			t.Errorf("%s: accepted: %+v", name, res)
		}
		if e.a.AppliedSeq() != 0 {
			t.Fatalf("%s: state moved", name)
		}
	}
}

// ---- Retry persistence ----

// The cursor of the wanted walk is on disk: a Retry after a restart goes on
// where the last one stopped, so every wanted hash is tried within
// ceil(len/budget) passes (T-533).
func TestRetryCursorSurvivesARestart(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	const n = 300
	var blobs [][]byte
	for i := 0; i < n; i++ {
		blobs = append(blobs, storetest.Blob(t, fmt.Sprintf("n%d.example.com", i))) // none on the hub
	}
	var eps []*policyv1.EndpointRecord
	for i := 0; i < n; i++ {
		eps = append(eps, storetest.Endpoint(byte(i%250+1), blobs[i]))
	}
	// 300 blobs wanted, none served. (Endpoint ids repeat after 250, which only
	// replaces a pending put by a later one in the same entry's map.)
	ent := &policyv1.ConfigEntry{}
	for _, b := range blobs {
		ent.PutBlobs = append(ent.PutBlobs, storetest.Ref(b))
	}
	e.mustApply(ent)
	r1 := e.a.Retry(context.Background())
	if r1.Err != nil {
		t.Fatal(r1.Err)
	}
	e.reopen()
	r2 := e.a.Retry(context.Background())
	if r2.Err != nil {
		t.Fatal(r2.Err)
	}
	tried := 0
	for _, b := range blobs {
		// Once by the entry, once by a Retry at least.
		if e.hub.Count[storetest.Hash(b)] >= 2 {
			tried++
		}
	}
	if tried != n {
		t.Fatalf("%d of %d wanted blobs were tried by the two Retry passes; the cursor was not kept", tried, n)
	}
	_ = eps
}

// ---- secrets ----

// After a full cycle of every kind of write, no file under the root holds the
// real proof_key or the DNS cookie secret (SC 8a.3, 7.2).
func TestSecretsNeverReachDisk(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	proofKey := storetest.RandomSecret(t, 32)
	cookie := storetest.RandomSecret(t, 32)

	nc := nodecfg.New(e.root.Path(store.DirConfig), e.root.W)
	nodeConfig := newNodeConfig(proofKey)
	if err := nc.Save(nodeConfig); err != nil {
		t.Fatal(err)
	}
	nodeConfig.Version = 2
	if err := nc.Save(nodeConfig); err != nil {
		t.Fatal(err)
	}

	a, b := e.blob("a.example.com"), e.blob("b.example.com")
	ent := putEntry([][]byte{a, b}, storetest.Endpoint(1, a), storetest.Endpoint(2, b))
	ent.PairTable = storetest.Table(3, 0)
	ent.PutClaims = []*policyv1.ClaimRecord{storetest.Claim(1, 1)}
	e.mustApply(ent)
	if r := e.push.ApplyPush(e.keys.Sign(t, withExpiry(storetest.Table(3, 99, 1), 1_001_800)), clock); !r.Accepted {
		t.Fatalf("%+v", r)
	}
	snap, _ := snapshotAt50(e, a, b)
	_ = snap
	e.a.ApplySnapshot(context.Background(), e.hub.Snapshot)
	e.a.Retry(context.Background())
	e.reopen()

	for name, secret := range map[string][]byte{"proof_key": proofKey, "dns cookie secret": cookie} {
		if storetest.Contains(t, e.dir, secret) {
			t.Fatalf("the %s reached a file under the root", name)
		}
	}
	// The config on disk holds the 16 zero bytes.
	got, err := nc.LoadServing("/nonexistent")
	if err != nil || !bytes.Equal(got.Config.ProofKey, make([]byte, 16)) {
		t.Fatalf("%+v %v", got, err)
	}
}

// ---- two tenants ----

// Tenant A and tenant B share a node. A's bad blob, hard disable and deletion
// touch only A; a lookup by A's resolver id never returns B's binding.
func TestTwoTenantsShareANodeWithoutSharingState(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	pa, pb := e.blob("a-profile.example.com"), e.blob("b-profile.example.com")
	shared := e.blob("shared.example.com")
	mk := func(id byte, rid string, profile []byte) *policyv1.EndpointRecord {
		ep := storetest.Endpoint(id, profile)
		h := identity.RIDHash(rid)
		ep.RidHash = h[:]
		return ep
	}
	a1, a2, b1 := mk(1, "ridA1", pa), mk(2, "ridA2", shared), mk(3, "ridB1", pb)
	ent := putEntry([][]byte{pa, pb, shared}, a1, a2, b1)
	ent.PutClaims = []*policyv1.ClaimRecord{storetest.Claim(1, 1), storetest.Claim(3, 3)}
	e.mustApply(ent)

	im := e.current()
	for rid, want := range map[string][]byte{"ridA1": pa, "ridA2": shared, "ridB1": pb} {
		ep, ok := im.ByResolverID(rid)
		if !ok || !bytes.Equal(ep.Record.Base.Profile1Hash, storetest.Ref(want).Hash) {
			t.Fatalf("%s resolves to another binding", rid)
		}
	}
	if _, ok := im.ByResolverID("ridC1"); ok {
		t.Fatal("an unknown resolver id found an Endpoint")
	}
	ownerOf := func(im *image.Image) map[[16]byte][16]byte {
		m := map[[16]byte][16]byte{}
		for _, c := range im.Claims() {
			m[c.ID] = c.EndpointID
		}
		return m
	}
	if o := ownerOf(im); o[key16(1)] != key16(1) || o[key16(3)] != key16(3) {
		t.Fatalf("claims: %v", o)
	}

	// A's profile is replaced by a blob that does not open; A hard-disables it too.
	bad := []byte("garbage that will hash right")
	e.hub.Add(bad)
	a1bad := mk(1, "ridA1", bad)
	a1bad.AdminState = commonv1.AdminState_ADMIN_STATE_HARD_DISABLED
	res := e.mustApply(&policyv1.ConfigEntry{
		PutBlobs:     []*policyv1.BlobRef{{Hash: sum(bad), Size: uint64(len(bad)), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}},
		PutEndpoints: []*policyv1.EndpointRecord{a1bad},
	})
	if len(res.Report.KeptPrevious) != 1 {
		t.Fatalf("%+v", res.Report)
	}
	im = e.current()
	epA, _ := im.ByResolverID("ridA1")
	if epA.Record.AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED || !bytes.Equal(epA.Record.Base.Profile1Hash, storetest.Ref(pa).Hash) {
		t.Fatal("A's hard disable did not apply with its previous binding kept")
	}
	epB, _ := im.ByResolverID("ridB1")
	if epB.Degraded || epB.Record.AdminState != commonv1.AdminState_ADMIN_STATE_ENABLED || !bytes.Equal(epB.Record.Base.Profile1Hash, storetest.Ref(pb).Hash) {
		t.Fatal("B was touched by A's bad blob")
	}

	// A is deleted. B keeps its Endpoint, claim and blob; the blob they shared stays for A2... which is gone with A.
	res = e.mustApply(&policyv1.ConfigEntry{DelEndpoints: [][]byte{a1.EndpointId, a2.EndpointId}, DelClaims: [][]byte{storetest.Claim(1, 1).ClaimId},
		DelBlobs: [][]byte{hashOf(pa), hashOf(shared)}})
	im = e.current()
	if _, ok := im.ByResolverID("ridA1"); ok {
		t.Fatal("A's Endpoint is still served")
	}
	if ep, ok := im.ByResolverID("ridB1"); !ok || ep.Degraded || len(im.Claims()) != 1 || im.Claims()[0].EndpointID != key16(3) {
		t.Fatal("B lost something when A was deleted")
	}
	e.mustApply(&policyv1.ConfigEntry{})
	e.mustApply(&policyv1.ConfigEntry{})
	if !e.root.HasBlob(storetest.Hash(pb)) || e.root.HasBlob(storetest.Hash(pa)) || e.root.HasBlob(storetest.Hash(shared)) {
		t.Fatal("blob garbage collection kept A's or dropped B's")
	}
}

// ---- readers during applies ----

// dns reads image/current while the agent applies entries: every read is a whole
// image consistent with itself, and none fails (SC 9.7 item 4: swapped only when
// built).
func TestReadersSeeOnlyWholeImagesWhileEntriesApply(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	b := e.blob("a.example.com")
	e.mustApply(putEntry([][]byte{b}, storetest.Endpoint(1, b)))
	var stop atomic.Bool
	var wg sync.WaitGroup
	var reads, bad atomic.Int64
	var first atomic.Value
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				im, err := image.OpenCurrent(e.imagesDir())
				reads.Add(1)
				if err != nil {
					bad.Add(1)
					first.CompareAndSwap(nil, err)
					continue
				}
				if im.EndpointCount() != int(im.Seq()) {
					bad.Add(1)
					first.CompareAndSwap(nil, fmt.Errorf("seq %d with %d endpoints", im.Seq(), im.EndpointCount()))
				}
				if ep, ok := im.ByEndpointID(key16(1)); !ok || ep.Degraded {
					bad.Add(1)
					first.CompareAndSwap(nil, errors.New("endpoint 1"))
				}
				if _, ok := im.ProfilePath(storetest.Hash(b)); !ok {
					bad.Add(1)
				} else if _, err := os.Stat(e.root.BlobPath(storetest.Hash(b))); err != nil {
					bad.Add(1)
					first.CompareAndSwap(nil, err)
				}
			}
		}()
	}
	for i := 2; i <= 14; i++ {
		e.mustApply(putEntry(nil, storetest.Endpoint(byte(i), b)))
	}
	stop.Store(true)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d of %d reads failed or were inconsistent; first: %v", bad.Load(), reads.Load(), first.Load())
	}
}

func sum(d []byte) []byte { h := sha256.Sum256(d); return h[:] }

func hashOf(d []byte) []byte { return sum(d) }

func withExpiry(pt *policyv1.PairTable, at int64) *policyv1.PairTable {
	pt.ExpiresAt = at
	return pt
}

func newNodeConfig(proofKey []byte) *hubv1.NodeConfig {
	return &hubv1.NodeConfig{
		Version: 1, DnsBindIp: []byte{10, 0, 0, 5}, DnsAdvertisedIp: []byte{8, 8, 8, 8}, ProxyBindIp: []byte{10, 0, 0, 5}, ProxyAdvertisedIp: []byte{8, 8, 8, 8},
		Zones: []string{"ctrlz.example"}, PanelHostnames: []string{"panel.example"},
		Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, ProofKey: proofKey,
	}
}
