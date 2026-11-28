package apply_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// A damaged state file makes the state fresh, and image/ keeps serving. The
// blobs under that image must survive the start: sweeping by the fresh state
// (which names nothing) would delete every file dns reads, and with the hub out
// of reach every Endpoint would be served degraded (review round 1, r1-1 and r1-5).
func TestCorruptStateKeepsTheBlobsTheImageServes(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a, b := e.blob("a.example.com"), e.blob("b.example.com")
	ent := putEntry([][]byte{a, b}, storetest.Endpoint(1, a), storetest.Endpoint(2, b))
	ent.PairTable = storetest.Table(3, 0)
	ent.FreeDns = &policyv1.FreeDns{Enabled: true, Qps: 40, Version: 2}
	e.mustApply(ent)
	p := e.root.Path(store.DirState, "state.bin")
	data, _ := os.ReadFile(p)
	data[50] ^= 0xff
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if e.rep.Load.Corrupt == nil || e.a.AppliedSeq() != 0 {
		t.Fatalf("%+v", e.rep)
	}
	if e.rep.Swept != 0 {
		t.Fatalf("%d blobs swept from under the image that is served", e.rep.Swept)
	}
	im := e.current()
	for _, d := range [][]byte{a, b} {
		path, ok := im.ProfilePath(storetest.Hash(d))
		if !ok {
			t.Fatal("the image lost a profile")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the image names a blob that is gone: %v", err)
		}
	}
	// The table the image was built with stays in use until a snapshot replaces it.
	if e.push.Table() == nil {
		t.Fatal("no zone table in use after the state was lost")
	}
	// A later start, once a snapshot has built a new state, sweeps normally: what
	// neither the state nor the image names is deleted.
	stray := storetest.Hash(storetest.Blob(t, "stray.example.com"))
	if err := e.root.PutBlob(stray, storetest.Blob(t, "stray.example.com")); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if e.root.HasBlob(stray) {
		t.Fatal("a stray blob was kept")
	}
}

// A snapshot names blobs and Endpoints the node already holds. They are carried
// over, not fetched again, and the Endpoints stay bound while the hub cannot
// serve anything (review round 1, r1-6).
func TestSnapshotKeepsWhatTheNodeHolds(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a, b := e.blob("a.example.com"), e.blob("b.example.com")
	e.mustApply(putEntry([][]byte{a, b}, storetest.Endpoint(1, a), storetest.Endpoint(2, b)))
	ha, hb := storetest.Hash(a), storetest.Hash(b)
	opensBefore := e.hub.Count[ha] + e.hub.Count[hb]
	// The hub's blob store is down from here on.
	e.hub.OpenHook = func(context.Context, [32]byte) (io.ReadCloser, error, bool) {
		return nil, io.ErrUnexpectedEOF, true
	}
	c := storetest.Blob(t, "c.example.com") // not on the hub
	hc := storetest.Hash(c)
	var head [32]byte
	head[0] = 0x50
	snap := &signv1.Snapshot{Seq: 50, EntryHash: head[:]}
	snap.Blobs = []*policyv1.BlobRef{storetest.Ref(a), storetest.Ref(b), storetest.Ref(c)}
	// Endpoint 1 is as it was, Endpoint 2 moves to c, which cannot be fetched.
	snap.Endpoints = []*policyv1.EndpointRecord{storetest.Endpoint(1, a), storetest.Endpoint(2, c)}
	res := e.a.ApplySnapshot(context.Background(), snap)
	if res.Err != nil || !res.Report.Advanced || res.ImageErr != nil {
		t.Fatalf("%+v", res)
	}
	if got := e.hub.Count[ha] + e.hub.Count[hb]; got != opensBefore {
		t.Fatalf("blobs the node holds were fetched again (%d opens)", got-opensBefore)
	}
	im := e.current()
	if ep, _ := im.ByEndpointID(key16(1)); ep.Degraded {
		t.Fatal("Endpoint 1 was served degraded although its blob is on disk")
	}
	ep2, _ := im.ByEndpointID(key16(2))
	if ep2.Degraded || !bytes.Equal(ep2.Record.Base.Profile1Hash, hb[:]) {
		t.Fatal("Endpoint 2 must keep its previous binding while c is missing")
	}
	e.a.Inspect(func(a *store.Applied) {
		p := a.Q.Pending[key16(2)]
		if p == nil || !bytes.Equal(p.Record.Base.Profile1Hash, hc[:]) || a.Q.Wanted[hc] == nil {
			t.Fatal("the move to c is not pending")
		}
	})
	// The hub comes back: the Endpoint moves to c.
	e.hub.OpenHook = nil
	e.hub.Add(c)
	if r := e.a.Retry(context.Background()); r.Err != nil || len(r.Report.Promoted) != 1 {
		t.Fatalf("%+v", r)
	}
	ep2, _ = e.current().ByEndpointID(key16(2))
	if ep2.Degraded || !bytes.Equal(ep2.Record.Base.Profile1Hash, hc[:]) {
		t.Fatal("Endpoint 2 did not move to c")
	}
}

// An Endpoint that kept its old binding while a newer record waits for a blob must
// not be sent back to the old binding when the old profile is lost on disk and
// comes back (review round 1, r1-2 and r1-8).
func TestLostBlobDoesNotReplaceANewerPendingRecord(t *testing.T) {
	skipWindows(t)
	for _, bReturns := range []bool{false, true} {
		e := newEnv(t)
		a := e.blob("a.example.com")
		b := storetest.Blob(t, "b.example.com") // not on the hub yet
		ha, hb := storetest.Hash(a), storetest.Hash(b)
		e.mustApply(putEntry([][]byte{a}, storetest.Endpoint(1, a)))
		// The move to b cannot be fetched: Endpoint 1 keeps a and waits for b.
		e.mustApply(putEntry(nil, storetest.Endpoint(1, b)))
		if err := e.root.DeleteBlob(ha); err != nil {
			t.Fatal(err)
		}
		e.reopen()
		if len(e.rep.Load.Lost) != 1 {
			t.Fatalf("%+v", e.rep.Load)
		}
		e.a.Inspect(func(s *store.Applied) {
			p := s.Q.Pending[key16(1)]
			if p == nil || !bytes.Equal(p.Record.Base.Profile1Hash, hb[:]) {
				t.Fatalf("the pending record was replaced by the old binding (b returns: %v)", bReturns)
			}
			if !s.Q.Degraded[key16(1)] {
				t.Fatal("an Endpoint with a lost profile must be degraded")
			}
		})
		if bReturns {
			e.hub.Add(b)
		}
		r := e.a.Retry(context.Background())
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		ep, _ := e.current().ByEndpointID(key16(1))
		if ep.Degraded {
			t.Fatalf("still degraded after its blobs are back (b returns: %v)", bReturns)
		}
		want := ha
		if bReturns {
			want = hb
		}
		if !bytes.Equal(ep.Record.Base.Profile1Hash, want[:]) {
			t.Fatalf("served binding is not the expected one (b returns: %v)", bReturns)
		}
		if !bReturns {
			// b arrives later: the Endpoint moves to the newer record, never back to a.
			e.hub.Add(b)
			if r := e.a.Retry(context.Background()); r.Err != nil || len(r.Report.Promoted) != 1 {
				t.Fatalf("%+v", r)
			}
			if ep, _ := e.current().ByEndpointID(key16(1)); !bytes.Equal(ep.Record.Base.Profile1Hash, hb[:]) {
				t.Fatal("the Endpoint did not reach the newer record")
			}
		}
	}
}

// ---- Retry and the apply mutex ----

func stallingHub(e *env, opens *atomic.Int32) {
	e.hub.OpenHook = func(ctx context.Context, _ [32]byte) (io.ReadCloser, error, bool) {
		opens.Add(1)
		<-ctx.Done()
		return nil, ctx.Err(), true
	}
}

// A Retry whose context is done fetches nothing, and one whose context ends
// while a fetch stalls stops there instead of going through the wanted list one
// 60 s fetch at a time (review round 1, r1-7).
func TestRetryStopsWhenItsContextEnds(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.timeout = 30 * time.Second
	e.reopen()
	var blobs [][]byte
	var eps []*policyv1.EndpointRecord
	for i := 0; i < 8; i++ {
		d := storetest.Blob(t, string(rune('a'+i))+".example.com") // not on the hub
		blobs = append(blobs, d)
		eps = append(eps, storetest.Endpoint(byte(i+1), d))
	}
	e.mustApply(putEntry(blobs, eps...))
	var opens atomic.Int32
	stallingHub(e, &opens)

	done, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if r := e.a.Retry(done); r.Err != nil || opens.Load() != 0 {
		t.Fatalf("a cancelled Retry fetched %d blobs: %+v", opens.Load(), r)
	}
	ctx, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	e.a.Retry(ctx)
	if opens.Load() != 1 {
		t.Fatalf("the Retry went on after its context ended: %d fetches", opens.Load())
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the Retry held on to the mutex")
	}
	e.a.Inspect(func(a *store.Applied) {
		if len(a.Q.Wanted) != 8 {
			t.Fatalf("wanted list: %d", len(a.Q.Wanted))
		}
	})
}

// An entry that arrives while a Retry is stalled on the hub does not wait for the
// Retry: it cancels it (a hard_disable must not sit behind 256 fetches of 60 s).
func TestAnEntryPreemptsARunningRetry(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.timeout = 30 * time.Second
	e.reopen()
	var blobs [][]byte
	var eps []*policyv1.EndpointRecord
	for i := 0; i < 4; i++ {
		d := storetest.Blob(t, string(rune('a'+i))+".example.com")
		blobs = append(blobs, d)
		eps = append(eps, storetest.Endpoint(byte(i+1), d))
	}
	e.mustApply(putEntry(blobs, eps...))
	var opens atomic.Int32
	var stall atomic.Bool
	stall.Store(true)
	e.hub.OpenHook = func(ctx context.Context, _ [32]byte) (io.ReadCloser, error, bool) {
		opens.Add(1)
		if !stall.Load() {
			return nil, nil, false // the hub does not have it: a fast miss
		}
		<-ctx.Done()
		return nil, ctx.Err(), true
	}

	retried := make(chan struct{})
	go func() {
		defer close(retried)
		e.a.Retry(context.Background())
	}()
	deadline := time.Now().Add(10 * time.Second)
	for opens.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the Retry never started a fetch")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Only the fetch the Retry is stuck in stays stuck: the entry's own walk of the
	// wanted list must not add 30 s timeouts of its own to what this measures.
	stall.Store(false)
	start := time.Now()
	res := e.apply(&policyv1.ConfigEntry{})
	if !res.Report.Advanced || res.Err != nil {
		t.Fatalf("%+v", res)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the entry waited %v behind the Retry", d)
	}
	select {
	case <-retried:
	case <-time.After(5 * time.Second):
		t.Fatal("the Retry did not end")
	}
	// The cancelled Retry lost nothing: with the hub back, the next one finishes.
	e.hub.OpenHook = nil
	for _, d := range blobs {
		e.hub.Add(d)
	}
	if r := e.a.Retry(context.Background()); r.Err != nil || len(r.Report.Promoted) != 4 {
		t.Fatalf("%+v", r)
	}
}

// A hub that stalls costs one entry a bounded time, not one timeout per wanted
// blob: once the failing fetches have used the budget the rest are refused, the
// entry still applies and the blobs stay wanted (review round 1, r1-7).
func TestAStalledHubCostsAnEntryOnlyItsBudget(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.timeout = 400 * time.Millisecond
	e.budget = 500 * time.Millisecond
	e.reopen()
	var blobs [][]byte
	var eps []*policyv1.EndpointRecord
	for i := 0; i < 6; i++ {
		d := storetest.Blob(t, string(rune('a'+i))+".example.com") // not on the hub: the first apply sees misses
		blobs = append(blobs, d)
		eps = append(eps, storetest.Endpoint(byte(i+1), d))
	}
	e.mustApply(putEntry(blobs, eps...))
	var opens atomic.Int32
	stallingHub(e, &opens)
	start := time.Now()
	res := e.apply(&policyv1.ConfigEntry{})
	if !res.Report.Advanced || res.Err != nil {
		t.Fatalf("%+v", res)
	}
	if n := opens.Load(); n != 2 {
		t.Fatalf("%d fetches started, the budget allows 2 of 400 ms", n)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the entry waited for every wanted blob")
	}
	e.a.Inspect(func(a *store.Applied) {
		if len(a.Q.Wanted) != 6 || len(a.Q.Pending) != 6 {
			t.Fatalf("wanted %d pending %d", len(a.Q.Wanted), len(a.Q.Pending))
		}
	})
}
