package apply_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/push"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the image swap is a symlink rename, which is Linux")
	}
}

// A first entry with two Endpoints, a claim, a table of three nodes and a free
// DNS value: everything the image holds.
func TestFullCycleBuildsTheImageAndSurvivesARestart(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	b1, b2 := e.blob("a.example.com"), e.blob("b.example.com")
	ent := putEntry([][]byte{b1, b2}, storetest.Endpoint(1, b1), storetest.Endpoint(2, b2))
	ent.PutClaims = []*policyv1.ClaimRecord{storetest.Claim(5, 1)}
	ent.PairTable = storetest.Table(3, 0)
	ent.FreeDns = &policyv1.FreeDns{Enabled: true, Qps: 40, Version: 2}
	res := e.mustApply(ent)
	if e.a.AppliedSeq() != 1 || res.Image == "" || len(res.Report.Degraded) != 0 {
		t.Fatalf("%+v", res)
	}

	check := func(im *image.Image) {
		t.Helper()
		if im.Seq() != 1 || im.EndpointCount() != 2 || len(im.Claims()) != 1 || im.PairTable() == nil || im.Zone() == nil {
			t.Fatalf("image %+v", im.Meta())
		}
		if ep, ok := im.ByEndpointID(key16(1)); !ok || ep.Degraded {
			t.Fatal("endpoint 1")
		}
		for _, d := range [][]byte{b1, b2} {
			p, ok := im.ProfilePath(storetest.Hash(d))
			if !ok {
				t.Fatal("no path for a profile")
			}
			if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, d) {
				t.Fatalf("the path does not hold the blob: %v", err)
			}
		}
		if en, qps, v, ok := im.FreeDNS(); !ok || !en || qps != 40 || v != 2 {
			t.Fatal("free dns")
		}
	}
	check(e.current())
	if len(e.push.Table().Nodes) != 3 {
		t.Fatal("table in use")
	}
	// The entry is stored with its exact bytes.
	stored, err := e.root.ReadEntry(1)
	if err != nil || wire.EntryHash([32]byte{}, stored) != e.chain.Head {
		t.Fatal("stored entry bytes do not hash to the chain head")
	}

	// A second entry that carries no table and no free value changes neither.
	e.mustApply(putEntry(nil, storetest.Endpoint(3, b1)))
	// Restart: the same state, an image that matches (not rebuilt), the table back.
	e.reopen()
	if e.a.AppliedSeq() != 2 || e.rep.Image != apply.ImageOK || e.rep.Load.Fresh || len(e.rep.Load.Lost) != 0 {
		t.Fatalf("%+v", e.rep)
	}
	im := e.current()
	if im.Seq() != 2 || im.EndpointCount() != 3 || im.Zone() == nil {
		t.Fatalf("after a restart %+v", im.Meta())
	}
	if en, _, _, ok := im.FreeDNS(); !ok || !en {
		t.Fatal("free dns value lost by an entry that did not carry it")
	}
	if e.push.Table() == nil || len(e.push.Table().Nodes) != 3 {
		t.Fatal("the table in use was not rebuilt from the state")
	}
	// The chain continues from the loaded head.
	e.mustApply(putEntry(nil, storetest.Endpoint(4, b1)))
	// The previous image is kept one generation, the older ones are gone.
	names, _ := image.Images(e.imagesDir())
	if len(names) > 2 {
		t.Fatalf("images: %v", names)
	}
}

// 9.7: a bad blob is set aside, the Endpoint that binds it keeps its previous
// binding or is degraded, every other record applies, and later entries apply.
func TestBadBlobIsQuarantinedAndLaterEntriesApply(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	good := e.blob("good.example.com")
	bad := append([]byte(nil), storetest.Blob(t, "bad.example.com")...)
	bad[0] = 'X' // bad magic, but the hub serves exactly these bytes under their hash
	e.hub.Add(bad)

	ep1 := storetest.Endpoint(1, good)
	e.mustApply(putEntry([][]byte{good}, ep1))

	ep1b := storetest.Endpoint(1, bad)
	ep2 := storetest.Endpoint(2, bad)
	res := e.mustApply(putEntry([][]byte{bad}, ep1b, ep2, storetest.Endpoint(3, good)))
	if len(res.Report.Quarantined) != 1 || res.Report.Quarantined[0].Reason != reason.BadMagic {
		t.Fatalf("%+v", res.Report)
	}
	if len(res.Report.KeptPrevious) != 1 || len(res.Report.Degraded) != 1 {
		t.Fatalf("%+v", res.Report)
	}
	bh := storetest.Hash(bad)
	// The bytes are in quarantine/, exact, and not in blobs/.
	if got, err := os.ReadFile(e.root.QuarantinePath(bh)); err != nil || !bytes.Equal(got, bad) {
		t.Fatalf("set-aside bytes: %v", err)
	}
	if e.root.HasBlob(bh) {
		t.Fatal("a bad blob is in blobs/")
	}
	im := e.current()
	if ep, _ := im.ByEndpointID(key16(1)); ep.Degraded || !bytes.Equal(ep.Record.Base.Profile1Hash, storetest.Ref(good).Hash) {
		t.Fatal("endpoint 1 lost its previous binding")
	}
	if ep, _ := im.ByEndpointID(key16(2)); !ep.Degraded {
		t.Fatal("endpoint 2 has no binding and must be degraded")
	}
	if ep, _ := im.ByEndpointID(key16(3)); ep.Degraded {
		t.Fatal("a good endpoint of the same entry was held back")
	}
	// Quarantine survives a restart, and a quarantined hash is not fetched again.
	e.reopen()
	before := e.hub.Count[bh]
	e.mustApply(&policyv1.ConfigEntry{PutBlobs: []*policyv1.BlobRef{storetest.Ref(bad)}})
	if e.hub.Count[bh] != before {
		t.Fatal("a quarantined blob was fetched again")
	}
}

// A refused entry leaves the last good state, the image and the table as they
// were, and the next good entry applies on top of it.
func TestRefusedEntriesKeepTheLastGoodState(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	b := e.blob("a.example.com")
	first := putEntry([][]byte{b}, storetest.Endpoint(1, b))
	first.PairTable = storetest.Table(2, 0)
	e.mustApply(first)
	stateBefore, _ := e.root.StateHash()
	imgBefore, _ := image.CurrentName(e.imagesDir())

	refuse := func(name string, stored []byte, wantReason reason.Code, section string) {
		t.Helper()
		res := e.a.ApplyEntry(context.Background(), stored)
		if res.Report.Advanced || res.Report.Entry == nil || res.Err != nil {
			t.Fatalf("%s: %+v", name, res)
		}
		if wantReason != "" && res.Report.Entry.Reason != wantReason {
			t.Errorf("%s: reason %s", name, res.Report.Entry.Reason)
		}
		if section != "" && res.Report.Entry.Section != section {
			t.Errorf("%s: section %q", name, res.Report.Entry.Section)
		}
		if len(res.Report.Entry.Section) > wire.MaxSectionName {
			t.Errorf("%s: section %q too long for a QuarantineReport", name, res.Report.Entry.Section)
		}
		if e.a.AppliedSeq() != 1 {
			t.Errorf("%s: applied_seq moved", name)
		}
		if h, _ := e.root.StateHash(); h != stateBefore {
			t.Errorf("%s: the state file changed", name)
		}
		if n, _ := image.CurrentName(e.imagesDir()); n != imgBefore {
			t.Errorf("%s: the image changed", name)
		}
		if len(e.push.Table().Nodes) != 2 {
			t.Errorf("%s: the table changed", name)
		}
	}
	refuse("garbage", []byte("not an entry"), "", "")
	refuse("empty", nil, "", "")
	// Wrong chain: an entry that does not follow the head.
	wrong := storetest.Chain{Seq: 1, Head: [32]byte{9}}
	refuse("prev_hash", wrong.Marshal(t, &policyv1.ConfigEntry{}), reason.HashMismatch, "prev_hash")
	gap := storetest.Chain{Seq: 5, Head: e.chain.Head}
	refuse("seq gap", gap.Marshal(t, &policyv1.ConfigEntry{}), reason.IndexRange, "seq")
	// A table that fails to build: DecodeEntry refuses it already (item 1).
	badTable := storetest.Table(2, 0)
	badTable.Nodes[1].DnsIp = badTable.Nodes[0].DnsIp
	c := e.chain
	refuse("bad table", c.Marshal(t, &policyv1.ConfigEntry{PairTable: badTable}), "", "")

	// The next good entry applies on the unchanged state.
	res := e.mustApply(&policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(2, b)}})
	if res.Report.Seq != 2 {
		t.Fatalf("%+v", res)
	}
}

// Item 4: the table of an entry builds under the flag map as it is when the
// writer builds it. If that build fails after item 1 passed, nothing of the
// entry is swapped in, applied_seq does not advance and the failure is an entry
// failure (L11).
func TestATableThatFailsAtTheSwapRefusesTheWholeEntry(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.fakeTables = func(real *push.Writer) apply.Tables { return &failingSwap{Tables: real} }
	e.reopen()
	b := e.blob("a.example.com")
	first := putEntry([][]byte{b}, storetest.Endpoint(1, b))
	first.PairTable = storetest.Table(2, 0)
	// Let the first entry through.
	e.tables.(*failingSwap).fail.Store(false)
	e.mustApply(first)
	stateBefore, _ := e.root.StateHash()
	imgBefore, _ := image.CurrentName(e.imagesDir())

	e.tables.(*failingSwap).fail.Store(true)
	ent := putEntry([][]byte{e.blob("c.example.com")}, storetest.Endpoint(2, b))
	ent.PairTable = storetest.Table(3, 0)
	res := e.apply(ent)
	if res.Report.Advanced || res.Report.Entry == nil || res.Report.Entry.Scope != 1 || res.Err != nil {
		t.Fatalf("%+v", res)
	}
	if res.Report.Entry.Section != "pair_table" {
		t.Fatalf("%+v", res.Report.Entry)
	}
	if e.a.AppliedSeq() != 1 || len(e.push.Table().Nodes) != 2 {
		t.Fatal("part of the entry took effect")
	}
	if h, _ := e.root.StateHash(); h != stateBefore {
		t.Fatal("state file changed")
	}
	if n, _ := image.CurrentName(e.imagesDir()); n != imgBefore {
		t.Fatal("image changed")
	}
	if e.root.HasBlob(storetest.Hash(storetest.Blob(t, "c.example.com"))) {
		t.Fatal("a blob of the refused entry was kept")
	}
	// The refused entry is retried on the next try, and then applies.
	e.tables.(*failingSwap).fail.Store(false)
	e.mustApply(ent)
	if e.a.AppliedSeq() != 2 || len(e.push.Table().Nodes) != 3 {
		t.Fatal("retry")
	}
}

// ---- crash safety ----

// Every write an Apply makes, failed in turn (a crash standing for each): the
// previous state stays loadable, the image dns reads is whole and matches a state
// that a restart finds, and the entry applies when the hub resends it.
func TestCrashAtEveryWriteOfAnApply(t *testing.T) {
	skipWindows(t)
	prepare := func() (*env, *policyv1.ConfigEntry) {
		e := newEnv(t)
		b1, b2 := e.blob("one.example.com"), e.blob("two.example.com")
		first := putEntry([][]byte{b1}, storetest.Endpoint(1, b1))
		first.PairTable = storetest.Table(2, 0)
		e.mustApply(first)
		second := putEntry([][]byte{b2}, storetest.Endpoint(2, b2))
		second.PairTable = storetest.Table(3, 0)
		second.PutClaims = []*policyv1.ClaimRecord{storetest.Claim(1, 2)}
		return e, second
	}

	// Count the writes of the second entry.
	var events []string
	{
		e, second := prepare()
		e.hook = func(p string, s fsx.Step) error {
			events = append(events, fmt.Sprintf("%s/%s:%v", filepath.Base(filepath.Dir(p)), filepath.Base(p), s))
			return nil
		}
		e.mustApply(second)
	}
	if len(events) < 20 {
		t.Fatalf("only %d writes recorded", len(events))
	}

	for i := range events {
		i := i
		t.Run(fmt.Sprintf("%02d %s", i, events[i]), func(t *testing.T) {
			t.Parallel()
			e, second := prepare()
			n := 0
			e.hook = func(string, fsx.Step) error {
				defer func() { n++ }()
				if n == i {
					return fsx.ErrInjected
				}
				return nil
			}
			res := e.apply(second)
			e.hook = nil
			staging := strings.HasPrefix(events[i], "incoming/")
			if staging {
				// A blob that cannot be staged is a blob that is not available now: the
				// entry still applies, the Endpoint waits for it, degraded, and a Retry
				// fetches it again. A node whose disk fails must not stop applying.
				if !res.Report.Advanced || len(res.Report.Missing) != 1 || len(res.Report.Degraded) != 1 {
					t.Fatalf("a blob that could not be staged: %+v", res)
				}
			} else if res.Err == nil && res.ImageErr == nil {
				t.Fatalf("a failed write was not reported: %+v", res)
			}
			memSeq := e.a.AppliedSeq()
			// dns reads the image at every point, before any restart.
			if im := e.current(); im.Seq() != 1 && im.Seq() != 2 {
				t.Fatalf("image seq %d", im.Seq())
			}

			e.reopen() // the restart
			seq := e.a.AppliedSeq()
			if seq != 1 && seq != 2 {
				t.Fatalf("applied_seq %d after a restart", seq)
			}
			if memSeq == 2 && seq != 2 {
				t.Fatal("the process had committed entry 2, and the disk lost it")
			}
			im := e.current()
			if im.Seq() != seq || im.EndpointCount() != int(seq) {
				t.Fatalf("image seq %d with %d endpoints, state at %d", im.Seq(), im.EndpointCount(), seq)
			}
			if got := len(e.push.Table().Nodes); got != int(seq)+1 {
				t.Fatalf("table has %d nodes at seq %d", got, seq)
			}
			for _, h := range []string{"one.example.com"} {
				if !e.root.HasBlob(storetest.Hash(storetest.Blob(t, h))) {
					t.Fatal("a blob the state names is gone")
				}
			}
			// The hub resends the entry: seq 2 applies (or is already applied).
			if seq == 1 {
				e.chain = storetest.Chain{Seq: 1}
				stored, err := e.root.ReadEntry(1)
				if err != nil {
					t.Fatal(err)
				}
				e.chain.Head = wire.EntryHash([32]byte{}, stored)
				e.mustApply(second)
			}
			if im := e.current(); im.Seq() != 2 || im.EndpointCount() != 2 || len(im.Claims()) != 1 {
				t.Fatalf("after the resend %+v", im.Meta())
			}
			// And the directory holds nothing that a start would not clean.
			e.reopen()
			if ents, _ := os.ReadDir(e.root.IncomingDir()); len(ents) != 0 {
				t.Fatal("staged blobs left")
			}
		})
	}
}

// A damaged state file at start: the node starts fresh and says so, image/ keeps
// serving the image it had, and the node recovers from a snapshot.
func TestCorruptStateAtStart(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	b := e.blob("a.example.com")
	e.mustApply(putEntry([][]byte{b}, storetest.Endpoint(1, b)))
	p := e.root.Path(store.DirState, "state.bin")
	data, _ := os.ReadFile(p)
	data[50] ^= 0xff
	_ = os.WriteFile(p, data, 0o600)
	e.reopen()
	if e.rep.Load.Corrupt == nil || !e.rep.Load.Fresh || e.a.AppliedSeq() != 0 {
		t.Fatalf("%+v", e.rep)
	}
	if im := e.current(); im.Seq() != 1 || im.EndpointCount() != 1 {
		t.Fatal("dns lost the image it was serving")
	}
}

// ---- fetch: size 0, stall, hostile bytes, T-533 ----

// An Endpoint put binds a hash that no entry sent a BlobRef for (size 0): the
// blob is fetched under the kind's cap and the Endpoint is bound.
func TestABindingHashWithNoRefIsFetched(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	b := e.blob("a.example.com")
	res := e.mustApply(putEntry(nil, storetest.Endpoint(1, b)))
	if len(res.Report.Degraded) != 0 || e.hub.Count[storetest.Hash(b)] != 1 {
		t.Fatalf("%+v", res.Report)
	}
	if ep, _ := e.current().ByEndpointID(key16(1)); ep.Degraded {
		t.Fatal("degraded")
	}
}

// A blob the hub does not serve in time: the entry advances, the Endpoint is
// degraded and pending, the miss is reported, and a Retry once the hub has it
// promotes the Endpoint, saves the state and rebuilds the image.
func TestAStalledBlobDegradesThenRetryPromotes(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.timeout = 300 * time.Millisecond
	e.reopen()
	b := storetest.Blob(t, "slow.example.com")
	h := e.hub.Add(b)
	var stall atomic.Bool
	stall.Store(true)
	e.hub.OpenHook = func(ctx context.Context, k [32]byte) (io.ReadCloser, error, bool) {
		if stall.Load() {
			<-ctx.Done()
			return nil, ctx.Err(), true
		}
		return nil, nil, false
	}
	start := time.Now()
	res := e.mustApply(putEntry([][]byte{b}, storetest.Endpoint(1, b)))
	if time.Since(start) > 10*time.Second {
		t.Fatal("the stall held the Apply")
	}
	if len(res.Report.Missing) != 1 || len(res.Report.Degraded) != 1 {
		t.Fatalf("%+v", res.Report)
	}
	if ep, _ := e.current().ByEndpointID(key16(1)); !ep.Degraded {
		t.Fatal("must be degraded")
	}
	// The wanted list and the pending Endpoint survive a restart.
	e.reopen()
	e.a.Inspect(func(a *store.Applied) {
		if a.Q.Wanted[h] == nil || a.Q.Pending[key16(1)] == nil {
			t.Fatal("wanted list lost")
		}
	})
	// Retry with the stall still on changes nothing worth a new image.
	imgBefore, _ := image.CurrentName(e.imagesDir())
	if r := e.a.Retry(context.Background()); r.Err != nil || len(r.Report.Promoted) != 0 {
		t.Fatalf("%+v", r)
	}
	if n, _ := image.CurrentName(e.imagesDir()); n == imgBefore && false {
		t.Log("same image")
	}
	stall.Store(false)
	r := e.a.Retry(context.Background())
	if r.Err != nil || len(r.Report.Promoted) != 1 || r.Image == "" || r.Image == imgBefore {
		t.Fatalf("%+v", r)
	}
	if ep, _ := e.current().ByEndpointID(key16(1)); ep.Degraded {
		t.Fatal("still degraded after the promote")
	}
	if !e.root.HasBlob(h) || e.a.AppliedSeq() != 1 {
		t.Fatal("retry")
	}
	e.reopen()
	e.a.Inspect(func(a *store.Applied) {
		if len(a.Q.Wanted) != 0 || len(a.Q.Pending) != 0 || a.Q.Degraded[key16(1)] {
			t.Fatal("the promote was not saved")
		}
	})
}

// Hostile bytes from the hub: wrong content, over-long, endless, short, empty and
// a source that panics. Nothing is kept, nothing is quarantined, the blob stays
// wanted and nothing is left staged; the node keeps working.
func TestHostileFetchBytes(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	good := storetest.Blob(t, "a.example.com")
	h := storetest.Hash(good)
	modes := []struct {
		name string
		body func() (io.ReadCloser, error)
	}{
		{"wrong content", func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{1}, len(good)))), nil
		}},
		{"over long", func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(append(append([]byte(nil), good...), 0))), nil
		}},
		{"short", func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(good[:len(good)-1])), nil }},
		{"empty", func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(nil)), nil }},
		{"endless", func() (io.ReadCloser, error) { return io.NopCloser(zeros{}), nil }},
		{"panic", func() (io.ReadCloser, error) { panic("hostile source") }},
		{"error", func() (io.ReadCloser, error) { return nil, errors.New("reset") }},
	}
	ent := putEntry([][]byte{good}, storetest.Endpoint(1, good))
	for i, m := range modes {
		m := m
		e.hub.OpenHook = func(ctx context.Context, k [32]byte) (io.ReadCloser, error, bool) {
			rc, err := m.body()
			return rc, err, true
		}
		var res apply.Result
		if i == 0 {
			res = e.mustApply(ent)
		} else {
			res = e.a.Retry(context.Background())
		}
		if res.Err != nil || len(res.Report.Quarantined) != 0 {
			t.Fatalf("%s: %+v", m.name, res)
		}
		if i == 0 && len(res.Report.Failed) != 1 {
			t.Fatalf("%s: a transfer that delivered the wrong bytes must be reported: %+v", m.name, res.Report)
		}
		if e.root.HasBlob(h) || e.hasFile(store.DirQuarantine, store.HashHex(h)) {
			t.Fatalf("%s: hostile bytes were kept", m.name)
		}
		if ents, _ := os.ReadDir(e.root.IncomingDir()); len(ents) != 0 {
			t.Fatalf("%s: staged files left", m.name)
		}
		e.a.Inspect(func(a *store.Applied) {
			if a.Q.Wanted[h] == nil || !a.Q.Degraded[key16(1)] {
				t.Fatalf("%s: the blob must stay wanted and the Endpoint degraded", m.name)
			}
			if _, bad := a.Q.Quarantined[h]; bad {
				t.Fatalf("%s: a transfer fault quarantined the hash", m.name)
			}
		})
	}
	// The hub recovers: the blob arrives and the Endpoint is promoted.
	e.hub.OpenHook = nil
	e.hub.Add(good)
	if r := e.a.Retry(context.Background()); r.Err != nil || len(r.Report.Promoted) != 1 {
		t.Fatalf("%+v", r)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { return len(p), nil }

// Bytes that do hash to the name but are not a blob are quarantined (set aside
// with their exact bytes), and a decoder that is fed garbage never panics the node.
func TestBytesThatHashRightButDoNotOpenAreSetAside(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	for i, bad := range [][]byte{
		[]byte("garbage"), {}, bytes.Repeat([]byte{0xff}, 4096),
		append([]byte("CZPB"), bytes.Repeat([]byte{0}, 100)...),
	} {
		h := e.hub.Add(bad)
		ref := &policyv1.BlobRef{Hash: h[:], Size: uint64(len(bad)), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
		res := e.mustApply(&policyv1.ConfigEntry{PutBlobs: []*policyv1.BlobRef{ref}})
		if len(res.Report.Quarantined) != 1 {
			t.Fatalf("case %d: %+v", i, res.Report)
		}
		if got, err := os.ReadFile(e.root.QuarantinePath(h)); err != nil || !bytes.Equal(got, bad) {
			t.Fatalf("case %d: %v", i, err)
		}
		if e.root.HasBlob(h) {
			t.Fatalf("case %d: in blobs/", i)
		}
	}
	e.reopen()
	e.a.Inspect(func(a *store.Applied) {
		if len(a.Q.Quarantined) != 4 {
			t.Fatalf("quarantined list after a restart: %d", len(a.Q.Quarantined))
		}
	})
}

// A raw Fetcher that panics reaches neither Apply nor Retry as a crash: Apply
// has its own recover and Retry runs under one here (T-533).
func TestAPanickingFetcherNeverCrashesApplyOrRetry(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	b := storetest.Blob(t, "a.example.com")
	e.rawFet = panicFetcher{}
	e.reopen()
	res := e.apply(putEntry([][]byte{b}, storetest.Endpoint(1, b)))
	if res.Report.Advanced || (res.Err == nil && res.Report.Entry == nil) {
		t.Fatalf("%+v", res)
	}
	if e.a.AppliedSeq() != 0 {
		t.Fatal("state moved")
	}
	// Get a wanted entry in, with a fetcher that fails politely, then panic in Retry.
	e.rawFet = missingFetcher{}
	e.reopen()
	e.mustApply(putEntry([][]byte{b}, storetest.Endpoint(1, b)))
	e.rawFet = panicFetcher{}
	e.reopen()
	r := e.a.Retry(context.Background())
	if r.Err == nil {
		t.Fatalf("a panic in Retry went unreported: %+v", r)
	}
	if e.a.AppliedSeq() != 1 {
		t.Fatal("state moved")
	}
	e.a.Inspect(func(a *store.Applied) {
		if a.Q.Wanted[storetest.Hash(b)] == nil {
			t.Fatal("the wanted list was lost")
		}
	})
	// And the applier is still usable.
	e.rawFet = nil
	e.hub.Add(b)
	e.reopen()
	if r := e.a.Retry(context.Background()); r.Err != nil || len(r.Report.Promoted) != 1 {
		t.Fatalf("%+v", r)
	}
}

type panicFetcher struct{}

func (panicFetcher) Fetch([32]byte, policyv1.BlobKind, uint64) ([]byte, bool) { panic("boom") }

type missingFetcher struct{}

func (missingFetcher) Fetch([32]byte, policyv1.BlobKind, uint64) ([]byte, bool) { return nil, false }

// ---- del_blobs and the deferred delete ----

func TestADeletedBlobLeavesDiskOneCommitLater(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	a, b := e.blob("a.example.com"), e.blob("b.example.com")
	e.mustApply(putEntry([][]byte{a, b}, storetest.Endpoint(1, a)))
	ha, hb := storetest.Hash(a), storetest.Hash(b)
	// b is in no Endpoint's binding; a is.
	e.mustApply(&policyv1.ConfigEntry{DelBlobs: [][]byte{hb[:], ha[:]}})
	if !e.root.HasBlob(hb) {
		t.Fatal("the blob the previous image lists was deleted at once")
	}
	e.mustApply(&policyv1.ConfigEntry{})
	if e.root.HasBlob(hb) {
		t.Fatal("a deleted blob stayed on disk")
	}
	if !e.root.HasBlob(ha) {
		t.Fatal("a blob an Endpoint still binds was deleted")
	}
	// A restart sweeps what nothing names: put a stray file in blobs/.
	stray := sha256.Sum256([]byte("stray"))
	_ = os.WriteFile(e.root.BlobPath(stray), []byte("stray"), 0o640)
	e.reopen()
	if e.rep.Swept != 1 || e.root.HasBlob(stray) {
		t.Fatalf("swept %d", e.rep.Swept)
	}
}

// failingSwap passes everything to the real writer except the build of item 4,
// which it can be told to fail after item 1 passed.
type failingSwap struct {
	apply.Tables
	fail atomic.Bool
}

func (f *failingSwap) SetMembership(pt *policyv1.PairTable) (func(), error) {
	if f.fail.Load() {
		return nil, &zone.BuildError{Field: "pair_table", Msg: "built with the flags of a push that arrived meanwhile"}
	}
	return f.Tables.SetMembership(pt)
}

var _ = sync.Mutex{}
var _ = nodecfg.Current
