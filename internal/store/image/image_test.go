package image_test

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the image swap is a symlink rename, which is Linux")
	}
}

// input has n Endpoints; every Endpoint's rid hash is that of "rid<i>", so the
// lookup by resolver id can be tested.
func input(t *testing.T, seq uint64, n int) image.Input {
	t.Helper()
	in := image.Input{Seq: seq, Head: [32]byte{byte(seq)},
		Endpoints: map[[16]byte]*policyv1.EndpointRecord{}, Claims: map[[16]byte]*policyv1.ClaimRecord{},
		Degraded: map[[16]byte]bool{}, Profiles: map[[32]byte]bool{}, BlockPages: map[[32]byte]bool{}}
	for i := 0; i < n; i++ {
		d := storetest.Blob(t, fmt.Sprintf("n%d.example.com", i))
		ep := storetest.Endpoint(byte(i+1), d)
		rid := identity.RIDHash(fmt.Sprintf("rid%d", i))
		ep.RidHash = rid[:]
		in.Endpoints[[16]byte(ep.EndpointId)] = ep
		in.Profiles[storetest.Hash(d)] = true
	}
	in.Claims[[16]byte(storetest.Claim(2, 1).ClaimId)] = storetest.Claim(2, 1)
	in.Claims[[16]byte(storetest.Claim(1, 2).ClaimId)] = storetest.Claim(1, 2)
	in.Degraded[[16]byte(storetest.Endpoint(2, nil).EndpointId)] = true
	in.Member = storetest.Table(3, 0)
	in.FreeDNS = &policyv1.FreeDns{Enabled: true, Qps: 70, Version: 9}
	in.BlockPages[[32]byte{0xbb}] = true
	return in
}

func build(t *testing.T, dir string, in image.Input) string {
	t.Helper()
	name, err := image.Build(&fsx.Writer{}, dir, in)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestBuildOpenRoundTrip(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "image")
	_ = os.MkdirAll(dir, 0o755)
	in := input(t, 12, 3)
	name := build(t, dir, in)
	if name != image.DirName(12, 0) {
		t.Fatalf("name %s", name)
	}
	im, err := image.Open(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if im.Seq() != 12 || im.EndpointCount() != 3 || len(im.Claims()) != 2 || !im.Meta().HasZone {
		t.Fatalf("%+v", im.Meta())
	}
	// Lookup by resolver id, by hash and by endpoint id.
	e, ok := im.ByResolverID("rid1")
	if !ok || e.Record.EndpointId[0] != 2 || !e.Degraded {
		t.Fatalf("%v %v", e, ok)
	}
	if e0, ok := im.ByResolverID("rid0"); !ok || e0.Degraded {
		t.Fatal("rid0")
	}
	if _, ok := im.ByResolverID("nobody"); ok {
		t.Fatal("unknown id found")
	}
	if e2, ok := im.ByEndpointID([16]byte(e.Record.EndpointId)); !ok || e2 != e {
		t.Fatal("by endpoint id")
	}
	// Claims come back sorted by claim id, with parsed prefixes.
	cl := im.Claims()
	if cl[0].ID[0] != 1 || cl[1].ID[0] != 2 || cl[0].Prefix.String() != "198.51.1.0/24" || cl[0].EndpointID[0] != 2 {
		t.Fatalf("%+v", cl)
	}
	// Blob paths exist for what was on disk and not for anything else.
	for h := range in.Profiles {
		p, ok := im.ProfilePath(h)
		if !ok || filepath.Base(p) != fmt.Sprintf("%x", h) || filepath.Base(filepath.Dir(p)) != "blobs" {
			t.Fatalf("%s %v", p, ok)
		}
	}
	if _, ok := im.ProfilePath([32]byte{0x01}); ok {
		t.Fatal("a blob that is not in the image has a path")
	}
	if _, ok := im.BlockPagePath([32]byte{0xbb}); !ok {
		t.Fatal("block page")
	}
	if _, ok := im.ProfilePath([32]byte{0xbb}); ok {
		t.Fatal("a block page is not a profile")
	}
	if im.Zone() == nil || len(im.PairTable().Nodes) != 3 {
		t.Fatal("zone table")
	}
	if en, qps, v, ok := im.FreeDNS(); !ok || !en || qps != 70 || v != 9 {
		t.Fatal("free dns")
	}
}

func TestImageWithNoTableOrFreeValue(t *testing.T) {
	dir := t.TempDir()
	in := input(t, 1, 1)
	in.Member, in.FreeDNS = nil, nil
	im, err := image.Open(filepath.Join(dir, build(t, dir, in)))
	if err != nil {
		t.Fatal(err)
	}
	if im.Zone() != nil || im.PairTable() != nil {
		t.Fatal("zone table from nothing")
	}
	if _, _, _, ok := im.FreeDNS(); ok {
		t.Fatal("a free value from nothing")
	}
}

// The same input gives the same bytes, so two builds of one state are equal.
func TestBuildIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	in := input(t, 5, 4)
	a, b := build(t, dir, in), build(t, dir, in)
	if a == b {
		t.Fatal("a rebuild reused a name")
	}
	da, _ := image.Digest(filepath.Join(dir, a))
	db, _ := image.Digest(filepath.Join(dir, b))
	// Only meta differs (the generation); the record files are equal.
	_ = da
	_ = db
	for _, f := range []string{"endpoints", "claims", "blobs", "zone"} {
		x, _ := os.ReadFile(filepath.Join(dir, a, f))
		y, _ := os.ReadFile(filepath.Join(dir, b, f))
		if string(x) != string(y) {
			t.Errorf("%s differs between two builds of one input", f)
		}
	}
}

func TestRebuildOfOneSeqGetsANewName(t *testing.T) {
	dir := t.TempDir()
	in := input(t, 5, 1)
	n0, n1, n2 := build(t, dir, in), build(t, dir, in), build(t, dir, in)
	if n0 != image.DirName(5, 0) || n1 != image.DirName(5, 1) || n2 != image.DirName(5, 2) {
		t.Fatalf("%s %s %s", n0, n1, n2)
	}
	build(t, dir, input(t, 4, 1))
	names, _ := image.Images(dir)
	if len(names) != 4 || names[0] != image.DirName(4, 0) || names[3] != image.DirName(5, 2) {
		t.Fatalf("%v", names)
	}
	for _, n := range names {
		s, g, ok := image.ParseDirName(n)
		if !ok || image.DirName(s, g) != n {
			t.Fatalf("%s does not round trip", n)
		}
	}
	for _, bad := range []string{"current", "5", "00000000000000000005.0", "00000000000000000005.x", "0000000000000000000a"} {
		if _, _, ok := image.ParseDirName(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if err := image.Prune(dir, n2); err != nil {
		t.Fatal(err)
	}
	if names, _ := image.Images(dir); len(names) != 1 {
		t.Fatalf("%v", names)
	}
}

// Every file is sealed: a flipped bit anywhere makes Open fail, and so does a
// missing file, an extra record, or a count that differs from meta.
func TestOpenRefusesADamagedImage(t *testing.T) {
	dir := t.TempDir()
	name := build(t, dir, input(t, 3, 3))
	for _, f := range []string{"meta", "endpoints", "claims", "blobs", "zone"} {
		p := filepath.Join(dir, name, f)
		orig, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, off := range []int{0, 5, 40, len(orig) - 1} {
			bad := append([]byte(nil), orig...)
			bad[off] ^= 0x40
			if err := os.WriteFile(p, bad, 0o640); err != nil {
				t.Fatal(err)
			}
			if _, err := image.Open(filepath.Join(dir, name)); err == nil {
				t.Fatalf("%s flipped at %d opened", f, off)
			}
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if _, err := image.Open(filepath.Join(dir, name)); err == nil {
			t.Fatalf("%s missing opened", f)
		}
		if err := os.WriteFile(p, orig, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := image.Open(filepath.Join(dir, name)); err != nil {
		t.Fatalf("restored image does not open: %v", err)
	}
	// A sealed file that is valid but is another image's: counts differ from meta.
	other := build(t, dir, input(t, 3, 5))
	b, _ := os.ReadFile(filepath.Join(dir, other, "endpoints"))
	_ = os.WriteFile(filepath.Join(dir, name, "endpoints"), b, 0o640)
	if _, err := image.Open(filepath.Join(dir, name)); err == nil {
		t.Fatal("an endpoints file of another image opened")
	}
}

// An image whose zone table does not build is never written.
func TestBuildRefusesATableThatDoesNotBuild(t *testing.T) {
	dir := t.TempDir()
	in := input(t, 1, 1)
	in.Member.GlobalPairId = []byte("short")
	if _, err := image.Build(&fsx.Writer{}, dir, in); err == nil {
		t.Fatal("built an image with a bad table")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("a failed build left %d entries", len(ents))
	}
}

// A crash at any step of a build leaves nothing under a final name, so a reader
// that lists the directory finds no half-built image, and the swap has not moved.
func TestCrashDuringBuildLeavesNoImage(t *testing.T) {
	skipWindows(t)
	for _, step := range fsx.Steps() {
		for _, file := range []string{"endpoints", "meta", "", image.DirName(2, 0)} {
			t.Run(fmt.Sprintf("%v/%s", step, file), func(t *testing.T) {
				dir := t.TempDir()
				old := build(t, dir, input(t, 1, 1))
				if err := image.SetCurrent(&fsx.Writer{}, dir, old); err != nil {
					t.Fatal(err)
				}
				w := &fsx.Writer{Hook: func(p string, s fsx.Step) error {
					if s == step && (file == "" || filepath.Base(p) == file) && filepath.Base(p) != "current" {
						return fsx.ErrInjected
					}
					return nil
				}}
				_, err := image.Build(w, dir, input(t, 2, 2))
				if err == nil {
					return // the hook did not match a step of this build
				}
				if !errors.Is(err, fsx.ErrInjected) {
					t.Fatal(err)
				}
				// After a start's cleanup, only the old image is left, and it is current.
				if _, err := fsx.CleanTemps(dir, false); err != nil {
					t.Fatal(err)
				}
				names, _ := image.Images(dir)
				if len(names) != 1 || names[0] != old {
					// A stop before the final sync of the directory happens after the
					// rename, so the new image is complete (and still not current).
					if !(step == fsx.StepSyncDir && file == image.DirName(2, 0)) {
						t.Fatalf("images after a crash at %v/%s: %v", step, file, names)
					}
				}
				im, err := image.OpenCurrent(dir)
				if err != nil || im.Seq() != 1 {
					t.Fatalf("current after a crash: %v", err)
				}
			})
		}
	}
}

// Swapping the link never exposes a half-built image: a reader that opens
// image/current in a loop while a writer builds and swaps always gets a whole
// image whose content is consistent (here: as many Endpoints as its seq), and
// never an error.
func TestSwapNeverExposesAHalfBuiltImage(t *testing.T) {
	skipWindows(t)
	dir := t.TempDir()
	w := &fsx.Writer{}
	first, err := image.Build(w, dir, input(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := image.SetCurrent(w, dir, first); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var reads, bad atomic.Int64
	var firstErr atomic.Value
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				im, err := image.OpenCurrent(dir)
				reads.Add(1)
				if err != nil {
					bad.Add(1)
					firstErr.CompareAndSwap(nil, err)
					continue
				}
				if im.EndpointCount() != int(im.Seq()) {
					bad.Add(1)
					firstErr.CompareAndSwap(nil, fmt.Errorf("seq %d with %d endpoints", im.Seq(), im.EndpointCount()))
				}
			}
		}()
	}
	prev := first
	for seq := uint64(2); seq <= 40; seq++ {
		name, err := image.Build(w, dir, input(t, seq, int(seq)))
		if err != nil {
			t.Fatal(err)
		}
		if err := image.SetCurrent(w, dir, name); err != nil {
			t.Fatal(err)
		}
		if err := image.Prune(dir, name, prev); err != nil {
			t.Fatal(err)
		}
		prev = name
	}
	stop.Store(true)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d of %d reads failed or were inconsistent, first: %v", bad.Load(), reads.Load(), firstErr.Load())
	}
	if reads.Load() == 0 {
		t.Fatal("no reads ran")
	}
}

// An Endpoint record the wire validator accepts can be bigger than 1 MiB (10,000
// clients, each with a two-profile stack). Build writes it, so Open must read it:
// a reader that refused it would cost the node its whole image, every tenant's,
// for one big record (review round 1, p4n-W5a-r1-3).
func TestImageHoldsTheBiggestEndpointTheWireAllows(t *testing.T) {
	skipWindows(t)
	dir := t.TempDir()
	in := input(t, 1, 1)
	big := storetest.Endpoint(77, storetest.Blob(t, "big.example.com"))
	for i := 0; i < wire.MaxClientsPerEP; i++ {
		var id, hash [16]byte
		binary.BigEndian.PutUint32(id[:], uint32(i+1))
		binary.BigEndian.PutUint32(hash[:], uint32(i+1))
		p1, p2 := sha256.Sum256(id[:]), sha256.Sum256(hash[:])
		big.Clients = append(big.Clients, &policyv1.ClientRecord{ClientId: id[:], ClientHash: hash[:],
			Stack: &policyv1.StackRecord{Profile1Hash: p1[:], Profile2Hash: p2[:]}})
	}
	if err := wire.ValidateEndpoint(big); err != nil {
		t.Fatal(err)
	}
	if n := proto.Size(big); n <= 1<<20 {
		t.Fatalf("the record is %d bytes: the test no longer covers the old bound", n)
	}
	in.Endpoints[[16]byte(big.EndpointId)] = big
	im, err := image.Open(filepath.Join(dir, build(t, dir, in)))
	if err != nil {
		t.Fatalf("an image Build wrote does not open: %v", err)
	}
	ep, ok := im.ByEndpointID([16]byte(big.EndpointId))
	if !ok || len(ep.Record.Clients) != wire.MaxClientsPerEP {
		t.Fatal("the big record did not come back whole")
	}
}

// Review round 4 (r4-3): two tenants' Endpoints that share a rid_hash must not
// resolve to either. The later one used to replace the earlier, so one tenant's
// devices got the other's policy and its hard_disable was unreachable.
func TestImageRefusesALookupByACollidingRIDHash(t *testing.T) {
	skipWindows(t)
	dir := filepath.Join(t.TempDir(), "image")
	_ = os.MkdirAll(dir, 0o755)
	in := input(t, 5, 4)
	shared := identity.RIDHash("rid0")
	for _, id := range []byte{1, 2, 3} { // three tenants' Endpoints, one rid_hash
		ep := in.Endpoints[[16]byte(storetest.Endpoint(id, nil).EndpointId)]
		ep.RidHash = shared[:]
	}
	if got := image.RIDCollisions(in.Endpoints); len(got) != 3 || got[0][0] != 1 || got[1][0] != 2 || got[2][0] != 3 {
		t.Fatalf("collisions %v", got)
	}
	name := build(t, dir, in)
	im, err := image.Open(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := im.ByResolverID("rid0"); ok {
		t.Fatalf("a colliding rid_hash resolved to endpoint %x", e.Record.EndpointId[0])
	}
	if e, ok := im.ByResolverID("rid3"); !ok || e.Record.EndpointId[0] != 4 {
		t.Fatal("the Endpoint that does not collide was lost")
	}
	// The Endpoints stay in the image by id: claims name them.
	if im.EndpointCount() != 4 {
		t.Fatalf("count %d", im.EndpointCount())
	}
}
