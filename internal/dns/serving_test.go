package dns

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func claim(id byte, p string) image.Claim {
	return image.Claim{ID: [16]byte{id}, EndpointID: [16]byte{id}, Prefix: netip.MustParsePrefix(p)}
}

// The longest claim prefix wins, a prefix of the other family never matches, and a
// mapped address is the plain one (T-011).
func TestPrefixTableLongestMatch(t *testing.T) {
	tb := newPrefixTable([]image.Claim{
		claim(1, "198.51.100.0/24"), claim(2, "198.51.100.64/26"), claim(3, "198.51.100.77/32"),
		claim(4, "2001:db8::/32"), claim(5, "2001:db8:1::/48"),
	}, nil)
	for addr, want := range map[string]byte{
		"198.51.100.5": 1, "198.51.100.70": 2, "198.51.100.77": 3, "198.51.100.200": 1,
		"::ffff:198.51.100.77": 3, "2001:db8:2::1": 4, "2001:db8:1::9": 5,
	} {
		e, ok := tb.lookup(netip.MustParseAddr(addr))
		if !ok || e.ID[0] != want {
			t.Errorf("%s: got %v %v, want claim %d", addr, e, ok, want)
		}
	}
	for _, addr := range []string{"198.51.101.1", "10.0.0.1", "2001:db9::1"} {
		if _, ok := tb.lookup(netip.MustParseAddr(addr)); ok {
			t.Errorf("%s matched", addr)
		}
	}
	// Two claims on one prefix: the first by claim id keeps it.
	tb = newPrefixTable([]image.Claim{claim(1, "192.0.2.0/24"), {ID: [16]byte{2}, EndpointID: [16]byte{9}, Prefix: netip.MustParsePrefix("192.0.2.0/24")}}, nil)
	if e, _ := tb.lookup(netip.MustParseAddr("192.0.2.1")); e.ID[0] != 1 {
		t.Fatal("duplicate prefix")
	}
}

// A new image keeps what the old one knew of its claims' validation (so a swap does
// not make every claim stale), and serves the new records.
func TestSetImageSwapKeepsClaimValidationTimes(t *testing.T) {
	w := newWorld(t)
	udp := func() listen.Reply {
		return w.call(qopt{t: listen.UDP, src: "127.0.0.2", validated: vptr(false)}, "www.example.com", dns.TypeA)
	}
	if !udp().Msg.Truncated {
		t.Fatal("expected TC before any validation")
	}
	w.plain(epB, "www.example.com", dns.TypeA) // TCP validates
	if udp().Msg.Truncated {
		t.Fatal("expected an answer after validation")
	}
	w.h.SetImage(w.img) // the same image again: a fresh Serving
	if udp().Msg.Truncated {
		t.Fatal("a swap forgot the validation")
	}
}

// A corrupt image is refused by the reader (a flipped byte fails its seal), and the
// handler keeps serving the one it has: the caller opens before it swaps.
func TestCorruptImageIsRefusedAndTheOldOneKeepsServing(t *testing.T) {
	w := newWorld(t)
	dir := w.img.Dir()
	for _, f := range []string{"endpoints", "claims", "meta", "blobs", "zone"} {
		path := filepath.Join(dir, f)
		orig, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		bad := append([]byte(nil), orig...)
		bad[len(bad)-1] ^= 0x01
		if err := os.WriteFile(path, bad, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := image.Open(dir); err == nil {
			t.Errorf("%s: a damaged file was accepted", f)
		}
		// Truncated, too.
		if err := os.WriteFile(path, orig[:len(orig)/2], 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := image.Open(dir); err == nil {
			t.Errorf("%s: a truncated file was accepted", f)
		}
		if err := os.WriteFile(path, orig, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The handler was never handed the damaged image: it answers as before.
	wantA(t, "still serving", w.dot(epB, "www.example.com", dns.TypeA), "192.0.2.20")
}

// A profile blob that rots on disk after the image was built does not change what an
// Endpoint is told: the Endpoint degrades to the default answer rather than
// running a policy nobody checked, and others are untouched.
func TestRottedProfileBlobDegradesItsEndpointOnly(t *testing.T) {
	w := newWorld(t)
	hA := w.profile["A"]
	path, ok := w.img.ProfilePath(hA)
	if !ok {
		t.Fatal("no path")
	}
	if err := os.WriteFile(path, []byte("rotted"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.h.SetImage(w.img) // a fresh Serving, so the Endpoints compile again
	w.h.cfg.Profiles.Purge()
	wantA(t, "A degraded", w.dot(epA, "www.example.com", dns.TypeA), "192.0.2.20")
	wantA(t, "B unchanged", w.dot(epB, "ads.example.com", dns.TypeA), "0.0.0.0")
}

// Local mode and failover on the table in use, through the handler: with the panel
// stale and the primary seen down by this node, the fallback answers; a node the hub
// withdrew stays withdrawn (8a.5).
func TestZoneLocalModeThroughTheHandler(t *testing.T) {
	w := newWorld(t)
	tbl := w.img.Zone()
	var self, primary zone.NodeID
	copy(self[:], w.img.PairTable().Nodes[1].NodeId)
	copy(primary[:], w.img.PairTable().Nodes[0].NodeId)
	apex := qopt{t: listen.DoT, sni: testZone}
	name := rid(epA) + "." + testZone
	wantA(t, "primary", w.call(apex, name, dns.TypeA), "8.8.8.8")
	// Panel stale, the primary down by this node's probes: the fallback.
	w.h.SetZoneState(&ZoneState{Table: tbl, Local: zone.Local{Self: self, PanelStale: true, PeerDown: map[zone.NodeID]bool{primary: true}}})
	wantA(t, "fallback", w.call(apex, name, dns.TypeA), "8.8.4.4")
	// Not stale: the node's own view is ignored.
	w.h.SetZoneState(&ZoneState{Table: tbl, Local: zone.Local{Self: self, PeerDown: map[zone.NodeID]bool{primary: true}}})
	wantA(t, "not stale", w.call(apex, name, dns.TypeA), "8.8.8.8")
}

// A profile that is new after the first image was built must be enforced once a
// later image names it. A loader bound to the first image's files degraded every
// such Endpoint to the default answer, silently, until restart (p4n-W7-r1-1/7).
func TestProfileNewInALaterImageIsEnforced(t *testing.T) {
	w := newWorld(t)
	wantA(t, "before", w.dot(epB, "ads.example.com", dns.TypeA), "0.0.0.0")
	wantA(t, "before", w.dot(epB, "other.example.com", dns.TypeA), "192.0.2.99")

	// The tenant of B now blocks other.example.com as well: a new blob, a new
	// hash, which the first image never held.
	d, h := mkProfile(t, blob.ActBypass, [2]string{"ads.example.com", "block"}, [2]string{"other.example.com", "block"})
	if err := os.WriteFile(filepath.Join(w.root, "blobs", hex32(h)), d, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := record(epB, h)
	in := image.Input{Seq: 8, Head: [32]byte{8},
		Endpoints:  map[[16]byte]*policyv1.EndpointRecord{[16]byte(rec.EndpointId): rec},
		Claims:     map[[16]byte]*policyv1.ClaimRecord{},
		Degraded:   map[[16]byte]bool{},
		Profiles:   map[[32]byte]bool{h: true},
		BlockPages: map[[32]byte]bool{},
		Member:     storetest.Table(3, 0)}
	cid := bytes.Repeat([]byte{epB + 0x40}, 16)
	in.Claims[[16]byte(cid)] = &policyv1.ClaimRecord{ClaimId: cid, EndpointId: rec.EndpointId, Prefix: prefix("127.0.0.2/32")}
	name, err := image.Build(&fsx.Writer{}, filepath.Join(w.root, "image"), in)
	if err != nil {
		t.Fatal(err)
	}
	img2, err := image.Open(filepath.Join(w.root, "image", name))
	if err != nil {
		t.Fatal(err)
	}
	w.h.SetImage(img2)
	wantA(t, "new profile enforced", w.dot(epB, "other.example.com", dns.TypeA), "0.0.0.0")
	wantA(t, "old rule kept", w.dot(epB, "ads.example.com", dns.TypeA), "0.0.0.0")
	if w.h.degraded.Load() != 0 {
		t.Fatalf("the Endpoint was served degraded %d times", w.h.degraded.Load())
	}
}

// scriptLoader is a ProfileLoader whose behaviour a test sets: it counts calls,
// can hold them until released, and can fail with a chosen error.
type scriptLoader struct {
	inner   policy.ProfileLoader
	calls   atomic.Int32
	release chan struct{}
	fail    atomic.Pointer[error]
}

func (l *scriptLoader) Profile(h [32]byte) (*blob.Profile, error) {
	l.calls.Add(1)
	if l.release != nil {
		<-l.release
	}
	if e := l.fail.Load(); e != nil {
		return nil, *e
	}
	return l.inner.Profile(h)
}

// Concurrent first queries of one Endpoint share one compile (p4n-W7-r2-4): each
// compile opens the profile blobs, so N compiles are N times the blob memory.
func TestColdEndpointCompilesOnce(t *testing.T) {
	w := newWorld(t)
	sv := NewServing(w.img, w.h.cfg.Profiles, nil)
	l := &scriptLoader{inner: sv.loader, release: make(chan struct{})}
	sv.loader = l
	ep, ok := w.img.ByResolverID(rid(epA))
	if !ok {
		t.Fatal("no endpoint")
	}
	const n = 64
	got := make([]*epState, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); got[i] = sv.endpoint(ep) }()
	}
	time.Sleep(200 * time.Millisecond)
	close(l.release)
	wg.Wait()
	// Endpoint A binds two profile slots at most; what matters is that it is not a
	// multiple of n.
	if c := l.calls.Load(); c > 2 {
		t.Fatalf("%d profile loads for %d concurrent first queries", c, n)
	}
	for i := range got {
		if got[i] == nil || got[i] != got[0] || got[i].degraded {
			t.Fatalf("waiter %d holds a different or degraded state", i)
		}
	}
	if sv.endpoint(ep) != got[0] {
		t.Fatal("the compiled state was not kept")
	}
}

// A read that fails for a reason that is not about the blob serves that query
// degraded but is not remembered: the next query compiles again and filters
// (p4n-W7-r2-6). A blob that is really gone stays degraded and is remembered.
func TestTransientBlobErrorIsNotCached(t *testing.T) {
	w := newWorld(t)
	sv := NewServing(w.img, w.h.cfg.Profiles, nil)
	l := &scriptLoader{inner: sv.loader}
	sv.loader = l
	ep, _ := w.img.ByResolverID(rid(epA))
	e := error(policy.ErrBlobUnreadable)
	l.fail.Store(&e)
	if st := sv.endpoint(ep); !st.degraded || !st.transient {
		t.Fatalf("transient failure: %+v", st)
	}
	l.fail.Store(nil)
	if st := sv.endpoint(ep); st.degraded {
		t.Fatal("the transient failure was remembered: the Endpoint stayed degraded")
	}
	// A missing blob is remembered.
	ep2, _ := w.img.ByResolverID(rid(epB))
	m := error(policy.ErrBlobMissing)
	l.fail.Store(&m)
	first := sv.endpoint(ep2)
	if !first.degraded || first.transient {
		t.Fatalf("missing blob: %+v", first)
	}
	l.fail.Store(nil)
	if sv.endpoint(ep2) != first {
		t.Fatal("a missing blob was recompiled")
	}
}
