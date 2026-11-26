package dns

// The test world: a real image on disk (built by the store's own builder, with
// real profile blobs), a real Handler, a stand-in for the identified Unbound, and
// a recorder for what the handler tells the agent. Direct calls go through
// ServeDNS with a hand-made Request; the end-to-end tests of e2e_test.go put the
// same handler behind the W6 listeners on loopback ports 5750 to 5799.

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"os"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const (
	testZone  = "dns.test"
	selfDNSIP = "8.8.8.8" // node 0 of storetest.Table, and so this node's own address
)

// Resolver ids and DoH tokens of the test Endpoints: 26 and 32 characters of the
// lower-case base32 alphabet.
func rid(c byte) string { return strings.Repeat(string(rune('a'+c)), 26) }
func tok(c byte) string { return strings.Repeat(string(rune('a'+c)), 32) }

// The Endpoints. Letters name them; the byte is their id, their rid and token
// are rid(byte) and tok(byte), and their Plain DNS claim is 127.0.0.<byte>/32.
const (
	epA byte = 1  // tenant 1: Default Block, one Bypass rule, Expose IP, Authorize Secure DNS
	epB byte = 2  // tenant 2: Default Bypass, one Block rule
	epC byte = 4  // hard_disabled
	epD byte = 5  // soft_disabled, Default Block
	epE byte = 6  // Require Authorized IPs, list does not hold loopback, Authorize Secure DNS
	epF byte = 7  // Require Authorized IPs, list holds loopback
	epG byte = 8  // authorized list, clients "kid" and "default" with their own stacks
	epH byte = 9  // degraded: its profile blob is not on disk
	epR byte = 10 // Redirect rules
)

type world struct {
	t        testing.TB
	root     string
	img      *image.Image
	h        *Handler
	rep      *recorder
	back     *fakeBackend
	cache    *cache.Cache
	res      *policy.Resolver
	profile  map[string][32]byte
	clock    atomic.Int64 // unix nanoseconds, 0 means the real clock
	proof    []byte
	settings *Settings
}

func (w *world) now() time.Time {
	if n := w.clock.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Now()
}

func (w *world) setNow(t time.Time) { w.clock.Store(t.UnixNano()) }

func (w *world) advance(d time.Duration) { w.setNow(w.now().Add(d)) }

// ---- profiles

func mkProfile(t testing.TB, def blob.Action, ruleSpecs ...[2]string) ([]byte, [32]byte) {
	t.Helper()
	spec := &blob.Spec{Default: def}
	for i, r := range ruleSpecs {
		p, err := rules.Parse(r[0])
		if err != nil {
			t.Fatal(err)
		}
		act := blob.ActBlock
		if r[1] == "bypass" {
			act = blob.ActBypass
		}
		spec.Rules = append(spec.Rules, blob.RuleSpec{ID: [16]byte{byte(i + 1)}, Pattern: p, Action: act})
	}
	d, err := blob.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	return d, storetest.Hash(d)
}

func record(id byte, h [32]byte) *policyv1.EndpointRecord {
	r := rid(id)
	rh := identity.RIDHash(r)
	th := identity.TokenHash(tok(id))
	return &policyv1.EndpointRecord{
		EndpointId: bytes.Repeat([]byte{id}, 16), RidHash: rh[:], DohTokenHash: th[:],
		PairId: bytes.Repeat([]byte{0xb0}, 16), AdminState: commonv1.AdminState_ADMIN_STATE_ENABLED,
		LegacyDns: true, AnalyticsLevel: commonv1.AnalyticsLevel_ANALYTICS_LEVEL_SOME,
		Base: &policyv1.StackRecord{Profile1Hash: h[:]},
	}
}

// addEndpoint puts a record and its Plain DNS claim (127.0.0.<id>/32) into an image input.
func addEndpoint(in *image.Input, r *policyv1.EndpointRecord) {
	in.Endpoints[[16]byte(r.EndpointId)] = r
	in.Claims[[16]byte(bytes.Repeat([]byte{r.EndpointId[0] + 0x40}, 16))] = &policyv1.ClaimRecord{
		ClaimId: bytes.Repeat([]byte{r.EndpointId[0] + 0x40}, 16), EndpointId: r.EndpointId,
		Prefix: prefix("127.0.0." + itoa(int(r.EndpointId[0])) + "/32"),
	}
}

func prefix(s string) *commonv1.Prefix {
	p := netip.MustParsePrefix(s)
	return &commonv1.Prefix{Addr: p.Addr().AsSlice(), Bits: uint32(p.Bits())}
}

// ---- the world

func newWorld(t testing.TB) *world { return newWorldTuned(t, nil) }

// newWorldTuned is newWorld with a hook that changes the image input before the
// image is built (records, extra Endpoints through addEndpoint, extra profile blobs
// through put), for a test that needs what the standard world lacks.
func newWorldTuned(t testing.TB, tune func(in *image.Input, put func(name string, d []byte, h [32]byte))) *world {
	t.Helper()
	w := &world{t: t, root: t.TempDir(), rep: &recorder{}, back: newFakeBackend(), profile: map[string][32]byte{}}
	imgDir := filepath.Join(w.root, "image")
	blobDir := filepath.Join(w.root, "blobs")
	for _, d := range []string{imgDir, blobDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	put := func(name string, d []byte, h [32]byte, onDisk bool) {
		w.profile[name] = h
		if onDisk {
			if err := os.WriteFile(filepath.Join(blobDir, hex32(h)), d, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A: everything blocked except allow.example.com.
	d, h := mkProfile(t, blob.ActBlock, [2]string{"allow.example.com", "bypass"})
	put("A", d, h, true)
	// B: everything passes except ads.example.com.
	d, h = mkProfile(t, blob.ActBypass, [2]string{"ads.example.com", "block"})
	put("B", d, h, true)
	// D: Default Block (soft_disabled must still answer truly).
	d, h = mkProfile(t, blob.ActBlock)
	put("D", d, h, true)
	// kid: blocks www.example.com for the client "kid" of G.
	d, h = mkProfile(t, blob.ActBypass, [2]string{"www.example.com", "block"})
	put("kid", d, h, true)
	// R: Redirect rules, for the Iranian-name tests (T-524): a Redirect to an
	// address for two names, one under .ir, and a Redirect to a location, which a
	// node with no proxy cannot honour.
	{
		mk := func(tok string, tg *blob.TargetSpec, id byte) blob.RuleSpec {
			p, err := rules.Parse(tok)
			if err != nil {
				t.Fatal(err)
			}
			return blob.RuleSpec{ID: [16]byte{id}, Pattern: p, Action: blob.ActRedirect, Target: tg}
		}
		ipT := &blob.TargetSpec{Kind: blob.TargetIP, V4: netip.MustParseAddr("192.0.2.250")}
		locT := &blob.TargetSpec{Kind: blob.TargetLocation, Location: 5}
		rd, err := blob.Build(&blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{
			mk("www.example.com", ipT, 1), mk("www.example.ir", ipT, 2), mk("*.example.ir", ipT, 3), mk("loc.example.com", locT, 4),
		}})
		if err != nil {
			t.Fatal(err)
		}
		put("R", rd, storetest.Hash(rd), true)
	}
	// H's profile is never written: the Endpoint is degraded.
	d, h = mkProfile(t, blob.ActBlock, [2]string{"missing.example.com", "block"})
	put("missing", d, h, false)

	in := image.Input{Seq: 7, Head: [32]byte{7},
		Endpoints: map[[16]byte]*policyv1.EndpointRecord{}, Claims: map[[16]byte]*policyv1.ClaimRecord{},
		Degraded: map[[16]byte]bool{}, Profiles: map[[32]byte]bool{}, BlockPages: map[[32]byte]bool{},
		Member: storetest.Table(3, 0)}
	add := func(r *policyv1.EndpointRecord) { addEndpoint(&in, r) }
	a := record(epA, w.profile["A"])
	a.ExposeIp, a.AuthorizeSecureDns = true, true
	add(a)
	add(record(epB, w.profile["B"]))
	c := record(epC, w.profile["A"])
	c.AdminState = commonv1.AdminState_ADMIN_STATE_HARD_DISABLED
	add(c)
	dd := record(epD, w.profile["D"])
	dd.AdminState = commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED
	add(dd)
	e := record(epE, w.profile["A"])
	e.RequireAuthorizedIps, e.AuthorizeSecureDns = true, true
	e.Authorized = []*commonv1.Prefix{prefix("10.9.9.0/24")}
	add(e)
	f := record(epF, w.profile["A"])
	f.RequireAuthorizedIps = true
	f.Authorized = []*commonv1.Prefix{prefix("127.0.0.0/8")}
	add(f)
	g := record(epG, w.profile["B"])
	g.AuthorizeSecureDns = true
	g.Authorized = []*commonv1.Prefix{prefix("127.0.0.0/8"), prefix("127.0.0.0/24")}
	kh := identity.ClientHash("kid")
	// "default" holds the stack of Plain DNS (P3 3.3); here it is the same blocking profile.
	dh := identity.ClientHash("default")
	g.Clients = []*policyv1.ClientRecord{
		{ClientId: bytes.Repeat([]byte{0x77}, 16), ClientHash: kh[:], Stack: &policyv1.StackRecord{Profile1Hash: ptr(w.profile["kid"])}},
		{ClientId: bytes.Repeat([]byte{0x78}, 16), ClientHash: dh[:], Stack: &policyv1.StackRecord{Profile1Hash: ptr(w.profile["kid"])}},
	}
	add(g)
	add(record(epR, w.profile["R"]))
	hh := record(epH, w.profile["missing"])
	add(hh)
	for _, n := range []string{"A", "B", "D", "kid", "R"} {
		in.Profiles[w.profile[n]] = true
	}
	// H's binding names a blob that is not on disk, so the image marks it so.
	in.Degraded[[16]byte(hh.EndpointId)] = true

	if tune != nil {
		tune(&in, func(name string, d []byte, h [32]byte) {
			put(name, d, h, true)
			in.Profiles[h] = true
		})
	}
	name, err := image.Build(&fsx.Writer{}, imgDir, in)
	if err != nil {
		t.Fatal(err)
	}
	w.img, err = image.Open(filepath.Join(imgDir, name))
	if err != nil {
		t.Fatal(err)
	}

	w.cache = cache.New(cache.Config{SharedBytes: 8 << 20, FreeBytes: 8 << 20})
	w.res = &policy.Resolver{Cache: w.cache, Segment: cache.Shared, Backend: w.back, Deadline: 2 * time.Second}
	profiles := policy.NewProfiles(64)
	h2, err := New(Config{
		Resolver: w.res, Reporter: w.rep, Profiles: profiles,
		NeverProxied: neverIR, Now: w.now,
		Self: func() sharedpolicy.SelfAddrs { return sharedpolicy.SelfAddrs{DNSIP: netip.MustParseAddr(selfDNSIP)} },
	})
	if err != nil {
		t.Fatal(err)
	}
	w.h = h2
	w.proof = bytes.Repeat([]byte{0x5a}, 32)
	zones := []names.Name{names.MustString(testZone)}
	panel := []names.Name{names.MustString("panel.example.org"), names.MustString("admin.example.org")}
	w.settings = NewSettings(zones, panel, netip.MustParseAddr(selfDNSIP), w.proof, false)
	w.h.SetSettings(w.settings)
	w.h.SetImage(w.img)
	// The agent, not the image, says which table is in use (SC 8a.5): a test world
	// has the image's table with no withdrawal flags, as a caught-up node does.
	w.h.SetZoneState(&ZoneState{Table: w.img.Zone()})
	return w
}

func ptr(h [32]byte) []byte { return h[:] }

func hex32(h [32]byte) string {
	const d = "0123456789abcdef"
	b := make([]byte, 64)
	for i, c := range h {
		b[2*i], b[2*i+1] = d[c>>4], d[c&15]
	}
	return string(b)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// neverIR is a stand-in for P2's noredirect.Name: the names under .ir.
func neverIR(n names.Name) bool {
	return n.Labels() > 0 && string(n.Label(n.Labels()-1)) == "ir"
}

// ---- a request, by hand

type qopt struct {
	t         listen.Transport
	src       string
	sni       string
	http      *listen.HTTPInfo
	validated *bool
	do, cd    bool
	edns      bool
	cookie    bool
}

func (w *world) call(o qopt, name string, qt uint16) listen.Reply {
	w.t.Helper()
	return w.callMsg(o, mkq(name, qt, o))
}

func mkq(name string, qt uint16, o qopt) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.RecursionDesired = true
	m.CheckingDisabled = o.cd
	if o.do || o.edns {
		m.SetEdns0(1232, o.do)
	}
	return m
}

func (w *world) callMsg(o qopt, m *dns.Msg) listen.Reply {
	w.t.Helper()
	if o.src == "" {
		o.src = "127.0.0.1"
	}
	v := o.t != listen.UDP
	if o.validated != nil {
		v = *o.validated
	}
	req := &listen.Request{Msg: m, Transport: o.t, Source: netip.AddrPortFrom(netip.MustParseAddr(o.src), 40000), Validated: v, SNI: o.sni, HTTP: o.http}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return w.h.ServeDNS(ctx, req)
}

func vptr(b bool) *bool { return &b }

// dohInfo is the HTTPInfo of a DoH POST that a resolver client would send.
func dohInfo(path, authority string) *listen.HTTPInfo {
	return &listen.HTTPInfo{Path: path, Authority: authority, Method: "POST", ContentType: "application/dns-message"}
}

// Shorthands for the identity forms of one Endpoint.
func (w *world) dot(ep byte, name string, qt uint16) listen.Reply {
	return w.call(qopt{t: listen.DoT, sni: rid(ep) + "." + testZone}, name, qt)
}

func (w *world) doq(ep byte, name string, qt uint16) listen.Reply {
	return w.call(qopt{t: listen.DoQ, sni: rid(ep) + "." + testZone}, name, qt)
}

func (w *world) doh(ep byte, name string, qt uint16) listen.Reply {
	return w.call(qopt{t: listen.DoH, sni: "x." + testZone, http: dohInfo("/"+tok(ep), rid(ep)+"."+testZone)}, name, qt)
}

func (w *world) doh3(ep byte, name string, qt uint16) listen.Reply {
	return w.call(qopt{t: listen.DoH3, sni: "x." + testZone, http: dohInfo("/"+tok(ep), rid(ep)+"."+testZone)}, name, qt)
}

// plain asks over TCP from the claim address of an Endpoint (validated).
func (w *world) plain(ep byte, name string, qt uint16) listen.Reply {
	return w.call(qopt{t: listen.TCP, src: "127.0.0." + itoa(int(ep))}, name, qt)
}

// every transport, with a function that asks as Endpoint ep.
type asker struct {
	name string
	t    listen.Transport
	ask  func(w *world, ep byte, name string, qt uint16) listen.Reply
}

func allAskers() []asker {
	return []asker{
		{"dot", listen.DoT, (*world).dot},
		{"doq", listen.DoQ, (*world).doq},
		{"doh", listen.DoH, (*world).doh},
		{"doh3", listen.DoH3, (*world).doh3},
		{"tcp", listen.TCP, (*world).plain},
	}
}
