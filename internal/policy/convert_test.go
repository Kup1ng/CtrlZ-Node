package policy

import (
	"bytes"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

func hdr(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: 300}
}

// Records survive the trip to the evaluator's form and back byte for byte, for
// the types a resolver answers with.
func TestRRRoundTrip(t *testing.T) {
	rrs := []dns.RR{
		&dns.A{Hdr: hdr("a.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.1").To4()},
		&dns.AAAA{Hdr: hdr("a.example.com.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")},
		&dns.CNAME{Hdr: hdr("c.example.com.", dns.TypeCNAME), Target: "a.example.com."},
		&dns.MX{Hdr: hdr("example.com.", dns.TypeMX), Preference: 10, Mx: "mail.example.com."},
		&dns.TXT{Hdr: hdr("example.com.", dns.TypeTXT), Txt: []string{"v=spf1", "second string"}},
		&dns.SOA{Hdr: hdr("example.com.", dns.TypeSOA), Ns: "ns.example.com.", Mbox: "h.example.com.", Serial: 5, Refresh: 1, Retry: 2, Expire: 3, Minttl: 4},
		&dns.SRV{Hdr: hdr("_s._tcp.example.com.", dns.TypeSRV), Priority: 1, Weight: 2, Port: 3, Target: "t.example.com."},
		&dns.NS{Hdr: hdr("example.com.", dns.TypeNS), Ns: "ns1.example.com."},
		&dns.PTR{Hdr: hdr("1.0.0.127.in-addr.arpa.", dns.TypePTR), Ptr: "localhost."},
		&dns.HINFO{Hdr: hdr("example.com.", dns.TypeHINFO), Cpu: "RFC8482", Os: ""},
		&dns.RFC3597{Hdr: hdr("example.com.", 65400), Rdata: "0102030405"},
		&dns.DS{Hdr: hdr("example.com.", dns.TypeDS), KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "0102"},
	}
	for _, rr := range rrs {
		r, ok := RRFromDNS(rr)
		if !ok {
			t.Fatalf("%s: not converted", rr.Header().Name)
		}
		back, err := RRToDNS(r)
		if err != nil {
			t.Fatalf("%v: %v", rr, err)
		}
		a, b := make([]byte, 600), make([]byte, 600)
		na, e1 := dns.PackRR(rr, a, 0, nil, false)
		nb, e2 := dns.PackRR(back, b, 0, nil, false)
		if e1 != nil || e2 != nil || !bytes.Equal(a[:na], b[:nb]) {
			t.Fatalf("%v came back as %v", rr, back)
		}
	}
}

// RDATA that does not parse for its type is kept as it is, never repaired and
// never dropped.
func TestRRToDNSKeepsOpaqueData(t *testing.T) {
	n := names.MustString("x.example.com")
	for _, tp := range []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeHTTPS, dns.TypeA, dns.TypeMX} {
		in := sharedpolicy.RR{Name: n, Type: tp, Class: 1, TTL: 5, Data: []byte{0xab, 0xcd}}
		rr, err := RRToDNS(in)
		if err != nil {
			t.Fatalf("%d: %v", tp, err)
		}
		out, ok := RRFromDNS(rr)
		if !ok || !bytes.Equal(out.Data, in.Data) || out.Type != tp {
			t.Fatalf("%d: %v", tp, out)
		}
	}
}

func TestNameConversions(t *testing.T) {
	n, err := NameFromDNS("WWW.Example.COM.")
	if err != nil || n.String() != "www.example.com" {
		t.Fatalf("%v %v", n.String(), err)
	}
	if NameToDNS(n) != "www.example.com." {
		t.Fatal(NameToDNS(n))
	}
	// An escaped dot is one label, not two.
	n, err = NameFromDNS(`a\.b.example.com.`)
	if err != nil || n.Labels() != 3 {
		t.Fatalf("%v %v", n.Labels(), err)
	}
	if _, err := NameFromDNS(string(bytes.Repeat([]byte("a"), 64)) + ".com."); err == nil {
		t.Fatal("a label of 64 bytes")
	}
	root, err := NameFromDNS(".")
	if err != nil || !root.IsRoot() {
		t.Fatal("root")
	}
}

func reply(q string, rcode int, ans ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(q, dns.TypeA)
	m.Response, m.Rcode = true, rcode
	m.Answer = ans
	return m
}

func TestTrueAnswerFromMsg(t *testing.T) {
	q := names.MustString("www.example.com")
	a1 := &dns.A{Hdr: hdr("www.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.1").To4()}

	// Validation: AD is Secure, no AD is Insecure.
	m := reply("www.example.com.", 0, a1)
	m.AuthenticatedData = true
	if ta := TrueAnswerFromMsg(q, m); ta.Validation != sharedpolicy.Secure || ta.Failed || len(ta.Answer) != 1 {
		t.Fatalf("%+v", ta)
	}
	if ta := TrueAnswerFromMsg(q, reply("www.example.com.", 0, a1)); ta.Validation != sharedpolicy.Insecure {
		t.Fatal("insecure")
	}
	// An extended error that says the chain is bogus.
	m = reply("www.example.com.", dns.RcodeServerFailure)
	m.SetEdns0(1232, true)
	m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: 6})
	if ta := TrueAnswerFromMsg(q, m); ta.Validation != sharedpolicy.Bogus || !ta.Failed || ta.RCode != sharedpolicy.RCodeServFail {
		t.Fatalf("%+v", ta)
	}
	// Other codes are failures; NXDOMAIN is an answer.
	for _, rc := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeFormatError, dns.RcodeNotImplemented} {
		if ta := TrueAnswerFromMsg(q, reply("www.example.com.", rc)); !ta.Failed {
			t.Errorf("rcode %d is not a failure", rc)
		}
	}
	if ta := TrueAnswerFromMsg(q, reply("www.example.com.", dns.RcodeNameError)); ta.Failed || ta.RCode != sharedpolicy.RCodeNXDomain {
		t.Fatal("nxdomain")
	}
	// The ECS scope the upstream returned.
	m = reply("www.example.com.", 0, a1)
	m.SetEdns0(1232, false)
	m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 20, Address: net.ParseIP("192.0.2.0").To4()})
	if ta := TrueAnswerFromMsg(q, m); ta.ECSScope != 20 {
		t.Fatalf("scope %d", ta.ECSScope)
	}
	// The chain follows CNAMEs from the qname; a loop ends it; unrelated owners go.
	m = reply("www.example.com.", 0,
		&dns.CNAME{Hdr: hdr("www.example.com.", dns.TypeCNAME), Target: "b.example.net."},
		&dns.CNAME{Hdr: hdr("b.example.net.", dns.TypeCNAME), Target: "c.example.net."},
		&dns.CNAME{Hdr: hdr("c.example.net.", dns.TypeCNAME), Target: "www.example.com."}, // a loop
		&dns.A{Hdr: hdr("c.example.net.", dns.TypeA), A: net.ParseIP("192.0.2.2").To4()},
		&dns.A{Hdr: hdr("evil.example.org.", dns.TypeA), A: net.ParseIP("6.6.6.6").To4()},
	)
	ta := TrueAnswerFromMsg(q, m)
	if len(ta.Chain) != 3 || ta.Chain[1].String() != "b.example.net" || ta.Chain[2].String() != "c.example.net" {
		t.Fatalf("chain %v", ta.Chain)
	}
	if len(ta.Answer) != 4 {
		t.Fatalf("%d records kept, want the 4 on the chain", len(ta.Answer))
	}
	for _, r := range ta.Answer {
		if addr, ok := r.Addr(); ok && addr.String() == "6.6.6.6" {
			t.Fatal("a record for another name passed")
		}
	}
	// A DNAME at an ancestor of a chain name, and its signature, are kept.
	m = reply("www.old.example.com.", 0,
		&dns.DNAME{Hdr: hdr("old.example.com.", dns.TypeDNAME), Target: "new.example.com."},
		&dns.CNAME{Hdr: hdr("www.old.example.com.", dns.TypeCNAME), Target: "www.new.example.com."},
		&dns.A{Hdr: hdr("www.new.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.3").To4()})
	ta = TrueAnswerFromMsg(names.MustString("www.old.example.com"), m)
	if len(ta.Answer) != 3 {
		t.Fatalf("dname answer kept %d records", len(ta.Answer))
	}
	// p4n-W7-r6-2: a DNAME or RRSIG that no chain step needs is not kept, whatever
	// ancestor it sits on. Only the DNAME behind the CNAME step, and its RRSIG, stay.
	sig := func(owner string, covered uint16) dns.RR {
		return &dns.RRSIG{Hdr: hdr(owner, dns.TypeRRSIG), TypeCovered: covered, Algorithm: 13, Labels: 3,
			OrigTtl: 60, Expiration: 2, Inception: 1, KeyTag: 1, SignerName: "example.com.", Signature: "AAAA"}
	}
	m = reply("www.old.example.com.", 0,
		&dns.DNAME{Hdr: hdr("com.", dns.TypeDNAME), Target: "evil.net."},
		&dns.DNAME{Hdr: hdr("example.com.", dns.TypeDNAME), Target: "evil.net."},
		&dns.DNAME{Hdr: hdr("old.example.com.", dns.TypeDNAME), Target: "evil.net."}, // right owner, wrong target
		sig("com.", dns.TypeDNAME), sig("example.com.", dns.TypeA),
		&dns.DNAME{Hdr: hdr("old.example.com.", dns.TypeDNAME), Target: "new.example.com."},
		sig("old.example.com.", dns.TypeDNAME),
		&dns.CNAME{Hdr: hdr("www.old.example.com.", dns.TypeCNAME), Target: "www.new.example.com."},
		&dns.A{Hdr: hdr("www.new.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.3").To4()})
	ta = TrueAnswerFromMsg(names.MustString("www.old.example.com"), m)
	var gotD, gotS int
	for _, r := range ta.Answer {
		switch r.Type {
		case typeDNAME:
			gotD++
			if r.Name.String() != "old.example.com" {
				t.Fatalf("a DNAME at %s was kept", r.Name.String())
			}
		case sharedpolicy.TypeRRSIG:
			gotS++
			if r.Name.String() != "old.example.com" {
				t.Fatalf("an RRSIG at %s was kept", r.Name.String())
			}
		}
	}
	if gotD != 1 || gotS != 1 || len(ta.Answer) != 4 {
		t.Fatalf("kept %d DNAME, %d RRSIG, %d records; want 1, 1, 4", gotD, gotS, len(ta.Answer))
	}
	// p4n-W7-r7-5: the owner com. is the bytes \x03com\x00, which the single label
	// abc\003com also ends in. The split must fall on a label boundary, so this
	// DNAME at the TLD is not kept.
	m = reply("abc\\003com.", 0,
		&dns.DNAME{Hdr: hdr("com.", dns.TypeDNAME), Target: "abc.xyz."},
		sig("com.", dns.TypeDNAME),
		&dns.CNAME{Hdr: hdr("abc\\003com.", dns.TypeCNAME), Target: "abc\\003abc.xyz."},
		&dns.A{Hdr: hdr("abc\\003abc.xyz.", dns.TypeA), A: net.ParseIP("192.0.2.4").To4()})
	var qbuf [256]byte
	qlen, err := dns.PackDomainName("abc\\003com.", qbuf[:], 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	qn, err := names.FromCanonicalWire(qbuf[:qlen])
	if err != nil {
		t.Fatal(err)
	}
	ta = TrueAnswerFromMsg(qn, m)
	for _, r := range ta.Answer {
		if r.Type == typeDNAME || r.Type == sharedpolicy.TypeRRSIG {
			t.Fatalf("a record of type %d at %s was kept", r.Type, r.Name.String())
		}
	}
	if len(ta.Answer) != 2 {
		t.Fatalf("kept %d records, want the CNAME and the A", len(ta.Answer))
	}
}

// ---- blobs and endpoints

func writeBlob(t *testing.T, dir string, spec *blob.Spec) [32]byte {
	t.Helper()
	d, err := blob.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := blob.Open(d)
	h := p.Hash()
	name := ""
	const hexd = "0123456789abcdef"
	for _, c := range h {
		name += string([]byte{hexd[c>>4], hexd[c&15]})
	}
	if err := os.WriteFile(filepath.Join(dir, name), d, 0o644); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestProfilesLoaderChecksHashAndCaches(t *testing.T) {
	dir := t.TempDir()
	pat, _ := rules.Parse("a.example.com")
	h := writeBlob(t, dir, &blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: pat, Action: blob.ActBlock}}})
	reads := 0
	path := func(x [32]byte) (string, bool) {
		reads++
		const hexd = "0123456789abcdef"
		name := ""
		for _, c := range x {
			name += string([]byte{hexd[c>>4], hexd[c&15]})
		}
		return filepath.Join(dir, name), true
	}
	p := NewProfiles(2).Bind(path)
	for i := 0; i < 3; i++ {
		if _, err := p.Profile(h); err != nil {
			t.Fatal(err)
		}
	}
	if reads != 1 {
		t.Fatalf("%d path lookups for three loads", reads)
	}
	// A file whose content is not the hash it is named by is a missing one.
	bad := [32]byte{0xee}
	bp, _ := path(bad)
	_ = os.WriteFile(bp, mustRead(t, filepath.Join(dir, nameOf(h))), 0o644)
	if _, err := p.Profile(bad); err != ErrBlobMissing {
		t.Fatalf("a renamed blob was accepted: %v", err)
	}
	// Garbage and a missing file likewise.
	g := [32]byte{0xdd}
	gp, _ := path(g)
	_ = os.WriteFile(gp, []byte("not a profile"), 0o644)
	if _, err := p.Profile(g); err != ErrBlobMissing {
		t.Fatal("garbage accepted")
	}
	if _, err := p.Profile([32]byte{0xcc}); err != ErrBlobMissing {
		t.Fatal("missing file")
	}
	// No path at all.
	if _, err := NewProfiles(1).Bind(func([32]byte) (string, bool) { return "", false }).Profile(h); err != ErrBlobMissing {
		t.Fatal("no path")
	}
}

func nameOf(h [32]byte) string {
	const hexd = "0123456789abcdef"
	n := ""
	for _, c := range h {
		n += string([]byte{hexd[c>>4], hexd[c&15]})
	}
	return n
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCompileEndpoint(t *testing.T) {
	dir := t.TempDir()
	pat, _ := rules.Parse("a.example.com")
	h1 := writeBlob(t, dir, &blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: pat, Action: blob.ActBlock}}})
	h2 := writeBlob(t, dir, &blob.Spec{Default: blob.ActBlock})
	p := NewProfiles(8).Bind(func(x [32]byte) (string, bool) { return filepath.Join(dir, nameOf(x)), true })

	rec := &policyv1.EndpointRecord{
		EndpointId: bytes.Repeat([]byte{1}, 16),
		Base:       &policyv1.StackRecord{Profile1Hash: h1[:], Profile2Hash: h2[:]},
		Clients: []*policyv1.ClientRecord{
			{ClientId: bytes.Repeat([]byte{2}, 16), ClientHash: bytes.Repeat([]byte{3}, 16), Stack: &policyv1.StackRecord{Profile1Hash: h2[:]}},
			{ClientId: bytes.Repeat([]byte{4}, 16), ClientHash: []byte{1}}, // malformed: skipped
		},
		Schedule: &policyv1.ScheduleRecord{
			Zone: "Asia/Tehran", BaseOffset: 12600, Grid: make([]byte, 336),
			Windows: []*policyv1.WindowRecord{{WindowId: bytes.Repeat([]byte{5}, 16), Stack: &policyv1.StackRecord{Profile1Hash: h1[:]}}},
		},
	}
	rec.Schedule.Grid[10] = 1
	v, err := CompileEndpoint(rec, p)
	if err != nil {
		t.Fatal(err)
	}
	if v.Base == nil || v.Base.Slots[0] == nil || v.Base.Slots[1] == nil || len(v.Clients) != 1 || v.Sched == nil || len(v.Windows) != 1 || v.WindowIDs[0][0] != 5 {
		t.Fatalf("%+v", v)
	}
	// A schedule whose grid names a window that does not exist is refused.
	rec.Schedule.Grid[11] = 9
	if _, err := CompileEndpoint(rec, p); err == nil {
		t.Fatal("bad schedule accepted")
	}
	rec.Schedule.Grid[11] = 0
	// A profile that is not on disk is ErrBlobMissing, whichever slot names it.
	rec.Base.Profile2Hash = bytes.Repeat([]byte{0x99}, 32)
	if _, err := CompileEndpoint(rec, p); err != ErrBlobMissing {
		t.Fatalf("%v", err)
	}
	rec.Base.Profile2Hash = nil
	rec.Base.Profile1Hash = []byte{1, 2}
	if _, err := CompileEndpoint(rec, p); err == nil {
		t.Fatal("short hash")
	}
	// No profile at all is a valid binding (the Endpoint has none yet).
	rec.Base = &policyv1.StackRecord{}
	rec.Schedule = nil
	if _, err := CompileEndpoint(rec, p); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileEndpoint(&policyv1.EndpointRecord{}, p); err == nil {
		t.Fatal("no endpoint id")
	}
	if ClientHash("") != ([16]byte{}) || ClientHash("kid") == ([16]byte{}) {
		t.Fatal("client hash")
	}
	_ = commonv1.AdminState_ADMIN_STATE_ENABLED
}

// A blob that is evicted from the warm LRU while a compiled Endpoint still holds
// it is not read a second time: the live copy is found by hash (p4n-W7-r1-11).
func TestProfilesShareALiveBlobAfterEviction(t *testing.T) {
	dir := t.TempDir()
	pat, _ := rules.Parse("a.example.com")
	big := writeBlob(t, dir, &blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: pat, Action: blob.ActBlock}}})
	var others [][32]byte
	for i := 0; i < 4; i++ {
		p2, _ := rules.Parse("b" + string(rune('a'+i)) + ".example.com")
		others = append(others, writeBlob(t, dir, &blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{{ID: [16]byte{byte(i + 2)}, Pattern: p2, Action: blob.ActBlock}}}))
	}
	reads := 0
	load := NewProfiles(2).Bind(func(x [32]byte) (string, bool) { reads++; return filepath.Join(dir, nameOf(x)), true })
	held, err := load.Profile(big) // a compiled Endpoint keeps this one
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range others { // churn: the LRU of 2 evicts big
		if _, err := load.Profile(o); err != nil {
			t.Fatal(err)
		}
	}
	before := reads
	again, err := load.Profile(big)
	if err != nil {
		t.Fatal(err)
	}
	if again != held || reads != before {
		t.Fatalf("a second copy of a live blob was made (same=%v, reads %d -> %d)", again == held, before, reads)
	}
}

// Two images with different files share one cache and each reads its own files.
func TestProfilesBindsPerImage(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	pat, _ := rules.Parse("a.example.com")
	h1 := writeBlob(t, d1, &blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: pat, Action: blob.ActBlock}}})
	h2 := writeBlob(t, d2, &blob.Spec{Default: blob.ActBlock})
	p := NewProfiles(8)
	in := func(dir string, h [32]byte) func([32]byte) (string, bool) {
		return func(x [32]byte) (string, bool) { return filepath.Join(dir, nameOf(x)), x == h }
	}
	l1, l2 := p.Bind(in(d1, h1)), p.Bind(in(d2, h2))
	if _, err := l1.Profile(h1); err != nil {
		t.Fatal(err)
	}
	if _, err := l2.Profile(h2); err != nil {
		t.Fatalf("the second image's blob was not found: %v", err)
	}
	if _, err := l2.Profile(h1); err != nil { // cached by content: right for any image that names it
		t.Fatalf("shared cache missed: %v", err)
	}
}

// A validated denial of existence carries AD too (RFC 6840): NXDOMAIN with AD is
// Secure, and any other rcode with AD is not an answer at all (p4n-W7-r1-3).
func TestValidatedNXDomainIsSecure(t *testing.T) {
	q := names.MustString("nope.example.com")
	m := reply("nope.example.com.", dns.RcodeNameError)
	m.AuthenticatedData = true
	if ta := TrueAnswerFromMsg(q, m); ta.Validation != sharedpolicy.Secure || ta.Failed || ta.RCode != sharedpolicy.RCodeNXDomain {
		t.Fatalf("%+v", ta)
	}
	m = reply("nope.example.com.", dns.RcodeRefused)
	m.AuthenticatedData = true
	if ta := TrueAnswerFromMsg(q, m); ta.Validation == sharedpolicy.Secure || !ta.Failed {
		t.Fatalf("%+v", ta)
	}
}

// Concurrent first loads of one blob share a single read and a single resident
// copy (p4n-W7-r2-4): without it, queries times blob size is the peak.
func TestProfilesColdLoadsAreCoalesced(t *testing.T) {
	dir := t.TempDir()
	pat, _ := rules.Parse("a.example.com")
	h := writeBlob(t, dir, &blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: pat, Action: blob.ActBlock}}})
	p := NewProfiles(4)
	var reads atomic.Int32
	release := make(chan struct{})
	p.read = func(f string) ([]byte, error) {
		reads.Add(1)
		<-release
		return os.ReadFile(f)
	}
	load := p.Bind(func(x [32]byte) (string, bool) { return filepath.Join(dir, nameOf(x)), true })
	const n = 64
	got := make([]*blob.Profile, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pr, err := load.Profile(h)
			if err != nil {
				t.Error(err)
			}
			got[i] = pr
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	if reads.Load() != 1 {
		t.Fatalf("%d reads for %d concurrent first loads", reads.Load(), n)
	}
	for i := range got {
		if got[i] == nil || got[i] != got[0] {
			t.Fatal("waiters hold different copies")
		}
	}
	// A failed load is shared by the waiters of the same file, and the next call
	// tries again.
	bad := [32]byte{0xaa}
	reads.Store(0)
	release = make(chan struct{})
	p.read = func(f string) ([]byte, error) {
		reads.Add(1)
		<-release
		return nil, fs.ErrNotExist
	}
	var errs atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := load.Profile(bad); err == ErrBlobMissing {
				errs.Add(1)
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	if errs.Load() != 16 || reads.Load() != 1 {
		t.Fatalf("failed load: %d errors, %d reads", errs.Load(), reads.Load())
	}
}

// A read that fails for a reason that is not about the blob is not "missing": it
// is ErrBlobUnreadable, and the next call reads again (p4n-W7-r2-6).
func TestProfilesTransientReadErrorIsDistinct(t *testing.T) {
	dir := t.TempDir()
	h := writeBlob(t, dir, &blob.Spec{Default: blob.ActBlock})
	p := NewProfiles(4)
	fail := true
	p.read = func(f string) ([]byte, error) {
		if fail {
			return nil, &fs.PathError{Op: "open", Path: f, Err: syscall.EMFILE}
		}
		return os.ReadFile(f)
	}
	load := p.Bind(func(x [32]byte) (string, bool) { return filepath.Join(dir, nameOf(x)), true })
	if _, err := load.Profile(h); !errors.Is(err, ErrBlobUnreadable) || errors.Is(err, ErrBlobMissing) {
		t.Fatalf("EMFILE gave %v", err)
	}
	fail = false
	if _, err := load.Profile(h); err != nil {
		t.Fatalf("the next call did not retry: %v", err)
	}
}

// p4n-W7-r8-2: the authority section follows the same rule as the answer
// section. An NS or SOA for a zone that is not an ancestor of the chain is
// dropped, the SOA of the zone and its denial records stay.
func TestTrueAnswerAuthorityOwnerCheck(t *testing.T) {
	soa := func(owner string) dns.RR {
		return &dns.SOA{Hdr: hdr(owner, dns.TypeSOA), Ns: "ns." + owner, Mbox: "h." + owner, Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minttl: 60}
	}
	m := reply("a.example.", dns.RcodeNameError)
	m.Ns = []dns.RR{
		soa("example."),
		&dns.NS{Hdr: hdr("com.", dns.TypeNS), Ns: "evil.net."}, // another zone
		soa("other.org."),
		&dns.NS{Hdr: hdr("b.example.", dns.TypeNS), Ns: "evil.net."}, // a sibling of the qname's zone, not an ancestor
		&dns.NSEC{Hdr: hdr("a0.example.", dns.TypeNSEC), NextDomain: "b.example.", TypeBitMap: []uint16{dns.TypeA}},
		&dns.RRSIG{Hdr: hdr("a0.example.", dns.TypeRRSIG), TypeCovered: dns.TypeNSEC, Algorithm: 13, Labels: 1,
			OrigTtl: 60, Expiration: 2, Inception: 1, KeyTag: 1, SignerName: "example.", Signature: "AAAA"},
		&dns.NSEC{Hdr: hdr("x.com.", dns.TypeNSEC), NextDomain: "y.com.", TypeBitMap: []uint16{dns.TypeA}}, // denial outside the zone
		&dns.TXT{Hdr: hdr("a0.example.", dns.TypeTXT), Txt: []string{"x"}},                                 // not a denial record
	}
	ta := TrueAnswerFromMsg(names.MustString("a.example"), m)
	var got []string
	for _, r := range ta.Authority {
		got = append(got, r.Name.String())
		if r.Type == sharedpolicy.TypeNS || r.Type == sharedpolicy.TypeTXT {
			t.Fatalf("authority record of type %d at %s was kept", r.Type, r.Name.String())
		}
	}
	// the SOA, then the NSEC and its RRSIG
	if len(ta.Authority) != 3 || got[0] != "example" || got[1] != "a0.example" || got[2] != "a0.example" {
		t.Fatalf("kept %v", got)
	}
	// An owner that only ends in the bytes of an ancestor is no ancestor.
	m = reply("abc\003com.", dns.RcodeNameError)
	m.Ns = []dns.RR{soa("com.")}
	var buf [256]byte
	n, err := dns.PackDomainName("abc\003com.", buf[:], 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	qn, err := names.FromCanonicalWire(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if ta := TrueAnswerFromMsg(qn, m); len(ta.Authority) != 0 {
		t.Fatalf("an SOA at com. was kept for a single-label name that ends in its bytes")
	}
	// The root is an ancestor of every name: the SOA of a nonexistent TLD stays.
	m = reply("a.invalid.", dns.RcodeNameError)
	m.Ns = []dns.RR{&dns.SOA{Hdr: hdr(".", dns.TypeSOA), Ns: "a.root-servers.net.", Mbox: "h.root-servers.net.", Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minttl: 60}}
	if ta := TrueAnswerFromMsg(names.MustString("a.invalid"), m); len(ta.Authority) != 1 {
		t.Fatal("the root SOA was dropped")
	}
}
