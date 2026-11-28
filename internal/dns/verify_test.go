package dns

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

func newLabel(t *testing.T) string {
	t.Helper()
	l, err := identity.NewVerifyLabel()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func verifyName(label string) string { return label + ".verify." + testZone }

// get runs GET /v the way the listener does: a request whose TLS server name is
// the verify host.
func (w *world) get(method, label, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+verifyName(label)+"/v", nil)
	r.TLS = &tls.ConnectionState{ServerName: verifyName(label)}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	w.h.Verify().ServeHTTP(rec, r)
	return rec
}

func tagOf(label string, n []byte, parts ...[]byte) string {
	m := hmac.New(sha256.New, append([]byte(label), n...))
	m.Write(bytes.Join(parts, nil))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) (verifyBody, []byte, map[string]any) {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var b verifyBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	n, err := hex.DecodeString(b.N)
	if err != nil || len(n) != 16 {
		t.Fatalf("n %q", b.N)
	}
	return b, n, raw
}

// A answers with the node's own address and TTL 0 on every transport, for an
// identified query and an unidentified one; other types are NODATA with the zone
// SOA (T-045).
func TestVerifyNameAnswers(t *testing.T) {
	w := newWorld(t)
	for _, a := range allAskers() {
		r := a.ask(w, epA, verifyName(newLabel(t)), dns.TypeA)
		wantA(t, a.name, r, selfDNSIP)
		if r.Msg.Answer[0].Header().Ttl != 0 || !r.Msg.Authoritative {
			t.Errorf("%s: %v", a.name, r.Msg)
		}
		r = a.ask(w, epA, verifyName(newLabel(t)), dns.TypeAAAA)
		if rcodeOf(r) != "NOERROR" || len(r.Msg.Answer) != 0 || len(r.Msg.Ns) != 1 {
			t.Errorf("%s: AAAA %v", a.name, r.Msg)
		}
	}
	// Unidentified, and even with Default Block there is no policy on it.
	wantA(t, "dot, no identity", w.call(qopt{t: listen.DoT, sni: testZone}, verifyName(newLabel(t)), dns.TypeA), selfDNSIP)
	wantA(t, "udp stranger", w.call(qopt{t: listen.UDP, src: "127.0.0.3"}, verifyName(newLabel(t)), dns.TypeA), selfDNSIP)
}

// The proof code over UDP (SC 3.5): the first 10 characters of the HMAC, for the
// label and the source address. TCP and the encrypted transports have no code,
// and a node with no proof key gives none.
func TestProofCodeOverUDP(t *testing.T) {
	w := newWorld(t)
	label := newLabel(t)
	r := w.call(qopt{t: listen.UDP, src: "127.0.0.3"}, verifyName(label), dns.TypeTXT)
	if len(r.Msg.Answer) != 1 {
		t.Fatalf("%v", r.Msg)
	}
	got := r.Msg.Answer[0].(*dns.TXT).Txt[0]
	want := identity.ProofCode(w.proof, label, mustAddr("127.0.0.3"))
	if got != want || len(got) != 10 {
		t.Fatalf("code %q want %q", got, want)
	}
	// A mapped source gives the same code as the plain one.
	r = w.call(qopt{t: listen.UDP, src: "::ffff:127.0.0.3"}, verifyName(label), dns.TypeTXT)
	if r.Msg.Answer[0].(*dns.TXT).Txt[0] != want {
		t.Fatal("mapped source")
	}
	for _, o := range []qopt{{t: listen.TCP, src: "127.0.0.3"}, {t: listen.DoT, sni: testZone}, {t: listen.DoT, sni: rid(epA) + "." + testZone}} {
		r := w.call(o, verifyName(label), dns.TypeTXT)
		if len(r.Msg.Answer) != 0 {
			t.Errorf("%s: a code over a transport that needs none", o.t)
		}
	}
	// No key, no code.
	w.h.SetSettings(NewSettings(w.settings.zones, w.settings.panel, w.settings.selfIP, make([]byte, 32), false))
	r = w.call(qopt{t: listen.UDP, src: "127.0.0.3"}, verifyName(label), dns.TypeTXT)
	if len(r.Msg.Answer) != 0 {
		t.Fatal("an all-zero key gave a code")
	}
}

// GET /v (T-046): the body, the tags, CORS and no-store.
func TestVerifyEndpointBody(t *testing.T) {
	w := newWorld(t)
	label := newLabel(t)
	// An identified DoT query on Endpoint A with a client label.
	w.call(qopt{t: listen.DoT, sni: rid(epA) + "-pc." + testZone}, verifyName(label), dns.TypeA)

	rec := w.get("GET", label, "")
	b, n, raw := decodeBody(t, rec)
	if len(raw) != 5 {
		t.Fatalf("the body has %d fields: %v", len(raw), raw)
	}
	if !b.Seen {
		t.Fatal("not seen")
	}
	rd := []byte(rid(epA))
	if b.RIDTag != tagOf(label, n, rd) {
		t.Fatal("rid_tag")
	}
	if b.ClientTag != tagOf(label, n, rd, []byte{0}, []byte("pc")) {
		t.Fatal("client_tag")
	}
	if b.ProtoTag != tagOf(label, n, rd, []byte{1}, []byte{byte(commonv1.Protocol_PROTOCOL_DOT)}) {
		t.Fatal("proto_tag")
	}
	// Nothing in the clear: not the rid, the label, a protocol name.
	for _, s := range []string{rid(epA), label, "dot", "DOT", "identified", "protocol"} {
		if bytes.Contains(rec.Body.Bytes(), []byte(s)) {
			t.Fatalf("the body holds %q: %s", s, rec.Body.String())
		}
	}
	// Headers.
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%v", rec.Header())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS with no Origin")
	}
	// A second read shares no value with the first (n and every tag are new).
	b2, _, _ := decodeBody(t, w.get("GET", label, ""))
	if b2.N == b.N || b2.RIDTag == b.RIDTag || b2.ClientTag == b.ClientTag || b2.ProtoTag == b.ProtoTag {
		t.Fatal("two reads share a value")
	}
	// The proto tag differs between transports: the panel can tell which one came.
	l2 := newLabel(t)
	w.call(qopt{t: listen.DoQ, sni: rid(epA) + "." + testZone}, verifyName(l2), dns.TypeA)
	b3, n3, _ := decodeBody(t, w.get("GET", l2, ""))
	if b3.ProtoTag != tagOf(l2, n3, rd, []byte{1}, []byte{byte(commonv1.Protocol_PROTOCOL_DOQ)}) || b3.ClientTag != tagOf(l2, n3, rd, []byte{0}) {
		t.Fatal("DoQ tags")
	}
}

// An unknown label is HTTP 200 with seen false and random tags (so the health
// probe with a fresh label passes); a label seen without an identity has random
// tags too, two reads of it differ, and it is not seen after the LRU's 60 s.
func TestVerifyEndpointUnknownAndUnidentified(t *testing.T) {
	w := newWorld(t)
	label := newLabel(t)
	b1, _, _ := decodeBody(t, w.get("GET", label, ""))
	b2, _, _ := decodeBody(t, w.get("GET", label, ""))
	if b1.Seen || b2.Seen || b1.RIDTag == b2.RIDTag {
		t.Fatalf("unknown label: %+v %+v", b1, b2)
	}
	// Seen on a stranger's UDP query: seen true, nothing identified.
	w.call(qopt{t: listen.UDP, src: "127.0.0.3"}, verifyName(label), dns.TypeA)
	b3, n3, _ := decodeBody(t, w.get("GET", label, ""))
	if !b3.Seen {
		t.Fatal("not seen")
	}
	if b3.RIDTag == tagOf(label, n3, []byte(rid(epA))) || len(b3.RIDTag) != 32 || b3.ProtoTag == b2.ProtoTag {
		t.Fatal("tags look derived")
	}
	b4, _, _ := decodeBody(t, w.get("GET", label, ""))
	if b3.ProtoTag == b4.ProtoTag || b3.ClientTag == b4.ClientTag {
		t.Fatal("a fixed tag for an unidentified label")
	}
	// A spoofed unidentified query for an identified label does not turn it
	// unidentified.
	l2 := newLabel(t)
	w.call(qopt{t: listen.DoT, sni: rid(epB) + "." + testZone}, verifyName(l2), dns.TypeA)
	w.call(qopt{t: listen.UDP, src: "198.51.100.9"}, verifyName(l2), dns.TypeA)
	b5, n5, _ := decodeBody(t, w.get("GET", l2, ""))
	if b5.RIDTag != tagOf(l2, n5, []byte(rid(epB))) {
		t.Fatal("an unidentified query erased the identity")
	}
	// 60 seconds later it is gone.
	w.advance(61 * time.Second)
	if b6, _, _ := decodeBody(t, w.get("GET", l2, "")); b6.Seen {
		t.Fatal("seen after the LRU time")
	}
}

func TestVerifyEndpointCORSAndMethods(t *testing.T) {
	w := newWorld(t)
	label := newLabel(t)
	rec := w.get("GET", label, "https://panel.example.org")
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://panel.example.org" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%v", rec.Header())
	}
	rec = w.get("GET", label, "https://admin.example.org")
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://admin.example.org" {
		t.Fatal("admin origin")
	}
	for _, o := range []string{"https://evil.example", "http://panel.example.org", "https://panel.example.org.evil.example", "null"} {
		if rec := w.get("GET", label, o); rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("ACAO for %q", o)
		}
	}
	// A preflight is answered for the panel and refused for anyone else.
	if rec := w.get("OPTIONS", label, "https://panel.example.org"); rec.Code != 204 || rec.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("preflight: %d %v", rec.Code, rec.Header())
	}
	if rec := w.get("OPTIONS", label, "https://evil.example"); rec.Code != 405 || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign preflight: %d", rec.Code)
	}
	if rec := w.get("POST", label, "https://panel.example.org"); rec.Code != 405 {
		t.Fatalf("POST: %d", rec.Code)
	}
	// Which hosts are verify hosts.
	v := w.h.Verify()
	for sni, want := range map[string]bool{verifyName(label): true, "x." + testZone: false, testZone: false, rid(epA) + "." + testZone: false, "verify." + testZone: false, verifyName(label) + ".evil": false, "": false} {
		if v.VerifyHost(sni) != want {
			t.Errorf("VerifyHost(%q) != %v", sni, want)
		}
	}
	// The zone SNI of a request that is not a verify host is 404, never a body.
	r := httptest.NewRequest("GET", "https://x/v", nil)
	r.TLS = &tls.ConnectionState{ServerName: "x." + testZone}
	rr := httptest.NewRecorder()
	v.ServeHTTP(rr, r)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("%d", rr.Code)
	}
}

// A proof observation under exactly the conditions of 7.6 and SC 3.5, each case a
// row, and every one that is reported passes the hub's validator.
func TestProofObservationConditions(t *testing.T) {
	w := newWorld(t)
	label := newLabel(t)
	name := verifyName(label)
	ridA := identity.RIDHash(rid(epA))
	post := func() *listen.HTTPInfo { return dohInfo("/"+tok(epA), rid(epA)+"."+testZone) }
	with := func(f func(*listen.HTTPInfo)) *listen.HTTPInfo { h := post(); f(h); return h }

	type row struct {
		name string
		o    qopt
		qt   uint16
		want bool
		rid  []byte // expected rid_hash when reported
		prot commonv1.Protocol
	}
	rows := []row{
		{"udp TXT", qopt{t: listen.UDP, src: "127.0.0.3"}, dns.TypeTXT, true, nil, commonv1.Protocol_PROTOCOL_UDP},
		{"udp A", qopt{t: listen.UDP, src: "127.0.0.3"}, dns.TypeA, false, nil, 0},
		{"udp AAAA", qopt{t: listen.UDP, src: "127.0.0.3"}, dns.TypeAAAA, false, nil, 0},
		{"udp HTTPS", qopt{t: listen.UDP, src: "127.0.0.3"}, dns.TypeHTTPS, false, nil, 0},
		{"tcp TXT", qopt{t: listen.TCP, src: "127.0.0.3"}, dns.TypeTXT, true, nil, commonv1.Protocol_PROTOCOL_TCP},
		{"tcp A", qopt{t: listen.TCP, src: "127.0.0.3"}, dns.TypeA, false, nil, 0},
		{"udp TXT from a claim", qopt{t: listen.UDP, src: "127.0.0.2"}, dns.TypeTXT, true, nil, commonv1.Protocol_PROTOCOL_UDP},
		{"dot A", qopt{t: listen.DoT, sni: rid(epA) + "." + testZone}, dns.TypeA, true, ridA[:], commonv1.Protocol_PROTOCOL_DOT},
		{"dot AAAA", qopt{t: listen.DoT, sni: rid(epA) + "." + testZone}, dns.TypeAAAA, true, ridA[:], commonv1.Protocol_PROTOCOL_DOT},
		{"dot no identity", qopt{t: listen.DoT, sni: testZone}, dns.TypeA, false, nil, 0},
		{"dot malformed sni", qopt{t: listen.DoT, sni: "a.b." + testZone}, dns.TypeA, false, nil, 0},
		{"doq A", qopt{t: listen.DoQ, sni: rid(epA) + "." + testZone}, dns.TypeA, true, ridA[:], commonv1.Protocol_PROTOCOL_DOQ},
		{"doq no identity", qopt{t: listen.DoQ, sni: ""}, dns.TypeA, false, nil, 0},
		{"doh POST", qopt{t: listen.DoH, http: post()}, dns.TypeA, true, ridA[:], commonv1.Protocol_PROTOCOL_DOH},
		{"doh3 POST", qopt{t: listen.DoH3, http: post()}, dns.TypeA, true, ridA[:], commonv1.Protocol_PROTOCOL_DOH3},
		{"doh GET", qopt{t: listen.DoH, http: with(func(h *listen.HTTPInfo) { h.Method, h.ContentType = "GET", "" })}, dns.TypeA, false, nil, 0},
		{"doh3 GET", qopt{t: listen.DoH3, http: with(func(h *listen.HTTPInfo) { h.Method, h.ContentType = "GET", "" })}, dns.TypeA, false, nil, 0},
		{"doh Origin", qopt{t: listen.DoH, http: with(func(h *listen.HTTPInfo) { h.HasOrigin = true })}, dns.TypeA, false, nil, 0},
		{"doh Referer", qopt{t: listen.DoH, http: with(func(h *listen.HTTPInfo) { h.HasReferer = true })}, dns.TypeA, false, nil, 0},
		{"doh Sec-Fetch-Site", qopt{t: listen.DoH3, http: with(func(h *listen.HTTPInfo) { h.HasSecFetchSite = true })}, dns.TypeA, false, nil, 0},
		{"doh other media type", qopt{t: listen.DoH, http: with(func(h *listen.HTTPInfo) { h.ContentType = "text/plain" })}, dns.TypeA, false, nil, 0},
		{"doh media type with a parameter", qopt{t: listen.DoH, http: with(func(h *listen.HTTPInfo) { h.ContentType = "application/dns-message; charset=x" })}, dns.TypeA, true, ridA[:], commonv1.Protocol_PROTOCOL_DOH},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w.rep.reset()
			l := newLabel(t)
			rep := w.call(r.o, verifyName(l), r.qt)
			// The verify name is always answered, reported or not.
			if rep.Msg == nil || rep.Msg.Rcode != dns.RcodeSuccess {
				t.Fatalf("not answered: %+v", rep)
			}
			p, _, _ := w.rep.counts()
			if (p == 1) != r.want || p > 1 {
				t.Fatalf("reported %d, want %v", p, r.want)
			}
			if !r.want {
				return
			}
			o := w.rep.proofs[0]
			if o.Label != l || o.Protocol != r.prot || !bytes.Equal(o.RidHash, r.rid) || len(o.SourceIp) != 4 {
				t.Fatalf("%+v", o)
			}
			if err := wire.ValidateProofObservation(o, w.now().Unix()); err != nil {
				t.Fatalf("the hub's validator refuses it: %v", err)
			}
		})
	}
	_ = name
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s).Unmap() }

// A browser reuses a connection for another name of the certificate: the label in
// the request's authority must be the SNI's, or the answer is 421 so the browser
// retries on its own connection (p4n-W7-r2-5).
func TestVerifyMisdirectedAuthority(t *testing.T) {
	w := newWorld(t)
	l1, l2 := newLabel(t), newLabel(t)
	w.call(qopt{t: listen.DoT, sni: rid(epA) + "." + testZone}, verifyName(l1), dns.TypeA)
	for host, want := range map[string]int{
		verifyName(l1):            200,
		verifyName(l1) + ":443":   200,
		verifyName(l2):            421,
		verifyName(l2) + ":8443":  421,
		"www.example.com":         421,
		rid(epA) + "." + testZone: 421,
	} {
		r := httptest.NewRequest("GET", "https://"+verifyName(l1)+"/v", nil)
		r.Host = host
		r.TLS = &tls.ConnectionState{ServerName: verifyName(l1)}
		rec := httptest.NewRecorder()
		w.h.Verify().ServeHTTP(rec, r)
		if rec.Code != want {
			t.Errorf("authority %q: status %d, want %d", host, rec.Code, want)
		}
		if want == 421 && rec.Body.Len() != 0 {
			t.Errorf("authority %q: a 421 carries a body", host)
		}
	}
}

// seqLabel is a valid verify label made from a counter, for floods too large to
// draw from crypto/rand.
func seqLabel(i int) string {
	const a = "abcdefghijklmnopqrstuvwxyz234567"
	b := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaa")
	for p := len(b) - 1; i > 0 && p >= 0; p-- {
		b[p] = a[i%32]
		i /= 32
	}
	return string(b)
}

// A flood of unidentified labels cannot push an identified one out of the table
// (p4n-W7-r4-2): the page that asks GET /v a second after the device resolved
// its label still finds it.
func TestVerifyFloodCannotEvictAnIdentifiedLabel(t *testing.T) {
	w := newWorld(t)
	label := newLabel(t)
	w.call(qopt{t: listen.DoT, sni: rid(epA) + "." + testZone}, verifyName(label), dns.TypeA)
	for i := 1; i <= verifyLRUSize+2000; i++ {
		w.call(qopt{t: listen.TCP, src: "127.0.0.9"}, verifyName(seqLabel(i)), dns.TypeA)
	}
	b, n, _ := decodeBody(t, w.get("GET", label, ""))
	if !b.Seen || b.RIDTag != tagOf(label, n, []byte(rid(epA))) {
		t.Fatalf("the identified label was evicted by an unidentified flood: %+v", b)
	}
}

// One Endpoint can hold only its own quota of labels, so a tenant that makes
// labels for its own resolver id as fast as it can evicts nobody else's.
func TestVerifyPerEndpointQuota(t *testing.T) {
	v := newVerifyTable()
	now := time.Unix(1_700_000_000, 0)
	other := verifyEntry{rid: "other", identified: true, at: now}
	v.note("otherlabel", other)
	for i := 0; i < verifyLRUSize*2; i++ {
		v.note(seqLabel(i+1), verifyEntry{rid: "greedy", identified: true, at: now})
	}
	if _, ok := v.get("otherlabel", now); !ok {
		t.Fatal("another Endpoint's label was evicted")
	}
	if v.ident.Len() > verifyPerRID+1 {
		t.Fatalf("the identified table holds %d labels for two Endpoints", v.ident.Len())
	}
	// Endpoints that went quiet are forgotten.
	later := now.Add(2 * verifyTTL)
	for i := 0; i < 1024; i++ {
		v.note(seqLabel(900000+i), verifyEntry{rid: "late", identified: true, at: later})
	}
	if len(v.rings) != 1 {
		t.Fatalf("%d rings after a TTL of quiet", len(v.rings))
	}
}

// A query that 4b refuses is not an identified one: it cannot write the
// identified table, and a hard_disabled Endpoint's label reads as a stranger's.
func TestVerifyRefusedQueryIsUnidentified(t *testing.T) {
	w := newWorld(t)
	label := newLabel(t)
	w.call(qopt{t: listen.DoT, sni: rid(epE) + "." + testZone}, verifyName(label), dns.TypeA) // source outside the list
	b, n, _ := decodeBody(t, w.get("GET", label, ""))
	if !b.Seen {
		t.Fatal("not seen")
	}
	if b.RIDTag == tagOf(label, n, []byte(rid(epE))) {
		t.Fatal("a refused query was recorded as identified")
	}
}

// A repeat query of a live label keeps its Endpoint's ring young (p4n-W7-r5-5):
// prune must not drop a label that get still serves.
func TestVerifyRefreshKeepsALabelThroughPrune(t *testing.T) {
	v := newVerifyTable()
	t0 := time.Unix(1_700_000_000, 0)
	v.note("live", verifyEntry{rid: "x", identified: true, at: t0})
	v.note("live", verifyEntry{rid: "x", identified: true, at: t0.Add(55 * time.Second)})
	// An unidentified query of the same label also refreshes it.
	v.note("live2", verifyEntry{rid: "x", identified: true, at: t0})
	v.note("live2", verifyEntry{identified: false, at: t0.Add(55 * time.Second)})
	later := t0.Add(100 * time.Second)
	for i := 0; i < 1100; i++ { // another Endpoint's writes run prune
		v.note(seqLabel(i+1), verifyEntry{rid: "busy", identified: true, at: later})
	}
	for _, l := range []string{"live", "live2"} {
		if e, ok := v.get(l, later); !ok || !e.identified || e.rid != "x" {
			t.Fatalf("label %q was dropped by prune while still live: %+v %v", l, e, ok)
		}
	}
}

// A label the global LRU evicted and the Endpoint noted again is in the ring
// once, so the quota never drops the fresh entry in place of the stale one.
func TestVerifyRenotedLabelIsNotInTheRingTwice(t *testing.T) {
	v := newVerifyTable()
	now := time.Unix(1_700_000_000, 0)
	e := verifyEntry{rid: "x", identified: true, at: now}
	v.note("a", e)
	v.note("b", e)
	v.ident.Remove("a") // what the global LRU does under pressure
	v.note("a", e)
	n := 0
	for _, l := range v.rings["x"].labels {
		if l == "a" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("label held %d times in the ring", n)
	}
	for i := 0; i < verifyPerRID-1; i++ {
		v.note(seqLabel(i+1), e)
	}
	if _, ok := v.get("a", now); !ok {
		t.Fatal("the quota dropped the fresh entry of a re-noted label")
	}
}
