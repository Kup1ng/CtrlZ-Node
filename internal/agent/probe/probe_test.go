package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

const zoneName = "dns.test"

type pki struct {
	caPEM   *x509.CertPool
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	counter int64
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test zone CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &pki{caPEM: pool, caCert: cert, caKey: key}
}

func (p *pki) leaf(t *testing.T, notAfter time.Time, sans ...string) tls.Certificate {
	t.Helper()
	p.counter++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(100 + p.counter), Subject: pkix.Name{CommonName: sans[0]},
		DNSNames: sans, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (p *pki) good(t *testing.T) tls.Certificate {
	return p.leaf(t, time.Now().Add(time.Hour), zoneName, "*."+zoneName, "*.verify."+zoneName)
}

// soaReply is a correct answer to the probe's question.
func soaReply(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.Authoritative = true
	m.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 30},
		Ns: "ns1." + dns.Fqdn(zoneName), Mbox: "hostmaster." + dns.Fqdn(zoneName), Serial: 7, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 30}}
	return m
}

// node is a fake probe target: a DoT server and a DoH server.
type node struct {
	dotPort, dohPort int
	dotMutate        func(query, resp *dns.Msg) []byte // nil keeps the correct answer
	dohHandler       http.HandlerFunc
	cert             tls.Certificate
	lns              []net.Listener
	srv              *http.Server
}

func listenInRange(t *testing.T) (net.Listener, int) {
	t.Helper()
	for p := 5610; p < 5699; p++ {
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			return l, p
		}
	}
	t.Skip("no free port in the lane's range")
	return nil, 0
}

const goodBody = `{"seen":false,"n":"00112233445566778899aabbccddeeff","rid_tag":"00112233445566778899aabbccddeeff","client_tag":"00112233445566778899aabbccddeeff","proto_tag":"00112233445566778899aabbccddeeff"}`

func startNode(t *testing.T, cert tls.Certificate) *node {
	t.Helper()
	n := &node{cert: cert}
	n.dohHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, goodBody)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	dotL, dotPort := listenInRange(t)
	dohL, dohPort := listenInRange(t)
	n.dotPort, n.dohPort = dotPort, dohPort
	n.lns = []net.Listener{dotL, dohL}
	go func() {
		for {
			c, err := dotL.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := tls.Server(c, cfg)
				_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
				if tc.Handshake() != nil {
					return
				}
				var lb [2]byte
				if _, err := io.ReadFull(tc, lb[:]); err != nil {
					return
				}
				buf := make([]byte, int(lb[0])<<8|int(lb[1]))
				if _, err := io.ReadFull(tc, buf); err != nil {
					return
				}
				q := new(dns.Msg)
				if q.Unpack(buf) != nil {
					return
				}
				resp := soaReply(q)
				var out []byte
				if n.dotMutate != nil {
					out = n.dotMutate(q, resp)
				}
				if out == nil {
					out, _ = resp.Pack()
				}
				_, _ = tc.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...))
			}()
		}
	}()
	n.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.dohHandler(w, r) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = n.srv.Serve(tls.NewListener(dohL, n.srv.TLSConfig)) }()
	t.Cleanup(func() {
		for _, l := range n.lns {
			l.Close()
		}
		n.srv.Close()
	})
	return n
}

func prober(p *pki, n *node, mut ...func(*Config)) *Prober {
	cfg := Config{
		Zone:    func() string { return zoneName },
		Roots:   func() *x509.CertPool { return p.caPEM },
		DoTPort: n.dotPort, DoHPort: n.dohPort,
		Timeout: 2 * time.Second,
	}
	for _, m := range mut {
		m(&cfg)
	}
	return New(cfg)
}

var loop = netip.MustParseAddr("127.0.0.1")

func TestHealthyNodePasses(t *testing.T) {
	p := newPKI(t)
	n := startNode(t, p.good(t))
	if !prober(p, n).Probe(context.Background(), loop) {
		t.Fatal("a healthy node fails the probe")
	}
	// `seen` is not read: true passes too
	n.dohHandler = func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Replace(goodBody, `"seen":false`, `"seen":true`, 1))
	}
	if !prober(p, n).Probe(context.Background(), loop) {
		t.Error("seen=true failed the probe")
	}
}

func TestDoTFailures(t *testing.T) {
	for name, mutate := range map[string]func(q, r *dns.Msg) []byte{
		"AA=0":     func(q, r *dns.Msg) []byte { r.Authoritative = false; b, _ := r.Pack(); return b },
		"wrong ID": func(q, r *dns.Msg) []byte { r.Id ^= 1; b, _ := r.Pack(); return b },
		"SERVFAIL": func(q, r *dns.Msg) []byte { r.Rcode = dns.RcodeServerFailure; b, _ := r.Pack(); return b },
		"question case": func(q, r *dns.Msg) []byte {
			r.Question[0].Name = strings.ToUpper(r.Question[0].Name)
			r.Answer[0].Header().Name = r.Question[0].Name
			b, _ := r.Pack()
			return b
		},
		"other question": func(q, r *dns.Msg) []byte {
			r.Question[0].Name = "other.dns.test."
			b, _ := r.Pack()
			return b
		},
		"wrong MNAME": func(q, r *dns.Msg) []byte { r.Answer[0].(*dns.SOA).Ns = "ns.invalid."; b, _ := r.Pack(); return b },
		"wrong RNAME": func(q, r *dns.Msg) []byte { r.Answer[0].(*dns.SOA).Mbox = "x.invalid."; b, _ := r.Pack(); return b },
		"two SOAs": func(q, r *dns.Msg) []byte {
			r.Answer = append(r.Answer, dns.Copy(r.Answer[0]))
			b, _ := r.Pack()
			return b
		},
		"no answer": func(q, r *dns.Msg) []byte { r.Answer = nil; b, _ := r.Pack(); return b },
		"not an SOA": func(q, r *dns.Msg) []byte {
			r.Answer = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.dns.test."}}
			b, _ := r.Pack()
			return b
		},
		"owner not apex": func(q, r *dns.Msg) []byte { r.Answer[0].Header().Name = "x.dns.test."; b, _ := r.Pack(); return b },
		"garbage":        func(q, r *dns.Msg) []byte { return []byte{1, 2, 3} },
		"not a reply":    func(q, r *dns.Msg) []byte { r.Response = false; b, _ := r.Pack(); return b },
	} {
		t.Run(name, func(t *testing.T) {
			p := newPKI(t)
			n := startNode(t, p.good(t))
			n.dotMutate = mutate
			if prober(p, n).Probe(context.Background(), loop) {
				t.Error("passed")
			}
		})
	}
}

func TestDoHFailures(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"500":           func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"404":           func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"redirect":      func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://elsewhere.example/v", 302) },
		"not json":      func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello") },
		"missing field": func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"seen":true}`) },
		"short tag": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.Replace(goodBody, "00112233445566778899aabbccddeeff", "00", 1))
		},
		"non-hex n": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.Replace(goodBody, "00112233445566778899aabbccddeeff", strings.Repeat("z", 32), 1))
		},
		"seen not bool": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.Replace(goodBody, `"seen":false`, `"seen":"no"`, 1))
		},
		"huge body": func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, goodBody[:len(goodBody)-1]+strings.Repeat(" ", 8000)+"}")
		},
		"slow": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPKI(t)
			n := startNode(t, p.good(t))
			n.dohHandler = h
			start := time.Now()
			if prober(p, n, func(c *Config) { c.Timeout = 600 * time.Millisecond }).Probe(context.Background(), loop) {
				t.Error("passed")
			}
			if time.Since(start) > 3*time.Second {
				t.Errorf("took %v: the timeout does not bound the probe", time.Since(start))
			}
		})
	}
}

// The probes check the chain and the exact name, as a client does.
func TestCertificateChecks(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t) // a different CA
	cases := map[string]struct {
		cert  tls.Certificate
		roots func() *x509.CertPool
	}{
		"wrong CA":        {other.good(t), nil},
		"wrong name":      {p.leaf(t, time.Now().Add(time.Hour), "other.example", "*.other.example"), nil},
		"no verify names": {p.leaf(t, time.Now().Add(time.Hour), "ns1."+zoneName), nil},
		"expired":         {p.leaf(t, time.Now().Add(-time.Minute), zoneName, "*."+zoneName, "*.verify."+zoneName), nil},
		"self-signed": {func() tls.Certificate {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), DNSNames: []string{"ns1." + zoneName, "*.verify." + zoneName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		}(), nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := startNode(t, c.cert)
			if prober(p, n).Probe(context.Background(), loop) {
				t.Error("a bad certificate passed")
			}
			// each part alone fails too
			pr := prober(p, n)
			// each part alone fails too, except that a certificate for the DoT name alone is
			// right for the DoT part
			if name != "no verify names" && pr.dot(context.Background(), loop, zoneName) == nil {
				t.Error("the DoT part passed")
			}
			if pr.doh(context.Background(), loop, zoneName) == nil {
				t.Error("the DoH part passed")
			}
		})
	}
	// With no roots configured the system pool is used, which holds no test CA.
	n := startNode(t, p.good(t))
	if prober(p, n, func(c *Config) { c.Roots = nil }).Probe(context.Background(), loop) {
		t.Error("the system roots trusted a test CA")
	}
	// A dead address fails inside the timeout.
	start := time.Now()
	dead := New(Config{Zone: func() string { return zoneName }, Roots: func() *x509.CertPool { return p.caPEM }, DoTPort: 1, DoHPort: 1, Timeout: 500 * time.Millisecond})
	if dead.Probe(context.Background(), loop) || time.Since(start) > 3*time.Second {
		t.Error("dead address")
	}
}

func TestLabels(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200000; i++ {
		l, err := Label()
		if err != nil || len(l) != LabelLen {
			t.Fatal(l, err)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
				t.Fatalf("label %q holds %q", l, c)
			}
		}
		if seen[l] {
			t.Fatalf("label repeated after %d draws", i)
		}
		seen[l] = true
	}
}

func TestParseVerify(t *testing.T) {
	if err := ParseVerify([]byte(goodBody)); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(goodBody), &m)
	if _, err := hex.DecodeString(m["n"].(string)); err != nil {
		t.Fatal(err)
	}
}

// Probe state follows the contract: unknown at first, three rounds in a row to
// change, the peer view says known and down, and a node that leaves is forgotten.
func TestStatesAndPeerView(t *testing.T) {
	p := newPKI(t)
	n := startNode(t, p.good(t))
	var mu sync.Mutex
	clk := time.Unix(1_000_000, 0)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clk }
	adv := func(d time.Duration) { mu.Lock(); clk = clk.Add(d); mu.Unlock() }
	pr := prober(p, n, func(c *Config) { c.Now = now })
	id1, id2 := zone.NodeID{1}, zone.NodeID{2}
	pr.SetTargets([]Target{{id1, loop}})
	view := func() map[zone.NodeID][2]bool {
		out := map[zone.NodeID][2]bool{}
		for _, v := range pr.PeerView() {
			var id zone.NodeID
			copy(id[:], v.NodeId)
			out[id] = [2]bool{v.Known, v.Down}
		}
		return out
	}
	if v := view(); v[id1] != [2]bool{false, false} {
		t.Fatalf("a new target must be unknown: %v", v)
	}
	ctx := context.Background()
	pr.Round(ctx)
	adv(5 * time.Second)
	pr.Round(ctx)
	if v := view(); v[id1][0] {
		t.Fatal("two rounds make no state")
	}
	adv(5 * time.Second)
	pr.Round(ctx)
	if v := view(); v[id1] != [2]bool{true, false} {
		t.Fatalf("three passes: %v", v)
	}
	// the node dies
	n.dotMutate = func(q, r *dns.Msg) []byte { r.Rcode = dns.RcodeServerFailure; b, _ := r.Pack(); return b }
	adv(5 * time.Second)
	pr.Round(ctx)
	if v := view(); v[id1] != [2]bool{true, false} {
		t.Fatalf("one failed round changes nothing: %v", v)
	}
	adv(5 * time.Second)
	pr.Round(ctx)
	adv(5 * time.Second)
	pr.Round(ctx)
	if v := view(); v[id1] != [2]bool{true, true} {
		t.Fatalf("three failed rounds: %v", v)
	}
	// a stalled prober never keeps a stale state: unknown after 15 s with no round
	adv(16 * time.Second)
	if v := view(); v[id1][0] {
		t.Fatalf("stale state kept: %v", v)
	}
	// PeerDown follows 90 s of failures without a break
	for i := 0; i < 20; i++ {
		adv(5 * time.Second)
		pr.Round(ctx)
	}
	if !pr.PeerDown()[id1] {
		t.Error("90 s of failed rounds did not set PeerDown")
	}
	// targets change: the old one is forgotten, the new one is unknown
	pr.SetTargets([]Target{{id2, loop}})
	if v := view(); len(v) != 1 || v[id2] != [2]bool{false, false} {
		t.Fatalf("after SetTargets: %v", v)
	}
	if pr.PeerDown()[id1] {
		t.Error("a node that left the table is still down")
	}
}

// p4n-W5b-r3-3: a node that knows no live zone yet has probed nothing, so its
// rounds record nothing: the peers stay unknown rather than failing.
func TestRoundWithNoZoneRecordsNothing(t *testing.T) {
	p := newPKI(t)
	n := startNode(t, p.good(t))
	var mu sync.Mutex
	clk := time.Unix(1_000_000, 0)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clk }
	adv := func(d time.Duration) { mu.Lock(); clk = clk.Add(d); mu.Unlock() }
	pr := prober(p, n, func(c *Config) { c.Now = now; c.Zone = func() string { return "" } })
	id := zone.NodeID{1}
	pr.SetTargets([]Target{{id, loop}})
	for i := 0; i < 30; i++ { // 150 s: past the 3 rounds and the 90 s of PeerDown
		pr.Round(context.Background())
		adv(5 * time.Second)
	}
	for _, v := range pr.PeerView() {
		if v.Known || v.Down {
			t.Fatalf("a round with no zone left a state: %v", v)
		}
	}
	if pr.PeerDown()[id] {
		t.Fatal("a round with no zone marked the peer down")
	}
}
