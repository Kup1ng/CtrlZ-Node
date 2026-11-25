package dns

// End to end: the Handler behind the W6 listeners on loopback ports 5750 to 5799,
// with a real client for every transport. Plain DNS clients bind 127.0.0.x so that
// the claims of the test image (127.0.0.<n>/32) identify them.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/cookie"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

var e2ePort atomic.Int32

func allocPorts(t testing.TB) listen.Ports {
	t.Helper()
	for try := 0; try < 64; try++ {
		n := int(e2ePort.Add(1)-1) % 16
		base := 5750 + n*3
		ok := true
		var cl []io.Closer
		for p := base; p < base+3; p++ {
			ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(p))
			l, err := net.Listen("tcp", ap.String())
			if err != nil {
				ok = false
				break
			}
			cl = append(cl, l)
			u, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
			if err != nil {
				ok = false
				break
			}
			cl = append(cl, u)
		}
		for _, c := range cl {
			_ = c.Close()
		}
		if ok {
			return listen.Ports{DNS: uint16(base), TLS: uint16(base + 1), HTTPS: uint16(base + 2)}
		}
	}
	t.Fatal("no free ports in 5750-5799")
	return listen.Ports{}
}

func e2eCert(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: testZone},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		DNSNames:    []string{testZone, "*." + testZone, "*.verify." + testZone},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

type e2e struct {
	*world
	srv   *listen.Server
	ports listen.Ports
	pool  *x509.CertPool
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	w := newWorld(t)
	cert, pool := e2eCert(t)
	jar, err := cookie.New()
	if err != nil {
		t.Fatal(err)
	}
	exm := limits.NewExemption()
	exm.SetZones([]names.Name{names.MustString(testZone)})
	set, err := limits.NewSet(limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	e := &e2e{world: w, pool: pool, ports: allocPorts(t)}
	cfg := listen.Config{
		Bind: netip.MustParseAddr("127.0.0.1"), Ports: e.ports, Handler: w.h, Limits: set, Exempt: exm, Cookies: jar,
		Verify: w.h.Verify(),
		// The certificate provider of W5b, in miniature: a resolver name of an
		// unknown rid is refused with (nil, nil), which crypto/tls turns into the
		// unrecognized_name alert of SC 3.3; everything else gets the certificate.
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			h := identity.ParseHost(hi.ServerName, w.settings.zones)
			if h.Kind == identity.HostResolver {
				if _, ok := w.img.ByResolverID(h.RID); !ok {
					return nil, nil
				}
			}
			return &cert, nil
		},
	}
	srv, err := listen.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	t.Cleanup(srv.Close)
	return e
}

func (e *e2e) addr(t listen.Transport) string {
	p := e.ports.DNS
	switch t {
	case listen.DoT, listen.DoQ:
		p = e.ports.TLS
	case listen.DoH, listen.DoH3:
		p = e.ports.HTTPS
	}
	return fmt.Sprintf("127.0.0.1:%d", p)
}

func (e *e2e) tlsConf(sni string, alpn ...string) *tls.Config {
	return &tls.Config{RootCAs: e.pool, ServerName: sni, NextProtos: alpn, MinVersion: tls.VersionTLS12}
}

func local(ip string) *net.Dialer {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if ip != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(ip)}
	}
	return d
}

// ---- clients

// framed asks over one connection and reads one reply.
func framedAsk(c net.Conn, m *dns.Msg) (*dns.Msg, error) {
	b, err := m.Pack()
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, int(lb[0])<<8|int(lb[1]))
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	return r, r.Unpack(buf)
}

func (e *e2e) udp(src string, m *dns.Msg) (*dns.Msg, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if src != "" {
		d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(src)}
	}
	c, err := d.Dial("udp", e.addr(listen.UDP))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	b, _ := m.Pack()
	_, _ = c.Write(b)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	return r, r.Unpack(buf[:n])
}

func (e *e2e) tcp(src string, m *dns.Msg) (*dns.Msg, error) {
	c, err := local(src).Dial("tcp", e.addr(listen.TCP))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return framedAsk(c, m)
}

func (e *e2e) dotConn(sni string) (*tls.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", e.addr(listen.DoT), e.tlsConf(sni))
}

func (e *e2e) dot(sni string, m *dns.Msg) (*dns.Msg, error) {
	c, err := e.dotConn(sni)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return framedAsk(c, m)
}

func (e *e2e) doqConn(sni string) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return quic.DialAddr(ctx, e.addr(listen.DoQ), e.tlsConf(sni, "doq"), &quic.Config{MaxIdleTimeout: 20 * time.Second})
}

func (e *e2e) doq(sni string, m *dns.Msg) (*dns.Msg, error) {
	conn, err := e.doqConn(sni)
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	m = m.Copy()
	m.Id = 0
	b, _ := m.Pack()
	_ = str.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := str.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
		return nil, err
	}
	_ = str.Close()
	all, err := io.ReadAll(str)
	if err != nil || len(all) < 2 {
		return nil, fmt.Errorf("doq: %v", err)
	}
	r := new(dns.Msg)
	return r, r.Unpack(all[2:])
}

// httpClient makes a DoH client (h2 or http/1.1) or a DoH3 client whose TLS name
// is sni.
func (e *e2e) httpClient(t listen.Transport, sni string, h2 bool) (*http.Client, func()) {
	switch t {
	case listen.DoH3:
		tr := &http3.Transport{TLSClientConfig: e.tlsConf(sni, "h3"), QUICConfig: &quic.Config{}}
		return &http.Client{Transport: tr, Timeout: 8 * time.Second}, func() { _ = tr.Close() }
	}
	tr := &http.Transport{DisableKeepAlives: true}
	if h2 {
		tr.TLSClientConfig = e.tlsConf(sni, "h2", "http/1.1")
		tr.ForceAttemptHTTP2 = true
	} else {
		tr.TLSClientConfig = e.tlsConf(sni, "http/1.1")
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}, tr.CloseIdleConnections
}

type dohCall struct {
	t         listen.Transport
	h2        bool
	sni       string
	path      string
	authority string
	method    string
	hdr       http.Header
}

// doh sends m and returns the HTTP status, the DNS reply (nil when the status is
// not 200) and the response headers.
func (e *e2e) doh(c dohCall, m *dns.Msg) (int, *dns.Msg, http.Header, error) {
	if c.method == "" {
		c.method = "POST"
	}
	cl, closeFn := e.httpClient(c.t, c.sni, c.h2)
	defer closeFn()
	b, _ := m.Pack()
	url := "https://" + e.addr(c.t) + c.path
	var req *http.Request
	var err error
	if c.method == "GET" {
		req, err = http.NewRequest("GET", url+"?dns="+base64.RawURLEncoding.EncodeToString(b), nil)
	} else {
		req, err = http.NewRequest(c.method, url, bytes.NewReader(b))
		if err == nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
	}
	if err != nil {
		return 0, nil, nil, err
	}
	if c.authority != "" {
		req.Host = c.authority
	}
	for k, v := range c.hdr {
		req.Header[k] = v
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil, resp.Header, nil
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	return resp.StatusCode, r, resp.Header, nil
}

func q(name string, qt uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.RecursionDesired = true
	return m
}

// as asks as Endpoint ep over every transport, returning one reply (or nil with
// an error) for each, in a fixed order.
type e2eAsk struct {
	name string
	ask  func(e *e2e, ep byte, m *dns.Msg) (*dns.Msg, error)
}

func e2eAskers() []e2eAsk {
	h := func(t listen.Transport, h2 bool, form string) func(e *e2e, ep byte, m *dns.Msg) (*dns.Msg, error) {
		return func(e *e2e, ep byte, m *dns.Msg) (*dns.Msg, error) {
			c := dohCall{t: t, h2: h2, sni: "x." + testZone, path: "/" + tok(ep), authority: rid(ep) + "." + testZone}
			if form == "B" {
				c.path, c.authority = "/"+rid(ep)+"/"+tok(ep), testZone
			}
			st, r, _, err := e.doh(c, m)
			if err == nil && st != 200 {
				err = fmt.Errorf("http %d", st)
			}
			return r, err
		}
	}
	return []e2eAsk{
		{"tcp", func(e *e2e, ep byte, m *dns.Msg) (*dns.Msg, error) { return e.tcp("127.0.0."+itoa(int(ep)), m) }},
		{"udp-cookie", func(e *e2e, ep byte, m *dns.Msg) (*dns.Msg, error) { return e.udpCookie("127.0.0."+itoa(int(ep)), m) }},
		{"dot", func(e *e2e, ep byte, m *dns.Msg) (*dns.Msg, error) { return e.dot(rid(ep)+"."+testZone, m) }},
		{"doq", func(e *e2e, ep byte, m *dns.Msg) (*dns.Msg, error) { return e.doq(rid(ep)+"."+testZone, m) }},
		{"doh-h2", h(listen.DoH, true, "A")},
		{"doh-http1", h(listen.DoH, false, "B")},
		{"doh3", h(listen.DoH3, true, "A")},
	}
}

// udpCookie is how a Plain DNS client that supports cookies (RFC 7873) gets
// validated: its first query carries a client cookie only, the reply carries the
// server's, and the second query returns both.
func (e *e2e) udpCookie(src string, m *dns.Msg) (*dns.Msg, error) {
	client := "0102030405060708"
	first := m.Copy()
	first.SetEdns0(1232, false)
	first.IsEdns0().Option = append(first.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: client})
	r, err := e.udp(src, first)
	if err != nil {
		return nil, err
	}
	var server string
	if opt := r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if c, ok := o.(*dns.EDNS0_COOKIE); ok {
				server = c.Cookie
			}
		}
	}
	if server == "" {
		return nil, errors.New("no server cookie")
	}
	second := m.Copy()
	second.SetEdns0(1232, false)
	second.IsEdns0().Option = append(second.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: server})
	return e.udp(src, second)
}

// ---- tests

func TestE2EIdentifiedPolicyOnEveryTransport(t *testing.T) {
	e := newE2E(t)
	for _, a := range e2eAskers() {
		t.Run(a.name, func(t *testing.T) {
			r, err := a.ask(e, epA, q("www.example.com", dns.TypeA))
			if err != nil {
				t.Fatalf("A: %v", err)
			}
			if got := aAddrs(r); len(got) != 1 || got[0] != "0.0.0.0" {
				t.Fatalf("A blocked: %v", got)
			}
			r, err = a.ask(e, epB, q("www.example.com", dns.TypeA))
			if err != nil {
				t.Fatalf("B: %v", err)
			}
			if got := aAddrs(r); len(got) != 1 || got[0] != "192.0.2.20" {
				t.Fatalf("B bypass: %v", got)
			}
			// The system name, with Default Block, is true.
			r, err = a.ask(e, epA, q("panel.example.org", dns.TypeA))
			if err != nil || len(aAddrs(r)) != 1 || aAddrs(r)[0] != "192.0.2.77" {
				t.Fatalf("panel hostname: %v %v", r, err)
			}
			// myip answers the source address for A (Expose IP).
			r, err = a.ask(e, epA, q("myip."+testZone, dns.TypeA))
			if err != nil || len(aAddrs(r)) != 1 || aAddrs(r)[0] != "127.0.0.1" {
				if a.name == "tcp" || a.name == "udp-cookie" {
					// A's claim is 127.0.0.1 too, so the source is the claim address.
					t.Fatalf("myip: %v %v", r, err)
				}
				t.Fatalf("myip: %v %v", r, err)
			}
		})
	}
}

func TestE2EDisabledStatesOnEveryTransport(t *testing.T) {
	e := newE2E(t)
	// hard_disabled (C).
	// Plain: no reply at all (a silent drop), the connection stays.
	c, err := local("127.0.0.4").Dial("tcp", e.addr(listen.TCP))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := framedAsk(c, q("www.example.com", dns.TypeA)); err == nil || !isTimeout(err) {
		t.Fatalf("hard_disabled TCP got a reply or an unexpected error: %v", err)
	}
	if _, err := e.udp("127.0.0.4", q("www.example.com", dns.TypeA)); err == nil {
		t.Fatal("hard_disabled UDP answered")
	}
	// DoT and DoQ: REFUSED.
	if r, err := e.dot(rid(epC)+"."+testZone, q("www.example.com", dns.TypeA)); err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("dot: %v %v", r, err)
	}
	if r, err := e.doq(rid(epC)+"."+testZone, q("www.example.com", dns.TypeA)); err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("doq: %v %v", r, err)
	}
	// DoH and DoH3: HTTP 403, whatever the method.
	for _, c := range []dohCall{
		{t: listen.DoH, h2: true, sni: "x." + testZone, path: "/" + tok(epC), authority: rid(epC) + "." + testZone},
		{t: listen.DoH, h2: false, sni: "x." + testZone, path: "/" + tok(epC), authority: rid(epC) + "." + testZone, method: "GET"},
		{t: listen.DoH3, sni: "x." + testZone, path: "/" + tok(epC), authority: rid(epC) + "." + testZone},
	} {
		st, r, _, err := e.doh(c, q("www.example.com", dns.TypeA))
		if err != nil || st != 403 || r != nil {
			t.Fatalf("%v: %d %v", c.t, st, err)
		}
	}
	if e.h.Counters().HardDisabled < 7 {
		t.Fatalf("counter %d", e.h.Counters().HardDisabled)
	}

	// soft_disabled (D): the true answer, on every transport.
	for _, a := range e2eAskers() {
		r, err := a.ask(e, epD, q("www.example.com", dns.TypeA))
		if err != nil || len(aAddrs(r)) != 1 || aAddrs(r)[0] != "192.0.2.20" {
			t.Errorf("soft_disabled %s: %v %v", a.name, r, err)
		}
	}
}

func TestE2EUnidentified(t *testing.T) {
	e := newE2E(t)
	// A resolver name with an unknown rid is refused at the handshake on every
	// encrypted transport (SC 3.3, R7), with the unrecognized_name alert.
	unknown := rid(20) + "." + testZone
	if _, err := e.dotConn(unknown); err == nil || !strings.Contains(err.Error(), "unrecognized name") {
		t.Fatalf("dot: %v", err)
	}
	if _, err := e.doqConn(unknown); err == nil || !strings.Contains(err.Error(), "unrecognized name") {
		t.Fatalf("doq: %v", err)
	}
	cl, closeFn := e.httpClient(listen.DoH, unknown, true)
	if _, err := cl.Get("https://" + e.addr(listen.DoH) + "/"); err == nil {
		t.Fatal("doh handshake with an unknown rid")
	}
	closeFn()
	// The apex SNI completes the handshake, has no identity, and the zone answers
	// while everything else is REFUSED.
	r, err := e.dot(testZone, q("www.example.com", dns.TypeA))
	if err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("dot apex: %v %v", r, err)
	}
	r, err = e.dot(testZone, q(rid(20)+"."+testZone, dns.TypeA))
	if err != nil || len(aAddrs(r)) != 1 || aAddrs(r)[0] != "8.8.8.8" {
		t.Fatalf("zone answer on a connection with no identity: %v %v", r, err)
	}
	r, err = e.doq(testZone, q("www.example.com", dns.TypeA))
	if err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("doq apex: %v %v", r, err)
	}
	// DoH: 404 for a path or authority that names nobody, on both transports.
	for _, tr := range []listen.Transport{listen.DoH, listen.DoH3} {
		for _, c := range []dohCall{
			{t: tr, h2: true, sni: "x." + testZone, path: "/" + tok(21), authority: rid(epA) + "." + testZone},
			{t: tr, h2: true, sni: "x." + testZone, path: "/" + tok(epA), authority: testZone},
			{t: tr, h2: true, sni: "x." + testZone, path: "/nothing", authority: rid(epA) + "." + testZone},
		} {
			st, _, _, err := e.doh(c, q("www.example.com", dns.TypeA))
			if err != nil || st != 404 {
				t.Fatalf("%v: %d %v", tr, st, err)
			}
		}
	}
	// Plain DNS from a stranger: REFUSED, over UDP and TCP.
	for _, f := range []func() (*dns.Msg, error){
		func() (*dns.Msg, error) { return e.tcp("127.0.0.3", q("www.example.com", dns.TypeA)) },
		func() (*dns.Msg, error) { return e.udp("127.0.0.3", q("www.example.com", dns.TypeA)) },
	} {
		if r, err := f(); err != nil || r.Rcode != dns.RcodeRefused {
			t.Fatalf("stranger: %v %v", r, err)
		}
	}
}

// Plain UDP of a claim: TC=1 first, TCP validates, then UDP is answered.
func TestE2EPlainUDPClaimRule(t *testing.T) {
	e := newE2E(t)
	r, err := e.udp("127.0.0.2", q("www.example.com", dns.TypeA))
	if err != nil || !r.Truncated || len(r.Answer) != 0 {
		t.Fatalf("first UDP: %v %v", r, err)
	}
	if r, err := e.tcp("127.0.0.2", q("www.example.com", dns.TypeA)); err != nil || len(aAddrs(r)) != 1 {
		t.Fatalf("tcp: %v %v", r, err)
	}
	if r, err := e.udp("127.0.0.2", q("www.example.com", dns.TypeA)); err != nil || r.Truncated || aAddrs(r)[0] != "192.0.2.20" {
		t.Fatalf("udp after tcp: %v %v", r, err)
	}
}

func TestE2ERequireAuthorizedIPs(t *testing.T) {
	e := newE2E(t)
	if r, err := e.dot(rid(epE)+"."+testZone, q("www.example.com", dns.TypeA)); err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("dot: %v %v", r, err)
	}
	c := dohCall{t: listen.DoH, h2: true, sni: "x." + testZone, path: "/" + tok(epE), authority: rid(epE) + "." + testZone}
	if st, _, _, err := e.doh(c, q("www.example.com", dns.TypeA)); err != nil || st != 403 {
		t.Fatalf("doh: %d %v", st, err)
	}
	// The DoH refusal is the roaming case: reported as a learned address.
	if _, l, _ := e.rep.counts(); l != 1 {
		t.Fatalf("learned %d", l)
	}
	// F's list holds loopback.
	if r, err := e.dot(rid(epF)+"."+testZone, q("www.example.com", dns.TypeA)); err != nil || aAddrs(r)[0] != "0.0.0.0" {
		t.Fatalf("F: %v %v", r, err)
	}
}

// Verify over the wire: the A query over each transport, then GET /v on a verify
// SNI over DoH and DoH3, with CORS for the panel only and no-store (T-046).
func TestE2EVerifyPage(t *testing.T) {
	e := newE2E(t)
	for _, tr := range []struct {
		name string
		t    listen.Transport
		h2   bool
	}{{"doh-h2", listen.DoH, true}, {"doh-http1", listen.DoH, false}, {"doh3", listen.DoH3, true}} {
		t.Run(tr.name, func(t *testing.T) {
			label := newLabel(t)
			// The resolver of the visitor asks over DoT for the label.
			r, err := e.dot(rid(epA)+"-pc."+testZone, q(verifyName(label), dns.TypeA))
			if err != nil || len(aAddrs(r)) != 1 || aAddrs(r)[0] != selfDNSIP {
				t.Fatalf("verify A: %v %v", r, err)
			}
			get := func(origin, method string) (*http.Response, []byte) {
				cl, closeFn := e.httpClient(tr.t, verifyName(label), tr.h2)
				defer closeFn()
				req, _ := http.NewRequest(method, "https://"+e.addr(tr.t)+"/v", nil)
				req.Host = verifyName(label)
				if origin != "" {
					req.Header.Set("Origin", origin)
				}
				resp, err := cl.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				return resp, b
			}
			resp, body := get("https://panel.example.org", "GET")
			if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "https://panel.example.org" || resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("%d %v", resp.StatusCode, resp.Header)
			}
			if !strings.Contains(string(body), `"seen":true`) || !strings.Contains(string(body), `"rid_tag"`) {
				t.Fatalf("%s", body)
			}
			if resp, _ := get("https://evil.example", "GET"); resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("ACAO for a foreign origin")
			}
			// OPTIONS on the verify host for the panel is a preflight; for anyone
			// else it is 405.
			if resp, _ := get("https://evil.example", "OPTIONS"); resp.StatusCode != 405 {
				t.Fatalf("OPTIONS %d", resp.StatusCode)
			}
			// OPTIONS on /dns-query, on any host, is 405 with no CORS header.
			cl, closeFn := e.httpClient(tr.t, "x."+testZone, tr.h2)
			defer closeFn()
			req, _ := http.NewRequest("OPTIONS", "https://"+e.addr(tr.t)+"/dns-query", nil)
			req.Header.Set("Origin", "https://panel.example.org")
			resp2, err := cl.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp2.Body.Close()
			if resp2.StatusCode != 405 || resp2.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("OPTIONS /dns-query: %d %v", resp2.StatusCode, resp2.Header)
			}
		})
	}
}

// The proof over UDP and the observation it makes, on the wire.
func TestE2EProofOverUDP(t *testing.T) {
	e := newE2E(t)
	label := newLabel(t)
	r, err := e.udp("127.0.0.3", q(verifyName(label), dns.TypeTXT))
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("%v %v", r, err)
	}
	want := identity.ProofCode(e.proof, label, netip.MustParseAddr("127.0.0.3"))
	if r.Answer[0].(*dns.TXT).Txt[0] != want {
		t.Fatal("proof code")
	}
	if p, _, _ := e.rep.counts(); p != 1 {
		t.Fatalf("proofs %d", p)
	}
}

// A panic in the query path answers SERVFAIL, the process lives, and the
// connection serves the next query (T-549).
func TestE2EPanicInTheQueryPath(t *testing.T) {
	e := newE2E(t)
	e.h.cfg.Resolver = panicResolver{}
	c, err := e.dotConn(rid(epB) + "." + testZone)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := framedAsk(c, q("www.example.com", dns.TypeA))
	if err != nil || r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("%v %v", r, err)
	}
	// The same connection answers a query that needs no resolver.
	r, err = framedAsk(c, q(rid(epB)+"."+testZone, dns.TypeA))
	if err != nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("%v %v", r, err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type panicResolver struct{}

func (panicResolver) Lookup(context.Context, names.Name, uint16, sharedpolicy.ResolveParams) (*sharedpolicy.TrueAnswer, error) {
	panic("resolver panic")
}
