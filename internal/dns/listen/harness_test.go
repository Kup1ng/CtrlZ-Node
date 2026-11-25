package listen

// Test harness: a server on loopback ports 5500 to 5599 (the range of this
// lane), real clients for every transport (miekg/dns wire format on UDP, TCP
// and DoT, net/http for DoH over HTTP/1.1 and HTTP/2, quic-go http3 and a DoQ
// client), and counters for what the listeners tell the Observer.

import (
	"bufio"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/cookie"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const (
	portLo   = 5500
	testSNI  = "dns.test"
	zoneName = "dns.test"
)

var portNext atomic.Int32

// allocPorts finds three ports free for TCP and UDP on bind, in the lane's
// range. DoT and DoQ share the middle one, DoH and DoH3 the last, as 853 and
// 443 are shared in production.
func allocPorts(t testing.TB, bind netip.Addr) Ports {
	t.Helper()
	for try := 0; try < 64; try++ {
		n := int(portNext.Add(1)-1) % 32
		base := portLo + n*3
		ok := true
		var closers []io.Closer
		for p := base; p < base+3; p++ {
			ap := netip.AddrPortFrom(bind, uint16(p))
			l, err := net.Listen("tcp", ap.String())
			if err != nil {
				ok = false
				break
			}
			closers = append(closers, l)
			u, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
			if err != nil {
				ok = false
				break
			}
			closers = append(closers, u)
		}
		for _, c := range closers {
			_ = c.Close()
		}
		if ok {
			return Ports{DNS: uint16(base), TLS: uint16(base + 1), HTTPS: uint16(base + 2)}
		}
	}
	t.Fatal("no free ports in 5500-5599")
	return Ports{}
}

// testCert makes a self-signed certificate for the test names and loopback
// addresses, and a pool that trusts it. The key lives in memory only.
func testCert(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testSNI},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{testSNI, "*." + testSNI, "*.verify." + testSNI},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
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

// observed counts what a server's Observer reports.
type observed struct {
	mu      sync.Mutex
	closed  map[string]int // "transport/reason"
	refused map[Transport]int
	stopped map[Transport]int
	panics  map[Transport]int
	dropped map[Transport]int
}

func newObserved() *observed {
	return &observed{closed: map[string]int{}, refused: map[Transport]int{}, stopped: map[Transport]int{}, panics: map[Transport]int{}, dropped: map[Transport]int{}}
}

func reasonName(r CloseReason) string {
	switch r {
	case CloseIdle:
		return "idle"
	case CloseStall:
		return "stall"
	case CloseProtocol:
		return "protocol"
	case CloseHandshake:
		return "handshake"
	case ClosePeer:
		return "peer"
	case CloseShutdown:
		return "shutdown"
	case CloseHTTP:
		return "http"
	case CloseDrain:
		return "drain"
	}
	return "?"
}

func (o *observed) observer() Observer {
	return Observer{
		Closed: func(t Transport, why CloseReason) {
			o.mu.Lock()
			o.closed[t.String()+"/"+reasonName(why)]++
			o.mu.Unlock()
		},
		Refused: func(t Transport) { o.mu.Lock(); o.refused[t]++; o.mu.Unlock() },
		Stopped: func(t Transport) { o.mu.Lock(); o.stopped[t]++; o.mu.Unlock() },
		Panic:   func(t Transport) { o.mu.Lock(); o.panics[t]++; o.mu.Unlock() },
		Dropped: func(t Transport) { o.mu.Lock(); o.dropped[t]++; o.mu.Unlock() },
	}
}

func (o *observed) closedCount(t Transport, why CloseReason) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed[t.String()+"/"+reasonName(why)]
}

// closedExcept counts closes of t whose reason is not one of the listed ones.
func (o *observed) closedOtherThan(t Transport, ok ...CloseReason) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for k, v := range o.closed {
		if !strings.HasPrefix(k, t.String()+"/") {
			continue
		}
		skip := false
		for _, r := range ok {
			if k == t.String()+"/"+reasonName(r) {
				skip = true
			}
		}
		if !skip {
			n += v
		}
	}
	return n
}

// fixture is one running server and what a test needs to reach it.
type fixture struct {
	t     *testing.T
	srv   *Server
	cfg   Config
	bind  netip.Addr
	ports Ports
	stub  *Stub
	obs   *observed
	pool  *x509.CertPool
	jar   *cookie.Jar
	set   *limits.Set
	exm   *limits.Exemption
	certs atomic.Int32
	hello atomic.Int32 // TLS client hellos that asked for a certificate
}

type fixOpt func(*fixture)

func withRegistry(r limits.Registry) fixOpt {
	return func(f *fixture) {
		s, err := limits.NewSet(r)
		if err != nil {
			f.t.Fatal(err)
		}
		f.set = s
	}
}

func withSettings(mut func(s *limits.ListenerSettings)) fixOpt {
	return func(f *fixture) {
		ls := limits.CloneSettings(limits.Listeners())
		for i := range ls {
			mut(&ls[i])
		}
		f.cfg.Settings = ls
	}
}

func withTransports(ts ...Transport) fixOpt { return func(f *fixture) { f.cfg.Transports = ts } }
func withBind(a string) fixOpt              { return func(f *fixture) { f.bind = netip.MustParseAddr(a) } }
func withVerify(v VerifyHandler) fixOpt     { return func(f *fixture) { f.cfg.Verify = v } }
func withForceRetry() fixOpt                { return func(f *fixture) { f.cfg.ForceRetry = true } }
func withHandler(h Handler) fixOpt          { return func(f *fixture) { f.cfg.Handler = h } }

func newFixture(t *testing.T, opts ...fixOpt) *fixture {
	t.Helper()
	cert, pool := testCert(t)
	f := &fixture{t: t, pool: pool, stub: NewStub(), obs: newObserved(), bind: netip.MustParseAddr("127.0.0.1")}
	jar, err := cookie.New()
	if err != nil {
		t.Fatal(err)
	}
	f.jar = jar
	f.exm = limits.NewExemption()
	f.exm.SetZones([]names.Name{names.MustString(zoneName)})
	set, err := limits.NewSet(limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	f.set = set
	f.cfg = Config{
		Handler:  f.stub,
		Exempt:   f.exm,
		Cookies:  jar,
		Observer: f.obs.observer(),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			f.hello.Add(1)
			return &cert, nil
		},
	}
	for _, o := range opts {
		o(f)
	}
	f.cfg.Bind = f.bind
	f.cfg.Limits = f.set
	f.ports = allocPorts(t, f.bind)
	f.cfg.Ports = f.ports
	srv, err := Start(context.Background(), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	t.Cleanup(srv.Close)
	return f
}

func (f *fixture) addr(t Transport) string {
	ap := netip.AddrPortFrom(f.bind, f.ports.of(t))
	return ap.String()
}

func (f *fixture) tlsConf(sni string, alpn ...string) *tls.Config {
	if sni == "" {
		sni = testSNI
	}
	return &tls.Config{RootCAs: f.pool, ServerName: sni, NextProtos: alpn, MinVersion: tls.VersionTLS12}
}

// rid is a well-formed resolver name of the test zone; the name-form exemption
// treats every such name alike.
func rid(i int) string {
	const a = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, 26)
	for k := range b {
		b[k] = a[(i+k*7)%32]
	}
	return string(b) + "." + zoneName + "."
}

// exemptNames are queries L13 keeps out of every limit.
func exemptQueries() []*dns.Msg {
	return []*dns.Msg{
		mkq(rid(1), dns.TypeA),
		mkq(rid(2), dns.TypeAAAA),
		mkq(zoneName+".", dns.TypeNS),
		mkq("ns1."+zoneName+".", dns.TypeA),
	}
}

func mkq(name string, qt uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	return m
}

// qclient is one connection (or, for UDP, one source) of any transport.
type qclient interface {
	// exchange sends a query and returns the reply. It is safe for concurrent
	// use, so a test can pipeline.
	exchange(m *dns.Msg) (*dns.Msg, error)
	close()
}

func (f *fixture) dial(t Transport) (qclient, error) {
	switch t {
	case UDP:
		return &udpClient{addr: f.addr(UDP)}, nil
	case TCP:
		c, err := net.DialTimeout("tcp", f.addr(TCP), 3*time.Second)
		if err != nil {
			return nil, err
		}
		return newFrameClient(c), nil
	case DoT:
		d := &net.Dialer{Timeout: 3 * time.Second}
		c, err := tls.DialWithDialer(d, "tcp", f.addr(DoT), f.tlsConf(""))
		if err != nil {
			return nil, err
		}
		return newFrameClient(c), nil
	case DoH:
		return f.dohClient(true, ""), nil
	case DoQ:
		return f.doqClient("")
	case DoH3:
		return f.doh3Client(""), nil
	}
	return nil, errors.New("bad transport")
}

func (f *fixture) mustDial(t Transport) qclient {
	f.t.Helper()
	c, err := f.dial(t)
	if err != nil {
		f.t.Fatalf("dial %s: %v", t, err)
	}
	f.t.Cleanup(c.close)
	return c
}

// ask is exchange for one name and type.
func ask(c qclient, name string, qt uint16) (*dns.Msg, error) { return c.exchange(mkq(name, qt)) }

// ---- UDP

type udpClient struct {
	addr    string
	timeout time.Duration
}

func (u *udpClient) close() {}

func (u *udpClient) exchange(m *dns.Msg) (*dns.Msg, error) {
	c, err := net.Dial("udp", u.addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	b, err := m.Pack()
	if err != nil {
		return nil, err
	}
	if _, err := c.Write(b); err != nil {
		return nil, err
	}
	_ = c.SetReadDeadline(time.Now().Add(u.wait()))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return r, nil
}

// ---- TCP and DoT: one connection, many queries in flight, matched by ID

type frameClient struct {
	timeout time.Duration
	c       net.Conn
	wmu     sync.Mutex
	mu      sync.Mutex
	wait    map[uint16]chan *dns.Msg
	next    uint16
	dead    chan struct{}
	err     error
}

func newFrameClient(c net.Conn) *frameClient {
	fc := &frameClient{c: c, wait: map[uint16]chan *dns.Msg{}, dead: make(chan struct{})}
	go fc.readLoop()
	return fc
}

func (fc *frameClient) readLoop() {
	br := bufio.NewReader(fc.c)
	for {
		var lb [2]byte
		if _, err := io.ReadFull(br, lb[:]); err != nil {
			fc.fail(err)
			return
		}
		buf := make([]byte, int(lb[0])<<8|int(lb[1]))
		if _, err := io.ReadFull(br, buf); err != nil {
			fc.fail(err)
			return
		}
		m := new(dns.Msg)
		if m.Unpack(buf) != nil {
			continue
		}
		fc.mu.Lock()
		ch := fc.wait[m.Id]
		delete(fc.wait, m.Id)
		fc.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

func (fc *frameClient) fail(err error) {
	fc.mu.Lock()
	if fc.err == nil {
		fc.err = err
		close(fc.dead)
	}
	fc.mu.Unlock()
	// A client that is told the server is done closes its side, as a real one does.
	_ = fc.c.Close()
}

func (fc *frameClient) close() { _ = fc.c.Close() }

// closed reports whether the server (or the network) ended the connection.
func (fc *frameClient) closed() bool {
	select {
	case <-fc.dead:
		return true
	default:
		return false
	}
}

func (fc *frameClient) waitClosed(d time.Duration) bool {
	select {
	case <-fc.dead:
		return true
	case <-time.After(d):
		return false
	}
}

func (fc *frameClient) exchange(m *dns.Msg) (*dns.Msg, error) {
	m = m.Copy()
	ch := make(chan *dns.Msg, 1)
	fc.mu.Lock()
	fc.next++
	m.Id = fc.next
	fc.wait[m.Id] = ch
	fc.mu.Unlock()
	b, err := m.Pack()
	if err != nil {
		return nil, err
	}
	fc.wmu.Lock()
	_, err = fc.c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
	fc.wmu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		return r, nil
	case <-fc.dead:
		return nil, fmt.Errorf("connection closed: %v", fc.err)
	case <-time.After(fc.limit()):
		return nil, errors.New("timeout")
	}
}

// ---- DoH over HTTP/1.1 or HTTP/2

type dohHTTPClient struct {
	f       *fixture
	closeFn func()
	cl      *http.Client
	sni     string
	h2      bool
	base    string
	method  string // "POST" or "GET"
	hdr     http.Header
}

func (f *fixture) dohClient(h2 bool, sni string) *dohHTTPClient {
	tr := &http.Transport{MaxIdleConnsPerHost: 4}
	if h2 {
		tr.TLSClientConfig = f.tlsConf(sni, "h2", "http/1.1")
		tr.ForceAttemptHTTP2 = true
	} else {
		tr.TLSClientConfig = f.tlsConf(sni, "http/1.1")
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	var rt http.RoundTripper = tr
	closeFn := tr.CloseIdleConnections
	c := &dohHTTPClient{f: f, closeFn: closeFn, cl: &http.Client{Transport: rt, Timeout: 10 * time.Second}, h2: h2, method: "POST", hdr: http.Header{}}
	c.base = "https://" + f.addr(DoH) + "/dns-query"
	return c
}

func (c *dohHTTPClient) exchange(m *dns.Msg) (*dns.Msg, error) {
	r, err := c.do(m, c.method, c.hdr)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return readDoHReply(r)
}

func (c *dohHTTPClient) do(m *dns.Msg, method string, hdr http.Header) (*http.Response, error) {
	return dohDo(c.cl, c.base, m, method, hdr)
}

func dohDo(cl *http.Client, base string, m *dns.Msg, method string, hdr http.Header) (*http.Response, error) {
	b, err := m.Pack()
	if err != nil {
		return nil, err
	}
	var req *http.Request
	if method == "GET" {
		req, err = http.NewRequest("GET", base+"?dns="+base64.RawURLEncoding.EncodeToString(b), nil)
	} else {
		req, err = http.NewRequest("POST", base, bytes.NewReader(b))
		if err == nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	for k, v := range hdr {
		req.Header[k] = v
	}
	return cl.Do(req)
}

func readDoHReply(r *http.Response) (*dns.Msg, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("http %d", r.StatusCode)
	}
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return nil, err
	}
	return m, nil
}

// ---- DoH3

type doh3Client struct {
	f    *fixture
	tr   *http3.Transport
	cl   *http.Client
	base string
}

func (f *fixture) doh3Client(sni string) *doh3Client {
	tr := &http3.Transport{TLSClientConfig: f.tlsConf(sni, "h3"), QUICConfig: &quic.Config{}}
	return &doh3Client{f: f, tr: tr, cl: &http.Client{Transport: tr, Timeout: 10 * time.Second},
		base: "https://" + f.addr(DoH3) + "/dns-query"}
}

func (c *doh3Client) close() { _ = c.tr.Close() }

func (c *doh3Client) exchange(m *dns.Msg) (*dns.Msg, error) {
	r, err := dohDo(c.cl, c.base, m, "POST", nil)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return readDoHReply(r)
}

// ---- DoQ

type doqClient struct {
	conn *quic.Conn
}

func (f *fixture) doqClient(sni string) (*doqClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, f.addr(DoQ), f.tlsConf(sni, "doq"), &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		return nil, err
	}
	return &doqClient{conn: conn}, nil
}

func (c *doqClient) close() { _ = c.conn.CloseWithError(0, "") }

func (c *doqClient) exchange(m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	m = m.Copy()
	m.Id = 0 // RFC 9250: the ID is 0 on QUIC
	b, err := m.Pack()
	if err != nil {
		return nil, err
	}
	_ = str.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := str.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
		return nil, err
	}
	if err := str.Close(); err != nil {
		return nil, err
	}
	all, err := io.ReadAll(str)
	if err != nil {
		return nil, err
	}
	if len(all) < 2 {
		return nil, errors.New("short doq reply")
	}
	r := new(dns.Msg)
	if err := r.Unpack(all[2:]); err != nil {
		return nil, err
	}
	return r, nil
}

// answered says whether r is the stub's normal answer to q: NOERROR, not
// truncated, not refused.
func answered(r *dns.Msg) bool {
	return r != nil && r.Rcode == dns.RcodeSuccess && !r.Truncated
}

// all runs exchange for every query at once on c and returns the replies,
// with a nil where the exchange failed.
func exchangeAll(c qclient, qs []*dns.Msg) ([]*dns.Msg, []error) {
	rs := make([]*dns.Msg, len(qs))
	es := make([]error, len(qs))
	var wg sync.WaitGroup
	for i := range qs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rs[i], es[i] = c.exchange(qs[i])
		}()
	}
	wg.Wait()
	return rs, es
}

func (u *udpClient) wait() time.Duration {
	if u.timeout > 0 {
		return u.timeout
	}
	return 2 * time.Second
}

// scaled returns the default registry with every rate, burst and count
// multiplied by k, for tests that are not about limits.
func scaled(r limits.Registry, k float64) limits.Registry {
	r = r.Clone()
	for i := range r {
		r[i].Rate *= k
		r[i].Burst = int(float64(r[i].Burst) * k)
		r[i].Count = int(float64(r[i].Count) * k)
	}
	return r
}

func (fc *frameClient) limit() time.Duration {
	if fc.timeout > 0 {
		return fc.timeout
	}
	return 5 * time.Second
}

func (c *dohHTTPClient) close() { c.closeFn() }

// within is the time an exempt query may take from its arrival to its answer:
// the 2 s of L13 (2), which is the timeout of the failover probes. The race
// detector slows handshakes and packets enough that the clients' own dials and
// retransmissions (a QUIC client waits a probe timeout after a lost datagram,
// and loopback loses datagrams when a burst fills the socket buffer) use up
// that budget, so a race run allows ten times as much.
func within() time.Duration {
	if raceEnabled {
		return 20 * time.Second
	}
	return 2 * time.Second
}
