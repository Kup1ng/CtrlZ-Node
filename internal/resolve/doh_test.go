package resolve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
)

// rawDoH is dnsproxy's own DoH upstream, built directly, for the control of
// the tests that show what it would have leaked or kept open.
func rawDoH(t testing.TB, addr string, pool *x509.CertPool) upstream.Upstream {
	t.Helper()
	u, err := upstream.AddressToUpstream("https://"+addr+"/dns-query", &upstream.Options{
		Logger: slog.New(slog.DiscardHandler), RootCAs: pool, Timeout: 2 * time.Second,
		Bootstrap:    upstream.StaticResolver{loopback},
		HTTPVersions: []upstream.HTTPVersion{upstream.HTTPVersion2, upstream.HTTPVersion11},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	return u
}

// connServer is an HTTP/2 DoH server that counts its open connections and can
// stall chosen queries, so a client's error path is exercised.
type connServer struct {
	open    atomic.Int64
	peak    atomic.Int64
	total   atomic.Int64
	stall   atomic.Bool
	stallBy time.Duration
	addr    netip.AddrPort
}

func startConnServer(t *testing.T, cert tls.Certificate, stallBy time.Duration) *connServer {
	t.Helper()
	cs := &connServer{stallBy: stallBy}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 65535))
		req := new(dns.Msg)
		if req.Unpack(raw) != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if cs.stall.Load() && strings.HasPrefix(req.Question[0].Name, "slow") {
			select {
			case <-time.After(cs.stallBy):
			case <-r.Context().Done():
				return
			}
		}
		out, _ := answerA(req).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	srv := &http.Server{
		Handler: h, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ConnState: func(_ net.Conn, st http.ConnState) {
			switch st {
			case http.StateNew:
				cs.open.Add(1)
				cs.total.Add(1)
				for p := cs.peak.Load(); cs.open.Load() > p && !cs.peak.CompareAndSwap(p, cs.open.Load()); p = cs.peak.Load() {
				}
			case http.StateClosed, http.StateHijacked:
				cs.open.Add(-1)
			}
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	cs.addr = netip.AddrPortFrom(loopback, uint16(port))
	return cs
}

// The fault dnsproxy's client has (D66): under a steady error rate it makes a new
// transport for every error and the old connections stay open for minutes. Ours
// keeps one Transport, so the client never holds more than dohMaxConns
// connections and none are left behind when the traffic stops.
func TestDoHClientKeepsItsConnectionBoundUnderErrors(t *testing.T) {
	cert, pool := testCert(t)
	// The query timeout is also the dial and handshake timeout, so it is well above
	// what a loaded machine takes to handshake: a handshake cut off by the timeout is
	// a redial, which is not what this test is about. The server holds a stalled
	// query longer than that, so every slow query ends by timeout.
	cs := startConnServer(t, cert, 4*time.Second)
	cs.stall.Store(true)
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cs.addr.Port()))),
		RootCAs: pool, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	var wg sync.WaitGroup
	var errs, ok atomic.Int64
	stop := time.Now().Add(2 * time.Second)
	for i := 0; time.Now().Before(stop); i++ {
		wg.Add(2)
		go func() { // a query the server stalls: it ends by timeout
			defer wg.Done()
			if _, err := u.Exchange(context.Background(), query("slow.example.com")); err != nil {
				errs.Add(1)
			}
		}()
		go func() { // a good query in the same moment
			defer wg.Done()
			if _, err := u.Exchange(context.Background(), query("fast.example.com")); err == nil {
				ok.Add(1)
			}
		}()
		time.Sleep(10 * time.Millisecond)
	}
	wg.Wait()
	if errs.Load() < 50 {
		t.Fatalf("only %d errors, the test did not run an error rate", errs.Load())
	}
	if ok.Load() < errs.Load()/2 {
		t.Fatalf("good queries starved: %d ok of %d slow", ok.Load(), errs.Load())
	}
	// Counted on the client: the connections it holds can never pass the bound it
	// sets, and it knows how many it dialled. The server learns of a close later
	// than the client lets go of its slot, so its own peak can read above the bound
	// on a loaded machine without the client ever holding more.
	dc := u.u.(*dohClient)
	dc.mu.Lock()
	peak, total := dc.peak, dc.total
	dc.mu.Unlock()
	if total == 0 {
		t.Fatal("the client counted no connection")
	}
	if peak > dohMaxConns {
		t.Fatalf("the client held %d connections at once, bound is %d", peak, dohMaxConns)
	}
	if total > 2*dohMaxConns {
		t.Fatalf("%d connections opened in all: the transport was recreated", total)
	}
	// Idle connections of the one transport stay (that is the pool); closing the
	// upstream releases them, and nothing else is left on the server.
	_ = u.Close()
	deadline := time.Now().Add(3 * time.Second)
	for cs.open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := cs.open.Load(); n != 0 {
		t.Fatalf("%d connections orphaned after Close", n)
	}
}

// A control that shows the test above is not vacuous: dnsproxy's own client
// under the same error rate opens far more connections than our bound.
func TestDnsproxyDoHClientOrphansConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("control run")
	}
	cert, pool := testCert(t)
	cs := startConnServer(t, cert, 2*time.Second)
	cs.stall.Store(true)
	raw := rawDoH(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cs.addr.Port()))), pool)
	var wg sync.WaitGroup
	stop := time.Now().Add(2 * time.Second)
	for time.Now().Before(stop) {
		wg.Add(2)
		for _, n := range []string{"slow.example.com", "fast.example.com"} {
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
				defer cancel()
				_, _ = raw.Exchange(ctx, query(n))
			}()
		}
		time.Sleep(10 * time.Millisecond)
	}
	wg.Wait()
	if cs.total.Load() <= 2*dohMaxConns {
		t.Skipf("dnsproxy opened only %d connections; the defect this control shows is gone, revisit D66", cs.total.Load())
	}
}

// The client dials the bootstrap address only, checks the certificate against
// tls_name, and a name that is not the certificate's fails.
func TestDoHClientDialsBootstrapAndChecksName(t *testing.T) {
	cert, pool := testCert(t)
	cs := startConnServer(t, cert, 0)
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "named.invalid:" + strconv.Itoa(int(cs.addr.Port())),
		BootstrapIP: loopback, TLSName: testHost, RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	mustAnswer(t, u, "example.com")

	bad, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "other.invalid:" + strconv.Itoa(int(cs.addr.Port())),
		BootstrapIP: loopback, TLSName: "wrong.resolve.test", RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err := bad.Exchange(context.Background(), query("example.com")); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
}

// A non-200 status and a body that is not DNS fail without quoting the body, the
// URL path or the qname.
func TestDoHClientErrorsQuoteNothing(t *testing.T) {
	cert, pool := testCert(t)
	var mode atomic.Int32
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mode.Load() == 0 {
				http.Error(w, "secret-user-query is forbidden", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte("\x11secret-user-query\x00"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/token-path-xyz",
		RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for m := int32(0); m < 2; m++ {
		mode.Store(m)
		_, err := u.Exchange(context.Background(), query("secret-user-query.example.com"))
		if err == nil {
			t.Fatal("bad reply accepted")
		}
		for _, bad := range []string{"secret-user-query", "token-path-xyz", "forbidden"} {
			if strings.Contains(err.Error(), bad) {
				t.Fatalf("error %q quotes %q", err.Error(), bad)
			}
		}
	}
	// A dead port: the url.Error is unwrapped, so the path is not in the text.
	dead, _ := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "127.0.0.1:1/token-path-xyz", RootCAs: pool, Timeout: time.Second})
	defer dead.Close()
	if _, err := dead.Exchange(context.Background(), query("example.com")); err == nil || strings.Contains(err.Error(), "token-path-xyz") {
		t.Fatalf("dead upstream error: %v", err)
	}
}

// An HTTP redirect is not followed: an upstream cannot send the query elsewhere.
func TestDoHClientDoesNotFollowRedirects(t *testing.T) {
	cert, pool := testCert(t)
	var hits atomic.Int32
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Redirect(w, r, "https://elsewhere.invalid/dns-query", http.StatusTemporaryRedirect)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.Exchange(context.Background(), query("example.com")); err == nil {
		t.Fatal("redirect answered")
	}
	if hits.Load() != 1 {
		t.Fatalf("server hit %d times", hits.Load())
	}
}

// freezer is a TCP relay whose existing connections can be made to swallow
// everything, as a NAT or firewall does after it drops its state: no reset, no
// answer, nothing. New connections are relayed as usual.
type freezer struct {
	mu    sync.Mutex
	conns []*atomic.Bool
}

func (f *freezer) freeze() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.conns {
		c.Store(true)
	}
}

func startFreezer(t *testing.T, target netip.AddrPort) (*freezer, netip.AddrPort) {
	t.Helper()
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	f := &freezer{}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target.String())
			if err != nil {
				_ = c.Close()
				continue
			}
			frozen := &atomic.Bool{}
			f.mu.Lock()
			f.conns = append(f.conns, frozen)
			f.mu.Unlock()
			pipe := func(dst, src net.Conn) {
				defer dst.Close()
				defer src.Close()
				buf := make([]byte, 32<<10)
				for {
					n, err := src.Read(buf)
					if n > 0 && !frozen.Load() {
						if _, werr := dst.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			go pipe(up, c)
			go pipe(c, up)
		}
	}()
	return f, netip.AddrPortFrom(loopback, uint16(port))
}

// A connection that silently stopped answering is closed by the HTTP/2 liveness
// ping, so the next query dials a new one instead of waiting out its timeout on
// the dead one (p4n-W7-r1-6). The Transport is never replaced, so this is the
// only recovery there is.
func TestDoHClientRecoversFromASilentlyDeadConnection(t *testing.T) {
	cert, pool := testCert(t)
	cs := startConnServer(t, cert, 0)
	fz, via := startFreezer(t, cs.addr)
	c, err := newDoHClientPing("https://"+testHost+":"+strconv.Itoa(int(via.Port()))+"/dns-query", loopback, pool, 3*time.Second, 150*time.Millisecond, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ask := func() error {
		_, err := c.Exchange(context.Background(), query("example.com"))
		return err
	}
	if err := ask(); err != nil {
		t.Fatal(err)
	}
	fz.freeze()
	time.Sleep(900 * time.Millisecond) // idle ping, its timeout, and slack for a loaded machine
	start := time.Now()
	if err := ask(); err != nil {
		t.Fatalf("the query after the connection died failed: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("recovery took %v", d)
	}
}

// gatedListener accepts every connection, and while silent holds it without a
// byte exchanged: a peer or a middlebox that completes TCP and never answers the
// ClientHello. When it stops being silent the new connections reach the server.
type gatedListener struct {
	net.Listener
	silent atomic.Bool
	mu     sync.Mutex
	held   []net.Conn
}

func (g *gatedListener) Accept() (net.Conn, error) {
	for {
		c, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if g.silent.Load() {
			g.mu.Lock()
			g.held = append(g.held, c)
			g.mu.Unlock()
			continue
		}
		return c, nil
	}
}

func (g *gatedListener) closeHeld() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range g.held {
		_ = c.Close()
	}
	g.held = nil
}

// A DoH upstream whose handshakes stalled must be reachable again once it
// answers (p4n-W7-r5-1). net/http leaves a dial running after its request ended,
// and the dial keeps a connection slot until its handshake ends, so more stalled
// handshakes than dohMaxConns would lock the client for good without the
// handshake timer.
func TestDoHClientRecoversAfterStalledHandshakes(t *testing.T) {
	cert, pool := testCert(t)
	var gl *gatedListener
	port := scanPorts(t, func(p int) error {
		ln, err := net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		if err == nil {
			gl = &gatedListener{Listener: ln}
		}
		return err
	})
	gl.silent.Store(true)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 65535))
			req := new(dns.Msg)
			if req.Unpack(raw) != nil {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			out, _ := answerA(req).Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(out)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() { _ = srv.ServeTLS(gl, "", "") }()
	t.Cleanup(func() { _ = srv.Close(); gl.closeHeld() })

	// 300 ms: the first query after recovery sets up a fresh TCP, TLS and HTTP/2
	// connection inside it, which took more than 100 ms under -race on a loaded
	// machine (p4n-W7-r7-6). The stalled slots were already free by then.
	const callTimeout = 300 * time.Millisecond
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		RootCAs: pool, Timeout: callTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	// More concurrent requests than slots, every one ending by its own deadline.
	var wg sync.WaitGroup
	for i := 0; i < 3*dohMaxConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := u.Exchange(context.Background(), query("example.com")); err == nil {
				t.Error("a query succeeded through a silent peer")
			}
		}()
	}
	wg.Wait()
	// The stalled dials outlive their requests; the handshake timer ends them.
	time.Sleep(callTimeout + dohHandshakeSlack + 500*time.Millisecond)
	gl.silent.Store(false)
	for i := 0; i < 5; i++ {
		if _, err := u.Exchange(context.Background(), query("example.com")); err != nil {
			t.Fatalf("query %d after the peer recovered: %v", i, err)
		}
	}
}
