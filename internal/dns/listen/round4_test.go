package listen

// Tests of review round 4 (p4n-W6-r4-*): a connection accepted while the
// server closes, DoH3 header-queue tokens, a ticket for a name that became
// unknown, QUIC handshakes of one source, and the DoQ source after migration.

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// A connection that was accepted just before the server closed and has not
// registered yet must be failed when it does, not left in its handshake or its
// idle wait while Close waits for it (p4n-W6-r4-1).
func TestStreamConnAcceptedDuringCloseEnds(t *testing.T) {
	f := newFixture(t, withTransports(TCP))
	ctx, cancel := context.WithCancel(context.Background())
	c, err := newCore(ctx, &f.cfg, TCP)
	if err != nil {
		t.Fatal(err)
	}
	s := newStream(c, nil, nil)
	cancel() // Server.Close cancels before it calls close()
	srvEnd, cliEnd := net.Pipe()
	defer cliEnd.Close()
	slot, ok := f.set.Admit(TCP, netip.MustParseAddr("192.0.2.9"))
	if !ok {
		t.Fatal("not admitted")
	}
	s.wg.Add(1)
	go s.serveConn(srvEnd, netip.MustParseAddrPort("192.0.2.9:1000"), slot)
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a connection accepted during Close stays until its idle deadline")
	}
}

// Request streams that quic-go finishes before any handler runs must not leave
// their tokens behind: the tokens of one connection stay within the stream cap
// however fast a peer opens and closes streams (p4n-W6-r4-2).
func TestDoH3HeaderTokensFollowTheirStreams(t *testing.T) {
	f := newFixture(t, withTransports(DoH3))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, f.addr(DoH3), f.tlsConf("", "h3"), &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	var opened atomic.Int64
	stop := time.Now().Add(2 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			for time.Now().Before(stop) {
				sctx, c := context.WithTimeout(context.Background(), time.Second)
				str, err := conn.OpenStreamSync(sctx)
				c()
				if err != nil {
					return
				}
				_ = str.Close() // a FIN and no HEADERS
				opened.Add(1)
			}
		})
	}
	wg.Wait()
	if opened.Load() < 300 {
		t.Fatalf("only %d streams opened: the test measured nothing", opened.Load())
	}
	b := f.srv.doh3.quicBase
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.conns) != 1 {
		t.Fatalf("%d connections", len(b.conns))
	}
	set, _ := limits.SettingsFor(limits.Listeners(), DoH3)
	for _, qc := range b.conns {
		if n := qc.hdr.maxHeld(); n > set.MaxStreams {
			t.Fatalf("the header queue held %d tokens after %d streams, the stream cap is %d", n, opened.Load(), set.MaxStreams)
		}
	}
}

// ---- a ticket for a name that became unknown

// withRevocableName makes the certificate provider refuse name once revoked is set.
func withRevocableName(name string, revoked *atomic.Bool) fixOpt {
	return func(f *fixture) {
		inner := f.cfg.GetCertificate
		f.cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName == name && revoked.Load() {
				return nil, nil
			}
			return inner(h)
		}
	}
}

// A ticket issued while a name was good must not carry the name through the
// handshake after the provider has begun to refuse it: the resolver ID was
// rotated, and SC 3.3 says the handshake ends with unrecognized_name (p4n-W6-r4-3).
func TestResumptionRefusedAfterTheNameBecomesUnknown(t *testing.T) {
	const name = "rotated.dns.test"
	var revoked atomic.Bool
	f := newFixture(t, withRevocableName(name, &revoked))
	for _, tr := range []Transport{DoT, DoH, DoQ, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			revoked.Store(false)
			cache := &anyKeyCache{}
			if _, err := dialResume(f, tr, name, cache, 0); err != nil {
				t.Fatal(err)
			}
			if cache.count() == 0 {
				t.Fatal("no session ticket was issued: the test measured nothing")
			}
			if resumed, err := dialResume(f, tr, name, cache, 0); err != nil || !resumed {
				t.Fatalf("while the name is good: resumed=%v err=%v", resumed, err)
			}
			revoked.Store(true)
			_, err := dialResume(f, tr, name, cache, 0)
			if err == nil {
				t.Fatal("a ticket carried a revoked name through the handshake")
			}
			if !strings.Contains(err.Error(), "unrecognized name") && !strings.Contains(err.Error(), "0x170") {
				t.Fatalf("want the unrecognized_name alert, got: %v", err)
			}
		})
	}
}

// ---- QUIC handshakes of one source

// One real host that opens QUIC connections as fast as it can must not make the
// node run many more TLS handshakes than the same host makes it run on DoT, where
// the limit applies right after the TCP handshake (p4n-W6-r4-4).
func TestQUICHandshakesOfOneSourceAreBounded(t *testing.T) {
	f := newFixture(t, withTransports(DoT, DoQ))
	const n = 200
	burst := func(dial func()) int32 {
		before := f.hello.Load()
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Go(dial)
		}
		wg.Wait()
		time.Sleep(200 * time.Millisecond)
		return f.hello.Load() - before
	}
	dot := burst(func() {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", f.addr(DoT), f.tlsConf(""))
		if err == nil {
			_ = c.Close()
		}
	})
	doq := burst(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := quic.DialAddr(ctx, f.addr(DoQ), f.tlsConf("", "doq"), nil)
		if err == nil {
			_ = c.CloseWithError(0, "")
		}
	})
	t.Logf("handshakes run: DoT %d, DoQ %d", dot, doq)
	if dot == 0 || doq == 0 {
		t.Fatal("the test measured nothing")
	}
	// DoT is the bar: the burst of 40 plus what refills while the dials run.
	// DoQ runs a few more, because its dials take longer and the bucket refills, and
	// the handshakes that were in flight before the first was counted; before the
	// fix it ran every one of the 200.
	if int(doq) > 2*int(dot)+limits.RetryPerSource {
		t.Fatalf("DoQ ran %d handshakes for one source against %d on DoT", doq, dot)
	}
}

// The per-source rule of Retry: a source with RetryPerSource handshakes in
// progress is asked for a Retry, another source is not, and the count follows
// the handshakes (p4n-W6-r4-4).
func TestRetryPerSource(t *testing.T) {
	h := &handshakes{}
	a := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000}
	a2 := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2000} // the same host
	b := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1000}
	var cancels []context.CancelFunc
	for i := 0; i < limits.RetryPerSource; i++ {
		if h.verify(a, nil) {
			t.Fatalf("Retry asked with %d handshakes in progress", i)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		if _, err := h.connContext(ctx, &quic.ClientInfo{RemoteAddr: a}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !h.verify(a2, nil) {
		t.Fatal("no Retry for a source over its handshakes in progress")
	}
	if h.verify(b, nil) {
		t.Fatal("Retry asked of another source")
	}
	// A validated handshake is not counted.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := h.connContext(ctx, &quic.ClientInfo{RemoteAddr: b, AddrVerified: true}, nil); err != nil {
		t.Fatal(err)
	}
	if h.verify(b, nil) {
		t.Fatal("a validated handshake was counted")
	}
	cancels[0]()
	deadline := time.Now().Add(2 * time.Second)
	for h.verify(a, nil) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.verify(a, nil) {
		t.Fatal("a finished handshake still counts")
	}
	for _, c := range cancels {
		c()
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		n := len(h.bySrc)
		h.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.bySrc) != 0 {
		t.Fatalf("%d sources still held after every handshake ended", len(h.bySrc))
	}
}

// A source over a connection limit is asked for a Retry; the answer of the
// limits is what decides.
func TestRetryForASourceOverALimit(t *testing.T) {
	h := &handshakes{}
	a := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000}
	if h.verify(a, func(netip.Addr) bool { return false }) {
		t.Fatal("Retry asked of a source inside its limits")
	}
	if !h.verify(a, func(ip netip.Addr) bool { return ip == netip.MustParseAddr("192.0.2.1") }) {
		t.Fatal("no Retry for a source over a limit")
	}
}

// ---- DoQ keeps up with a migrating client

// quic-go follows a client that migrates to another address once the new path
// is validated. The source of a query is the address the connection has now, not
// the one it was accepted from (p4n-W6-r4-5).
func TestDoQSourceFollowsMigration(t *testing.T) {
	f := newFixture(t, withTransports(DoQ))
	udp1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udp2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr1, tr2 := &quic.Transport{Conn: udp1}, &quic.Transport{Conn: udp2}
	defer tr1.Close()
	defer tr2.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(f.addr(DoQ)))
	conn, err := tr1.Dial(ctx, raddr, f.tlsConf("", "doq"), &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	c := &doqClient{conn: conn}
	port1 := netip.MustParseAddrPort(udp1.LocalAddr().String()).Port()
	port2 := netip.MustParseAddrPort(udp2.LocalAddr().String()).Port()
	lastPort := func() uint16 {
		rs := f.stub.Requests()
		return rs[len(rs)-1].Source.Port()
	}
	if r, err := ask(c, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("first query: %v %v", r, err)
	}
	if p := lastPort(); p != port1 {
		t.Fatalf("source port %d before migration, want %d", p, port1)
	}
	path, err := conn.AddPath(tr2)
	if err != nil {
		t.Fatal(err)
	}
	if err := path.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := path.Switch(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := ask(c, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("query after the switch: %v %v", r, err)
		}
		if lastPort() == port2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the source stayed on port %d after the connection moved to %d", lastPort(), port2)
}
