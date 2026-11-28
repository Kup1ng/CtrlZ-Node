package proxy

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

func proxyVerdict(socks ...string) func(uint64) *sock.LinkVerdict {
	return func(uint64) *sock.LinkVerdict {
		v := &sock.LinkVerdict{Kind: sock.VerdictProxy, Tag: []byte("tag")}
		for _, s := range socks {
			v.Targets = append(v.Targets, sock.Target{Socks: s, Host: "example.com", Port: 443})
		}
		return v
	}
}

func TestLinkOrderAndListening(t *testing.T) {
	r := newRig(t, nil)
	// The proxy says hello and lists its open connections (none) before anything.
	if items := r.handshake(nil); len(items) != 0 {
		t.Fatal("open items at start")
	}
	if r.p.Listening() {
		t.Fatal("listening before a config")
	}
	r.handshakeConfig()
	if !r.p.Listening() {
		t.Fatal("not listening after a config")
	}
	// Link down: both listeners close, so a client gets a refused connection.
	addr := r.addr(0)
	r.dns.Close()
	for i := 0; i < 200 && r.p.Listening(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if r.p.Listening() {
		t.Fatal("still listening with the link down")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a connection was accepted with no link")
	}
}

func (r *rig) handshakeConfig() {
	r.t.Helper()
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkConfig, Config: testConfig()}); err != nil {
		r.t.Fatal(err)
	}
	r.waitListening()
}

func TestKind1Splice(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	s := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	hello := clientHello(t, "Example.COM.")
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	lk := r.route(true, proxyVerdict(s.addr()))
	// dns is asked for the normalised wire name, the source and the port.
	if string(lk.Name) != "\x07example\x03com\x00" || lk.Port != 443 || len(lk.Source) != 4 {
		t.Fatalf("lookup %+v", lk)
	}
	if got := readSome(t, c, 3*time.Second); string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	// After the first byte the splice runs both ways.
	_, _ = c.Write([]byte("ping"))
	if got := readSome(t, c, 3*time.Second); string(got) != "ping" {
		t.Fatalf("echo %q", got)
	}
	reqs := s.requests()
	if len(reqs) != 1 || reqs[0].host != "example.com" || reqs[0].port != 443 || !bytes.Equal(reqs[0].data, hello) {
		t.Fatalf("socks saw %+v", reqs)
	}
	if r.p.Open() != 1 {
		t.Fatalf("open %d", r.p.Open())
	}
	// A close with a byte received is a plain close, not a pending dial.
	_ = c.Close()
	m := r.recvType(sock.TLinkClosed)
	if len(m.Closed.IDs) != 1 || len(m.Closed.Pending) != 0 {
		t.Fatalf("closed %+v", m.Closed)
	}
}

func TestVerdictNoneClosesWithNoByte(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "blocked.example"))
	r.route(true, func(uint64) *sock.LinkVerdict { return &sock.LinkVerdict{Kind: sock.VerdictNone} })
	expectClosed(t, c)
}

func TestBadNamesCloseBeforeALookup(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	for _, name := range []string{"", "127.0.0.1", "bücher.example", "a..b"} {
		c := dialClient(t, r.addr(1))
		var hello []byte
		if name == "" {
			hello = clientHello(t, "")
		} else {
			// crypto/tls does not send an IP as an SNI, so the bytes are put in by hand.
			ph := strings.Repeat("a", len(name))
			hello = bytes.Replace(clientHello(t, ph), []byte(ph), []byte(name), 1)
		}
		_, _ = c.Write(hello)
		r.answerSource(true)
		expectClosed(t, c)
	}
}

func TestIranianKind1IsClosedAndKind2IsServed(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	s := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "shop.ir"))
	r.route(true, proxyVerdict(s.addr()))
	expectClosed(t, c)
	if len(s.requests()) != 0 {
		t.Fatal("the proxy dialled an Iranian name")
	}

	// A block page for the same kind of name is allowed (D42).
	blk := listenTCP(t)
	r.serveAddr = blk.Addr().String()
	got := make(chan *sock.ServeFrame, 1)
	rest := make(chan []byte, 1)
	go func() {
		sc, err := blk.Accept()
		if err != nil {
			return
		}
		defer sc.Close()
		f, err := sock.ServeCodec.Read(sc)
		if err != nil {
			return
		}
		got <- f
		b := make([]byte, 16<<10)
		_ = sc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := sc.Read(b)
		rest <- b[:n]
		_, _ = sc.Write([]byte("page"))
	}()
	c2 := dialClient(t, r.addr(1))
	hello := clientHello(t, "shop.ir")
	_, _ = c2.Write(hello)
	ep, ac := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	r.route(false, func(uint64) *sock.LinkVerdict {
		return &sock.LinkVerdict{Kind: sock.VerdictBlock, Endpoint: ep, Account: ac, PageHash: bytes.Repeat([]byte{3}, 32)}
	})
	select {
	case f := <-got:
		if f.Name != "shop.ir" || f.Port != 443 || !bytes.Equal(f.Endpoint, ep) || !bytes.Equal(f.Account, ac) || len(f.Source) != 4 {
			t.Fatalf("frame %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no serve frame")
	}
	// The ClientHello the proxy had already read is the first thing block sees.
	if b := <-rest; !bytes.Equal(b, hello) {
		t.Fatal("the recorded bytes were not replayed")
	}
	if got := readSome(t, c2, 3*time.Second); string(got) != "page" {
		t.Fatalf("got %q", got)
	}
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestFailoverAfterAnEndedTarget(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	dead := newSocks(t, closeAtOnce)
	live := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	hello := clientHello(t, "example.com")
	_, _ = c.Write(hello)
	r.route(true, proxyVerdict(dead.addr(), live.addr()))
	mv := r.recvType(sock.TLinkMoved).Moved
	// An EOF ended that dial: nothing is left behind (5.5).
	if mv.Socks != live.addr() || mv.Left != nil {
		t.Fatalf("moved %+v", mv)
	}
	if got := readSome(t, c, 3*time.Second); string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	// The recorded bytes were sent again to the later target.
	if reqs := live.requests(); len(reqs) != 1 || !bytes.Equal(reqs[0].data, hello) {
		t.Fatal("the second target did not get the hello")
	}
}

func TestMoveAfterSilenceNamesTheDialItLeft(t *testing.T) {
	cfg := testConfig()
	cfg.DialFirstByteMS = 200
	r := newRig(t, nil)
	r.handshake(cfg)
	silent := newSocks(t, hangForever)
	live := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	r.route(true, proxyVerdict(silent.addr(), live.addr()))
	mv := r.recvType(sock.TLinkMoved).Moved
	if mv.Left == nil || mv.Left.Socks != silent.addr() || mv.Left.StartMS > 100 || mv.Socks != live.addr() {
		t.Fatalf("moved %+v", mv)
	}
	if got := readSome(t, c, 3*time.Second); string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestLastTargetFailingLeavesAPendingDial(t *testing.T) {
	cfg := testConfig()
	cfg.DialFirstByteMS = 150
	r := newRig(t, nil)
	r.handshake(cfg)
	silent := newSocks(t, hangForever)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	r.route(true, proxyVerdict(silent.addr()))
	expectClosed(t, c)
	m := r.recvType(sock.TLinkClosed)
	if len(m.Closed.IDs) != 0 || len(m.Closed.Pending) != 1 || m.Closed.Pending[0].StartMS > 100 {
		t.Fatalf("closed %+v", m.Closed)
	}
}

func TestEndByIDAndBySocks(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	s := newSocks(t, answerThenEcho)
	var conns []net.Conn
	var ids []uint64
	for i := 0; i < 2; i++ {
		c := dialClient(t, r.addr(1))
		_, _ = c.Write(clientHello(t, "example.com"))
		id := r.answerSource(true)
		r.recvType(sock.TLinkLookup)
		v := proxyVerdict(s.addr())(id)
		v.ID = id
		r.verdict(v)
		ids = append(ids, id)
		readSome(t, c, 3*time.Second)
		conns = append(conns, c)
	}
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkEnd, End: &sock.LinkEnd{IDs: ids[:1]}}); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, conns[0])
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkEnd, End: &sock.LinkEnd{Socks: []string{s.addr()}}}); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, conns[1])
}

func TestHTTPSniff(t *testing.T) {
	pair := func(req string) (*httpFirst, error) {
		a, b := net.Pipe()
		go func() { _, _ = a.Write([]byte(req)) }()
		defer a.Close()
		defer b.Close()
		return sniffHTTP(b, time.Now().Add(2*time.Second))
	}
	h, err := pair("GET /x HTTP/1.1\r\nHost: Example.com:80\r\n\r\n")
	if err != nil || h.Host != "Example.com" || !h.Movable {
		t.Fatalf("%+v %v", h, err)
	}
	if h, err := pair("POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"); err != nil || h.Movable {
		t.Fatalf("a POST must not move: %+v %v", h, err)
	}
	if _, err := pair("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"); err == nil {
		t.Fatal("CONNECT accepted")
	}
	if _, err := pair("GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n"); err == nil {
		t.Fatal("an absolute target with another Host was accepted")
	}
	if h, err := pair("GET http://a.example/ HTTP/1.1\r\nHost: A.example\r\n\r\n"); err != nil || h.Host != "a.example" {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := pair("GET / HTTP/1.1\r\n\r\n"); err == nil {
		t.Fatal("no host accepted")
	}
	// Over the sniff limit.
	if _, err := pair("GET / HTTP/1.1\r\nHost: a.example\r\nX: " + strings.Repeat("a", MaxSniff) + "\r\n\r\n"); err == nil {
		t.Fatal("an oversize request was accepted")
	}
}

func TestPort80PostStaysWithItsFirstTarget(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	dead := newSocks(t, closeAtOnce)
	live := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(0))
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"
	_, _ = c.Write([]byte(req))
	lk := r.route(true, func(uint64) *sock.LinkVerdict {
		v := proxyVerdict(dead.addr(), live.addr())(0)
		for i := range v.Targets {
			v.Targets[i].Port = 80
		}
		return v
	})
	if lk.Port != 80 {
		t.Fatalf("port %d", lk.Port)
	}
	expectClosed(t, c)
	if len(live.requests()) != 0 {
		t.Fatal("a POST was sent to a later target")
	}
}

func TestPreGrantEviction(t *testing.T) {
	cfg := testConfig()
	cfg.OtherPerSource = 2
	r := newRig(t, nil)
	r.handshake(cfg)
	var cs []net.Conn
	for i := 0; i < 3; i++ {
		c := dialClient(t, r.addr(1))
		cs = append(cs, c)
		r.answerSource(false)
	}
	// The source's own oldest connection is the one that goes.
	expectClosed(t, cs[0])
}

// A connection that has a verdict goes on when the link drops, and the next link's
// open list names it (5.1: dns rebuilds its table from that list).
func TestReconnectListsOpenConnections(t *testing.T) {
	dns2, prox2 := sockfake.LinkPair()
	r := newRig(t, nil)
	r.more <- prox2.Conn
	r.handshake(testConfig())
	s := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	r.route(true, proxyVerdict(s.addr()))
	readSome(t, c, 3*time.Second)
	r.dns.Close()

	r2 := &rig{t: t, dns: dns2, p: r.p, listeners: r.listeners}
	items := r2.handshake(nil)
	if len(items) != 1 || items[0].Socks != s.addr() || string(items[0].Tag) != "tag" || len(items[0].Source) != 4 {
		t.Fatalf("open list %+v", items)
	}
	// The connection is still there and still carries bytes.
	_, _ = c.Write([]byte("again"))
	if got := readSome(t, c, 3*time.Second); string(got) != "again" {
		t.Fatalf("got %q", got)
	}
	dns2.Close()
}

func TestADnsFrameOfTheWrongSideEndsTheLink(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	// hello is the proxy's to send: dns sending it is a protocol error.
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: 1}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200 && r.p.Listening(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if r.p.Listening() {
		t.Fatal("the link went on after a frame of the other side")
	}
}

func TestNewConnectionRate(t *testing.T) {
	cfg := testConfig()
	cfg.NewRate, cfg.NewBurst = 1, 2
	r := newRig(t, nil)
	r.handshake(cfg)
	var cs []net.Conn
	for i := 0; i < 3; i++ {
		cs = append(cs, dialClient(t, r.addr(1)))
	}
	r.answerSource(false)
	r.answerSource(false)
	// The third came over the burst and is closed with no byte, no ask made.
	expectClosed(t, cs[2])
	if r.p.refused[rRate].Load() != 1 {
		t.Fatalf("rate refusals %d", r.p.refused[rRate].Load())
	}
}
