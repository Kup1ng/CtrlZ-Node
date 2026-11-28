package link

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
	"github.com/Kup1ng/CtrlZ-Node/internal/grant"
	"github.com/Kup1ng/CtrlZ-Node/internal/proxy"
)

// fake is a Backend that records what the proxy says and answers by name.
type fake struct {
	mu      sync.Mutex
	up      chan uint64
	items   []grant.OpenItem
	sources []netip.Addr
	looks   []string
	closed  []uint64
	moved   []sock.LinkMoved
	states  []sock.LinkState
	down    chan struct{}
	cfgOK   bool
	srv     *Server
	// slowCtx is the context of the lookup of "slow.test", which waits for its end;
	// staleAtUp is what a LinkUp saw of it.
	slowCtx   chan context.Context
	lastSlow  context.Context
	staleAtUp []bool
}

func newFake() *fake {
	return &fake{up: make(chan uint64, 4), down: make(chan struct{}, 4), cfgOK: true, slowCtx: make(chan context.Context, 4)}
}

func (f *fake) ProxyConfig() (sock.ProxyConfig, bool) {
	return sock.ProxyConfig{BindIP: "127.0.0.1", MainPerSource: 512, MainNode: 8192, MainSniffMS: 3000,
		OtherPerSource: 64, OtherNode: 2048, OtherFirstMS: 1000, NewRate: 1000, NewBurst: 1000,
		LookupPerSource: 64, LookupNode: 8192, MemUnit: 1 << 30, MemSlots: 1 << 30,
		DialFirstByteMS: 5000, MaxAgeS: 86400, IdleS: 600}, f.cfgOK
}
func (f *fake) LinkUp(run uint64, items []grant.OpenItem) {
	f.mu.Lock()
	f.staleAtUp = append(f.staleAtUp, f.lastSlow != nil && f.lastSlow.Err() != nil)
	f.items = items
	f.mu.Unlock()
	f.up <- run
}
func (f *fake) LinkDown() { f.down <- struct{}{} }
func (f *fake) Source(src netip.Addr) bool {
	f.mu.Lock()
	f.sources = append(f.sources, src)
	f.mu.Unlock()
	return true
}
func (f *fake) Lookup(ctx context.Context, _ uint64, src netip.Addr, name []byte, port uint16) *sock.LinkVerdict {
	if string(name) == "\x04slow\x04test\x00" {
		f.mu.Lock()
		f.lastSlow = ctx
		f.mu.Unlock()
		f.slowCtx <- ctx
		<-ctx.Done()
		return &sock.LinkVerdict{Kind: sock.VerdictBlock, Endpoint: bytes.Repeat([]byte{1}, 16), Account: bytes.Repeat([]byte{2}, 16), Tag: []byte("late")}
	}
	f.mu.Lock()
	f.looks = append(f.looks, string(name))
	f.mu.Unlock()
	if string(name) == "\x05block\x04test\x00" {
		return &sock.LinkVerdict{Kind: sock.VerdictBlock, Endpoint: bytes.Repeat([]byte{1}, 16), Account: bytes.Repeat([]byte{2}, 16), Tag: []byte("tag")}
	}
	return &sock.LinkVerdict{Kind: sock.VerdictNone}
}
func (f *fake) Moved(m *sock.LinkMoved) { f.mu.Lock(); f.moved = append(f.moved, *m); f.mu.Unlock() }
func (f *fake) Closed(c *sock.LinkClosed) {
	f.mu.Lock()
	f.closed = append(f.closed, c.IDs...)
	f.mu.Unlock()
}
func (f *fake) State(s *sock.LinkState) { f.mu.Lock(); f.states = append(f.states, *s); f.mu.Unlock() }
func (f *fake) Stats() *sock.LinkStatsRes {
	return &sock.LinkStatsRes{Counters: []sock.Counter{{Name: "puts_ok", Value: 3}}, LastRefused: "collision"}
}

// chanListener hands out the connections a test makes.
type chanListener struct {
	c    chan net.Conn
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { close(l.done); return nil }
func (l *chanListener) Addr() net.Addr { return &net.UnixAddr{} }

func newServer(t *testing.T, f *fake) (*Server, *chanListener) {
	t.Helper()
	srv := New(Config{Backend: f, Get: sockfake.GetUID, ProxyUID: sockfake.UIDProxy, HelloWithin: 3 * time.Second})
	f.srv = srv
	ln := &chanListener{c: make(chan net.Conn, 4), done: make(chan struct{})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return srv, ln
}

func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() { _ = tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake() }()
	buf := make([]byte, 16<<10)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	_ = b.Close()
	return buf[:n]
}

// The real client of B4 (internal/proxy) against this server over the fake socket: the
// two agree on hello, the open list, config, source, lookup, verdict, closed and end
// (2.1, 5.1).
func TestServerAgainstTheRealProxy(t *testing.T) {
	f := newFake()
	srv, ln := newServer(t, f)

	serve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serve.Close() })
	got := make(chan *sock.ServeFrame, 1)
	go func() {
		c, err := serve.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if fr, err := sock.ServeCodec.Read(c); err == nil {
			got <- fr
		}
		_, _ = c.Write([]byte("page"))
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // held open until the proxy closes it
	}()
	var lmu sync.Mutex
	var listeners []net.Listener
	dnsEnd, proxyEnd := sockfake.LinkPair()
	dialed := make(chan struct{}, 1)
	p := proxy.New(proxy.Options{
		DialLink: func(ctx context.Context) (net.Conn, error) {
			select {
			case dialed <- struct{}{}:
				ln.c <- dnsEnd.Conn
				return proxyEnd.Conn, nil
			default:
				<-ctx.Done()
				return nil, ctx.Err()
			}
		},
		DialServe: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serve.Addr().String())
		},
		DialTarget: func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed },
		Listen: func(string) (net.Listener, error) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				lmu.Lock()
				listeners = append(listeners, l)
				lmu.Unlock()
			}
			return l, err
		},
		Sys:   proxy.NewSys(),
		Retry: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-f.up:
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy's hello and open list never reached the backend")
	}
	// config comes after the open list: the proxy then listens.
	var addr string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		lmu.Lock()
		if len(listeners) > 1 {
			addr = listeners[1].Addr().String() // [0] is port 80, [1] port 443
		}
		lmu.Unlock()
		if addr != "" {
			break
		}
	}
	if addr == "" {
		t.Fatal("the proxy never listened: no config reached it")
	}
	if !srv.Up() {
		t.Fatal("the server does not hold the proxy")
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello := clientHello(t, "block.test")
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case fr := <-got:
		if fr.Name != "block.test" || fr.Port != 443 || !bytes.Equal(fr.Endpoint, bytes.Repeat([]byte{1}, 16)) {
			t.Fatalf("serve frame %+v", fr)
		}
	case <-time.After(5 * time.Second):
		f.mu.Lock()
		t.Fatalf("no serve frame: the verdict did not reach the proxy (sources %v, looks %q, closed %v, states %+v)", f.sources, f.looks, f.closed, f.states)
	}
	f.mu.Lock()
	if len(f.looks) != 1 || f.looks[0] != "\x05block\x04test\x00" || len(f.sources) == 0 || f.sources[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("looks %q sources %v", f.looks, f.sources)
	}
	f.mu.Unlock()
	// A name the backend answers none for: closed with no byte.
	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	_, _ = c2.Write(clientHello(t, "other.test"))
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _ := c2.Read(make([]byte, 1)); n != 0 {
		t.Fatal("a none verdict sent bytes")
	}

	// end by id closes the block connection, and `closed` reaches the backend.
	if !srv.End([]uint64{1}, nil) {
		t.Fatal("End found no proxy")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		f.mu.Lock()
		n := len(f.closed)
		f.mu.Unlock()
		if n > 0 {
			break
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.closed) == 0 {
		t.Fatal("no `closed` reached the backend")
	}
}

// The peer checks (2.1): a uid of root may send `stats` and nothing else, a stranger's
// connection is closed, and a proxy frame of dns's own type ends the link.
func TestPeerChecks(t *testing.T) {
	f := newFake()
	_, ln := newServer(t, f)

	root, rc := sockfake.LinkPairAs(sockfake.UIDRoot)
	ln.c <- root.Conn
	if err := rc.Send(&sock.LinkMsg{Type: sock.TLinkStats, Stats: &sock.LinkStats{}}); err != nil {
		t.Fatal(err)
	}
	m, err := rc.Recv()
	if err != nil || m.Type != sock.TLinkStatsRes || m.StatsRes.LastRefused != "collision" {
		t.Fatalf("%+v %v", m, err)
	}

	// root sending anything else is closed.
	root2, rc2 := sockfake.LinkPairAs(sockfake.UIDRoot)
	ln.c <- root2.Conn
	_ = rc2.Send(&sock.LinkMsg{Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: 1}})
	if _, err := rc2.Recv(); err == nil {
		t.Fatal("root may send stats alone")
	}

	// A stranger's uid is closed before a frame is read.
	st, sc := sockfake.LinkPairAs(sockfake.UIDBlock)
	ln.c <- st.Conn
	if _, err := sc.Recv(); err == nil {
		t.Fatal("a stranger was served")
	}

	// The proxy sends a frame that only dns may send: the link ends.
	d, p := sockfake.LinkPair()
	ln.c <- d.Conn
	_ = p.Send(&sock.LinkMsg{Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: 7}})
	_ = p.Send(&sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Last: true}})
	select {
	case <-f.up:
	case <-time.After(5 * time.Second):
		t.Fatal("link-up")
	}
	if m, err := p.Recv(); err != nil || m.Type != sock.TLinkConfig {
		t.Fatalf("config after the list: %+v %v", m, err)
	}
	_ = p.Send(&sock.LinkMsg{Type: sock.TLinkVerdict, Verdict: &sock.LinkVerdict{ID: 1, Kind: sock.VerdictNone}})
	select {
	case <-f.down:
	case <-time.After(5 * time.Second):
		t.Fatal("a frame of dns's type did not end the link")
	}
}

// A new proxy replaces the old one; the old one's close does not take the new one's
// place down.
func TestNewProxyReplacesTheOld(t *testing.T) {
	f := newFake()
	srv, ln := newServer(t, f)
	hs := func() (*sockfake.Endpoint[sock.LinkMsg], *sockfake.Endpoint[sock.LinkMsg]) {
		d, p := sockfake.LinkPair()
		ln.c <- d.Conn
		_ = p.Send(&sock.LinkMsg{Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: 1}})
		_ = p.Send(&sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Last: true}})
		<-f.up
		return d, p
	}
	_, p1 := hs()
	_, p2 := hs()
	if _, err := p1.Recv(); err == nil {
		// the first frame may be its config; the next read must fail once it is closed
		if _, err := p1.Recv(); err == nil {
			t.Fatal("the old proxy's link stayed open")
		}
	}
	time.Sleep(50 * time.Millisecond)
	if !srv.Up() {
		t.Fatal("the new proxy was dropped with the old")
	}
	if m, err := p2.Recv(); err != nil || m.Type != sock.TLinkConfig {
		t.Fatalf("%+v %v", m, err)
	}
	// The fake socket is synchronous: a write waits for the read.
	sent := make(chan bool, 1)
	go func() { sent <- srv.End(nil, []string{"127.0.0.20:20001"}) }()
	if m, err := p2.Recv(); err != nil || m.Type != sock.TLinkEnd || m.End.Socks[0] != "127.0.0.20:20001" {
		t.Fatalf("%+v %v", m, err)
	}
	if !<-sent {
		t.Fatal("end")
	}
}

// The lookups of a replaced proxy session are cancelled before the new session's
// table is rebuilt, and its frames no longer reach the Backend: a late admit or a
// stale closed must not touch the rebuilt table (ids restart with each proxy run).
func TestReplacedSessionIsCutOffBeforeTheRebuild(t *testing.T) {
	f := newFake()
	srv, ln := newServer(t, f)
	d1, p1 := sockfake.LinkPair()
	ln.c <- d1.Conn
	_ = p1.Send(&sock.LinkMsg{Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: 1}})
	_ = p1.Send(&sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Last: true}})
	<-f.up
	if m, err := p1.Recv(); err != nil || m.Type != sock.TLinkConfig {
		t.Fatalf("%+v %v", m, err)
	}
	_ = p1.Send(&sock.LinkMsg{Type: sock.TLinkLookup, Lookup: &sock.LinkLookup{ID: 9, Source: netip.MustParseAddr("192.0.2.1").AsSlice(), Name: []byte("\x04slow\x04test\x00"), Port: 443}})
	var oldCtx context.Context
	select {
	case oldCtx = <-f.slowCtx:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup did not start")
	}
	srv.mu.Lock()
	oldSession := srv.cur
	srv.mu.Unlock()

	d2, p2 := sockfake.LinkPair()
	ln.c <- d2.Conn
	_ = p2.Send(&sock.LinkMsg{Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: 2}})
	_ = p2.Send(&sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Last: true}})
	<-f.up
	f.mu.Lock()
	stale := append([]bool(nil), f.staleAtUp...)
	f.mu.Unlock()
	if len(stale) != 2 || !stale[1] || oldCtx.Err() == nil {
		t.Fatalf("the old session's lookup must be cancelled before the new LinkUp: %v", stale)
	}
	ran := false
	if srv.current(oldSession, func() { ran = true }) || ran {
		t.Fatal("a frame of the replaced session reached the Backend")
	}
}
