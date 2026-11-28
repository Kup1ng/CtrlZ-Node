package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

// clientHello returns the bytes a TLS client sends first for the server name. The
// client talks to a pipe that is read once and then dropped, so the bytes are real
// and no server is needed.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	}()
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

// testConfig is a config with room for every test; each test lowers what it tests.
func testConfig() *sock.ProxyConfig {
	return &sock.ProxyConfig{
		BindIP:        "127.0.0.1",
		MainPerSource: 512, MainNode: 8192, MainSniffMS: 3000,
		OtherPerSource: 64, OtherNode: 2048, OtherFirstMS: 1000,
		NewRate: 1000, NewBurst: 1000,
		LookupPerSource: 64, LookupNode: 8192,
		MemUnit: 1 << 30, MemSlots: 1 << 30,
		DialFirstByteMS: 5000, MaxAgeS: 86400, IdleS: 600,
	}
}

// rig is a proxy with a fake dns on the other end of its link, and real loopback
// listeners and SOCKS targets.
type rig struct {
	t      *testing.T
	p      *Proxy
	dns    *sockfake.Endpoint[sock.LinkMsg]
	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.Mutex
	listeners []net.Listener
	serveAddr string
	Sys       *fakeSys
	// more are the links after the first, for a test of a reconnect.
	more chan net.Conn
}

func newRig(t *testing.T, mod func(*Options)) *rig {
	t.Helper()
	r := &rig{t: t, done: make(chan struct{}), Sys: &fakeSys{}, more: make(chan net.Conn, 4)}
	dns, prox := sockfake.LinkPair()
	r.dns = dns
	dialed := make(chan struct{}, 1)
	o := Options{
		DialLink: func(ctx context.Context) (net.Conn, error) {
			select {
			case dialed <- struct{}{}:
				return prox.Conn, nil
			default:
				select {
				case c := <-r.more:
					return c, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		},
		DialTarget: func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		DialServe: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", r.serveAddr)
		},
		Listen: func(string) (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				r.mu.Lock()
				r.listeners = append(r.listeners, ln)
				r.mu.Unlock()
			}
			return ln, err
		},
		Sys:   r.Sys,
		Retry: 20 * time.Millisecond,
		Sweep: 20 * time.Millisecond,
	}
	if mod != nil {
		mod(&o)
	}
	r.p = New(o)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { _ = r.p.Run(ctx); close(r.done) }()
	t.Cleanup(func() {
		cancel()
		<-r.done
		dns.Close()
	})
	return r
}

// handshake plays dns for the start of a link: hello, the open list, and a config.
func (r *rig) handshake(cfg *sock.ProxyConfig) []sock.OpenItem {
	r.t.Helper()
	m := r.recv()
	if m.Type != sock.TLinkHello {
		r.t.Fatalf("first frame %q", m.Type)
	}
	var items []sock.OpenItem
	for {
		m = r.recv()
		if m.Type != sock.TLinkOpen {
			r.t.Fatalf("want open, got %q", m.Type)
		}
		items = append(items, m.Open.Items...)
		if m.Open.Last {
			break
		}
	}
	if cfg != nil {
		if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkConfig, Config: cfg}); err != nil {
			r.t.Fatal(err)
		}
		r.waitListening()
	}
	return items
}

func (r *rig) waitListening() {
	r.t.Helper()
	for i := 0; i < 500; i++ {
		r.mu.Lock()
		n := len(r.listeners)
		r.mu.Unlock()
		if n >= 2 && r.p.Listening() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatal("the proxy never listened")
}

func (r *rig) addr(i int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listeners[i].Addr().String()
}

func (r *rig) recv() *sock.LinkMsg {
	r.t.Helper()
	m, err := r.dns.Recv()
	if err != nil {
		r.t.Fatalf("link read: %v", err)
	}
	return m
}

// recvType reads frames until one of the type arrives; state frames in between are
// skipped.
func (r *rig) recvType(typ string) *sock.LinkMsg {
	r.t.Helper()
	for i := 0; i < 50; i++ {
		m := r.recv()
		if m.Type == typ {
			return m
		}
		if m.Type != sock.TLinkState && m.Type != sock.TLinkClosed {
			r.t.Fatalf("want %q, got %q", typ, m.Type)
		}
	}
	r.t.Fatalf("no %q", typ)
	return nil
}

// answerSource answers the source ask of a new connection.
func (r *rig) answerSource(known bool) uint64 {
	r.t.Helper()
	m := r.recvType(sock.TLinkSource)
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkSourceKnown, SourceKnown: &sock.LinkSourceKnown{ID: m.Source.ID, Known: known}}); err != nil {
		r.t.Fatal(err)
	}
	return m.Source.ID
}

func (r *rig) verdict(v *sock.LinkVerdict) {
	r.t.Helper()
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkVerdict, Verdict: v}); err != nil {
		r.t.Fatal(err)
	}
}

// route plays dns for one new connection: known source, then the verdict for its
// lookup; it returns the lookup that was asked.
func (r *rig) route(known bool, mk func(id uint64) *sock.LinkVerdict) *sock.LinkLookup {
	r.t.Helper()
	id := r.answerSource(known)
	m := r.recvType(sock.TLinkLookup)
	if m.Lookup.ID != id {
		r.t.Fatalf("lookup id %d, source id %d", m.Lookup.ID, id)
	}
	v := mk(id)
	v.ID = id
	r.verdict(v)
	return m.Lookup
}

func dialClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readSome(t *testing.T, c net.Conn, d time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if n == 0 && err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

// expectClosed checks that the connection ends with no byte.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(make([]byte, 64))
	if n != 0 || err == nil {
		t.Fatalf("want a closed connection, got %d bytes, err %v", n, err)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the connection stayed open")
	}
}

// socksServer is a SOCKS5 inbound with a behaviour per connection.
type socksServer struct {
	ln   net.Listener
	mu   sync.Mutex
	reqs []socksReq
	// behave runs after a good handshake; the connection is the target's side.
	behave func(c net.Conn, got []byte)
}

type socksReq struct {
	host string
	port uint16
	data []byte
}

func newSocks(t *testing.T, behave func(c net.Conn, got []byte)) *socksServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksServer{ln: ln, behave: behave}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *socksServer) addr() string { return s.ln.Addr().String() }

func (s *socksServer) serve(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 5 || hdr[3] != 5 {
		return
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		return
	}
	var host string
	switch one[0] {
	case 1:
		a := make([]byte, 4)
		_, _ = io.ReadFull(c, a)
		host = net.IP(a).String()
	case 3:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		n := make([]byte, int(l[0]))
		_, _ = io.ReadFull(c, n)
		host = string(n)
	}
	pb := make([]byte, 2)
	_, _ = io.ReadFull(c, pb)
	_, _ = c.Write([]byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	// The recorded bytes follow at once.
	// Read until the client has been quiet for a moment: the hello may arrive in pieces.
	buf := make([]byte, 32<<10)
	n := 0
	for {
		_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		m, err := c.Read(buf[n:])
		n += m
		if err != nil || n == len(buf) {
			break
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	s.mu.Lock()
	s.reqs = append(s.reqs, socksReq{host: host, port: uint16(pb[0])<<8 | uint16(pb[1]), data: bytes.Clone(buf[:n])})
	s.mu.Unlock()
	if s.behave != nil {
		s.behave(c, buf[:n])
	}
}

func (s *socksServer) requests() []socksReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]socksReq(nil), s.reqs...)
}

// echo answers with a fixed greeting and then copies.
func answerThenEcho(c net.Conn, _ []byte) {
	_, _ = c.Write([]byte("hello"))
	_, _ = io.Copy(c, c)
}

func hangForever(c net.Conn, _ []byte) { time.Sleep(10 * time.Second) }

func closeAtOnce(net.Conn, []byte) {}

type fakeSys struct {
	mu      sync.Mutex
	moved   map[net.Conn]uint64
	waiting map[net.Conn]int
	mem     map[string]uint64
}

func (f *fakeSys) Moved(c net.Conn) (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.moved[c]
	return v, ok
}

func (f *fakeSys) Waiting(c net.Conn) (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.waiting[c]
	return v, ok
}

func (f *fakeSys) SockMem(p string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mem[p], nil
}
