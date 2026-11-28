package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

// frames collects what dns receives, so a test can look at a period of silence on
// the link. The reader ends when the rig closes the link.
func (r *rig) frames() <-chan *sock.LinkMsg {
	out := make(chan *sock.LinkMsg, 256)
	go func() {
		for {
			m, err := r.dns.Recv()
			if err != nil {
				return
			}
			out <- m
		}
	}()
	return out
}

// waitPoll waits up to 3 s for cond.
func waitPoll(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never happened: %s", what)
}

// A connection that dns ends while it waits for the first byte of its first target
// goes to no later target and moves nowhere (5.2): dns was told it is closed, and a
// `moved` for it would hold a place for dial_hold.
func TestEndDuringTheFirstByteWaitDialsNothingMore(t *testing.T) {
	cfg := testConfig()
	cfg.DialFirstByteMS = 600
	r := newRig(t, nil)
	r.handshake(cfg)
	silent := newSocks(t, hangForever)
	live := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	lk := r.route(true, proxyVerdict(silent.addr(), live.addr()))
	waitPoll(t, "the first target got the hello", func() bool { return len(silent.requests()) == 1 })
	got := r.frames()
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkEnd, End: &sock.LinkEnd{IDs: []uint64{lk.ID}}}); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	closed := false
	deadline := time.After(1500 * time.Millisecond) // past the first-byte deadline
	for done := false; !done; {
		select {
		case m := <-got:
			switch m.Type {
			case sock.TLinkMoved:
				t.Fatalf("a moved frame for an ended connection: %+v", m.Moved)
			case sock.TLinkClosed:
				for _, p := range m.Closed.Pending {
					closed = closed || p.ID == lk.ID
				}
				for _, id := range m.Closed.IDs {
					closed = closed || id == lk.ID
				}
			}
		case <-deadline:
			done = true
		}
	}
	if !closed {
		t.Fatal("dns was not told the connection closed")
	}
	if n := len(live.requests()); n != 0 {
		t.Fatalf("the ended connection reached the next exit %d times", n)
	}
}

// bufConn records the buffer sizes set on it, as the unix socket of serve.sock
// would take them.
type bufConn struct {
	net.Conn
	read, write chan int
}

func (b *bufConn) SetReadBuffer(n int) error  { b.read <- n; return nil }
func (b *bufConn) SetWriteBuffer(n int) error { b.write <- n; return nil }

// The proxy's end of serve.sock holds 32 KiB buffers (10.2), as the block
// process's does, so a stalled page reader costs what the unit limits assume.
func TestServeSocketGets32KiBBuffers(t *testing.T) {
	read, write := make(chan int, 4), make(chan int, 4)
	var r *rig
	r = newRig(t, func(o *Options) {
		o.DialServe = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", r.serveAddr)
			if err != nil {
				return nil, err
			}
			return &bufConn{Conn: c, read: read, write: write}, nil
		}
	})
	blk := listenTCP(t)
	r.serveAddr = blk.Addr().String()
	go func() {
		if sc, err := blk.Accept(); err == nil {
			defer sc.Close()
			_, _ = io.Copy(io.Discard, sc)
		}
	}()
	r.handshake(testConfig())
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	r.route(true, func(uint64) *sock.LinkVerdict {
		return &sock.LinkVerdict{Kind: sock.VerdictBlock, Endpoint: bytes.Repeat([]byte{1}, 16), Account: bytes.Repeat([]byte{2}, 16), PageHash: bytes.Repeat([]byte{3}, 32)}
	})
	for _, ch := range []chan int{read, write} {
		select {
		case n := <-ch:
			if n != 32<<10 {
				t.Fatalf("buffer %d, want 32 KiB", n)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a buffer was not set")
		}
	}
}

// The idle rule of 5.4 also reaches a block-page connection: its far socket is a
// unix socket with no TCP_INFO, so the client socket alone is judged. Without that
// a client that sends its hello and goes silent holds a kind 2 place for the age cap.
func TestIdleBlockPageConnectionWithANonTCPFarSocketEnds(t *testing.T) {
	cfg := testConfig()
	cfg.IdleS = 1
	var r *rig
	r = newRig(t, func(o *Options) { o.Sweep = time.Hour })
	r.Sys.moved, r.Sys.waiting, r.Sys.mem = map[net.Conn]uint64{}, map[net.Conn]int{}, map[string]uint64{}
	blk := listenTCP(t)
	r.serveAddr = blk.Addr().String()
	go func() {
		if sc, err := blk.Accept(); err == nil {
			defer sc.Close()
			_, _ = io.Copy(io.Discard, sc)
		}
	}()
	r.handshake(cfg)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	r.route(true, func(uint64) *sock.LinkVerdict {
		return &sock.LinkVerdict{Kind: sock.VerdictBlock, Endpoint: bytes.Repeat([]byte{1}, 16), Account: bytes.Repeat([]byte{2}, 16), PageHash: bytes.Repeat([]byte{3}, 32)}
	})
	waitPoll(t, "the connection holds a block socket", func() bool {
		s := r.p.snapshot()
		return len(s) == 1 && s[0].far() != nil
	})
	cn := r.p.snapshot()[0]
	// Only the client socket is known to the fake kernel: the far one is not TCP.
	r.Sys.mu.Lock()
	r.Sys.moved[cn.c] = 500
	r.Sys.mu.Unlock()
	now := time.Now()
	r.p.samplePass(now)
	if r.p.Open() != 1 {
		t.Fatal("ended at the first sample")
	}
	r.p.samplePass(now.Add(2 * time.Second))
	if r.p.Open() != 0 || r.p.refused[rIdle].Load() != 1 {
		t.Fatalf("open %d, idle %d", r.p.Open(), r.p.refused[rIdle].Load())
	}
	expectClosed(t, c)
}

// A hello over MaxSniff is refused with no lookup: the recorder stops the read at
// 16 KiB, so a source cannot make the proxy buffer more before dns has judged it.
func TestHelloOverTheSniffLimitIsRefused(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	c := dialClient(t, r.addr(1))
	r.answerSource(true)
	// A record header that promises 30,000 bytes, then more than the limit.
	big := append([]byte{22, 3, 1, 0x75, 0x30}, bytes.Repeat([]byte{1}, MaxSniff+1000)...)
	_, _ = c.Write(big)
	expectClosed(t, c)
	if r.p.refused[rSniff].Load() != 1 {
		t.Fatalf("sniff refusals %d", r.p.refused[rSniff].Load())
	}
}

// The read deadline is absolute from the first byte of waiting: a hello that is
// never finished, and one that trickles in a byte at a time, are both cut at the
// pool's time and neither holds its place longer (5.4).
func TestSlowHelloIsCutAtThePoolTime(t *testing.T) {
	for _, known := range []bool{true, false} {
		name := "main pool"
		if !known {
			name = "other pool"
		}
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			cfg.MainSniffMS, cfg.OtherFirstMS = 400, 400
			r := newRig(t, nil)
			r.handshake(cfg)
			hello := clientHello(t, "example.com")
			c := dialClient(t, r.addr(1))
			r.answerSource(known)
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			go func() {
				// One byte every 40 ms: the whole hello would take seconds.
				for _, b := range hello {
					select {
					case <-stop:
						return
					case <-time.After(40 * time.Millisecond):
					}
					if _, err := c.Write([]byte{b}); err != nil {
						return
					}
				}
			}()
			start := time.Now()
			expectClosed(t, c)
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("held for %v", d)
			}
			if r.p.refused[rSniff].Load() != 1 {
				t.Fatalf("sniff refusals %d", r.p.refused[rSniff].Load())
			}
		})
	}
}

// A hello in two TLS records and several segments is read whole, its name is the
// one looked up, and the target gets exactly the bytes the client sent.
func TestHelloSplitOverRecordsAndSegments(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	live := newSocks(t, answerThenEcho)
	hello := clientHello(t, "example.com")
	payload := hello[5:]
	rec := func(p []byte) []byte {
		return append([]byte{22, hello[1], hello[2], byte(len(p) >> 8), byte(len(p))}, p...)
	}
	first, second := rec(payload[:30]), rec(payload[30:])
	sent := append(append([]byte(nil), first...), second...)
	c := dialClient(t, r.addr(1))
	go func() {
		// Cut inside the first header, inside the first payload and at the record end.
		for _, part := range [][]byte{sent[:3], sent[3:20], sent[20:len(first)], sent[len(first) : len(first)+4], sent[len(first)+4:]} {
			_, _ = c.Write(part)
			time.Sleep(30 * time.Millisecond)
		}
	}()
	lk := r.route(true, proxyVerdict(live.addr()))
	if want, _, _ := normalize("example.com"); !bytes.Equal(lk.Name, want) {
		t.Fatalf("looked up %q", lk.Name)
	}
	if got := readSome(t, c, 3*time.Second); string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	if reqs := live.requests(); len(reqs) != 1 || !bytes.Equal(reqs[0].data, sent) {
		t.Fatal("the target did not get the bytes the client sent")
	}
}

// The caps of lookups in flight, for one source and for the node (5.4): over a cap
// the connection is closed before any ask, and a place is free again once the
// verdict has come.
func TestLookupCaps(t *testing.T) {
	for _, tc := range []struct {
		name          string
		perSrc, perND uint32
	}{{"per source", 1, 64}, {"per node", 64, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.LookupPerSource, cfg.LookupNode = tc.perSrc, tc.perND
			r := newRig(t, nil)
			r.handshake(cfg)
			hello := clientHello(t, "example.com")
			c1 := dialClient(t, r.addr(1))
			_, _ = c1.Write(hello)
			id1 := r.answerSource(true)
			r.recvType(sock.TLinkLookup)

			c2 := dialClient(t, r.addr(1))
			_, _ = c2.Write(hello)
			r.answerSource(true)
			expectClosed(t, c2)
			if r.p.refused[rLookup].Load() != 1 {
				t.Fatalf("lookup refusals %d", r.p.refused[rLookup].Load())
			}

			// The verdict frees the place.
			r.verdict(&sock.LinkVerdict{ID: id1, Kind: sock.VerdictNone})
			expectClosed(t, c1)
			c3 := dialClient(t, r.addr(1))
			_, _ = c3.Write(hello)
			r.answerSource(true)
			r.recvType(sock.TLinkLookup)
		})
	}
}

// A link that drops while a lookup is in flight ends that connection with no byte,
// and the next link's open list does not name it: it never had a verdict.
func TestLinkDropDuringALookup(t *testing.T) {
	dns2, prox2 := sockfake.LinkPair()
	r := newRig(t, nil)
	r.more <- prox2.Conn
	r.handshake(testConfig())
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	r.answerSource(true)
	r.recvType(sock.TLinkLookup)
	r.dns.Close()
	expectClosed(t, c)
	r2 := &rig{t: t, dns: dns2, p: r.p, listeners: r.listeners}
	if items := r2.handshake(nil); len(items) != 0 {
		t.Fatalf("open list %+v", items)
	}
	dns2.Close()
}

// A connection ended while its lookup is in flight is reported closed to dns (which
// may already have charged a place for it), and the verdict that comes late is
// dropped: nothing is dialled for it.
func TestEndDuringALookupReportsClosedAndIgnoresTheLateVerdict(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	s := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	id := r.answerSource(true)
	r.recvType(sock.TLinkLookup)
	got := r.frames()
	if err := r.dns.Send(&sock.LinkMsg{Type: sock.TLinkEnd, End: &sock.LinkEnd{IDs: []uint64{id}}}); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	told := false
	timeout := time.After(3 * time.Second)
	for !told {
		select {
		case m := <-got:
			if m.Type == sock.TLinkClosed {
				for _, x := range m.Closed.IDs {
					told = told || x == id
				}
			}
		case <-timeout:
			t.Fatal("dns was not told the connection closed")
		}
	}
	v := proxyVerdict(s.addr())(id)
	v.ID = id
	r.verdict(v)
	time.Sleep(200 * time.Millisecond)
	if len(s.requests()) != 0 || r.p.Open() != 0 {
		t.Fatal("a late verdict was acted on")
	}
}

// A config that a link's reader decodes after the next session began is not applied:
// the listeners open only on the config of the link dns has judged the open list of.
func TestConfigOfAnOldLinkIsDropped(t *testing.T) {
	r := newRig(t, nil)
	r.handshake(testConfig())
	before := r.p.sweepConfig()
	old := *testConfig()
	old.MainNode = 1
	r.p.applyConfig(newLink(nil), &old)
	if r.p.sweepConfig() != before {
		t.Fatal("the config of another link was applied")
	}
}

// The recorder reads no byte past MaxSniff: a hello that needs more is refused with
// exactly the limit recorded, and not after buffering the rest of it.
func TestSniffTLSReadsNoMoreThanTheLimit(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// A handshake message of 25,000 bytes in records of 16,000: it cannot be
	// complete inside the limit.
	msg := append([]byte{1, 0, 0x61, 0xa8}, bytes.Repeat([]byte{7}, 25000)...)
	var wire []byte
	for len(msg) > 0 {
		n := min(len(msg), 16000)
		wire = append(wire, 22, 3, 1, byte(n>>8), byte(n))
		wire = append(wire, msg[:n]...)
		msg = msg[n:]
	}
	go func() { _, _ = a.Write(wire) }()
	_, rec, err := sniffTLS(b, time.Now().Add(2*time.Second))
	if err == nil {
		t.Fatal("an oversize hello was accepted")
	}
	if len(rec) > MaxSniff {
		t.Fatalf("recorded %d bytes, limit %d", len(rec), MaxSniff)
	}
}
