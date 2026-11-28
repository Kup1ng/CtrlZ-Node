package listen

// Tests of review round 1 (p4n-W6-r1-*): the write-stall deadline on every
// transport, the reply queue of a connection, the body deadline of DoH, the
// header deadline of DoH3 and the size of what a declared length commits.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"net/http"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// waitClosed polls the observer for a close of t with the reason.
func waitClosed(f *fixture, tr Transport, why CloseReason, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if f.obs.closedCount(tr, why) > 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return f.obs.closedCount(tr, why) > 0
}

// A peer that never reads but keeps sending queries must be closed at the stall
// time counted from its first blocked write, and must not make the node queue
// replies or goroutines without bound (p4n-W6-r1-1, -5). Driven on a net.Pipe,
// where every write blocks until it is read, the way a full socket does.
func TestReaderThatNeverReadsKeepsSending(t *testing.T) {
	f := newFixture(t, withTransports(TCP), shortSettings(func(s *limits.ListenerSettings) {
		s.IdleTimeout = 5 * time.Second
		s.BodyTimeout = 5 * time.Second
		s.WriteStall = time.Second // long enough to sample the connection after its start-up burst
	}))
	cfg := f.cfg
	cfg.Handler = f.stub
	c, err := newCore(context.Background(), &cfg, TCP)
	if err != nil {
		t.Fatal(err)
	}
	srv := newStream(c, nil, nil)
	cl, sv := net.Pipe()
	defer cl.Close()
	slot, _ := f.set.Admit(TCP, netip.MustParseAddr("127.0.0.1"))
	done := make(chan struct{})
	var why atomic.Uint32
	cfg.Observer.Closed = func(_ Transport, r CloseReason) { why.Store(uint32(r)) }
	srv.wg.Add(1)
	go func() {
		srv.serveConn(sv, netip.MustParseAddrPort("127.0.0.1:4000"), slot)
		close(done)
	}()

	base := runtime.NumGoroutine()
	var peak atomic.Int64
	stopSampling := make(chan struct{})
	began := time.Now()
	go func() {
		for {
			select {
			case <-stopSampling:
				return
			case <-time.After(5 * time.Millisecond):
				// The reader pauses once a reply is queued behind a write the peer does
				// not take. On a loaded machine the handlers of the first frames can wait
				// for a processor while the reader reads on, so the count is taken after
				// that start-up burst (a few hundred ms), which round 2 bounds in bytes.
				if time.Since(began) < 300*time.Millisecond {
					continue
				}
				if n := int64(runtime.NumGoroutine()); n > peak.Load() {
					peak.Store(n)
				}
			}
		}
	}()
	defer close(stopSampling)

	// The client sends queries as fast as the server reads them, and never reads.
	go func() {
		for i := 0; ; i++ {
			b, _ := mkq(fmt.Sprintf("q%d.example.org.", i), dns.TypeA).Pack()
			if _, err := cl.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("the connection of a peer that never reads but keeps sending stayed open")
	}
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("closed after %v, the stall time is 1 s from the first blocked write", d)
	}
	if CloseReason(why.Load()) != CloseStall {
		t.Fatalf("closed for %v, want a stall", CloseReason(why.Load()))
	}
	// 64 replies wait at most, plus the ones in the handler; not one goroutine
	// per query the peer manages to send.
	if grown := int(peak.Load()) - base; grown > 300 {
		t.Fatalf("goroutines grew by %d while the peer did not read", grown)
	}
}

// The queue of replies is bounded and the reader pauses while it is full; it
// resumes as the peer reads, and nothing is lost.
func TestReplyQueuePausesTheReaderAndResumes(t *testing.T) {
	f := newFixture(t, withTransports(TCP), shortSettings(func(s *limits.ListenerSettings) {
		s.WriteStall = 30 * time.Second
		s.IdleTimeout = 30 * time.Second
	}))
	c := f.mustDial(TCP).(*frameClient)
	// 400 pipelined queries answered by a client that reads: all of them come.
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := ask(c, fmt.Sprintf("p%d.example.org.", i), dns.TypeA)
			if err != nil || !answered(r) {
				bad.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d of 400 pipelined queries unanswered", bad.Load())
	}
}

// readBody does not allocate what a peer declares before the bytes arrive
// (p4n-W6-r1-3).
func TestReadBodyDoesNotTrustTheDeclaredLength(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const conns = 2000
	errs := make(chan error, conns)
	readers := make([]*io.PipeWriter, conns)
	for i := range readers {
		r, w := io.Pipe()
		readers[i] = w
		go func() { _, err := readBody(r, 65535); errs <- err }()
	}
	time.Sleep(300 * time.Millisecond)
	runtime.ReadMemStats(&after)
	grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	// 2000 declared frames of 64 KiB would be 128 MB; with nothing sent, a few KB each at most.
	if grown > 40<<20 {
		t.Fatalf("2000 frames that declared 64 KiB and sent nothing hold %d MB", grown>>20)
	}
	for _, w := range readers {
		_ = w.CloseWithError(io.ErrClosedPipe)
	}
	for range readers {
		<-errs
	}
	_ = pr
	// And a frame that does arrive is read whole.
	want := bytes.Repeat([]byte{7}, 50000)
	got, err := readBody(bytes.NewReader(want), len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("readBody of a whole frame: %v", err)
	}
	if _, err := readBody(bytes.NewReader(want[:10]), 20); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a short frame gave %v", err)
	}
}

// A DoH client that advertises a zero HTTP/2 window holds its replies in
// net/http's flow control, where no socket write is blocked. The connection
// must still be closed at the stall time (p4n-W6-r1-2, -6).
func TestHTTP2ZeroWindowIsClosed(t *testing.T) {
	f := newFixture(t, withTransports(DoH), shortSettings(nil))
	conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "h2"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(http2.ClientPreface))
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatal(err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for i := 0; i < 20; i++ {
		q, _ := mkq("big-"+itoa(i)+".example.org.", dns.TypeTXT).Pack()
		hb.Reset()
		for _, h := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", testSNI},
			{":path", "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(q)}, {"accept", "application/dns-message"}} {
			_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(2*i + 1), BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
	}
	// Answer the server's settings and pings, and never open the window.
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	for {
		fm, err := fr.ReadFrame()
		if err != nil {
			break
		}
		switch v := fm.(type) {
		case *http2.SettingsFrame:
			if !v.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !v.IsAck() {
				_ = fr.WritePing(true, v.Data)
			}
		case *http2.DataFrame:
			if len(v.Data()) > 0 {
				t.Fatal("a DATA frame was sent into a zero window")
			}
		}
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("the connection with a zero window stayed open for %v", d)
	}
	if !waitClosed(f, DoH, CloseStall, 2*time.Second) {
		t.Fatalf("closes: %v", f.obs.closed)
	}
}

// An HTTP/1.1 client that sends many requests for large replies and never
// reads: net/http writes inside the handler, which must count as a write the
// peer has not read.
func TestHTTP1NonReadingClientIsClosed(t *testing.T) {
	f := newFixture(t, withTransports(DoH), shortSettings(nil))
	conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q, _ := mkq("big-x.example.org.", dns.TypeTXT).Pack()
	req := fmt.Sprintf("GET /dns-query?dns=%s HTTP/1.1\r\nHost: %s\r\nAccept: application/dns-message\r\n\r\n",
		base64.RawURLEncoding.EncodeToString(q), testSNI)
	go func() {
		for i := 0; i < 20000; i++ {
			if _, err := io.WriteString(conn, req); err != nil {
				return
			}
		}
	}()
	if !waitClosed(f, DoH, CloseStall, 8*time.Second) {
		t.Fatalf("a client that never reads kept its connection: %v", f.obs.closed)
	}
}

// DoQ and DoH3 with a receive window that cannot take the reply.
func TestQUICTinyWindowIsClosed(t *testing.T) {
	f := newFixture(t, withTransports(DoQ, DoH3), shortSettings(nil))
	t.Run("DoQ", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, f.addr(DoQ), f.tlsConf("", "doq"), &quic.Config{
			MaxIdleTimeout: 20 * time.Second, InitialStreamReceiveWindow: 256, MaxStreamReceiveWindow: 256,
			InitialConnectionReceiveWindow: 1024, MaxConnectionReceiveWindow: 1024,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseWithError(0, "")
		for i := 0; i < 3; i++ {
			str, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			m := mkq("big-"+itoa(i)+".example.org.", dns.TypeTXT)
			m.Id = 0
			b, _ := m.Pack()
			_, _ = str.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
			_ = str.Close()
			// never read
		}
		if !waitClosed(f, DoQ, CloseStall, 5*time.Second) {
			t.Fatalf("a DoQ peer that never reads kept its connection: %v", f.obs.closed)
		}
	})
	t.Run("DoH3", func(t *testing.T) {
		tr := &http3.Transport{TLSClientConfig: f.tlsConf("", "h3"), QUICConfig: &quic.Config{
			MaxIdleTimeout: 20 * time.Second, InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024,
			InitialConnectionReceiveWindow: 4096, MaxConnectionReceiveWindow: 4096,
		}}
		defer tr.Close()
		cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
		for i := 0; i < 3; i++ {
			go func(i int) {
				resp, err := dohDo(cl, "https://"+f.addr(DoH3)+"/dns-query", mkq("big-"+itoa(i)+".example.org.", dns.TypeTXT), "POST", nil)
				if err == nil {
					time.Sleep(10 * time.Second) // the body is never read
					resp.Body.Close()
				}
			}(i)
		}
		if !waitClosed(f, DoH3, CloseStall, 6*time.Second) {
			t.Fatalf("a DoH3 peer that never reads kept its connection: %v", f.obs.closed)
		}
	})
}

// A DoH request whose body the handler never reads (a GET with a body, a POST
// answered 415) is thrown away by net/http, which must not be able to wait for
// it for longer than the body deadline (p4n-W6-r1-7).
func TestDoHUnreadBodyHasADeadline(t *testing.T) {
	f := newFixture(t, withTransports(DoH), shortSettings(nil))
	q, _ := mkq("x.example.org.", dns.TypeA).Pack()
	cases := map[string]string{
		"GET with a body": fmt.Sprintf("GET /dns-query?dns=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 60000\r\n\r\n",
			base64.RawURLEncoding.EncodeToString(q), testSNI),
		"POST of another type": fmt.Sprintf("POST /dns-query HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nContent-Length: 60000\r\n\r\n", testSNI),
	}
	for name, head := range cases {
		t.Run(name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "http/1.1"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, head)
			stop := make(chan struct{})
			defer close(stop)
			go func() { // one byte every 300 ms, for ever
				for {
					select {
					case <-stop:
						return
					case <-time.After(300 * time.Millisecond):
						if _, err := conn.Write([]byte{'x'}); err != nil {
							return
						}
					}
				}
			}()
			_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			start := time.Now()
			// Either the answer comes (net/http answers first) and then the
			// connection ends, or the connection ends: in both, within the
			// deadline and a margin, and not never.
			if _, err := io.ReadAll(conn); err != nil && isTimeout(err) {
				t.Fatalf("still open after %v with a body that never ends", time.Since(start))
			}
		})
	}
}

// A POST whose handler runs longer than the body deadline is still answered:
// the deadline is cleared once the body is read.
func TestDoHSlowHandlerOutlivesTheBodyDeadline(t *testing.T) {
	f := newFixture(t, shortSettings(nil))
	f.stub.SlowFor = 1200 * time.Millisecond
	for _, tr := range []Transport{DoH, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			c := f.mustDial(tr)
			r, err := ask(c, "slow-x.example.org.", dns.TypeA)
			if err != nil || !answered(r) {
				t.Fatalf("a POST answered after more than the body deadline: %v %v", r, err)
			}
		})
	}
	f2 := newFixture(t, withTransports(DoH), shortSettings(nil))
	f2.stub.SlowFor = 1200 * time.Millisecond
	c := f2.dohClient(false, "")
	defer c.close()
	if r, err := ask(c, "slow-y.example.org.", dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("HTTP/1.1: %v %v", r, err)
	}
}

// DoH3 has the header deadline of its registry entry, and the idle deadline
// cannot close a connection while a request's headers are arriving
// (p4n-W6-r1-4, -8).
func TestDoH3HeaderDeadlineAndIdle(t *testing.T) {
	f := newFixture(t, withTransports(DoH3), shortSettings(func(s *limits.ListenerSettings) {
		s.IdleTimeout = 400 * time.Millisecond
		s.ReadHeaderTimeout = 1200 * time.Millisecond
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, f.addr(DoH3), f.tlsConf("", "h3"), &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The start of a HEADERS frame of 16 bytes, with one byte of it.
	_, _ = str.Write([]byte{0x01, 0x10, 0x00})
	start := time.Now()
	_ = str.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, err = str.Read(make([]byte, 1))
	d := time.Since(start)
	var se *quic.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("the stream ended with %v after %v, want a reset of that stream", err, d)
	}
	if d < 900*time.Millisecond || d > 2500*time.Millisecond {
		t.Fatalf("the stream was reset after %v, want about the 1.2 s header deadline (the idle deadline is 400 ms and must not act)", d)
	}
}

// The header-phase queue of DoH3: a stream waiting for its headers keeps the
// connection from being idle, ends when a handler starts, and at the deadline.
func TestHdrQueue(t *testing.T) {
	q, idle, _, _ := fakeQuiet(10*time.Second, 30*time.Second)
	h := newHdrQueue(q, 100*time.Millisecond)
	defer h.stop()
	if !idle.on() {
		t.Fatal("not idle")
	}
	h.add(1)
	if idle.on() {
		t.Fatal("idle armed with a request stream whose headers are not read")
	}
	// The handler of some stream starts: its own item opens first, then the
	// header wait ends, so the connection is never seen quiet in between.
	own := q.begin()
	h.endStream(1)
	if idle.on() {
		t.Fatal("idle armed with a handler running")
	}
	q.abort(own)
	if !idle.on() {
		t.Fatal("idle not armed after the request")
	}
	// A stream that dies before its handler is ended by the deadline.
	h.add(1)
	if idle.on() {
		t.Fatal("idle armed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !idle.on() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !idle.on() {
		t.Fatal("a stream that never sent its headers still counts after the deadline")
	}
}

// A datagram that does not parse is answered FORMERR only while its source is
// inside the step-1 limits, never past them (p4n-W6-r1-9).
func TestUDPFormErrIsLimited(t *testing.T) {
	r := limits.Default()
	r = lowered(r, "udp-query-addr", func(e *limits.Entry) { e.Rate, e.Burst = 1, 3 })
	f := newFixture(t, withTransports(UDP), withRegistry(r))
	c, err := net.Dial("udp", f.addr(UDP))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	junk := []byte{0, 1, 0x01, 0, 0, 5, 0, 0, 0, 0, 0, 0, 1, 2, 3} // QR=0, 5 questions announced, none present
	got := 0
	for i := 0; i < 40; i++ {
		_, _ = c.Write(junk)
	}
	buf := make([]byte, 512)
	for {
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		if _, err := c.Read(buf); err != nil {
			break
		}
		got++
	}
	if got == 0 || got > 8 {
		t.Fatalf("%d FORMERR replies to 40 junk datagrams from one address with a burst of 3", got)
	}
}

// Config refuses an unspecified bind address (p4n-W6-r1-11).
func TestConfigRefusesUnspecifiedBind(t *testing.T) {
	for _, a := range []string{"0.0.0.0", "::"} {
		cfg := Config{Bind: netip.MustParseAddr(a), Ports: Ports{DNS: 5599, TLS: 5598, HTTPS: 5597}, Handler: NewStub(),
			Limits: func() *limits.Set { s, _ := limits.NewSet(limits.Default()); return s }(), Transports: []Transport{UDP}}
		if err := cfg.validate(); err == nil {
			t.Fatalf("bind %s accepted", a)
		}
	}
}
