package listen

// Tests of review round 2 (p4n-W6-r2-*): the bound of the reply queue of a
// stream connection, a half-closed peer, the verify path under the write-stall
// and body deadlines, and the unrecognized_name alert.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// slowBig answers every name after delay with a reply of about 9 KiB, so a
// burst of queries read before the first answer lands makes a burst of large
// replies at once.
type slowBig struct {
	delay time.Duration
	reqs  atomic.Int64
}

func (h *slowBig) ServeDNS(ctx context.Context, req *Request) Reply {
	h.reqs.Add(1)
	select {
	case <-time.After(h.delay):
	case <-ctx.Done():
	}
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	hdr := dns.RR_Header{Name: req.Msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}
	for i := 0; i < 45; i++ {
		m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{strings.Repeat("x", 200)}})
	}
	return Reply{Msg: m}
}

// pipeStream runs a stream connection of the listener over a net.Pipe, where
// every write blocks until the other end reads, the way a full socket does.
func pipeStream(t *testing.T, f *fixture, h Handler) (cl net.Conn, srv *streamServer, done <-chan struct{}) {
	t.Helper()
	cfg := f.cfg
	cfg.Handler = h
	c, err := newCore(context.Background(), &cfg, TCP)
	if err != nil {
		t.Fatal(err)
	}
	srv = newStream(c, nil, nil)
	cl, sv := net.Pipe()
	t.Cleanup(func() { _ = cl.Close() })
	slot, _ := f.set.Admit(TCP, netip.MustParseAddr("127.0.0.1"))
	d := make(chan struct{})
	srv.wg.Add(1)
	go func() {
		srv.serveConn(sv, netip.MustParseAddrPort("127.0.0.1:4000"), slot)
		close(d)
	}()
	return cl, srv, d
}

func frameOf(name string) []byte {
	b, _ := mkq(name, dns.TypeTXT).Pack()
	return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)
}

// A peer that sends thousands of queries at once and never reads must not make
// the node hold their replies: the bytes queued stay near the cap, whatever the
// handler latency (p4n-W6-r2-1, -5). Before the fix 5000 replies of 9 KiB
// queued, 45 MB on one connection.
func TestStreamQueuedBytesAreBounded(t *testing.T) {
	f := newFixture(t, withTransports(TCP), shortSettings(func(s *limits.ListenerSettings) {
		s.IdleTimeout = time.Minute
		s.WriteStall = time.Minute
		s.BodyTimeout = 5 * time.Second
	}))
	h := &slowBig{delay: 300 * time.Millisecond}
	cl, srv, _ := pipeStream(t, f, h)
	const n = 5000
	go func() {
		var buf bytes.Buffer
		for i := 0; i < n; i++ {
			buf.Write(frameOf(fmt.Sprintf("q%d.example.org.", i)))
		}
		_, _ = cl.Write(buf.Bytes()) // blocks once the server stops reading
	}()
	var peak int64
	end := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(end) {
		if q := srv.queued.Load(); q > peak {
			peak = q
		}
		time.Sleep(5 * time.Millisecond)
	}
	set, _ := limits.SettingsFor(limits.Listeners(), TCP)
	// One connection cap, plus the short SERVFAILs that stand in for the rest.
	if limit := int64(set.MaxQueuedBytes) + int64(n)*100; peak > limit {
		t.Fatalf("%d bytes of replies queued for a peer that does not read, want at most %d", peak, limit)
	}
	if peak == 0 {
		t.Fatal("no reply was ever queued: the test measured nothing")
	}
}

// While the peer is behind, the reader stops at MaxQueuedReplies waiting
// queries, so the node reads no more than that from a peer that does not read;
// the queries it did read are answered when the peer reads (p4n-W6-r2-1, -5).
func TestStreamReaderPausesWhenPeerIsBehindAndResumes(t *testing.T) {
	f := newFixture(t, withTransports(TCP), shortSettings(func(s *limits.ListenerSettings) {
		s.IdleTimeout = time.Minute
		s.WriteStall = time.Minute
		s.BodyTimeout = 5 * time.Second
	}))
	cl, _, _ := pipeStream(t, f, f.stub)
	// The reader stops only while the peer is behind, which a reply queued and a
	// write that cannot finish show. Establish that with one query before the
	// flood: on a loaded machine the handler goroutines of the first frames can wait
	// behind the reader and the sender, and the reader then reads ahead of replies
	// that do not exist yet (a slow handler is not a peer that is behind).
	if _, err := cl.Write(frameOf("p-first.example.org.")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200 && len(f.stub.Requests()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // its reply is queued and the writer is blocked on it
	var sent atomic.Int64
	go func() {
		for i := 0; i < 1000; i++ {
			if _, err := cl.Write(frameOf(fmt.Sprintf("p%d.example.org.", i))); err != nil {
				return
			}
			sent.Add(1)
		}
	}()
	time.Sleep(500 * time.Millisecond)
	first := len(f.stub.Requests())
	time.Sleep(500 * time.Millisecond)
	if again := len(f.stub.Requests()); again != first {
		t.Fatalf("the reader kept reading: %d queries then %d", first, again)
	}
	set, _ := limits.SettingsFor(limits.Listeners(), TCP)
	// 64 waiting, plus the frame the reader holds when it looks, plus pipe and
	// bufio read-ahead of at most a few frames.
	if first < set.MaxQueuedReplies-2 || first > set.MaxQueuedReplies+8 {
		t.Fatalf("read %d queries from a peer that does not read, want about %d", first, set.MaxQueuedReplies)
	}
	// Now the peer reads: everything sent is answered.
	got := 0
	_ = cl.SetReadDeadline(time.Now().Add(10 * time.Second))
	for got < 1001 { // the first query and the 1000 of the flood
		var lb [2]byte
		if _, err := io.ReadFull(cl, lb[:]); err != nil {
			t.Fatalf("after %d replies: %v", got, err)
		}
		if _, err := io.CopyN(io.Discard, cl, int64(lb[0])<<8|int64(lb[1])); err != nil {
			t.Fatal(err)
		}
		got++
	}
}

// A peer that half-closes after sending its queries still gets every answer
// (p4n-W6-r2-3). Plain TCP gets a FIN, DoT a close_notify.
func TestHalfClosedPeerStillGetsItsAnswers(t *testing.T) {
	f := newFixture(t, withTransports(TCP, DoT), shortSettings(func(s *limits.ListenerSettings) {
		s.IdleTimeout = 5 * time.Second
		s.WriteStall = 5 * time.Second
	}))
	for _, tr := range []Transport{TCP, DoT} {
		t.Run(tr.String(), func(t *testing.T) {
			var conn interface {
				net.Conn
				CloseWrite() error
			}
			if tr == TCP {
				c, err := net.Dial("tcp", f.addr(TCP))
				if err != nil {
					t.Fatal(err)
				}
				conn = c.(*net.TCPConn)
			} else {
				c, err := tls.Dial("tcp", f.addr(DoT), f.tlsConf(""))
				if err != nil {
					t.Fatal(err)
				}
				conn = c
			}
			defer conn.Close()
			for i := 0; i < 3; i++ {
				_, _ = conn.Write(frameOf(fmt.Sprintf("slow-%d.example.org.", i)))
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			for i := 0; i < 3; i++ {
				var lb [2]byte
				if _, err := io.ReadFull(conn, lb[:]); err != nil {
					t.Fatalf("answer %d of 3: %v", i, err)
				}
				if _, err := io.CopyN(io.Discard, conn, int64(lb[0])<<8|int64(lb[1])); err != nil {
					t.Fatal(err)
				}
			}
			// With everything answered the connection ends.
			if _, err := conn.Read(make([]byte, 1)); err == nil || isTimeout(err) {
				t.Fatalf("the connection stayed open after its answers: %v", err)
			}
		})
	}
}

// ---- The verify path

func verifyFixture(t *testing.T, tr Transport, v VerifyHandler) *fixture {
	return newFixture(t, withTransports(tr), withVerify(v), shortSettings(nil))
}

// A zero HTTP/2 window holds the verify hook's reply in flow control, outside
// the handler; the stall deadline must still see it (p4n-W6-r2-2).
func TestVerifyReplyInAZeroWindowIsClosed(t *testing.T) {
	f := verifyFixture(t, DoH, &fakeVerify{})
	conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("abc.verify."+zoneName, "h2"))
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
		hb.Reset()
		for _, h := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "abc.verify." + zoneName}, {":path", "/v"}} {
			_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(2*i + 1), BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
	}
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
		}
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("a verify reply in a zero window held the connection for %v", d)
	}
	if !waitClosed(f, DoH, CloseStall, 2*time.Second) {
		t.Fatalf("closes: %v", f.obs.closed)
	}
}

// The same over HTTP/3, with a receive window that cannot take the reply.
func TestVerifyReplyInATinyQUICWindowIsClosed(t *testing.T) {
	f := verifyFixture(t, DoH3, &midVerify{})
	tr := &http3.Transport{TLSClientConfig: f.tlsConf("abc.verify."+zoneName, "h3"), QUICConfig: &quic.Config{
		MaxIdleTimeout: 20 * time.Second, InitialStreamReceiveWindow: 512, MaxStreamReceiveWindow: 512,
		InitialConnectionReceiveWindow: 4096, MaxConnectionReceiveWindow: 4096,
	}}
	defer tr.Close()
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	for i := 0; i < 3; i++ {
		go func() {
			resp, err := cl.Get("https://" + f.addr(DoH3) + "/v")
			if err == nil {
				time.Sleep(10 * time.Second) // the body is never read
				resp.Body.Close()
			}
		}()
	}
	// quic-go lets Write return once the data is queued, so a small reply can wait
	// in the window with the handler gone. quiet then sees a connection with
	// nothing unread or unanswered, and the idle deadline (10 s, below the stall)
	// closes it: either reason ends the connection, and none leaves it open.
	closed := false
	for end := time.Now().Add(6 * time.Second); time.Now().Before(end) && !closed; time.Sleep(20 * time.Millisecond) {
		closed = f.obs.closedCount(DoH3, CloseStall)+f.obs.closedCount(DoH3, CloseIdle) > 0
	}
	if !closed {
		t.Fatalf("a DoH3 verify peer that never reads kept its connection: %v", f.obs.closed)
	}
}

// A GET /v that declares a body and never sends it must not pin the connection
// for ever: net/http throws the body away once the hook returns, and that read
// is under the body deadline (p4n-W6-r2-6). The ordinary GET path has the same.
func TestUndeliveredGETBodyIsClosed(t *testing.T) {
	q, _ := mkq("x.example.org.", dns.TypeA).Pack()
	for _, c := range []struct{ name, sni, req string }{
		{"verify", "abc.verify." + zoneName, "GET /v HTTP/1.1\r\nHost: abc.verify." + zoneName + "\r\nContent-Length: 200000\r\n\r\n"},
		{"dns-query", "", fmt.Sprintf("GET /dns-query?dns=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 200000\r\n\r\n",
			base64.RawURLEncoding.EncodeToString(q), testSNI)},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, withTransports(DoH), withVerify(&fakeVerify{}), shortSettings(func(s *limits.ListenerSettings) {
				s.WriteStall = 30 * time.Second // the body deadline must end it, not the stall
			}))
			conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf(c.sni, "http/1.1"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, c.req)
			_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			start := time.Now()
			if _, err := io.ReadAll(conn); err != nil && isTimeout(err) {
				t.Fatalf("still open after %v with a body that never comes", time.Since(start))
			}
		})
	}
}

// ---- unrecognized_name

// withRefusedName makes the certificate provider answer (nil, nil) for one name.
func withRefusedName(name string) fixOpt {
	return func(f *fixture) {
		inner := f.cfg.GetCertificate
		f.cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName == name {
				return nil, nil
			}
			return inner(h)
		}
	}
}

// A certificate provider that returns (nil, nil) refuses the handshake with the
// unrecognized_name alert on every transport (SC 3.3, R7); an error would send
// internal_error (p4n-W6-r2-4).
func TestNilCertificateSendsUnrecognizedName(t *testing.T) {
	const unknown = "nope.dns.test"
	f := newFixture(t, withRefusedName(unknown))
	dial := func(tr Transport) error {
		switch tr {
		case DoT:
			_, err := tls.Dial("tcp", f.addr(DoT), f.tlsConf(unknown))
			return err
		case DoH:
			_, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf(unknown, "h2"))
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		alpn, addr := "doq", f.addr(DoQ)
		if tr == DoH3 {
			alpn, addr = "h3", f.addr(DoH3)
		}
		conn, err := quic.DialAddr(ctx, addr, f.tlsConf(unknown, alpn), nil)
		if err == nil {
			_ = conn.CloseWithError(0, "")
		}
		return err
	}
	for _, tr := range []Transport{DoT, DoH, DoQ, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			err := dial(tr)
			if err == nil {
				t.Fatal("a handshake for an unknown name succeeded")
			}
			var qerr *quic.TransportError
			switch {
			case strings.Contains(err.Error(), "unrecognized name"):
			case errors.As(err, &qerr) && qerr.ErrorCode == 0x100+112:
			default:
				t.Fatalf("want the unrecognized_name alert (112), got: %v", err)
			}
		})
	}
	// A known name still works.
	c, err := tls.Dial("tcp", f.addr(DoT), f.tlsConf(""))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

// midVerify is a verify hook whose reply is larger than a small QUIC window but small enough for the handler to return before the window opens.
type midVerify struct{ fakeVerify }

func (v *midVerify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(bytes.Repeat([]byte("v"), 600))
}

// A UDP limit whatever its answer stops the query it acts on: a keyless entry
// that answers REFUSED must not be ignored (p4n-W6-r2-9).
func TestUDPLimitWithAnotherAnswerStopsTheQuery(t *testing.T) {
	r := limits.Registry{
		{Name: "udp-node", Acts: limits.ActsQuery, Transports: []Transport{UDP}, Key: limits.Key{Kind: limits.KeyNone},
			Rate: 0.001, Burst: 1, Answer: limits.AnswerRefused},
	}
	f := newFixture(t, withTransports(UDP), withRegistry(r))
	c := f.mustDial(UDP)
	if r, err := ask(c, "one.example.org.", dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("first query: %v %v", r, err)
	}
	r2, err := ask(c, "two.example.org.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Rcode != dns.RcodeRefused {
		t.Fatalf("a query the limit stopped got rcode %d, want REFUSED", r2.Rcode)
	}
	if n := len(f.stub.Requests()); n != 1 {
		t.Fatalf("the handler saw %d queries, want 1", n)
	}
}
