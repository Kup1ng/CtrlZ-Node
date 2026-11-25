package listen

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

func hasA(r *dns.Msg) bool {
	if r == nil {
		return false
	}
	for _, rr := range r.Answer {
		if _, ok := rr.(*dns.A); ok {
			return true
		}
	}
	return false
}

// Every transport answers, and the request the handler sees carries what the
// query path needs of the transport (7.4, T-001 to T-004, T-548).
func TestEveryTransportAnswers(t *testing.T) {
	f := newFixture(t)
	for _, tr := range limits6() {
		t.Run(tr.String(), func(t *testing.T) {
			f.stub.Reset()
			c := f.mustDial(tr)
			r, err := ask(c, "www.example.org.", dns.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			if !answered(r) || !hasA(r) {
				t.Fatalf("reply: %v", r)
			}
			reqs := f.stub.Requests()
			if len(reqs) != 1 {
				t.Fatalf("handler saw %d requests", len(reqs))
			}
			q := reqs[0]
			if q.Transport != tr {
				t.Errorf("transport %v", q.Transport)
			}
			if !q.Source.Addr().IsLoopback() {
				t.Errorf("source %v", q.Source)
			}
			// Only a UDP query with no server cookie is unvalidated.
			if q.Validated == (tr == UDP) {
				t.Errorf("validated = %v", q.Validated)
			}
			wantSNI := tr == DoT || tr == DoH || tr == DoH3 || tr == DoQ
			if (q.SNI == testSNI) != wantSNI {
				t.Errorf("sni %q", q.SNI)
			}
			if (q.HTTP != nil) != (tr == DoH || tr == DoH3) {
				t.Errorf("http info %v", q.HTTP)
			}
			if q.HTTP != nil && (q.HTTP.Path != "/dns-query" || q.HTTP.Method != "POST" ||
				q.HTTP.ContentType != "application/dns-message" || q.HTTP.Authority == "" ||
				q.HTTP.HasOrigin || q.HTTP.HasReferer || q.HTTP.HasSecFetchSite) {
				t.Errorf("http info %+v", q.HTTP)
			}
		})
	}
}

func limits6() []Transport { return []Transport{UDP, TCP, DoT, DoH, DoH3, DoQ} }

// Nothing but the six listeners is bound, and only on the address given.
func TestOnlyTheRequestedListenersBind(t *testing.T) {
	f := newFixture(t, withTransports(UDP, TCP))
	if _, err := net.DialTimeout("tcp", f.addr(DoT), 300*time.Millisecond); err == nil {
		t.Fatal("DoT is listening although it was not asked for")
	}
	if _, ok := f.srv.Addr(DoT); ok {
		t.Fatal("DoT has an address")
	}
	ap, ok := f.srv.Addr(UDP)
	if !ok || ap.Addr() != f.bind {
		t.Fatalf("UDP bound on %v", ap)
	}
	// A wrong config is refused at start, nothing is left bound.
	if _, err := Start(context.Background(), Config{Bind: f.bind, Ports: f.ports, Handler: f.stub, Limits: f.set, Transports: []Transport{DoT}}); err == nil {
		t.Fatal("DoT without a certificate provider started")
	}
}

// The request the handler sees on DoH never takes its source from a header,
// and carries the proof-rule flags (D52, 7.6).
func TestDoHSourceIsTheConnection(t *testing.T) {
	f := newFixture(t)
	hdrs := http.Header{
		"X-Forwarded-For":  {"203.0.113.9"},
		"Cf-Connecting-Ip": {"203.0.113.10"},
		"True-Client-Ip":   {"203.0.113.11"},
		"X-Real-Ip":        {"203.0.113.12"},
		"Forwarded":        {"for=203.0.113.13"},
		"Origin":           {"https://evil.example"},
		"Referer":          {"https://evil.example/x"},
		"Sec-Fetch-Site":   {"cross-site"},
	}
	for _, name := range []string{"doh1", "doh2", "doh3"} {
		t.Run(name, func(t *testing.T) {
			f.stub.Reset()
			var r *http.Response
			var err error
			m := mkq("www.example.org.", dns.TypeA)
			switch name {
			case "doh1":
				r, err = f.dohClient(false, "").do(m, "POST", hdrs)
			case "doh2":
				r, err = f.dohClient(true, "").do(m, "GET", hdrs)
			default:
				c := f.doh3Client("")
				defer c.close()
				r, err = dohDo(c.cl, c.base, m, "POST", hdrs)
			}
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			reqs := f.stub.Requests()
			if len(reqs) != 1 {
				t.Fatalf("%d requests", len(reqs))
			}
			q := reqs[0]
			if q.Source.Addr().String() != "127.0.0.1" {
				t.Fatalf("source taken from a header: %v", q.Source)
			}
			if !q.HTTP.HasOrigin || !q.HTTP.HasReferer || !q.HTTP.HasSecFetchSite {
				t.Fatalf("flags %+v", q.HTTP)
			}
			if name == "doh2" && q.HTTP.Method != "GET" {
				t.Fatalf("method %s", q.HTTP.Method)
			}
		})
	}
}

// RFC 8484 GET and POST on HTTP/1.1, HTTP/2 and HTTP/3; no Alt-Svc, no CORS
// header; OPTIONS is 405 (7.4).
func TestDoHMethodsAndHeaders(t *testing.T) {
	f := newFixture(t)
	type cl struct {
		name  string
		do    func(m *dns.Msg, method string) (*http.Response, error)
		opt   func() (*http.Response, error)
		proto int
	}
	h1 := f.dohClient(false, "")
	h2 := f.dohClient(true, "")
	h3 := f.doh3Client("")
	t.Cleanup(h3.close)
	opts := func(c *http.Client, base string) func() (*http.Response, error) {
		return func() (*http.Response, error) {
			req, _ := http.NewRequest("OPTIONS", base, nil)
			req.Header.Set("Origin", "https://panel.example")
			req.Header.Set("Access-Control-Request-Method", "GET")
			return c.Do(req)
		}
	}
	clients := []cl{
		{"http1", func(m *dns.Msg, me string) (*http.Response, error) { return h1.do(m, me, nil) }, opts(h1.cl, h1.base), 1},
		{"http2", func(m *dns.Msg, me string) (*http.Response, error) { return h2.do(m, me, nil) }, opts(h2.cl, h2.base), 2},
		{"http3", func(m *dns.Msg, me string) (*http.Response, error) { return dohDo(h3.cl, h3.base, m, me, nil) }, opts(h3.cl, h3.base), 3},
	}
	for _, c := range clients {
		for _, method := range []string{"GET", "POST"} {
			r, err := c.do(mkq("www.example.org.", dns.TypeA), method)
			if err != nil {
				t.Fatalf("%s %s: %v", c.name, method, err)
			}
			if r.ProtoMajor != c.proto {
				t.Errorf("%s: protocol %s", c.name, r.Proto)
			}
			m, err := readDoHReply(r)
			if err != nil || !hasA(m) {
				t.Errorf("%s %s: %v %v", c.name, method, m, err)
			}
			if r.Header.Get("Content-Type") != "application/dns-message" {
				t.Errorf("%s: content type %q", c.name, r.Header.Get("Content-Type"))
			}
			if r.Header.Get("Alt-Svc") != "" {
				t.Errorf("%s: Alt-Svc %q (D51: HTTP/3 discovery is off)", c.name, r.Header.Get("Alt-Svc"))
			}
			if r.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s: CORS header on a DoH answer", c.name)
			}
		}
		r, err := c.opt()
		if err != nil {
			t.Fatalf("%s OPTIONS: %v", c.name, err)
		}
		r.Body.Close()
		if r.StatusCode != 405 {
			t.Errorf("%s: OPTIONS gave %d", c.name, r.StatusCode)
		}
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") || strings.EqualFold(k, "Alt-Svc") {
				t.Errorf("%s: OPTIONS answer has %s", c.name, k)
			}
		}
	}
}

// Size caps of 7.4: a POST with no Content-Length or above 65535 is 413, a dns=
// that decodes to more than 65535 bytes is 413 (or refused before the handler
// by the 16 KiB header cap), and a malformed query is 400.
func TestDoHSizeCaps(t *testing.T) {
	f := newFixture(t)
	for _, h2 := range []bool{false, true} {
		c := f.dohClient(h2, "")
		name := map[bool]string{false: "http1", true: "http2"}[h2]
		post := func(body []byte, length int64, ct string) int {
			req, _ := http.NewRequest("POST", c.base, strings.NewReader(string(body)))
			req.ContentLength = length
			if length < 0 {
				req.Body = nopReader(body)
			}
			req.Header.Set("Content-Type", ct)
			r, err := c.cl.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			r.Body.Close()
			return r.StatusCode
		}
		q, _ := mkq("www.example.org.", dns.TypeA).Pack()
		if got := post(q, -1, "application/dns-message"); got != 413 {
			t.Errorf("%s: POST with no Content-Length gave %d", name, got)
		}
		big := make([]byte, 65536)
		if got := post(big, int64(len(big)), "application/dns-message"); got != 413 {
			t.Errorf("%s: POST of 65536 bytes gave %d", name, got)
		}
		if got := post(q, int64(len(q)), "text/plain"); got != 415 {
			t.Errorf("%s: POST of the wrong type gave %d", name, got)
		}
		if got := post([]byte("not dns at all"), 14, "application/dns-message"); got != 400 {
			t.Errorf("%s: a malformed query gave %d", name, got)
		}
		if got := post(q, int64(len(q)), "application/dns-message"); got != 200 {
			t.Errorf("%s: a good POST gave %d", name, got)
		}
		// A dns= of 100 KB: refused, with 413 where it reaches the handler and
		// otherwise (the request line is above the 16 KiB header cap) with 431. The
		// HTTP/2 client does not even send it: the server advertises the header cap.
		r, err := c.cl.Get(c.base + "?dns=" + strings.Repeat("A", 100000))
		switch {
		case err != nil && h2 && strings.Contains(err.Error(), "larger than peer's advertised limit"):
		case err != nil:
			t.Fatalf("%s: %v", name, err)
		default:
			r.Body.Close()
			if r.StatusCode != 413 && r.StatusCode != 431 {
				t.Errorf("%s: oversize dns= gave %d", name, r.StatusCode)
			}
		}
		r, err = c.cl.Get(c.base)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Errorf("%s: GET with no dns= gave %d", name, r.StatusCode)
		}
	}
}

// Handler status: a Reply with a Status is an HTTP status with no DNS body.
func TestDoHStatusReply(t *testing.T) {
	f := newFixture(t)
	for _, tr := range []Transport{DoH, DoH3} {
		c := f.mustDial(tr)
		_, err := ask(c, "status-x.example.org.", dns.TypeA)
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("%s: %v", tr, err)
		}
	}
}

// The handler's drop is silent on Plain DNS only.
func TestPlainSilentDrop(t *testing.T) {
	f := newFixture(t)
	if _, err := ask(&udpClient{addr: f.addr(UDP), timeout: 400 * time.Millisecond}, "drop-x.example.org.", dns.TypeA); err == nil {
		t.Fatal("UDP answered a dropped query")
	}
	c := f.mustDial(TCP)
	c.(*frameClient).timeout = 400 * time.Millisecond
	if _, err := ask(c, "drop-x.example.org.", dns.TypeA); err == nil {
		t.Fatal("TCP answered a dropped query")
	}
	// The connection is still there for the next query.
	if r, err := ask(c, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("connection after a drop: %v %v", r, err)
	}
}

// A handler error or panic answers SERVFAIL for that query and never closes the
// connection (T-549), on every transport.
func TestHandlerErrorAndPanicAnswerServFail(t *testing.T) {
	f := newFixture(t)
	for _, tr := range limits6() {
		t.Run(tr.String(), func(t *testing.T) {
			c := f.mustDial(tr)
			for _, name := range []string{"panic-x.example.org.", "error-x.example.org."} {
				r, err := ask(c, name, dns.TypeA)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if r.Rcode != dns.RcodeServerFailure {
					t.Fatalf("%s: rcode %d", name, r.Rcode)
				}
				// The same connection answers the next query.
				r, err = ask(c, "www.example.org.", dns.TypeA)
				if err != nil || !answered(r) {
					t.Fatalf("after %s: %v %v", name, r, err)
				}
			}
		})
	}
	f.obs.mu.Lock()
	defer f.obs.mu.Unlock()
	for _, tr := range limits6() {
		if f.obs.panics[tr] != 1 {
			t.Errorf("%s: %d panics counted", tr, f.obs.panics[tr])
		}
	}
	for _, tr := range []Transport{TCP, DoT, DoQ, DoH3} {
		for k := range f.obs.closed {
			if strings.HasPrefix(k, tr.String()+"/") && !strings.HasSuffix(k, "/peer") && !strings.HasSuffix(k, "/shutdown") {
				t.Errorf("%s was closed by the listener: %s", tr, k)
			}
		}
	}
}

// Queries pipelined on one TCP or DoT connection are answered in parallel and
// out of order, and a connection carries more than 128 of them (L13 (2)).
func TestPipelinedOutOfOrderAndNoQueryCap(t *testing.T) {
	f := newFixture(t, withRegistry(scaled(limits.Default(), 1000)))
	f.stub.SlowFor = 1200 * time.Millisecond // far above any scheduling hiccup of a loaded machine
	for _, tr := range []Transport{TCP, DoT} {
		t.Run(tr.String(), func(t *testing.T) {
			c := f.mustDial(tr).(*frameClient)
			slowDone := make(chan time.Time, 1)
			go func() {
				_, _ = ask(c, "slow-a.example.org.", dns.TypeA)
				slowDone <- time.Now()
			}()
			time.Sleep(50 * time.Millisecond)
			start := time.Now()
			if r, err := ask(c, "fast.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatal(err)
			}
			fastAt := time.Now()
			if d := fastAt.Sub(start); d > 600*time.Millisecond { // blocked behind the slow one it would be about 1.1 s
				t.Fatalf("a fast query waited %v behind a slow one", d)
			}
			if at := <-slowDone; !at.After(fastAt) {
				t.Fatal("the slow answer did not come after the fast one")
			}
			for i := 0; i < 400; i++ {
				if r, err := ask(c, "many.example.org.", dns.TypeA); err != nil || !answered(r) {
					t.Fatalf("query %d: %v", i, err)
				}
			}
			if c.closed() {
				t.Fatal("the connection was closed")
			}
		})
	}
}

// A malformed message on a stream transport closes that connection and no
// other: a length below 12, or a frame that does not parse.
func TestMalformedFrameClosesThatConnection(t *testing.T) {
	f := newFixture(t)
	for _, tr := range []Transport{TCP, DoT} {
		for name, frame := range map[string][]byte{
			"length 3":    {0, 3, 1, 2, 3},
			"unparseable": append([]byte{0, 20}, []byte(strings.Repeat("\xff", 20))...),
		} {
			t.Run(tr.String()+"/"+name, func(t *testing.T) {
				good := f.mustDial(tr)
				bad := f.mustDial(tr).(*frameClient)
				if _, err := bad.c.Write(frame); err != nil {
					t.Fatal(err)
				}
				if !bad.waitClosed(2 * time.Second) {
					t.Fatal("the connection with a malformed frame stayed open")
				}
				if r, err := ask(good, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
					t.Fatalf("other connection: %v %v", r, err)
				}
			})
		}
	}
	// The server closes the socket first and tells the observer when the
	// connection's goroutine ends, so the client can see the close before the
	// count exists (p4n-W7-r5-2): wait for the count.
	counted := func() bool {
		return f.obs.closedCount(TCP, CloseProtocol) >= 2 && f.obs.closedCount(DoT, CloseProtocol) >= 2
	}
	for end := time.Now().Add(5 * time.Second); !counted() && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if !counted() {
		t.Fatalf("protocol closes not counted: %v", f.obs.closed)
	}
}

// Plain UDP: step 1 drops, FORMERR, truncation to the client's size.
func TestUDPStepOne(t *testing.T) {
	f := newFixture(t)
	addr := f.addr(UDP)
	send := func(b []byte, wantReply bool) []byte {
		c, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write(b)
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			if wantReply {
				t.Fatalf("no reply: %v", err)
			}
			return nil
		}
		if !wantReply {
			t.Fatalf("a reply to a datagram that must be dropped: %x", buf[:n])
		}
		return buf[:n]
	}
	q, _ := mkq("www.example.org.", dns.TypeA).Pack()
	// Shorter than a header: dropped.
	send(q[:11], false)
	// QR=1: dropped.
	resp := append([]byte(nil), q...)
	resp[2] |= 0x80
	send(resp, false)
	// A header with QR=0 and a body that does not parse: FORMERR, 12 bytes.
	bad := append(append([]byte(nil), q[:12]...), 0xff, 0xff, 0xff)
	bad[4], bad[5] = 0, 1 // QDCOUNT 1, with a broken question
	out := send(bad, true)
	if len(out) != 12 || out[3]&0x0f != byte(dns.RcodeFormatError) || out[2]&0x80 == 0 || out[0] != q[0] || out[1] != q[1] {
		t.Fatalf("FORMERR reply: %x", out)
	}
	// A normal query still works.
	if out := send(q, true); len(out) < 12 {
		t.Fatal("short reply")
	}

	// Truncation: 40 TXT records of 200 bytes do not fit 512 or 1232 bytes.
	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	m := mkq("big-x.example.org.", dns.TypeTXT)
	r, _, err := cl.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated {
		t.Fatal("a 8 KB answer was not truncated for a client with no EDNS")
	}
	m.SetEdns0(4096, false)
	r, _, err = cl.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || r.Len() > 1232 {
		t.Fatalf("EDNS size 4096 must still be cut to 1232: tc=%v len=%d", r.Truncated, r.Len())
	}
	// Over TCP the same answer comes whole.
	r, _, err = (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(mkq("big-x.example.org.", dns.TypeTXT), f.addr(TCP))
	if err != nil || r.Truncated || len(r.Answer) != 40 {
		t.Fatalf("TCP: %v %v", r, err)
	}
}

// The source-port rule of step 1: a datagram from a reflector port is dropped,
// unless it is a well-formed query that L13 names.
func TestUDPReflectorPorts(t *testing.T) {
	f := newFixture(t)
	for _, port := range []int{7, 123, 1900, 11211} {
		la := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
		c, err := net.DialUDP("udp", la, mustUDPAddr(f.addr(UDP)))
		if err != nil {
			t.Logf("cannot bind source port %d here: %v", port, err)
			continue
		}
		ordinary, _ := mkq("www.example.org.", dns.TypeA).Pack()
		named, _ := mkq(rid(3), dns.TypeA).Pack()
		_, _ = c.Write(ordinary)
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 512)
		if _, err := c.Read(buf); err == nil {
			t.Errorf("port %d: an ordinary query was answered", port)
		}
		_, _ = c.Write(named)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(buf); err != nil || n < 12 {
			t.Errorf("port %d: a query for an Endpoint hostname was dropped: %v", port, err)
		}
		c.Close()
	}
}

func mustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panic(err)
	}
	return a
}

// DNS cookies, L14: a client cookie alone, or a server cookie the node cannot
// verify, is answered as if there were none, with a fresh server cookie. Never
// BADCOOKIE, TC=1 or a drop; over UDP and over TCP; for the names that must
// always be answered too.
func TestCookiesAreNeverRefused(t *testing.T) {
	f := newFixture(t)
	client := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	mk := func(name string, qt uint16, cookieHex string) *dns.Msg {
		m := mkq(name, qt)
		m.SetEdns0(1232, false)
		m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookieHex})
		return m
	}
	cookieOf := func(r *dns.Msg) []byte {
		if o := r.IsEdns0(); o != nil {
			for _, e := range o.Option {
				if c, ok := e.(*dns.EDNS0_COOKIE); ok {
					b, _ := hex.DecodeString(c.Cookie)
					return b
				}
			}
		}
		return nil
	}
	queries := []struct {
		name string
		qt   uint16
	}{
		{"www.example.org.", dns.TypeA},
		{rid(1), dns.TypeA},
		{rid(99), dns.TypeAAAA}, // an unknown rid is the same form
		{zoneName + ".", dns.TypeNS},
		{"ns1." + zoneName + ".", dns.TypeA},
	}
	for _, network := range []string{"udp", "tcp"} {
		cl := &dns.Client{Net: network, Timeout: time.Second}
		addr := f.addr(UDP)
		if network == "tcp" {
			addr = f.addr(TCP)
		}
		for _, q := range queries {
			// Client cookie only.
			r, _, err := cl.Exchange(mk(q.name, q.qt, hex.EncodeToString(client)), addr)
			if err != nil {
				t.Fatalf("%s %s client only: %v", network, q.name, err)
			}
			if r.Rcode != dns.RcodeSuccess || r.Truncated {
				t.Fatalf("%s %s client only: rcode %d tc %v", network, q.name, r.Rcode, r.Truncated)
			}
			ck := cookieOf(r)
			if len(ck) != 24 || string(ck[:8]) != string(client) {
				t.Fatalf("%s %s: reply cookie %x", network, q.name, ck)
			}
			// The cookie the node just made, sent back, is valid.
			f.stub.Reset()
			r, _, err = cl.Exchange(mk(q.name, q.qt, hex.EncodeToString(ck)), addr)
			if err != nil || r.Rcode != dns.RcodeSuccess {
				t.Fatalf("%s %s valid cookie: %v", network, q.name, err)
			}
			if network == "udp" {
				if rq := f.stub.Requests(); len(rq) != 1 || !rq[0].Validated {
					t.Fatalf("a valid server cookie did not validate the UDP source: %+v", rq)
				}
			}
			// A cookie the node cannot verify: made under a secret it has wiped.
			if err := f.jar.Wipe(); err != nil {
				t.Fatal(err)
			}
			f.stub.Reset()
			r, _, err = cl.Exchange(mk(q.name, q.qt, hex.EncodeToString(ck)), addr)
			if err != nil {
				t.Fatalf("%s %s wiped: %v", network, q.name, err)
			}
			if r.Rcode != dns.RcodeSuccess || r.Truncated {
				t.Fatalf("%s %s wiped: rcode %d tc %v (L14: never BADCOOKIE or TC)", network, q.name, r.Rcode, r.Truncated)
			}
			fresh := cookieOf(r)
			if len(fresh) != 24 || string(fresh) == string(ck) {
				t.Fatalf("%s %s wiped: no fresh server cookie: %x", network, q.name, fresh)
			}
			if network == "udp" {
				if rq := f.stub.Requests(); len(rq) != 1 || rq[0].Validated {
					t.Fatalf("an unverifiable cookie validated the source: %+v", rq)
				}
			}
			// Garbage in the option is treated as no cookie and gets no option back.
			r, _, err = cl.Exchange(mk(q.name, q.qt, "0102"), addr)
			if err != nil || r.Rcode != dns.RcodeSuccess {
				t.Fatalf("%s %s malformed cookie: %v", network, q.name, err)
			}
		}
	}
	// A query with no cookie gets none.
	r, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(mkq("www.example.org.", dns.TypeA), f.addr(UDP))
	if err != nil || cookieOf(r) != nil {
		t.Fatalf("a cookie on a reply to a query that had none: %v", err)
	}
}

func nopReader(b []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(b)) }
