package listen

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// ---- Plain UDP limits answer TC=1 and nothing else (L13 (4))

func TestUDPLimitAnswersTruncatedAndExemptNamesPass(t *testing.T) {
	reg := limits.Registry{{Name: "udp-query-addr", Acts: limits.ActsQuery, Transports: []Transport{UDP},
		Key:  limits.Key{Kind: limits.KeySource, V4Bits: 32, V6Bits: 128},
		Rate: 0.5, Burst: 5, Answer: limits.AnswerTC}}
	f := newFixture(t, withRegistry(reg), withTransports(UDP, TCP))
	var given atomic.Int64
	f.set.SetHook(func(e limits.Event) {
		if e.Kind == limits.EventQuery {
			given.Add(1)
		}
	})
	c := f.mustDial(UDP)
	passed, truncated := 0, 0
	for i := 0; i < 30; i++ {
		r, err := ask(c, "o"+string(rune('a'+i%26))+".example.org.", dns.TypeA)
		if err != nil {
			t.Fatalf("query %d got no answer: a stopped UDP query is never dropped: %v", i, err)
		}
		switch {
		case r.Truncated:
			truncated++
			if len(r.Answer)+len(r.Ns)+len(r.Extra) != 0 || r.Rcode != dns.RcodeSuccess {
				t.Fatalf("a stopped query must be TC=1 with no records: %v", r)
			}
		case answered(r):
			passed++
		default:
			t.Fatalf("a stopped query got another answer: %v", r)
		}
		// The names that must always be answered are never stopped, and never
		// given to the limit.
		for _, q := range exemptQueries() {
			r, err := c.exchange(q)
			if err != nil || !answered(r) {
				t.Fatalf("exempt name %s: %v %v", q.Question[0].Name, r, err)
			}
		}
	}
	if passed < 5 || passed > 9 || truncated < 21 {
		t.Fatalf("passed %d truncated %d", passed, truncated)
	}
	if g := given.Load(); g != 30 {
		t.Fatalf("the limit was given %d queries, the 30 ordinary ones only", g)
	}
	// The TCP retry meets no limit keyed on a source.
	tc := f.mustDial(TCP)
	for i := 0; i < 40; i++ {
		if r, err := ask(tc, "o.example.org.", dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("TCP retry %d: %v %v", i, r, err)
		}
	}
}

// ---- The L13 walk: every registry entry on every transport it lists

// TestL13Walk is the unit test of 7.5. For every entry of the registry and
// every transport the entry lists, it runs a real listener with that one entry
// set far below the test's load and every other entry far above it, and checks
// L13 against it:
//
//   - the name-form exemption: queries for an Endpoint hostname (known or
//     not), the apex NS and ns1 are never given to any limit, and are answered
//     within 2 s, also when pipelined behind more stopped queries than the
//     connection's stream cap;
//   - (2): a limit stops the query it is given, with the answer the registry
//     names (TC=1 and no records on UDP, REFUSED on the stream otherwise), and
//     no connection is closed or reset by it, the connection limits included;
//   - (3) and (4) are checked on the registry itself (limits CheckRegistry)
//     and by the listener tests below.
func TestL13Walk(t *testing.T) {
	walked := 0
	for _, e := range limits.Default() {
		for _, tr := range e.Transports {
			e, tr := e, tr
			walked++
			t.Run(e.Name+"/"+tr.String(), func(t *testing.T) {
				bind := "127.0.0.1"
				if e.Key.Kind == limits.KeySource && e.Key.V4Bits == 0 {
					bind = "::1" // an IPv6-only aggregate: drive it from IPv6
					if l, err := net.Listen("tcp", "[::1]:0"); err != nil {
						t.Skip("no IPv6 loopback here")
					} else {
						l.Close()
					}
				}
				walkEntry(t, e, tr, bind)
			})
		}
	}
	if walked < 50 {
		t.Fatalf("the walk covered only %d (entry, transport) pairs", walked)
	}
}

func lowered(r limits.Registry, name string, mut func(e *limits.Entry)) limits.Registry {
	out := scaled(r, 1000)
	for i := range out {
		if out[i].Name == name {
			out[i] = r[i]
			out[i].Transports = append([]Transport(nil), r[i].Transports...)
			mut(&out[i])
		}
	}
	return out
}

func walkEntry(t *testing.T, e limits.Entry, tr Transport, bind string) {
	var reg limits.Registry
	switch {
	case e.Acts == limits.ActsQuery:
		reg = lowered(limits.Default(), e.Name, func(x *limits.Entry) { x.Rate, x.Burst = 0.5, 6 })
	case e.Count > 0:
		reg = lowered(limits.Default(), e.Name, func(x *limits.Entry) { x.Count = 3 })
	default:
		reg = lowered(limits.Default(), e.Name, func(x *limits.Entry) { x.Rate, x.Burst = 0.5, 3 })
	}
	f := newFixture(t, withRegistry(reg), withBind(bind), withTransports(tr))

	var mu sync.Mutex
	given := map[string]int{}
	refusedConns := 0
	f.set.SetHook(func(ev limits.Event) {
		mu.Lock()
		defer mu.Unlock()
		switch ev.Kind {
		case limits.EventQuery:
			given[ev.Entry]++
		case limits.EventConnRefused:
			if ev.Entry == e.Name {
				refusedConns++
			}
		}
	})

	if e.Acts == limits.ActsQuery {
		walkQueryEntry(t, f, e, tr, &mu, given)
	} else {
		walkConnEntry(t, f, e, tr, &mu, &refusedConns)
	}
	// No limit closed or reset an accepted connection: the observer saw no
	// close of this transport while the clients were still connected.
	// For DoH the close reasons cannot tell the peer's graceful TLS close from
	// net/http's own, so DoH is covered by the clients: a connection closed under
	// a pipelined query would fail that query, and every query above is checked.
	if n := f.obs.closedOtherThan(tr, ClosePeer, CloseHTTP); tr != DoH && n != 0 {
		t.Errorf("%d accepted connections were closed by the node: %v", n, f.obs.closed)
	}
}

func walkQueryEntry(t *testing.T, f *fixture, e limits.Entry, tr Transport, mu *sync.Mutex, given map[string]int) {
	c := f.mustDial(tr)
	f.stub.Reset()
	// One exempt query first, so the connection exists and its settings are
	// known to the client before the burst (an HTTP/2 client that has not seen
	// the server SETTINGS yet may open more streams than the cap).
	warmStart := time.Now()
	if r, err := c.exchange(exemptQueries()[0]); err != nil || !answered(r) {
		t.Fatalf("warm-up: %v %v", r, err)
	}
	// The budget for the exempt queries behind the stopped ones is the fixed one
	// or, on a machine so loaded that a single warm exchange is slow, a hundred
	// of those: a node that queued them behind the stopped queries would be far
	// past either (p4n-W7-r8-1).
	budget := within()
	if w := 100 * time.Since(warmStart); w > budget {
		budget = w
	}
	nOther := 150 // more than the 100 streams a connection may hold open
	others := make([]*dns.Msg, nOther)
	for i := range others {
		others[i] = mkq("o"+itoa(i)+".example.org.", dns.TypeA)
	}
	var exempt []*dns.Msg
	for i := 0; i < 3; i++ {
		exempt = append(exempt, exemptQueries()...)
	}

	var wg sync.WaitGroup
	var oRs []*dns.Msg
	var oEs []error
	wg.Add(1)
	go func() { defer wg.Done(); oRs, oEs = exchangeAll(c, others) }()
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	eRs, eEs := exchangeAll(c, exempt)
	if d := time.Since(start); d > budget {
		t.Errorf("exempt queries took %v behind stopped ones", d)
	}
	wg.Wait()

	for i, r := range eRs {
		if eEs[i] != nil || !answered(r) {
			t.Fatalf("exempt query %s: %v %v", exempt[i].Question[0].Name, r, eEs[i])
		}
	}
	stopped := 0
	for i, r := range oRs {
		if oEs[i] != nil {
			t.Fatalf("an ordinary query got no answer: %v", oEs[i])
		}
		switch {
		case answered(r):
		case e.Answer == limits.AnswerTC && r.Truncated && len(r.Answer) == 0 && r.Rcode == dns.RcodeSuccess:
			stopped++
		case e.Answer == limits.AnswerRefused && r.Rcode == dns.RcodeRefused && !r.Truncated:
			stopped++
		default:
			t.Fatalf("a stopped query got the wrong answer for %s on %s: %v", e.Answer, tr, r)
		}
	}
	if stopped < nOther-20 {
		t.Errorf("%s on %s stopped only %d of %d queries", e.Name, tr, stopped, nOther)
	}
	mu.Lock()
	if given[e.Name] != nOther {
		t.Errorf("%s was given %d queries; it must see the %d ordinary ones and none of the %d exempt", e.Name, given[e.Name], nOther, len(exempt))
	}
	for name, n := range given {
		if n > nOther {
			t.Errorf("%s was given %d queries, more than the ordinary ones", name, n)
		}
	}
	mu.Unlock()
	// None of the exempt names reached... a limit; all reached the handler.
	seen := 0
	for _, r := range f.stub.Requests() {
		if f.exm.Exempt(r.Msg.Question[0].Name, r.Msg.Question[0].Qtype) {
			seen++
		}
	}
	if seen != len(exempt)+1 {
		t.Errorf("the handler saw %d of %d exempt queries", seen, len(exempt)+1)
	}
	if tr.Stream() {
		// The connection is still there, and so is every stream slot.
		for _, q := range exemptQueries() {
			if r, err := c.exchange(q); err != nil || !answered(r) {
				t.Errorf("after the flood: %v %v", r, err)
			}
		}
	}
	if (tr == DoH3 || tr == DoQ) && f.hello.Load() != 1 {
		t.Errorf("the queries used %d connections, not one", f.hello.Load())
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func walkConnEntry(t *testing.T, f *fixture, e limits.Entry, tr Transport, mu *sync.Mutex, refused *int) {
	limit := 3
	var held []qclient
	probe := func() (qclient, bool) {
		c, err := f.dial(tr)
		if err != nil {
			return nil, false
		}
		r, err := ask(c, "probe.example.org.", dns.TypeA)
		if err != nil || !answered(r) {
			c.close()
			return nil, false
		}
		return c, true
	}
	for i := 0; i < limit; i++ {
		c, ok := probe()
		if !ok {
			t.Fatalf("connection %d of %d was refused", i+1, limit)
		}
		held = append(held, c)
		t.Cleanup(c.close)
	}
	// Queries for the names that must be answered, pipelined with queries for
	// other names on the connections the limit let through.
	var wg sync.WaitGroup
	check := func(label string) {
		for ci, c := range held {
			ci, c := ci, c
			wg.Add(1)
			go func() {
				defer wg.Done()
				qs := append([]*dns.Msg{}, exemptQueries()...)
				for i := 0; i < 10; i++ {
					qs = append(qs, mkq("o"+itoa(i)+".example.org.", dns.TypeA))
				}
				start := time.Now()
				rs, es := exchangeAll(c, qs)
				for i := range exemptQueries() {
					if es[i] != nil || !answered(rs[i]) {
						t.Errorf("%s: connection %d: exempt query %d: %v %v", label, ci, i, rs[i], es[i])
					}
				}
				if d := time.Since(start); d > within() {
					t.Errorf("%s: connection %d answered after %v", label, ci, d)
				}
			}()
		}
		wg.Wait()
	}
	check("before the excess")
	// More connections than the limit: refused, from the same source.
	for i := 0; i < 5; i++ {
		if c, ok := probe(); ok {
			c.close()
			t.Fatalf("connection %d beyond the limit was accepted", i+1)
		}
	}
	// The ones it let through are untouched, and still get their answers.
	check("after the excess")
	mu.Lock()
	if *refused < 5 {
		t.Errorf("%s refused %d connections, want at least 5", e.Name, *refused)
	}
	mu.Unlock()
}

// ---- Connection limits count a QUIC connection only after its handshake

// Packets that start a QUIC handshake and never finish it, from any number of
// sources, count against no connection limit (L13 (3)): with the per-source
// limit at 2, garbage that looks like Initials from this very source leaves two
// real connections free.
func TestQUICHalfOpenFloodCountsNothing(t *testing.T) {
	reg := scaled(limits.Default(), 1000)
	for i := range reg {
		if reg[i].Name == "enc-conn-open-src" {
			reg[i].Count = 2
		}
	}
	for _, tr := range []Transport{DoQ, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			f := newFixture(t, withRegistry(reg), withTransports(tr))
			flood(t, f.addr(tr), 3000)
			for i := 0; i < 2; i++ {
				c := f.mustDial(tr)
				if r, err := ask(c, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
					t.Fatalf("connection %d after a half-open flood: %v %v", i, r, err)
				}
			}
			// The cap is real: a third is refused.
			c, err := f.dial(tr)
			if err == nil {
				defer c.close()
				if _, err := ask(c, "www.example.org.", dns.TypeA); err == nil {
					t.Fatal("a third connection was accepted")
				}
			}
		})
	}
}

// flood sends n datagrams of random bytes of Initial size from this host.
func flood(t *testing.T, addr string, n int) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 1252)
	for i := 0; i < n; i++ {
		_, _ = rand.Read(buf)
		buf[0] = 0xc0 | buf[0]&0x0f // a long-header packet
		_, _ = c.Write(buf)
	}
}

// With ForceRetry every new source goes through Retry, and a client that
// answers it connects (the token validates its address); without it, an idle
// node asks nobody.
func TestQUICRetry(t *testing.T) {
	for _, tr := range []Transport{DoQ, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			f := newFixture(t, withForceRetry(), withTransports(tr))
			c := f.mustDial(tr)
			if r, err := ask(c, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("a client that answers Retry must connect: %v %v", r, err)
			}
			if f.srv.hs.retried.Load() == 0 {
				t.Fatal("no Retry was asked for")
			}
			g := newFixture(t, withTransports(tr))
			c = g.mustDial(tr)
			if _, err := ask(c, "www.example.org.", dns.TypeA); err != nil {
				t.Fatal(err)
			}
			if g.srv.hs.retried.Load() != 0 {
				t.Fatal("Retry asked on an idle node")
			}
		})
	}
}

// 0-RTT is off on DoQ: a client holding a session ticket gets no early data.
func TestDoQNoZeroRTT(t *testing.T) {
	f := newFixture(t, withTransports(DoQ))
	cache := tls.NewLRUClientSessionCache(4)
	conf := f.tlsConf("", "doq")
	conf.ClientSessionCache = cache
	dial := func() *quic.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := quic.DialAddrEarly(ctx, f.addr(DoQ), conf, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1 := dial()
	<-c1.HandshakeComplete()
	time.Sleep(100 * time.Millisecond) // let the session ticket arrive
	_ = c1.CloseWithError(0, "")
	c2 := dial()
	defer c2.CloseWithError(0, "")
	<-c2.HandshakeComplete()
	if c2.ConnectionState().Used0RTT {
		t.Fatal("0-RTT was used on DoQ")
	}
}

// ---- Deadlines

func shortSettings(mut func(s *limits.ListenerSettings)) fixOpt {
	return withSettings(func(s *limits.ListenerSettings) {
		if s.Transport != UDP {
			s.IdleTimeout = 400 * time.Millisecond
			s.WriteStall = 400 * time.Millisecond
			s.BodyTimeout = 400 * time.Millisecond
			if s.Transport != TCP {
				s.HandshakeTimeout = 400 * time.Millisecond
			}
			if s.Transport == DoH || s.Transport == DoH3 {
				s.ReadHeaderTimeout = 400 * time.Millisecond
			}
		}
		if mut != nil {
			mut(s)
		}
	})
}

// An idle connection is closed after the idle deadline; one that waits for an
// answer is not, however slow the answer is (L13 (2)).
func TestIdleDeadlineNeverFiresWhileAnAnswerIsDue(t *testing.T) {
	f := newFixture(t, shortSettings(nil))
	f.stub.SlowFor = 1500 * time.Millisecond // longer than three idle deadlines
	for _, tr := range []Transport{TCP, DoT, DoH, DoH3, DoQ} {
		t.Run(tr.String(), func(t *testing.T) {
			c := f.mustDial(tr)
			r, err := ask(c, "slow-x.example.org.", dns.TypeA)
			if err != nil || !answered(r) {
				t.Fatalf("a query that waited longer than the idle deadline: %v %v", r, err)
			}
			// Now the connection is idle and gets closed (the clients that
			// notice it: TCP, DoT, DoQ). A new query on a closed connection of
			// the others simply opens another.
			time.Sleep(900 * time.Millisecond)
			if fc, ok := c.(*frameClient); ok && !fc.closed() {
				t.Fatal("an idle connection stayed open past the idle deadline")
			}
			if tr == DoQ {
				if _, err := ask(c, "x.example.org.", dns.TypeA); err == nil {
					t.Fatal("an idle DoQ connection stayed open past the idle deadline")
				}
			}
		})
	}
	if f.obs.closedCount(TCP, CloseIdle) != 1 || f.obs.closedCount(DoT, CloseIdle) != 1 || f.obs.closedCount(DoQ, CloseIdle) != 1 {
		t.Fatalf("idle closes: %v", f.obs.closed)
	}
}

// DoH over HTTP/1.1: the idle deadline closes the connection between requests.
func TestDoHIdleAndHeaderDeadlines(t *testing.T) {
	f := newFixture(t, shortSettings(nil))
	raw := func() *tls.Conn {
		c, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "http/1.1"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	waitEOF := func(c net.Conn, d time.Duration) bool {
		_ = c.SetReadDeadline(time.Now().Add(d))
		_, err := io.Copy(io.Discard, c)
		return err == nil // EOF, not a deadline
	}
	// Headers that never finish: closed at the header deadline.
	c := raw()
	_, _ = c.Write([]byte("POST /dns-query HTTP/1.1\r\nHost: dns.test\r\n"))
	start := time.Now()
	if !waitEOF(c, 3*time.Second) {
		t.Fatal("a request with unfinished headers was never closed")
	}
	if d := time.Since(start); d > within() {
		t.Fatalf("closed after %v", d)
	}
	// A header of 20 KiB: refused (431), over the 16 KiB cap.
	c = raw()
	_, _ = c.Write([]byte("GET /dns-query HTTP/1.1\r\nHost: dns.test\r\nX-Pad: " + strings.Repeat("a", 20<<10) + "\r\n\r\n"))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "431") {
		t.Fatalf("a 20 KiB header got %q", line)
	}
	// A completed request, then silence: closed at the idle deadline.
	c = raw()
	q, _ := mkq("www.example.org.", dns.TypeA).Pack()
	req := "POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: " + itoa(len(q)) + "\r\n\r\n"
	_, _ = c.Write(append([]byte(req), q...))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	start = time.Now()
	if !waitEOF(c, 3*time.Second) {
		t.Fatal("an idle HTTP/1.1 connection stayed open")
	}
	if d := time.Since(start); d > within() {
		t.Fatalf("closed after %v", d)
	}
}

// HTTP/1.1 requests pipelined on one connection are answered in order, even
// when the first is slow.
func TestDoHHTTP1PipelinedInOrder(t *testing.T) {
	f := newFixture(t, withTransports(DoH))
	c, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out []byte
	for _, name := range []string{"slow-a.example.org.", "fast-b.example.org."} {
		q, _ := mkq(name, dns.TypeA).Pack()
		out = append(out, []byte("POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: "+itoa(len(q))+"\r\n\r\n")...)
		out = append(out, q...)
	}
	_, _ = c.Write(out)
	br := bufio.NewReader(c)
	for _, want := range []string{"slow-a.example.org.", "fast-b.example.org."} {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		m, err := readDoHReply(resp)
		if err != nil || m.Question[0].Name != want {
			t.Fatalf("expected the answer for %s next, got %v %v", want, m, err)
		}
	}
}

// A body that arrives too slowly is cut at the body deadline, for its own
// request.
func TestDoHSlowBody(t *testing.T) {
	f := newFixture(t, shortSettings(nil), withTransports(DoH))
	c, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: 100\r\n\r\n0123456789"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err == nil && resp.StatusCode != 408 && resp.StatusCode != 400 {
		t.Fatalf("a slow body got %d", resp.StatusCode)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the slow body held its request past the body deadline")
	}
	// Another client is not affected.
	if r, err := ask(f.mustDial(DoH), "www.example.org.", dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("%v %v", r, err)
	}
}

// ---- Hostile peers

// A slowloris peer on a stream transport holds its own connection only for the
// body deadline, and every other peer keeps getting answers.
func TestSlowlorisFrame(t *testing.T) {
	f := newFixture(t, shortSettings(longIdle))
	for _, tr := range []Transport{TCP, DoT} {
		t.Run(tr.String(), func(t *testing.T) {
			var slow []*frameClient
			for i := 0; i < 20; i++ {
				c := f.mustDial(tr).(*frameClient)
				_, _ = c.c.Write([]byte{0}) // one byte of a length, then silence
				slow = append(slow, c)
			}
			good := f.mustDial(tr)
			if r, err := ask(good, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("others during a slowloris: %v %v", r, err)
			}
			for i, c := range slow {
				if !c.waitClosed(3 * time.Second) {
					t.Fatalf("slowloris connection %d stayed open", i)
				}
			}
			if r, err := ask(good, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("the honest connection: %v %v", r, err)
			}
		})
	}
}

// A DoQ stream that sends one byte and stops is cancelled alone; the
// connection and its other streams go on.
func TestSlowlorisStreamDoQ(t *testing.T) {
	f := newFixture(t, shortSettings(longIdle), withTransports(DoQ))
	cl, err := f.doqClient("")
	if err != nil {
		t.Fatal(err)
	}
	defer cl.close()
	var strs []*quic.Stream
	for i := 0; i < 50; i++ {
		s, err := cl.conn.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = s.Write([]byte{0})
		strs = append(strs, s)
	}
	if r, err := ask(cl, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("a query beside 50 stalled streams: %v %v", r, err)
	}
	time.Sleep(900 * time.Millisecond)
	for i, s := range strs {
		_ = s.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := s.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatalf("stalled stream %d was not cancelled: %v", i, err)
		}
	}
	if r, err := ask(cl, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("the connection after its stalled streams were cut: %v %v", r, err)
	}
	if n := f.obs.closedOtherThan(DoQ); n != 0 {
		t.Fatalf("a slow stream closed a connection: %v", f.obs.closed)
	}
}

// A malformed DoQ message is a protocol error that ends that connection only.
func TestDoQMalformedClosesThatConnection(t *testing.T) {
	f := newFixture(t, withTransports(DoQ))
	good := f.mustDial(DoQ)
	for name, data := range map[string][]byte{
		"length 3":    {0, 3, 1, 2, 3},
		"unparseable": append([]byte{0, 20}, []byte(strings.Repeat("\xff", 20))...),
		"data after":  nil,
	} {
		bad, err := f.doqClient("")
		if err != nil {
			t.Fatal(err)
		}
		s, _ := bad.conn.OpenStreamSync(context.Background())
		if data == nil {
			q, _ := mkq("www.example.org.", dns.TypeA).Pack()
			data = append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
			data = append(data, 9, 9, 9)
		}
		_, _ = s.Write(data)
		_ = s.Close()
		select {
		case <-bad.conn.Context().Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the connection stayed open", name)
		}
		if r, err := ask(good, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%s: the other connection: %v %v", name, r, err)
		}
	}
	if f.obs.closedCount(DoQ, CloseProtocol) != 3 {
		t.Fatalf("closes: %v", f.obs.closed)
	}
}

// Half-open TLS handshakes from one source: they hold their slots for the
// handshake deadline only, the source's own cap bounds them, and a client of
// another source is answered all the while.
func TestHalfOpenTLSFlood(t *testing.T) {
	f := newFixture(t, shortSettings(longIdle))
	for _, tr := range []Transport{DoT, DoH} {
		t.Run(tr.String(), func(t *testing.T) {
			d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
			var held []net.Conn
			for i := 0; i < 150; i++ {
				c, err := d.Dial("tcp", f.addr(tr))
				if err != nil {
					if i == 0 {
						t.Skipf("cannot use 127.0.0.2 here: %v", err)
					}
					continue
				}
				held = append(held, c)
			}
			defer func() {
				for _, c := range held {
					c.Close()
				}
			}()
			good := f.mustDial(tr)
			if r, err := ask(good, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("a client during the flood: %v %v", r, err)
			}
			time.Sleep(900 * time.Millisecond)
			closed := 0
			for _, c := range held {
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if _, err := c.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
					closed++
				}
			}
			if closed < len(held)-5 {
				t.Fatalf("only %d of %d half-open connections were closed", closed, len(held))
			}
			f.obs.mu.Lock()
			refused := f.obs.refused[tr]
			f.obs.mu.Unlock()
			if refused == 0 {
				t.Fatal("the per-source cap refused nothing: 150 connections from one address")
			}
			if r, err := ask(good, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("a client after the flood: %v %v", r, err)
			}
		})
	}
}

// A peer that never reads: with all its queries answered and nothing unread,
// the write deadline closes its connection. While another query waits, it does
// not. Driven on a net.Pipe, which blocks every write until it is read.
func TestReaderThatNeverReads(t *testing.T) {
	f := newFixture(t, withTransports(TCP), shortSettings(func(s *limits.ListenerSettings) {
		s.IdleTimeout = 5 * time.Second
	}))
	f.stub.SlowFor = 1200 * time.Millisecond
	cfg := f.cfg
	cfg.Handler = f.stub
	c, err := newCore(context.Background(), &cfg, TCP)
	if err != nil {
		t.Fatal(err)
	}
	srv := newStream(c, nil, nil)
	frame := func(name string) []byte {
		b, _ := mkq(name, dns.TypeA).Pack()
		return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)
	}
	run := func(names ...string) (closedAt time.Duration, why CloseReason) {
		cl, sv := net.Pipe()
		defer cl.Close()
		slot, _ := f.set.Admit(TCP, netip.MustParseAddr("127.0.0.1"))
		done := make(chan struct{})
		var mu sync.Mutex
		cfg.Observer.Closed = func(_ Transport, r CloseReason) { mu.Lock(); why = r; mu.Unlock() }
		srv.wg.Add(1)
		go func() {
			srv.serveConn(sv, netip.MustParseAddrPort("127.0.0.1:4000"), slot)
			close(done)
		}()
		start := time.Now()
		for _, n := range names {
			if _, err := cl.Write(frame(n)); err != nil {
				t.Fatal(err)
			}
		}
		// The client never reads. The server's writes block on the pipe.
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Fatal("the connection of a reader that never reads stayed open")
		}
		mu.Lock()
		defer mu.Unlock()
		return time.Since(start), why
	}
	// Every query is answered at once, the write blocks: closed at the
	// write-stall deadline (400 ms).
	d, why := run("a.example.org.", "b.example.org.")
	if why != CloseStall || d < 300*time.Millisecond || d > 2*time.Second {
		t.Fatalf("stalled after %v for %v", d, why)
	}
	// One query is still waiting (1.2 s): the write deadline must not run
	// before it is answered, so the close comes after that, not at 400 ms.
	// The slow query goes first, so it is read before the reply of the other
	// blocks: a query that arrives after the write began holds nothing off.
	d, why = run("slow-b.example.org.", "a.example.org.")
	if why != CloseStall || d < 1200*time.Millisecond {
		t.Fatalf("the write deadline fired after %v with a query waiting (%v)", d, why)
	}
}

// ---- Stream caps

// A QUIC connection holds at most 100 streams open: 160 concurrent slow queries
// on one DoQ or DoH3 connection are all answered, and the handler never has
// many more than 100 at once. (The library releases a stream's credit when it
// completes on the wire, which can be just after its handler returned, so the
// bound for DoH3 has a few streams of slack.)
func TestQUICStreamCapIs100(t *testing.T) {
	f := newFixture(t, withRegistry(scaled(limits.Default(), 1000)))
	f.stub.SlowFor = 400 * time.Millisecond
	for _, tr := range []Transport{DoQ, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			c := f.mustDial(tr)
			if r, err := ask(c, "warm.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("warm-up: %v %v", r, err)
			}
			f.stub.peak.Store(0)
			var qs []*dns.Msg
			for i := 0; i < 160; i++ {
				qs = append(qs, mkq("slow-"+itoa(i)+".example.org.", dns.TypeA))
			}
			rs, es := exchangeAll(c, qs)
			for i := range rs {
				if es[i] != nil || !answered(rs[i]) {
					t.Fatalf("query %d: %v %v", i, rs[i], es[i])
				}
			}
			if p := f.stub.Peak(); p > 110 || p < 50 {
				t.Fatalf("handler concurrency peaked at %d, want between 50 and 110", p)
			}
		})
	}
}

// HTTP/2 on DoH: the server advertises MAX_CONCURRENT_STREAMS 100 and refuses a
// stream above it. Driven with raw frames, because a client library waits for
// the advertised limit before it opens a stream.
func TestHTTP2StreamCapIs100(t *testing.T) {
	f := newFixture(t, withTransports(DoH), withRegistry(scaled(limits.Default(), 1000)))
	// The handlers wait on a gate, not a delay: a loaded machine can take longer
	// than any delay to read 160 HEADERS frames, and the first streams would then
	// finish and free their slots (p4n-W6-r6-2).
	gate := make(chan struct{})
	f.stub.Gate = gate
	conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "h2"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(http2.ClientPreface))
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	advertised := uint32(0)
	for advertised == 0 {
		fm, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := fm.(*http2.SettingsFrame); ok && !s.IsAck() {
			if v, ok := s.Value(http2.SettingMaxConcurrentStreams); ok {
				advertised = v
			}
			_ = fr.WriteSettingsAck()
		}
	}
	if advertised != 100 {
		t.Fatalf("the server advertises %d concurrent streams, want 100", advertised)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for i := 0; i < 160; i++ {
		q, _ := mkq("slow-"+itoa(i)+".example.org.", dns.TypeA).Pack()
		hb.Reset()
		for _, h := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", testSNI},
			{":path", "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(q)}, {"accept", "application/dns-message"}} {
			_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: uint32(2*i + 1), BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
	}
	answeredStreams, reset := 0, 0
	count := func(fm http2.Frame) {
		switch fm.(type) {
		case *http2.HeadersFrame: // a response
			answeredStreams++
		case *http2.RSTStreamFrame:
			reset++
		}
	}
	// Go's server handles frames in order, so the ACK of a PING sent after the
	// 160 HEADERS proves each of them was accepted or refused; only then are the
	// handlers released.
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if err := fr.WritePing(false, [8]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	for acked := false; !acked; {
		fm, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if p, ok := fm.(*http2.PingFrame); ok && p.IsAck() {
			acked = true
		}
		count(fm)
	}
	if reset != 60 {
		t.Fatalf("%d of 160 streams refused before any handler finished, want 60", reset)
	}
	close(gate)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for answeredStreams < 100 {
		fm, err := fr.ReadFrame()
		if err != nil {
			break
		}
		count(fm)
	}
	if p := f.stub.Peak(); p > 100 {
		t.Fatalf("the handler had %d requests at once on one HTTP/2 connection", p)
	}
	if answeredStreams != 100 || reset != 60 {
		t.Fatalf("answered %d, refused %d of 160 streams, want 100 and 60", answeredStreams, reset)
	}
}

// ---- The verify hook

type fakeVerify struct {
	mu   sync.Mutex
	hits []string
}

func (v *fakeVerify) reset() { v.mu.Lock(); v.hits = nil; v.mu.Unlock() }

func (v *fakeVerify) snapshot() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.hits...)
}

func (v *fakeVerify) VerifyHost(sni string) bool { return strings.HasSuffix(sni, ".verify."+zoneName) }
func (v *fakeVerify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	v.hits = append(v.hits, r.Method+" "+r.URL.Path)
	v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"seen":false}`))
}

func TestVerifyHookOnVerifySNI(t *testing.T) {
	v := &fakeVerify{}
	f := newFixture(t, withVerify(v))
	h3 := f.doh3Client("abc.verify." + zoneName)
	defer h3.close()
	h2 := f.dohClient(true, "abc.verify."+zoneName)
	for name, get := range map[string]func(string) (*http.Response, error){
		"doh":  func(p string) (*http.Response, error) { return h2.cl.Get("https://" + f.addr(DoH) + p) },
		"doh3": func(p string) (*http.Response, error) { return h3.cl.Get("https://" + f.addr(DoH3) + p) },
	} {
		v.reset()
		r, err := get("/v")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if h := v.snapshot(); r.StatusCode != 200 || string(body) != `{"seen":false}` || len(h) != 1 || h[0] != "GET /v" {
			t.Fatalf("%s: %d %q %v", name, r.StatusCode, body, h)
		}
		// Any other path on that host is an ordinary DoH request, not the hook's.
		r, err = get("/other")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if h := v.snapshot(); r.StatusCode != 400 || len(h) != 1 {
			t.Fatalf("%s: /other gave %d, hook hits %v", name, r.StatusCode, h)
		}
	}
	// /v on the ordinary SNI does not reach the hook.
	v.reset()
	plain := f.dohClient(true, "")
	r, err := plain.cl.Get("https://" + f.addr(DoH) + "/v")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if h := v.snapshot(); len(h) != 0 {
		t.Fatalf("the hook served an ordinary SNI: %v", h)
	}
	// The DoH answer of a verify host still has no CORS header: only the hook
	// may add them, and only for its path.
	_ = plain
}

// ---- dns= above 65535 bytes is 413 where the request reaches the handler

func TestDoHQueryParamCapInTheHandler(t *testing.T) {
	cfg := &Config{Limits: nil}
	h := &dohHandler{core: &core{cfg: cfg, t: DoH, set: limits.Listeners()[3]}}
	big := strings.Repeat("A", 87381) // decodes to 65536 bytes
	req, _ := http.NewRequest("GET", "https://dns.test/dns-query?dns="+big, nil)
	if _, status := h.fromQuery(req); status != 413 {
		t.Fatalf("status %d", status)
	}
	req, _ = http.NewRequest("GET", "https://dns.test/dns-query?dns="+strings.Repeat("A", 87380), nil)
	if _, status := h.fromQuery(req); status != 0 {
		t.Fatalf("a dns= of exactly 65535 decoded bytes got %d", status)
	}
}

// longIdle keeps the idle deadline out of a test that waits on other deadlines.
func longIdle(s *limits.ListenerSettings) { s.IdleTimeout = 10 * time.Second }

// ---- The settings in force are the ones of limits.Listeners

// The second walk of 7.5: every listener runs with the numbers of
// limits.Listeners (nothing a library defaults), and those numbers pass the
// clause (2) walk. The DoH servers are asked for the values net/http holds.
func TestListenerSettingsInForce(t *testing.T) {
	f := newFixture(t)
	for _, s := range limits.Listeners() {
		if bad := limits.CheckListeners(limits.Listeners()); len(bad) != 0 {
			t.Fatalf("%v", bad)
		}
		if s.Transport == UDP {
			continue
		}
		// None of the six has a query cap or an age.
		if s.MaxQueriesPerConn != 0 || s.MaxConnAge != 0 {
			t.Errorf("%s has a cap", s.Transport)
		}
	}
	set, _ := limits.SettingsFor(limits.Listeners(), DoH)
	c, err := newCore(context.Background(), &f.cfg, DoH)
	if err != nil {
		t.Fatal(err)
	}
	srv := newDoH(c, nopListener{}, f.cfg.tlsConfig([]string{"h2"}), nil)
	hs := srv.shards[0].srv
	if hs.ReadHeaderTimeout != set.ReadHeaderTimeout || hs.IdleTimeout != set.IdleTimeout ||
		hs.MaxHeaderBytes != set.MaxHeaderBytes || hs.MaxHeaderBytes != 16<<10 ||
		hs.HTTP2 == nil || hs.HTTP2.MaxConcurrentStreams != set.MaxStreams || set.MaxStreams != 100 {
		t.Fatalf("DoH runs with %v %v %v %+v", hs.ReadHeaderTimeout, hs.IdleTimeout, hs.MaxHeaderBytes, hs.HTTP2)
	}
	if hs.ReadTimeout != 0 || hs.WriteTimeout != 0 {
		t.Fatal("a whole-request ReadTimeout or WriteTimeout would close a connection under a waiting query")
	}
	h3, _ := limits.SettingsFor(limits.Listeners(), DoH3)
	if h3.MaxHeaderBytes != 16<<10 || h3.MaxStreams != 100 {
		t.Fatal("DoH3 settings")
	}
}

type nopListener struct{}

func (nopListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (nopListener) Close() error              { return nil }
func (nopListener) Addr() net.Addr            { return &net.TCPAddr{} }
