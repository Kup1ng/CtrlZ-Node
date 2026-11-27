package resolve

// Tests of the free path's connection pools (SC 5.2a, Free resolver). Servers are
// on 127.0.0.1, ports 5600 to 5649 (the W9 lane's range).

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

const (
	freePortLo = 5600
	freePortHi = 5649
	secretName = "secret-label-of-a-user.example.com"
)

var freePortNext atomic.Int32

// freeListen binds a listener on the next free port of the lane's range.
func freeListen[T any](t testing.TB, try func(addr string) (T, error)) (T, int) {
	t.Helper()
	for i := 0; i < freePortHi-freePortLo+1; i++ {
		p := freePortLo + int(freePortNext.Add(1)-1)%(freePortHi-freePortLo+1)
		if v, err := try(fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			return v, p
		}
	}
	t.Fatalf("no free port in %d-%d", freePortLo, freePortHi)
	var z T
	return z, 0
}

// tcpFake is a plain TCP DNS server whose behaviour a test sets per query.
type tcpFake struct {
	ln      net.Listener
	conns   atomic.Int64
	queries atomic.Int64
	// onQuery runs for each query read, on the connection's own goroutine; it
	// answers through reply, now or later, from any goroutine.
	onQuery func(q *dns.Msg, reply func(*dns.Msg))
	// closeAtOnce ends every accepted connection without reading it.
	closeAtOnce bool
}

func startTCPFake(t testing.TB, f *tcpFake) netip.AddrPort {
	t.Helper()
	ln, port := freeListen(t, func(a string) (net.Listener, error) { return net.Listen("tcp", a) })
	f.ln = ln
	var mu sync.Mutex
	var all []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range all {
			_ = c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			mu.Lock()
			all = append(all, c)
			mu.Unlock()
			if f.closeAtOnce {
				_ = c.Close()
				continue
			}
			go f.serve(c)
		}
	}()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

func (f *tcpFake) serve(c net.Conn) {
	dc := &dns.Conn{Conn: c}
	var wmu sync.Mutex
	reply := func(m *dns.Msg) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = dc.WriteMsg(m)
	}
	for {
		q, err := dc.ReadMsg()
		if err != nil {
			return
		}
		f.queries.Add(1)
		f.onQuery(q, reply)
	}
}

func answerEach(q *dns.Msg, reply func(*dns.Msg)) { reply(answerA(q)) }

func udpPoolCfg(ap netip.AddrPort, timeout time.Duration) Config {
	return Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: ap.String(), Timeout: timeout}
}

func qn(i int) *dns.Msg { return query(fmt.Sprintf("n%d.example.com", i)) }

// Free misses to a udp upstream go over TCP, pipelined on a few connections, and
// each reply reaches the query it answers even when the server answers out of order.
func TestFreePoolPipelinesOverTCPAndMatchesReplies(t *testing.T) {
	const n = 8
	var mu sync.Mutex
	var held []func()
	f := &tcpFake{}
	f.onQuery = func(q *dns.Msg, reply func(*dns.Msg)) {
		mu.Lock()
		held = append(held, func() { reply(answerA(q)) })
		if len(held) == n { // answer all of them, last first
			for i := len(held) - 1; i >= 0; i-- {
				held[i]()
			}
		}
		mu.Unlock()
	}
	ap := startTCPFake(t, f)
	p, err := NewFreePool(udpPoolCfg(ap, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := qn(i)
			req.Id = uint16(1000 + i)
			resp, err := p.Exchange(context.Background(), req)
			if err != nil {
				t.Errorf("query %d: %v", i, err)
				return
			}
			if resp.Id != req.Id || !strings.EqualFold(resp.Question[0].Name, req.Question[0].Name) {
				t.Errorf("query %d got the reply of another: id %d, %s", i, resp.Id, resp.Question[0].Name)
			}
		}()
	}
	wg.Wait()
	if c := f.conns.Load(); c < 1 || c > FreeTCPConns {
		t.Fatalf("%d connections for a pool of %d", c, FreeTCPConns)
	}
}

// No free miss opens a connection beyond its pool, and the pool holds at most 64
// misses in flight on each of its connections: the next gets ErrFreePoolFull.
func TestFreePoolNeverExceedsItsConnectionsAndStreams(t *testing.T) {
	f := &tcpFake{onQuery: func(*dns.Msg, func(*dns.Msg)) {}} // never answers
	ap := startTCPFake(t, f)
	p, err := NewFreePool(udpPoolCfg(ap, 600*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	capTotal := FreeTCPConns * FreeStreamCap
	total := capTotal + 40
	var full, timedOut, other atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Exchange(context.Background(), qn(i))
			switch {
			case errors.Is(err, ErrFreePoolFull):
				full.Add(1)
			case errors.Is(err, context.DeadlineExceeded):
				timedOut.Add(1)
			default:
				other.Add(1)
				t.Errorf("query %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if full.Load() != 40 || timedOut.Load() != int64(capTotal) {
		t.Fatalf("full %d (want 40), timed out %d (want %d), other %d", full.Load(), timedOut.Load(), capTotal, other.Load())
	}
	if c := f.conns.Load(); c > FreeTCPConns {
		t.Fatalf("%d connections, the pool is %d", c, FreeTCPConns)
	}
	if p.Full() == 0 {
		t.Fatal("the pool did not count the calls that found it full")
	}
}

// The call that a full pool turns away says so in its own context, and no one
// else's does (p4n-W9-r1-3).
func TestFreePoolMarksOnlyTheCallItTurnedAway(t *testing.T) {
	f := &tcpFake{onQuery: func(*dns.Msg, func(*dns.Msg)) {}} // never answers
	ap := startTCPFake(t, f)
	p, err := NewFreePool(udpPoolCfg(ap, 400*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var wg sync.WaitGroup
	for i := 0; i < FreeTCPConns*FreeStreamCap; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Exchange(context.Background(), qn(i)) }()
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if f.queries.Load() >= int64(FreeTCPConns*FreeStreamCap) {
			break
		}
	}
	ctx1, m1 := WithFullMark(context.Background())
	_, m2 := WithFullMark(context.Background()) // another lookup, not in this call
	if _, err := p.Exchange(ctx1, qn(9999)); !errors.Is(err, ErrFreePoolFull) {
		t.Fatalf("a full pool: %v", err)
	}
	if !m1.Full() || m2.Full() {
		t.Fatalf("marks: this call %v, another lookup %v", m1.Full(), m2.Full())
	}
	// A call with no mark in its context is turned away all the same.
	if _, err := p.Exchange(context.Background(), qn(9998)); !errors.Is(err, ErrFreePoolFull) {
		t.Fatalf("a full pool, no mark: %v", err)
	}
	wg.Wait()
}

// A slot replaces a closed connection at most 10 times a second, so a server that
// closes every connection cannot make a flood of misses a flood of dials.
func TestFreePoolRedialIsRateLimited(t *testing.T) {
	f := &tcpFake{closeAtOnce: true}
	ap := startTCPFake(t, f)
	p, err := NewFreePool(udpPoolCfg(ap, 300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	deadline := time.Now().Add(1500 * time.Millisecond)
	calls := 0
	var slowest time.Duration
	for time.Now().Before(deadline) {
		start := time.Now()
		_, err := p.Exchange(context.Background(), qn(calls))
		if d := time.Since(start); d > slowest {
			slowest = d
		}
		if err == nil {
			t.Fatal("a closed connection answered")
		}
		calls++
		time.Sleep(time.Millisecond)
	}
	// 1.5 s: each of the four slots may dial once at once and 10 a second after.
	if c := f.conns.Load(); c > int64(FreeTCPConns*(15+2)) || c == 0 {
		t.Fatalf("%d dials in 1.5 s over %d calls, the bound is %d", c, calls, FreeTCPConns*17)
	}
	// A refused redial fails at once. The count of calls says nothing of that on a
	// loaded machine, where a 1 ms sleep may take ten times as long; the slowest call
	// does: none may wait for its timeout (300 ms).
	if slowest > 200*time.Millisecond {
		t.Fatalf("a call took %s of %d: a refused redial must fail at once", slowest, calls)
	}
}

func TestFreePoolRejectsAReplyToAnotherQuestionAndQuotesNothing(t *testing.T) {
	f := &tcpFake{onQuery: func(q *dns.Msg, reply func(*dns.Msg)) {
		m := answerA(q)
		m.Question[0].Name = "other.example.org."
		reply(m)
	}}
	ap := startTCPFake(t, f)
	p, err := NewFreePool(udpPoolCfg(ap, 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_, err = p.Exchange(context.Background(), query(secretName))
	if !errors.Is(err, ErrBadReply) {
		t.Fatalf("got %v, want ErrBadReply", err)
	}
	// Nothing an error says may hold the name the user asked for.
	dead, err := NewFreePool(udpPoolCfg(netip.MustParseAddrPort("127.0.0.1:1"), time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	_, err = dead.Exchange(context.Background(), query(secretName))
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "secret") {
		t.Fatalf("dial error %v", err)
	}
}

func TestFreePoolRefusesWhatNewUpstreamRefuses(t *testing.T) {
	for _, cfg := range []Config{
		{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "127.0.0.1:53"},                   // no timeout
		{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example:853", Timeout: 1000}, // no bootstrap
		{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "dns.example:53", Timeout: 1000},  // a name for udp
		{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "https://x/y", Timeout: 1000},     // a scheme
	} {
		if _, err := NewFreePool(cfg); err == nil {
			t.Errorf("%+v was accepted", cfg)
		}
	}
}

func TestFreePoolDoTUsesItsOwnTwoConnections(t *testing.T) {
	cert, roots := testCert(t)
	var conns atomic.Int64
	ln, port := freeListen(t, func(a string) (net.Listener, error) { return net.Listen("tcp", a) })
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { conns.Add(1); return nil, nil }})
	s := &dns.Server{Listener: tl, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { _ = w.WriteMsg(answerA(r)) })}
	serve(t, s)
	p, err := NewFreePool(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: fmt.Sprintf("%s:%d", testHost, port),
		BootstrapIP: netip.MustParseAddr("127.0.0.1"), RootCAs: roots, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for i := 0; i < 40; i++ {
		resp, err := p.Exchange(context.Background(), qn(i))
		if err != nil || len(resp.Answer) != 1 {
			t.Fatalf("query %d: %v %v", i, resp, err)
		}
	}
	if c := conns.Load(); c < 1 || c > FreeTLSConns {
		t.Fatalf("%d TLS connections for a pool of %d", c, FreeTLSConns)
	}
	// A server whose certificate is for another name is not talked to.
	bad, err := NewFreePool(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: fmt.Sprintf("wrong.example:%d", port),
		BootstrapIP: netip.MustParseAddr("127.0.0.1"), RootCAs: roots, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err := bad.Exchange(context.Background(), qn(1)); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
}

// DoH: one Transport with two connections, 64 streams each. The 129th miss is
// refused at once.
func TestFreePoolDoHHoldsTwoConnections(t *testing.T) {
	started := time.Now()
	cert, roots := testCert(t)
	var conns atomic.Int64
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 65535))
		req := new(dns.Msg)
		if req.Unpack(raw) != nil {
			http.Error(w, "bad", 400)
			return
		}
		<-release
		out, _ := answerA(req).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
	ln, port := freeListen(t, func(a string) (net.Listener, error) { return net.Listen("tcp", a) })
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { conns.Add(1); return nil, nil }}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	p, err := NewFreePool(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: fmt.Sprintf("%s:%d", testHost, port),
		BootstrapIP: netip.MustParseAddr("127.0.0.1"), RootCAs: roots, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	capTotal := FreeTLSConns * FreeStreamCap
	var ok, full atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < capTotal+30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := p.Exchange(context.Background(), qn(i))
			switch {
			case err == nil && len(resp.Answer) == 1:
				ok.Add(1)
			case errors.Is(err, ErrFreePoolFull):
				full.Add(1)
			default:
				t.Errorf("query %d: %v", i, err)
			}
		}()
	}
	// The refused ones return at once; the others wait for the server.
	deadline := time.Now().Add(5 * time.Second)
	for full.Load() < 30 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if full.Load() != 30 {
		t.Fatalf("%d refused while the pool was full, want 30", full.Load())
	}
	close(release)
	wg.Wait()
	if ok.Load() != int64(capTotal) {
		t.Fatalf("%d answered, want %d", ok.Load(), capTotal)
	}
	// Counted on the client, as the DoH client's own test does: the server learns of a
	// closed connection later than the client lets go of its slot.
	dc := p.slots[0].(*limitedSlot).x.(*dohClient)
	dc.mu.Lock()
	peak, total := dc.peak, dc.total
	dc.mu.Unlock()
	// A connection that closes is replaced, at the redial rate: the pool's two tokens
	// of burst and 20 a second after them.
	bound := 2*FreeTLSConns + int(20*time.Since(started).Seconds())
	if peak > FreeTLSConns || total > bound {
		t.Fatalf("the client held %d connections at once and dialled %d in all, the pool is %d and the bound %d (server saw %d hellos)", peak, total, FreeTLSConns, bound, conns.Load())
	}
}

func TestFreePoolDoQHasItsOwnClients(t *testing.T) {
	cert, roots := testCert(t)
	ln, port := freeListen(t, func(a string) (*quic.Listener, error) {
		return quic.ListenAddr(a, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13},
			&quic.Config{MaxIdleTimeout: 30 * time.Second})
	})
	ctx, cancel := context.WithCancel(context.Background())
	var conns atomic.Int64
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				for {
					st, err := c.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						var l [2]byte
						if _, err := io.ReadFull(st, l[:]); err != nil {
							return
						}
						buf := make([]byte, binary.BigEndian.Uint16(l[:]))
						if _, err := io.ReadFull(st, buf); err != nil {
							return
						}
						req := new(dns.Msg)
						if req.Unpack(buf) != nil {
							return
						}
						out, _ := answerA(req).Pack()
						_, _ = st.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
						_ = st.Close()
					}()
				}
			}()
		}
	}()
	p, err := NewFreePool(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOQ, Address: fmt.Sprintf("%s:%d", testHost, port),
		BootstrapIP: netip.MustParseAddr("127.0.0.1"), RootCAs: roots, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if len(p.slots) != FreeTLSConns {
		t.Fatalf("%d clients, want %d", len(p.slots), FreeTLSConns)
	}
	for i := 0; i < 20; i++ {
		resp, err := p.Exchange(context.Background(), qn(i))
		if err != nil || len(resp.Answer) != 1 {
			t.Fatalf("query %d: %v %v", i, resp, err)
		}
	}
	if c := conns.Load(); c < 1 || c > FreeTLSConns {
		t.Fatalf("%d QUIC connections, the pool is %d", c, FreeTLSConns)
	}
}

// limitedSlot holds its stream cap by a counter and never pauses a client after an
// error: one query's failure says nothing of the others (p4n-W9-r1-1).
func TestLimitedSlotBoundsInFlightAndKeepsGoingAfterAnError(t *testing.T) {
	block := make(chan struct{})
	var calls atomic.Int64
	fail := atomic.Bool{}
	x := exchangerFunc(func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("down")
		}
		<-block
		return answerA(req), nil
	})
	s := &limitedSlot{x: x, cap: 3, closer: closeFunc(func() error { return nil })}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.exchange(context.Background(), qn(i)) }()
	}
	for calls.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	if _, err := s.exchange(context.Background(), qn(9)); !errors.Is(err, errSlotFull) {
		t.Fatalf("a fourth in flight: %v", err)
	}
	close(block)
	wg.Wait()
	fail.Store(true)
	for i := 0; i < 5; i++ {
		if _, err := s.exchange(context.Background(), qn(i)); err == nil || errors.Is(err, errRedial) {
			t.Fatalf("call %d after a failure: %v", i, err)
		}
	}
	if calls.Load() != 3+5 {
		t.Fatalf("%d calls reached the client", calls.Load())
	}
}

type exchangerFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f exchangerFunc) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) { return f(ctx, m) }

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

// The free Router reaches an upstream only through its pool, never through the
// client the identified Router builds for the same row.
func TestFreeRouterUsesPoolsAndCountsFull(t *testing.T) {
	f := &tcpFake{onQuery: answerEach}
	ap := startTCPFake(t, f)
	hub := wireConfigWithUDPUpstream(t, ap)
	local := Member{X: exchangerFunc(func(ctx context.Context, m *dns.Msg) (*dns.Msg, error) { return nil, errors.New("no local") })}
	r, err := NewFreeRouterFromWire(hub, local, nil, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	resp, _, err := r.Exchange(context.Background(), qn(1))
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("%v %v", resp, err)
	}
	if f.conns.Load() == 0 {
		t.Fatal("the free Router did not dial the pool")
	}
	if FreePoolsFull(r) != 0 {
		t.Fatal("a pool counted a full call it never had")
	}
}

// Through a Router the mark still reaches the lookup the pool turned away
// (p4n-W9-r1-3): the Router fails with ErrNoPath, and the context says why.
func TestFreeRouterMarksALookupAFullPoolTurnedAway(t *testing.T) {
	f := &tcpFake{onQuery: func(*dns.Msg, func(*dns.Msg)) {}} // never answers
	ap := startTCPFake(t, f)
	hub := wireConfigWithUDPUpstream(t, ap)
	local := Member{X: exchangerFunc(func(ctx context.Context, m *dns.Msg) (*dns.Msg, error) { return nil, errors.New("no local") })}
	r, err := NewFreeRouterFromWire(hub, local, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fill, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < FreeTCPConns*FreeStreamCap; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, _ = r.Exchange(fill, qn(i)) }()
	}
	for deadline := time.Now().Add(3 * time.Second); f.queries.Load() < int64(FreeTCPConns*FreeStreamCap) && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	}
	ctx, mark := WithFullMark(context.Background())
	if _, _, err := r.Exchange(ctx, qn(7777)); err == nil || !mark.Full() {
		t.Fatalf("err %v, marked %v", err, mark.Full())
	}
	// A lookup that is not turned away (the local member answers) is not marked.
	wg.Wait()
	ctx2, mark2 := WithFullMark(context.Background())
	_, _, _ = r.Exchange(ctx2, qn(8888))
	if mark2.Full() && FreePoolsFull(r) == 0 {
		t.Fatal("marked with no full pool")
	}
}

func wireConfigWithUDPUpstream(t testing.TB, ap netip.AddrPort) *hubv1.NodeConfig {
	t.Helper()
	return &hubv1.NodeConfig{
		Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
		Upstreams: []*hubv1.Upstream{{
			Id: []byte("0123456789abcdef"), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: ap.String(), TimeoutMs: 5000,
		}},
	}
}

// A connection that accepts and never answers is replaced, but not on the word of
// one slow name: it goes after nothing was read from it for twice the timeout, and
// the replacement is held to the redial rate.
func TestFreePoolReplacesADeadConnectionAtTheRedialRate(t *testing.T) {
	f := &tcpFake{onQuery: func(*dns.Msg, func(*dns.Msg)) {}}
	ap := startTCPFake(t, f)
	p, err := NewFreePool(udpPoolCfg(ap, 100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for i := 0; time.Now().Before(deadline); i++ {
		if _, err := p.Exchange(context.Background(), qn(i)); err == nil {
			t.Fatal("a silent server answered")
		}
	}
	c := f.conns.Load()
	if c <= FreeTCPConns {
		t.Fatalf("%d connections: a dead one was never replaced", c)
	}
	if c > int64(FreeTCPConns*(15+2)) {
		t.Fatalf("%d dials in 1.5 s, the bound is %d", c, FreeTCPConns*17)
	}
}
