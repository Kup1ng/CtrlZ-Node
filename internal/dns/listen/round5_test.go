package listen

// Tests of review round 5 (p4n-W6-r5-*): the QUIC handshake deadline, NEW_TOKEN
// tokens that must not validate an address, the Retry decision under the
// aggregates, a certificate provider that fails on the resumption call, and the
// DoH3 header tokens of one stream.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// blackholeRelay forwards every datagram it gets to server from one socket of its
// own and throws the replies away, so a client behind it never completes a
// handshake while the server sees a source that has the client's IP. It stands
// for a peer that sends Initials with a spoofed source and never answers.
func blackholeRelay(t *testing.T, server string) (addr string) {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sa := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(server))
	t.Cleanup(func() { _ = l.Close(); _ = s.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := l.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = s.WriteToUDP(buf[:n], sa)
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := s.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	return l.LocalAddr().String()
}

// reuseStore keeps the first token it is given and hands it out again and
// again, which a real client never does but a peer that wants to reuse a token
// does.
type reuseStore struct {
	mu  sync.Mutex
	tok *quic.ClientToken
}

func (r *reuseStore) Pop(string) *quic.ClientToken {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tok
}

func (r *reuseStore) Put(_ string, t *quic.ClientToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tok == nil {
		r.tok = t
	}
}

func (r *reuseStore) has() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tok != nil
}

// A NEW_TOKEN token from an earlier connection must not make an Initial count as
// address-validated: a peer that holds one could send Initials with its victim's
// address, never answer, and take the victim's connection slots in ConnContext
// (p4n-W6-r5-3).
func TestNewTokenDoesNotValidateAnAddress(t *testing.T) {
	for _, tr := range []Transport{DoQ, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			f := newFixture(t, withTransports(tr))
			alpn := "doq"
			if tr == DoH3 {
				alpn = "h3"
			}
			store := &reuseStore{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, f.addr(tr), f.tlsConf("", alpn), &quic.Config{TokenStore: store})
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 40 && !store.has(); i++ {
				time.Sleep(50 * time.Millisecond)
			}
			_ = conn.CloseWithError(0, "")
			if !store.has() {
				t.Fatal("the server sent no NEW_TOKEN: the test measured nothing")
			}
			relay := blackholeRelay(t, f.addr(tr))
			var wg sync.WaitGroup
			for i := 0; i < 80; i++ {
				wg.Go(func() {
					c, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
					defer cancel()
					if cc, err := quic.DialAddr(c, relay, f.tlsConf("", alpn), &quic.Config{TokenStore: store}); err == nil {
						_ = cc.CloseWithError(0, "")
					}
				})
			}
			time.Sleep(250 * time.Millisecond)
			if n := f.set.Open(tr, "enc-conn-open-node"); n != 0 {
				t.Fatalf("%d connection slots held by handshakes that never finished", n)
			}
			wg.Wait()
			// A real client from the same IP is served.
			c := f.mustDial(tr)
			defer c.close()
			if r, err := ask(c, "www.example.org.", 1); err != nil || !answered(r) {
				t.Fatalf("a real client was refused after the flood: %v %v", r, err)
			}
		})
	}
}

// A QUIC handshake ends at HandshakeTimeout whatever progress the peer makes,
// not at twice that (p4n-W6-r5-1). The peer behind the relay never gets an
// answer but its client keeps retransmitting, which counts as progress for the
// idle part of the rule.
func TestQUICHandshakeEndsAtTheSetting(t *testing.T) {
	f := newFixture(t, withTransports(DoQ), withSettings(func(s *limits.ListenerSettings) {
		if s.Transport == DoQ {
			s.HandshakeTimeout = 1200 * time.Millisecond
		}
	}))
	relay := blackholeRelay(t, f.addr(DoQ))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	go func() { _, _ = quic.DialAddr(ctx, relay, f.tlsConf("", "doq"), nil) }()
	start := time.Now()
	for f.srv.hs.pending.Load() == 0 && time.Since(start) < 300*time.Millisecond {
		time.Sleep(5 * time.Millisecond)
	}
	if f.srv.hs.pending.Load() == 0 {
		t.Fatal("the handshake never started: the test measured nothing")
	}
	for f.srv.hs.pending.Load() != 0 && time.Since(start) < 4*time.Second {
		time.Sleep(10 * time.Millisecond)
	}
	d := time.Since(start)
	if f.srv.hs.pending.Load() != 0 {
		t.Fatal("the handshake was still counted after 4 s")
	}
	if d > 1800*time.Millisecond {
		t.Fatalf("the handshake ended after %v, want about the 1.2 s setting", d)
	}
}

// The Retry decision counts the handshakes in progress at every level of the
// aggregates: while few tokens are left in the /56 bucket, Initials from many
// /64s of that /56 do not all start a handshake (p4n-W6-r5-4).
func TestRetryCountsHandshakesUnderAggregates(t *testing.T) {
	r := limits.Registry{
		{Name: "new-64", Acts: limits.ActsConnection, Transports: []limits.Transport{limits.DoQ}, Key: limits.Key{Kind: limits.KeySource, V4Bits: 32, V6Bits: 64}, Rate: 0.001, Burst: 100},
		{Name: "new-56", Acts: limits.ActsConnection, Transports: []limits.Transport{limits.DoQ}, Key: limits.Key{Kind: limits.KeySource, V4Bits: 24, V6Bits: 56}, Rate: 0.001, Burst: 5},
	}
	set, err := limits.NewSet(r)
	if err != nil {
		t.Fatal(err)
	}
	h := &handshakes{}
	refuse := func(a netip.Addr) bool { return set.WouldRefuse(limits.DoQ, a) }
	begin := func(a netip.Addr) *limits.Pending { return set.BeginPending(limits.DoQ, a) }
	started := func(addr func(i int) *net.UDPAddr, n int) int {
		var cancels []context.CancelFunc
		defer func() {
			for _, c := range cancels {
				c()
			}
		}()
		k := 0
		for i := 0; i < n; i++ {
			a := addr(i)
			if h.verify(a, refuse) {
				continue // a Retry: no handshake, no TLS work
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)
			if _, err := h.connContext(ctx, &quic.ClientInfo{RemoteAddr: a}, begin); err != nil {
				t.Fatal(err)
			}
			k++
		}
		return k
	}
	// 200 different /64s of one /56, one Initial each.
	v6 := func(i int) *net.UDPAddr {
		return &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("2001:db8:0:%x::1", i)), Port: 1000}
	}
	if n := started(v6, 200); n > 5 {
		t.Fatalf("%d handshakes started from one /56 whose bucket holds 5", n)
	} else if n == 0 {
		t.Fatal("no handshake could start: the test measured nothing")
	}
	// The same for the /24 of IPv4 hosts.
	v4 := func(i int) *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i)), Port: 1000} }
	if n := started(v4, 200); n > 5 {
		t.Fatalf("%d handshakes started from one /24 whose bucket holds 5", n)
	}
}

// The certificate provider is called again when a session is resumed, with a
// ClientHelloInfo that has only ServerName. A provider that reads the rest must
// not take the process down: the resumption falls back to a full handshake
// (p4n-W6-r5-2, -5).
func TestResumptionSurvivesAProviderThatNeedsTheFullHello(t *testing.T) {
	f := newFixture(t, func(f *fixture) {
		inner := f.cfg.GetCertificate
		f.cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			_ = h.Context().Done() // a nil context panics here
			return inner(h)
		}
	})
	for _, tr := range []Transport{DoT, DoH, DoQ, DoH3} {
		t.Run(tr.String(), func(t *testing.T) {
			cache := &anyKeyCache{}
			if _, err := dialResume(f, tr, testSNI, cache, 0); err != nil {
				t.Fatal(err)
			}
			if cache.count() == 0 {
				t.Fatal("no session ticket was issued: the test measured nothing")
			}
			resumed, err := dialResume(f, tr, testSNI, cache, 0)
			if err != nil {
				t.Fatalf("the second handshake failed: %v", err)
			}
			if resumed {
				t.Fatal("resumed with a provider that cannot answer the thin call")
			}
		})
	}
}

// One stream's end takes its own token and no other: stream 2 starts its
// handler and finishes while stream 1 is still waiting for its headers
// (p4n-W6-r5-6).
func TestHdrQueueTokensAreTiedToTheirStreams(t *testing.T) {
	q, idle, _, _ := fakeQuiet(10*time.Second, 30*time.Second)
	h := newHdrQueue(q, 10*time.Second)
	defer h.stop()
	_ = h.add(1)
	tok2 := h.add(2)
	h.endStream(2) // the handler of stream 2 starts first
	h.end(tok2)    // and its stream finishes
	h.mu.Lock()
	n := len(h.toks)
	h.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d tokens, want the one of stream 1", n)
	}
	if idle.on() {
		t.Fatal("idle armed while stream 1 still waits for its headers")
	}
	h.endStream(1)
	if !idle.on() {
		t.Fatal("idle not armed after both streams ended")
	}
}

// The tokens never pass the stream cap, however far the goroutines that end them
// lag behind the streams quic-go has already closed. The test that opens streams
// as fast as it can (TestDoH3HeaderTokensFollowTheirStreams) failed on the
// unchanged round-4 code in 4 runs of 8 for want of this bound.
func TestHdrQueueIsBoundedByMax(t *testing.T) {
	q, idle, _, _ := fakeQuiet(10*time.Second, 30*time.Second)
	h := newHdrQueue(q, 10*time.Second)
	h.max = 3
	defer h.stop()
	var toks []*hdrTok
	for i := 1; i <= 10; i++ {
		toks = append(toks, h.add(quic.StreamID(i*4)))
		h.mu.Lock()
		n := len(h.toks)
		h.mu.Unlock()
		if n > 3 {
			t.Fatalf("%d tokens after %d streams, max 3", n, i)
		}
	}
	if idle.on() {
		t.Fatal("idle armed while streams wait for their headers")
	}
	for _, tok := range toks {
		h.end(tok) // ending a token that was replaced is a no-op
	}
	if !idle.on() {
		t.Fatal("idle not armed after every stream ended: a replaced token leaked its quiet item")
	}
}
