package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

var loopback = netip.MustParseAddr("127.0.0.1")

func hostport(ap netip.AddrPort, host string) string {
	return net.JoinHostPort(host, strconv.Itoa(int(ap.Port())))
}

func TestEveryKindAnswers(t *testing.T) {
	cert, pool := testCert(t)
	plain, udpHits, tcpHits := startPlain(t, false)
	trunc, truncUDP, truncTCP := startPlain(t, true)
	dot, dotHits := startDoT(t, cert)
	doh, dohSrv := startDoH(t, cert)
	doq, doqHits := startDoQ(t, cert)

	tests := []struct {
		name string
		cfg  Config
		hits func() int
	}{
		{"udp", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: plain.String()}, udpHits.Count},
		{"dot named", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: hostport(dot, testHost), BootstrapIP: loopback, RootCAs: pool}, dotHits.Count},
		{"dot numeric", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: dot.String(), RootCAs: pool}, dotHits.Count},
		{"dot tls_name", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: dot.String(), TLSName: testHost, RootCAs: pool}, dotHits.Count},
		{"doh named", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: hostport(doh, testHost), BootstrapIP: loopback, RootCAs: pool}, dohSrv.hits.Count},
		{"doh numeric", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: doh.String(), RootCAs: pool}, dohSrv.hits.Count},
		{"doh path", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: hostport(doh, testHost) + "/custom", BootstrapIP: loopback, RootCAs: pool}, dohSrv.hits.Count},
		{"doq named", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOQ, Address: hostport(doq, testHost), BootstrapIP: loopback, RootCAs: pool}, doqHits.Count},
		{"doq numeric", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOQ, Address: doq.String(), RootCAs: pool}, doqHits.Count},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Timeout = 5 * time.Second
			u, err := NewUpstream(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			// What the structural check N6 walks.
			if !u.BootstrapIP().IsValid() || u.Timeout() <= 0 {
				t.Fatalf("built upstream has bootstrap %v timeout %v", u.BootstrapIP(), u.Timeout())
			}
			before := tc.hits()
			mustAnswer(t, u, "example.com")
			if tc.hits() != before+1 {
				t.Fatalf("server saw %d new queries, want 1", tc.hits()-before)
			}
		})
	}

	t.Run("udp truncated falls back to tcp", func(t *testing.T) {
		u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: trunc.String(), Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		mustAnswer(t, u, "example.com")
		if truncUDP.Count() != 1 || truncTCP.Count() != 1 {
			t.Fatalf("udp %d tcp %d, want 1 and 1", truncUDP.Count(), truncTCP.Count())
		}
	})
	if tcpHits.Count() != 0 {
		t.Fatalf("plain tcp used without truncation: %d", tcpHits.Count())
	}
	// DoH must run over HTTP/2: the h2 client is the one the load test and
	// the two-connection cap are about.
	if dohSrv.h2Hits.Count() != dohSrv.hits.Count() || dohSrv.hits.Count() == 0 {
		t.Fatalf("doh queries over h2 = %d of %d", dohSrv.h2Hits.Count(), dohSrv.hits.Count())
	}
}

// A certificate that does not match the name is refused, so the explicit
// bootstrap never weakens verification.
func TestTLSNameMismatchRefused(t *testing.T) {
	cert, pool := testCert(t)
	dot, _ := startDoT(t, cert)
	u, err := NewUpstream(Config{
		Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: dot.String(), TLSName: "other.resolve.test",
		RootCAs: pool, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := u.Exchange(ctx, query("example.com")); err == nil {
		t.Fatal("exchange succeeded against a certificate for another name")
	}
}

func TestRefusals(t *testing.T) {
	const sec = 2 * time.Second
	b := loopback
	tests := []struct {
		name string
		cfg  Config
		want error
	}{
		{"dot name without bootstrap", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net", Timeout: sec}, ErrNoBootstrap},
		{"doh name without bootstrap", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "dns.example.net/dns-query", Timeout: sec}, ErrNoBootstrap},
		{"doq name without bootstrap", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOQ, Address: "dns.example.net:853", Timeout: sec}, ErrNoBootstrap},
		{"zero timeout udp", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "127.0.0.1:5353"}, ErrNoTimeout},
		{"zero timeout dot", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net", BootstrapIP: b}, ErrNoTimeout},
		{"negative timeout", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "dns.example.net", BootstrapIP: b, Timeout: -sec}, ErrNoTimeout},
		{"huge timeout", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "dns.example.net", BootstrapIP: b, Timeout: time.Hour}, ErrBadAddress},
		{"unspecified kind", Config{Address: "127.0.0.1:53", Timeout: sec}, ErrBadKind},
		{"udp with a name", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "dns.example.net:53", BootstrapIP: b, Timeout: sec}, ErrBadAddress},
		{"udp without port", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "127.0.0.1", Timeout: sec}, ErrBadAddress},
		{"udp bootstrap differs", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "127.0.0.1:53", BootstrapIP: netip.MustParseAddr("127.0.0.2"), Timeout: sec}, ErrBootstrapDiffer},
		{"numeric bootstrap differs", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "127.0.0.1:853", BootstrapIP: netip.MustParseAddr("127.0.0.2"), Timeout: sec}, ErrBootstrapDiffer},
		{"mapped bootstrap", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net", BootstrapIP: netip.MustParseAddr("::ffff:127.0.0.1"), Timeout: sec}, ErrBootstrapAddr},
		{"unspecified bootstrap", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net", BootstrapIP: netip.IPv4Unspecified(), Timeout: sec}, ErrBootstrapAddr},
		{"stamp", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5", BootstrapIP: b, Timeout: sec}, ErrBadAddress},
		{"scheme smuggled", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "h3://dns.example.net", BootstrapIP: b, Timeout: sec}, ErrBadAddress},
		{"userinfo", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "a@dns.example.net", BootstrapIP: b, Timeout: sec}, ErrBadAddress},
		{"path on dot", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net/x", BootstrapIP: b, Timeout: sec}, ErrBadAddress},
		{"empty host", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: ":853", BootstrapIP: b, Timeout: sec}, ErrBadAddress},
		{"tls_name is an IP", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net:853", BootstrapIP: netip.MustParseAddr("192.0.2.1"), TLSName: "127.0.0.1", Timeout: sec}, ErrBadAddress},
		{"numeric host and a different numeric tls_name", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "1.2.3.4", TLSName: "5.6.7.8", Timeout: sec}, ErrBadAddress},
		{"numeric host and its own IP as tls_name", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOQ, Address: "1.2.3.4:853", TLSName: "1.2.3.4", Timeout: sec}, ErrBadAddress},
		{"port zero", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net:0", BootstrapIP: b, Timeout: sec}, ErrBadAddress},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := NewUpstream(tc.cfg)
			if err == nil {
				_ = u.Close()
				t.Fatal("config accepted")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
		})
	}
}

// The whole point of rule 9 for upstreams: a named upstream is reached through
// its bootstrap address and nothing asks the host resolver. The .test name
// cannot resolve, and a hooked default resolver counts any attempt.
func TestNoLookupLeavesBootstrap(t *testing.T) {
	cert, pool := testCert(t)
	dot, _ := startDoT(t, cert)
	doh, _ := startDoH(t, cert)
	doq, _ := startDoQ(t, cert)

	var lookups atomic.Int64
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			lookups.Add(1)
			return nil, errors.New("system resolver used")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = old })

	for name, cfg := range map[string]Config{
		"dot": {Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: hostport(dot, testHost)},
		"doh": {Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: hostport(doh, testHost)},
		"doq": {Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOQ, Address: hostport(doq, testHost)},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.BootstrapIP, cfg.RootCAs, cfg.Timeout = loopback, pool, 5*time.Second
			u, err := NewUpstream(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			mustAnswer(t, u, "example.com")
			// A dead server must fail by timeout, not by falling through to
			// a lookup of the name.
			u2, err := NewUpstream(Config{Kind: cfg.Kind, Address: "dead.resolve.test:" + strconv.Itoa(portHi),
				BootstrapIP: loopback, RootCAs: pool, Timeout: 500 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			defer u2.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = u2.Exchange(ctx, query("example.com"))
		})
	}
	if n := lookups.Load(); n != 0 {
		t.Fatalf("the host resolver was used %d times", n)
	}
}

func TestConfigFromWire(t *testing.T) {
	cfg, err := ConfigFromWire(&hubv1.Upstream{
		Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "dns.example.net", BootstrapIp: []byte{192, 0, 2, 1},
		TlsName: "dns.example.net", TimeoutMs: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BootstrapIP != netip.MustParseAddr("192.0.2.1") || cfg.Timeout != 1500*time.Millisecond {
		t.Fatalf("got %+v", cfg)
	}
	u, err := NewUpstream(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Close()
	if _, err := ConfigFromWire(&hubv1.Upstream{BootstrapIp: []byte{1, 2, 3}}); !errors.Is(err, ErrBootstrapAddr) {
		t.Fatalf("3-byte bootstrap: %v", err)
	}
	// A zero timeout_ms in the message is refused at NewUpstream, not defaulted.
	cfg, _ = ConfigFromWire(&hubv1.Upstream{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "127.0.0.1:53"})
	if _, err := NewUpstream(cfg); !errors.Is(err, ErrNoTimeout) {
		t.Fatalf("zero timeout_ms: %v", err)
	}
}

// Control for TestNoLookupLeavesBootstrap: the same hook does see a lookup when
// dnsproxy is built directly with no Bootstrap, the silent fallback NewUpstream
// exists to prevent. Without this the zero-count above could mean a dead hook.
func TestLookupHookSeesHostResolver(t *testing.T) {
	var lookups atomic.Int64
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			lookups.Add(1)
			return nil, errors.New("hooked")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = old })

	raw, err := upstream.AddressToUpstream("tls://control.resolve.test:853", &upstream.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = raw.Exchange(ctx, query("example.com"))
	if lookups.Load() == 0 {
		t.Fatal("the hook did not see a lookup from an upstream with no Bootstrap")
	}
}

// The ID of the query that leaves the node is random and not the caller's, and
// the caller still gets its own ID back on the reply. Plain UDP is the
// transport where the ID is a defence against forged replies.
func TestExchangeUsesFreshID(t *testing.T) {
	var mu sync.Mutex
	var seen []uint16
	var pc net.PacketConn
	port := scanPorts(t, func(p int) error {
		var err error
		pc, err = net.ListenPacket("udp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	serve(t, &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		seen = append(seen, r.Id)
		mu.Unlock()
		_ = w.WriteMsg(answerA(r))
	})})

	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP,
		Address: netip.AddrPortFrom(loopback, uint16(port)).String(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	const rounds = 20
	for i := 0; i < rounds; i++ {
		req := query("example.com")
		req.Id = 0x1234
		resp, err := u.Exchange(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Id != 0x1234 {
			t.Fatalf("reply ID %#x, want the caller's 0x1234", resp.Id)
		}
		if req.Id != 0x1234 {
			t.Fatalf("the caller's message was modified: ID %#x", req.Id)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	same := 0
	for _, id := range seen {
		if id == 0x1234 {
			same++
		}
	}
	// A random ID hits 0x1234 once in 65536 draws; allow one lucky draw.
	if len(seen) != rounds || same > 1 {
		t.Fatalf("server saw %d queries, %d of them with the caller's ID", len(seen), same)
	}
}
