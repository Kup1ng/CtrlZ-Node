package resolve

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// stallServers starts a TCP listener that accepts and never writes (a path
// that completes the handshake of the transport below TLS and then stalls),
// and a UDP socket that reads and never answers.
func stallServers(t *testing.T) (tcp, udp netip.AddrPort) {
	t.Helper()
	var ln net.Listener
	var pc net.PacketConn
	port := scanPorts(t, func(p int) error {
		ap := netip.AddrPortFrom(loopback, uint16(p)).String()
		var err error
		if ln, err = net.Listen("tcp", ap); err != nil {
			return err
		}
		if pc, err = net.ListenPacket("udp", ap); err != nil {
			_ = ln.Close()
		}
		return err
	})
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = ln.Close(); _ = pc.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		go func() { <-done; _ = ln.Close() }()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	ap := netip.AddrPortFrom(loopback, uint16(port))
	return ap, ap
}

// Exchange returns within one Timeout whatever the transport does, and at once
// when ctx ends. dnsproxy's DoT handshake limit is a fixed 10 s and plain UDP
// retries with a fresh timeout, so the bound has to live in Exchange.
func TestExchangeBoundedByTimeout(t *testing.T) {
	_, pool := testCert(t)
	stall, _ := stallServers(t)
	const timeout = 500 * time.Millisecond
	const margin = 700 * time.Millisecond

	for _, tc := range []struct {
		name string
		kind commonv1.UpstreamKind
	}{
		{"udp", commonv1.UpstreamKind_UPSTREAM_KIND_UDP},
		{"dot", commonv1.UpstreamKind_UPSTREAM_KIND_DOT},
		{"doh", commonv1.UpstreamKind_UPSTREAM_KIND_DOH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Kind: tc.kind, Address: stall.String(), RootCAs: pool, Timeout: timeout}
			u, err := NewUpstream(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()

			// The caller's own deadline is far away: Timeout alone must bound it.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			start := time.Now()
			resp, err := u.Exchange(ctx, query("example.com"))
			if err == nil || resp != nil {
				t.Fatalf("stalled upstream answered: %v %v", resp, err)
			}
			if d := time.Since(start); d > timeout+margin {
				t.Fatalf("Exchange took %v, bound is %v", d, timeout)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error %v does not wrap the deadline", err)
			}
		})
	}

	t.Run("ctx cancel releases the caller", func(t *testing.T) {
		u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: stall.String(), RootCAs: pool, Timeout: 30 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		start := time.Now()
		_, err = u.Exchange(ctx, query("example.com"))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error %v, want context.Canceled", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("cancelled Exchange returned after %v", d)
		}
	})
}

// dnsproxy indexes req.Question[0] without a check; a query with none must be
// refused before it gets there.
func TestExchangeRefusesNoQuestion(t *testing.T) {
	plain, _, _ := startPlain(t, false)
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: plain.String(), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for name, req := range map[string]*dns.Msg{
		"none": new(dns.Msg),
		"two": func() *dns.Msg {
			m := query("a.example")
			m.Question = append(m.Question, dns.Question{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			return m
		}(),
	} {
		resp, err := u.Exchange(context.Background(), req)
		if !errors.Is(err, ErrBadQuery) || resp != nil {
			t.Fatalf("%s: %v %v", name, resp, err)
		}
	}
}

// A DoT server that answers for another name is not an answer: dnsproxy checks
// the question of the reply only for plain and DoH.
func TestExchangeChecksReplyQuestion(t *testing.T) {
	cert, pool := testCert(t)
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	mode := "other"
	s := &dns.Server{
		Listener: tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}),
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := answerA(r)
			switch mode {
			case "other":
				m.Question[0].Name = "b.example."
			case "type":
				m.Question[0].Qtype = dns.TypeAAAA
			case "none":
				m.Question = nil
			case "case":
				m.Question[0].Name = "EXAMPLE.com."
			}
			_ = w.WriteMsg(m)
		}),
	}
	serve(t, s)
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), RootCAs: pool, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	for _, m := range []string{"other", "type", "none"} {
		mode = m
		resp, err := u.Exchange(context.Background(), query("a.example"))
		if !errors.Is(err, ErrBadReply) || resp != nil {
			t.Fatalf("%s: %v %v", m, resp, err)
		}
	}
	mode = "case"
	if _, err := u.Exchange(context.Background(), query("example.com")); err != nil {
		t.Fatalf("a reply that differs in case only was refused: %v", err)
	}
}

// The error of a DoH exchange quotes the request URL, which carries the packed
// query, so the qname. Exchange cuts it out (SC 5.2a "No trace").
func TestExchangeErrorHasNoQuery(t *testing.T) {
	_, pool := testCert(t)
	// A port nothing listens on: the connection is refused and the client
	// error names the URL.
	var port int
	port = scanPorts(t, func(p int) error {
		l, err := net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		if err != nil {
			return err
		}
		return l.Close()
	})
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	req := query("secret-name.example.com")
	wire, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// The name starts at byte 12, a multiple of 3, so its base64 is a prefix
	// of the base64 of the whole message at a fixed offset.
	b64 := base64.RawURLEncoding.EncodeToString(wire[12 : len(wire)-6])

	// Control: the raw dnsproxy error does carry the query, so the check below
	// is not vacuous.
	raw := req.Copy()
	raw.Id = dns.Id()
	_, rawErr := rawDoH(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), pool).Exchange(context.Background(), raw)
	if rawErr == nil || !strings.Contains(rawErr.Error(), "dns=") {
		t.Skipf("dnsproxy error no longer quotes the DoH query: %v", rawErr)
	}

	_, err = u.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("dead DoH upstream answered")
	}
	if text := err.Error(); strings.Contains(text, "secret-name") || strings.Contains(text, b64[:12]) || strings.Contains(text, "dns=A") {
		t.Fatalf("error text carries the query: %q", text)
	}
}

func TestConfigFromWireRefusesViaLocation(t *testing.T) {
	_, err := ConfigFromWire(&hubv1.Upstream{
		Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "dns.example.net", BootstrapIp: []byte{192, 0, 2, 1},
		TimeoutMs: 1500, ViaLocation: 3,
	})
	if !errors.Is(err, ErrViaLocation) {
		t.Fatalf("via_location 3: %v", err)
	}
}

// Every IPv6 range that stands for an IPv4 address is refused as a bootstrap
// and as the address of a udp upstream, not only the IPv4-mapped one.
func TestRefusesEmbeddedIPv4Forms(t *testing.T) {
	for _, a := range []string{
		"::ffff:192.0.2.1",
		"64:ff9b::c000:201",
		"::c000:201",
		"2002:c000:201::1",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",
	} {
		addr := netip.MustParseAddr(a)
		if _, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net", BootstrapIP: addr, Timeout: time.Second}); !errors.Is(err, ErrBootstrapAddr) {
			t.Errorf("dot bootstrap %s: %v", a, err)
		}
		if _, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: netip.AddrPortFrom(addr, 53).String(), Timeout: time.Second}); !errors.Is(err, ErrBootstrapAddr) {
			t.Errorf("udp address %s: %v", a, err)
		}
	}
	// A plain global IPv6 address and ::1 stay valid.
	for _, a := range []string{"2606:4700:4700::1111", "::1"} {
		u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.net", BootstrapIP: netip.MustParseAddr(a), Timeout: time.Second})
		if err != nil {
			t.Errorf("%s refused: %v", a, err)
			continue
		}
		_ = u.Close()
	}
}

// A DoH reply that does not unpack makes dnsproxy put the whole body into its
// error. The body echoes the question and holds whatever the upstream sent, so
// Exchange must cut it, keep the text printable, and keep the cause.
func TestExchangeErrorHasNoReplyBody(t *testing.T) {
	cert, pool := testCert(t)
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(loopback, uint16(p)).String())
		return err
	})
	// Not a DNS message: it carries the qname in wire form, a control byte and
	// a forged log line.
	const body = "\x11secret-user-query\aexample\x00\n2026-11-22 level=ERROR msg=forged\n"
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write([]byte(body))
		}),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), RootCAs: pool, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	// Control: the raw dnsproxy error does carry the body.
	raw := query("secret-user-query.example.com")
	raw.Id = dns.Id()
	_, rawErr := rawDoH(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), pool).Exchange(context.Background(), raw)
	if rawErr == nil || !strings.Contains(rawErr.Error(), "forged") {
		t.Skipf("dnsproxy error no longer quotes the DoH body: %v", rawErr)
	}

	resp, err := u.Exchange(context.Background(), query("secret-user-query.example.com"))
	if err == nil || resp != nil {
		t.Fatalf("garbage reply accepted: %v %v", resp, err)
	}
	text := err.Error()
	if strings.Contains(text, "secret-user-query") || strings.Contains(text, "forged") || strings.Contains(text, "level=ERROR") {
		t.Fatalf("error text carries the reply body: %q", text)
	}
	for _, c := range []byte(text) {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("error text has a non-printable byte %#x: %q", c, text)
		}
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("cause lost")
	}
}

func TestRedactedErrorCapsLength(t *testing.T) {
	long := redactedError{errors.New(strings.Repeat("x", 5000) + "\n")}
	if n := len(long.Error()); n != maxErrorText {
		t.Fatalf("length %d, want %d", n, maxErrorText)
	}
}

// A stalled DoH upstream fails with a deadline error every time, not only when
// the call context wins a race against a transport timer of the same length
// (p4n-W7-r4-1). The stall is repeated because the old failure came about three
// runs in eight.
func TestDoHStallIsAlwaysADeadline(t *testing.T) {
	_, pool := testCert(t)
	stall, _ := stallServers(t)
	u, err := NewUpstream(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: stall.String(), RootCAs: pool, Timeout: 80 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := 0; i < 40; i++ {
		_, err := u.Exchange(context.Background(), query("example.com"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("round %d: %v does not wrap the deadline", i, err)
		}
	}
}
