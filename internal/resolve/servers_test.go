package resolve

// Loopback DNS servers for the upstream tests and the load test. Everything is
// generated at run time (certificates included) and bound to ports 5700 to
// 5749 on 127.0.0.1 (W7 lane: 5700 to 5799, the other half is the dns package tests).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	portLo = 5700
	portHi = 5749
	// testHost is the TLS name of every test server. The .test TLD never
	// resolves, so a connection to it proves the bootstrap address was used.
	testHost = "dns.resolve.test"
)

// answerA is the one answer every test server gives: an A record for the
// question name.
func answerA(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		})
	}
	return m
}

func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// scanPorts calls try on each port of the range, starting at a random one so
// two tests that overlap do not collide, until one succeeds.
func scanPorts(t testing.TB, try func(port int) error) int {
	t.Helper()
	span := portHi - portLo + 1
	start, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < span; i++ {
		p := portLo + (int(start.Int64())+i)%span
		if try(p) == nil {
			return p
		}
	}
	t.Fatalf("no free port in %d-%d", portLo, portHi)
	return 0
}

// testCert returns a self-signed certificate valid for testHost and 127.0.0.1,
// and a pool that trusts it. The key lives in memory only.
func testCert(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{testHost},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// counter counts queries a test server answered.
type counter struct {
	n atomic.Int64
	// conns counts TLS handshakes started, for the servers that have them.
	conns atomic.Int64
}

func (c *counter) Count() int { return int(c.n.Load()) }

// startPlain serves UDP and TCP on one loopback port. With truncate set, the
// UDP side answers TC=1 with no records so the client must retry over TCP.
func startPlain(t testing.TB, truncate bool) (netip.AddrPort, *counter, *counter) {
	t.Helper()
	udpHits, tcpHits := &counter{}, &counter{}
	var pc net.PacketConn
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		pc, err = net.ListenPacket("udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(p)).String())
		if err != nil {
			return err
		}
		ln, err = net.Listen("tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(p)).String())
		if err != nil {
			_ = pc.Close()
		}
		return err
	})
	udp := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		udpHits.n.Add(1)
		m := answerA(r)
		if truncate {
			m.Answer, m.Truncated = nil, true
		}
		_ = w.WriteMsg(m)
	})}
	tcp := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		tcpHits.n.Add(1)
		_ = w.WriteMsg(answerA(r))
	})}
	serve(t, udp, tcp)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), udpHits, tcpHits
}

func serve(t testing.TB, servers ...*dns.Server) {
	t.Helper()
	for _, s := range servers {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("dns server did not start")
		}
		t.Cleanup(func() { _ = s.Shutdown() })
	}
}

// startDoT serves DNS over TLS on one loopback port.
func startDoT(t testing.TB, cert tls.Certificate, delay ...time.Duration) (netip.AddrPort, *counter) {
	t.Helper()
	hits := &counter{}
	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(p)).String())
		return err
	})
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { hits.conns.Add(1); return nil, nil }})
	s := &dns.Server{Listener: tlsLn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		sleepFor(delay)
		hits.n.Add(1)
		_ = w.WriteMsg(answerA(r))
	})}
	serve(t, s)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), hits
}

// dohServer is a loopback RFC 8484 server (POST and GET) over HTTPS with HTTP/2.
type dohServer struct {
	hits   counter
	h2Hits counter
}

// startDoH serves DoH on one loopback port at /dns-query and at /custom.
func startDoH(t testing.TB, cert tls.Certificate, delay ...time.Duration) (netip.AddrPort, *dohServer) {
	t.Helper()
	d := &dohServer{}
	mux := http.NewServeMux()
	h := func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		var err error
		switch r.Method {
		case http.MethodPost:
			raw, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		case http.MethodGet:
			raw, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		req := new(dns.Msg)
		if err != nil || req.Unpack(raw) != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		sleepFor(delay)
		d.hits.n.Add(1)
		if r.ProtoMajor == 2 {
			d.h2Hits.n.Add(1)
		}
		out, err := answerA(req).Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}
	mux.HandleFunc("/dns-query", h)
	mux.HandleFunc("/custom", h)

	var ln net.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = net.Listen("tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(p)).String())
		return err
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { d.hits.conns.Add(1); return nil, nil }},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), d
}

// startDoQ serves RFC 9250 on one loopback UDP port: one query per stream,
// each message behind a two-byte length.
func startDoQ(t testing.TB, cert tls.Certificate) (netip.AddrPort, *counter) {
	t.Helper()
	hits := &counter{}
	var ln *quic.Listener
	port := scanPorts(t, func(p int) error {
		var err error
		ln, err = quic.ListenAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(p)).String(),
			&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13},
			&quic.Config{MaxIdleTimeout: 30 * time.Second})
		return err
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go serveDoQConn(ctx, conn, hits)
		}
	}()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), hits
}

func serveDoQConn(ctx context.Context, conn *quic.Conn, hits *counter) {
	for {
		st, err := conn.AcceptStream(ctx)
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
			hits.n.Add(1)
			out, err := answerA(req).Pack()
			if err != nil {
				return
			}
			framed := binary.BigEndian.AppendUint16(nil, uint16(len(out)))
			_, _ = st.Write(append(framed, out...))
			_ = st.Close()
		}()
	}
}

// mustAnswer checks one exchange returned the test answer.
func mustAnswer(t testing.TB, u *Upstream, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := u.Exchange(ctx, query(name))
	if err != nil {
		t.Fatalf("exchange %v: %v", u.Kind(), err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1 (rcode %d, tc %v)", len(resp.Answer), resp.Rcode, resp.Truncated)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Fatalf("unexpected answer %v", resp.Answer[0])
	}
}

// sleepFor models the round trip to a far upstream in the load test; tests
// pass no delay.
func sleepFor(d []time.Duration) {
	if len(d) > 0 && d[0] > 0 {
		time.Sleep(d[0])
	}
}
