package dns

// N7 (p4-nodes 11.2, SC 5.2a No trace, R21, Plan T-555): canary values go through
// every transport of the node while the test drives handler panics, malformed
// requests and TLS errors, and they must be in no sink afterwards: not the
// process's own log output (slog, log, stderr, stdout), not a file under the
// node's roots, and not what the node reports to the hub, apart from what a report
// carries by design.
//
// The canaries are the name and the source address of queries that identify no
// one, the DoH token, the rid and a client label of an Endpoint's queries, and the
// proof key. The agent's side of N7 (a refused NodeConfig, a CertBundle that does
// not open, a panic in apply) is in the agent package; Unbound's own log and core
// paths are the install test's, on a real host.
//
// Mutants, each of which fails this test: a log call with the name of a query (a
// log.Printf in the handler or the listeners, or a slog call), a listener that
// lets a handler panic reach net/http's default ErrorLog or the runtime's trace
// (the panic value here holds a name, an address, a token path and an SNI), and a
// file that gets a name or a token (a cache or a spool written to disk).

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/testsink"
)

const (
	canarySrc   = "127.0.0.123"                    // the address of queries that identify no one
	canaryLabel = "n7canarylabel"                  // a client label of an identified query
	unknownRID  = "zyxwvutsrqponmlkjihgfedcba"     // a resolver id no Endpoint has
	unknownTok  = "n7unknowntokenabcdefghijklmnop" // a DoH token no Endpoint has
)

// attempt runs one hostile or broken client action and ignores how it ends: the
// test is about what the node leaves behind, not about what each one gets.
func attempt(f func()) { f() }

func (e *e2e) rawConn(network string, tr listen.Transport) (net.Conn, error) {
	return (&net.Dialer{Timeout: 2 * time.Second}).Dial(network, e.addr(tr))
}

// rawDoH sends one HTTP request with a body the test chooses.
func (e *e2e) rawDoH(tr listen.Transport, h2 bool, sni, method, path, authority, ctype string, body []byte) {
	cl, closeFn := e.httpClient(tr, sni, h2)
	defer closeFn()
	req, err := http.NewRequest(method, "https://"+e.addr(tr)+path, bytes.NewReader(body))
	if err != nil {
		return
	}
	if authority != "" {
		req.Host = authority
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if resp, err := cl.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func TestN7NoTraceOfCanariesOnEveryTransport(t *testing.T) {
	e := newE2EWith(t, func(h listen.Handler) listen.Handler {
		// A fault in front of the real handler: a name that starts with n7-panic makes
		// the handler panic with a message that holds everything it was given.
		return listen.HandlerFunc(func(ctx context.Context, req *listen.Request) listen.Reply {
			if len(req.Msg.Question) > 0 && strings.HasPrefix(req.Msg.Question[0].Name, "n7-panic") {
				path := ""
				if req.HTTP != nil {
					path = req.HTTP.Path
				}
				panic(fmt.Sprintf("canary panic: %s from %s sni %s path %s", req.Msg.Question[0].Name, req.Source, req.SNI, path))
			}
			return h.ServeDNS(ctx, req)
		})
	})

	// A proof key of random bytes, so it is its own canary.
	proof := make([]byte, 32)
	for i := range proof {
		proof[i] = byte(0xA0 + i*7)
	}
	zones := []names.Name{names.MustString(testZone)}
	e.h.SetSettings(NewSettings(zones, e.settings.panel, e.settings.selfIP, proof, false))

	sinks := testsink.Start(t)
	sinks.Control(t) // the sinks work: without this a test that captured nothing would pass for ever

	var unidentified []string // names of queries that identify no one
	name := func(tag string) string {
		n := "n7-unid-" + tag + ".canary-net.example"
		unidentified = append(unidentified, n)
		return n
	}
	idRID, idTok := rid(epB), tok(epB)
	sniB := idRID + "-" + canaryLabel + "." + testZone // epB: Default Bypass, no Require Authorized IPs
	dohB := dohCall{sni: "x." + testZone, path: "/" + idTok, authority: idRID + "." + testZone}
	unidSNI := "x." + testZone // a DoT or DoQ query that names no Endpoint

	// 1. Queries with a name and a source of their own, on every transport.
	attempt(func() { _, _ = e.udp(canarySrc, q(name("udp"), dns.TypeA)) })
	attempt(func() { _, _ = e.udp("127.0.0.2", q("n7-ident-udp.canary-net.example", dns.TypeA)) })
	attempt(func() { _, _ = e.tcp(canarySrc, q(name("tcp"), dns.TypeA)) })
	attempt(func() { _, _ = e.tcp("127.0.0.2", q("n7-ident-tcp.canary-net.example", dns.TypeA)) })
	attempt(func() { _, _ = e.dot(unidSNI, q(name("dot"), dns.TypeA)) })
	attempt(func() { _, _ = e.dot(sniB, q("n7-ident-dot.canary-net.example", dns.TypeA)) })
	attempt(func() { _, _ = e.doq(unidSNI, q(name("doq"), dns.TypeA)) })
	attempt(func() { _, _ = e.doq(sniB, q("n7-ident-doq.canary-net.example", dns.TypeA)) })
	for _, c := range []struct {
		tag string
		tr  listen.Transport
		h2  bool
	}{{"doh", listen.DoH, true}, {"doh1", listen.DoH, false}, {"doh3", listen.DoH3, true}} {
		un, id := dohB, dohB
		un.t, un.h2, un.path, un.authority = c.tr, c.h2, "/", testZone // no token: names nobody
		id.t, id.h2 = c.tr, c.h2
		attempt(func() { _, _, _, _ = e.doh(un, q(name(c.tag), dns.TypeA)) })
		attempt(func() { _, _, _, _ = e.doh(id, q("n7-ident-"+c.tag+".canary-net.example", dns.TypeA)) })
	}

	// 2. A handler that panics, with each of those shapes of request.
	pn := func(tag string) *dns.Msg {
		n := "n7-panic-" + tag + ".canary-net.example"
		unidentified = append(unidentified, n)
		return q(n, dns.TypeA)
	}
	attempt(func() { _, _ = e.udp(canarySrc, pn("udp")) })
	attempt(func() { _, _ = e.tcp(canarySrc, pn("tcp")) })
	attempt(func() { _, _ = e.dot(unidSNI, pn("dot")) })
	attempt(func() { _, _ = e.dot(sniB, pn("dot-id")) })
	attempt(func() { _, _ = e.doq(unidSNI, pn("doq")) })
	attempt(func() { _, _ = e.doq(sniB, pn("doq-id")) })
	for _, c := range []struct {
		tr listen.Transport
		h2 bool
	}{{listen.DoH, true}, {listen.DoH, false}, {listen.DoH3, true}} {
		id := dohB
		id.t, id.h2 = c.tr, c.h2
		attempt(func() { _, _, _, _ = e.doh(id, pn("doh-id")) })
	}

	// 3. Malformed requests. Each carries a canary where a name or a token would be.
	packed, _ := q(name("cut"), dns.TypeA).Pack()
	attempt(func() { // UDP: a datagram cut in the middle of the name, a short header, a response
		if c, err := e.rawConn("udp", listen.UDP); err == nil {
			_, _ = c.Write(packed[:len(packed)-6])
			_, _ = c.Write([]byte{1, 2, 3})
			resp := q(name("qr"), dns.TypeA)
			resp.Response = true
			b, _ := resp.Pack()
			_, _ = c.Write(b)
			_ = c.Close()
		}
	})
	attempt(func() { // TCP: a length that promises more than comes, then a close; then garbage
		if c, err := e.rawConn("tcp", listen.TCP); err == nil {
			_, _ = c.Write(append([]byte{byte(len(packed) >> 8), byte(len(packed))}, packed[:len(packed)/2]...))
			_ = c.Close()
		}
		if c, err := e.rawConn("tcp", listen.TCP); err == nil {
			_, _ = c.Write([]byte("GET /" + idTok + " HTTP/1.1\r\nHost: " + canarySrc + "\r\n\r\n"))
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	})
	attempt(func() { // DoT: plaintext on the TLS port, an unknown rid, a bad ALPN, garbage inside TLS
		if c, err := e.rawConn("tcp", listen.DoT); err == nil {
			_, _ = c.Write([]byte("GET /" + idTok + " HTTP/1.1\r\nHost: " + idRID + "." + testZone + "\r\n\r\n"))
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
		if c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", e.addr(listen.DoT), e.tlsConf(unknownRID+"-"+canaryLabel+"."+testZone)); err == nil {
			_ = c.Close()
		}
		if c, err := e.dotConn(sniB); err == nil {
			_, _ = c.Write([]byte{0, 9, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5})
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	})
	attempt(func() { // DoQ: an unknown rid, a bad ALPN, garbage on a stream
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if cn, err := quic.DialAddr(ctx, e.addr(listen.DoQ), e.tlsConf(unknownRID+"."+testZone, "doq"), &quic.Config{}); err == nil {
			cn.CloseWithError(0, "")
		}
		if cn, err := quic.DialAddr(ctx, e.addr(listen.DoQ), e.tlsConf(sniB, "n7-canary-alpn"), &quic.Config{}); err == nil {
			cn.CloseWithError(0, "")
		}
		if cn, err := e.doqConn(sniB); err == nil {
			if st, err := cn.OpenStreamSync(ctx); err == nil {
				_, _ = st.Write([]byte{0, 40, 1, 2, 3})
				_ = st.Close()
				_, _ = io.ReadAll(st)
			}
			cn.CloseWithError(0, "")
		}
	})
	for _, c := range []struct {
		tr listen.Transport
		h2 bool
	}{{listen.DoH, true}, {listen.DoH, false}, {listen.DoH3, true}} {
		x := "x." + testZone
		e.rawDoH(c.tr, c.h2, x, "POST", "/"+idTok, idRID+"."+testZone, "application/dns-message", []byte{1, 2, 3, 4})
		e.rawDoH(c.tr, c.h2, x, "POST", "/"+idTok, idRID+"."+testZone, "text/plain", packed)
		e.rawDoH(c.tr, c.h2, x, "GET", "/"+idTok+"?dns=!!"+canaryLabel, idRID+"."+testZone, "", nil)
		e.rawDoH(c.tr, c.h2, x, "POST", "/"+unknownTok, unknownRID+"."+testZone, "application/dns-message", packed)
		e.rawDoH(c.tr, c.h2, unknownRID+"."+testZone, "POST", "/"+idTok, "", "application/dns-message", packed)
		e.rawDoH(c.tr, c.h2, x, "DELETE", "/"+idTok+"/"+canaryLabel, testZone, "", nil)
	}
	// The proof key's own route.
	attempt(func() {
		e.rawDoH(listen.DoH, true, "x."+testZone, "GET", "/v", "n7-verify-"+canaryLabel+".verify."+testZone, "", nil)
	})

	time.Sleep(500 * time.Millisecond) // let the last handlers and closes finish
	sinks.Stop()

	// What each sink must not hold.
	common := [][]byte{[]byte(canarySrc), []byte(idRID), []byte(idTok), []byte(unknownRID), []byte(unknownTok), proof,
		[]byte(hex.EncodeToString(proof)), []byte(base64.StdEncoding.EncodeToString(proof)), []byte(base64.RawURLEncoding.EncodeToString(proof)),
		[]byte(base64.URLEncoding.EncodeToString(proof))}
	for _, n := range unidentified {
		common = append(common, []byte(n), []byte(dns.Fqdn(n)))
	}
	withLabel := append(append([][]byte(nil), common...), []byte(canaryLabel), []byte("n7-ident-"), []byte("n7-panic"))

	check := func(sink string, hay []byte, needles [][]byte) {
		t.Helper()
		for _, n := range needles {
			if bytes.Contains(hay, n) {
				t.Errorf("%s holds a canary (%d bytes, starting %q)", sink, len(n), n[:min(len(n), 6)])
			}
		}
	}

	// The process's own output.
	check("the log output", sinks.Bytes(), withLabel)

	// Every file under the node's roots.
	var files int
	err := filepath.WalkDir(e.root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		files++
		check("file "+filepath.Base(p), b, withLabel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no file was scanned")
	}

	// What goes to the hub. An identified query's report carries its own client label
	// and the ids of its Endpoint by design, so the label is not looked for there; what
	// no report may carry is the name of any query, the address of an unidentified
	// source, the token, the rid or the proof key.
	e.rep.mu.Lock()
	var rep []byte
	for _, m := range e.rep.acts {
		rep = append(rep, prototext.Format(m)...)
	}
	for _, m := range e.rep.learned {
		rep = append(rep, prototext.Format(m)...)
	}
	for _, m := range e.rep.proofs {
		rep = append(rep, prototext.Format(m)...)
		b, _ := proto.Marshal(m)
		rep = append(rep, b...)
	}
	e.rep.mu.Unlock()
	check("the report to the hub", rep, append(append([][]byte(nil), common...), []byte("n7-ident-"), []byte("n7-panic")))
}
