package listen

// Tests of review round 8 (p4n-W6-r8-*): the verify hook under a recover, a
// Reply.Status WriteHeader would reject, and OPTIONS * reaching the DoH handler.

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type panicVerify struct{}

func (panicVerify) VerifyHost(sni string) bool { return strings.HasSuffix(sni, ".verify."+zoneName) }
func (panicVerify) ServeHTTP(http.ResponseWriter, *http.Request) {
	panic("verify hook: asked to panic")
}

// A panic in the verify hook answers 500 and leaves the connection, as a
// handler panic does for a DNS query (T-549). Checked through connection reuse
// on HTTP/1.1, where net/http would otherwise close the connection.
func TestVerifyHookPanicAnswers500AndKeepsTheConnection(t *testing.T) {
	sni := "abc.verify." + zoneName
	for _, tr := range []Transport{DoH, DoH3} {
		f := verifyFixture(t, tr, panicVerify{})
		var cl *http.Client
		var url string
		if tr == DoH {
			c := f.dohClient(false, sni)
			defer c.close()
			cl, url = c.cl, "https://"+f.addr(DoH)+"/v"
		} else {
			c := f.doh3Client(sni)
			defer c.close()
			cl, url = c.cl, "https://"+f.addr(DoH3)+"/v"
		}
		reused := false
		for i := 0; i < 2; i++ {
			req, _ := http.NewRequest("GET", url, nil)
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
				GotConn: func(ci httptrace.GotConnInfo) { reused = ci.Reused },
			}))
			resp, err := cl.Do(req)
			if err != nil {
				t.Fatalf("%s request %d: %v", tr, i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 500 {
				t.Fatalf("%s request %d: status %d, want 500", tr, i, resp.StatusCode)
			}
		}
		if tr == DoH && !reused {
			t.Fatalf("%s: the connection was closed by the hook's panic", tr)
		}
		f.obs.mu.Lock()
		n := f.obs.panics[tr]
		f.obs.mu.Unlock()
		if n != 2 {
			t.Fatalf("%s: %d panics counted, want 2", tr, n)
		}
	}
}

// A handler Reply.Status that WriteHeader rejects (it panics outside 100..999)
// is a SERVFAIL for that query on every DoH transport, and no panic.
func TestInvalidReplyStatusIsServFail(t *testing.T) {
	f := newFixture(t)
	for _, tr := range []Transport{DoH, DoH3} {
		for _, name := range []string{"statusbad-x.example.org.", "statusone-x.example.org."} {
			c := f.mustDial(tr)
			r, err := ask(c, name, dns.TypeA)
			if err != nil {
				t.Fatalf("%s %s: %v", tr, name, err)
			}
			if r.Rcode != dns.RcodeServerFailure {
				t.Fatalf("%s %s: rcode %d", tr, name, r.Rcode)
			}
		}
	}
}

// OPTIONS * with a declared body must meet the body deadline and the 405 of the
// DoH handler, not net/http's own OPTIONS handler, which reads the body with no
// deadline (p4n-W6-r8-2). The body is dripped; the request must end within the
// deadline plus a margin, and an answer, if one comes, is 405.
func TestOptionsStarMeetsTheBodyDeadline(t *testing.T) {
	f := newFixture(t, withTransports(DoH), shortSettings(nil))
	t.Run("h1", func(t *testing.T) {
		conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "http/1.1"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\n\r\n")
		status := make(chan int, 1)
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err == nil {
				status <- resp.StatusCode
				_, _ = io.Copy(io.Discard, resp.Body)
			}
		}()
		deadline := time.After(4 * time.Second)
		for {
			select {
			case <-closed:
				select {
				case s := <-status:
					if s != 405 {
						t.Fatalf("OPTIONS * answered %d, want 405", s)
					}
				default:
				}
				return
			case <-deadline:
				t.Fatal("OPTIONS * with a dripped body held the connection past the body deadline")
			case <-time.After(100 * time.Millisecond):
				_, _ = conn.Write([]byte("x"))
			}
		}
	})
	t.Run("h2", func(t *testing.T) {
		conn, err := tls.Dial("tcp", f.addr(DoH), f.tlsConf("", "h2"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, http2.ClientPreface)
		fr := http2.NewFramer(conn, conn)
		_ = fr.WriteSettings()
		var buf = new(bytesBuf)
		enc := hpack.NewEncoder(buf)
		for _, h := range [][2]string{{":method", "OPTIONS"}, {":scheme", "https"}, {":authority", "x"}, {":path", "*"}} {
			_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.b, EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
		ev := make(chan string, 1)
		go func() {
			dec := hpack.NewDecoder(4096, nil)
			for {
				fm, err := fr.ReadFrame()
				if err != nil {
					ev <- "closed"
					return
				}
				switch v := fm.(type) {
				case *http2.SettingsFrame:
					if !v.IsAck() {
						_ = fr.WriteSettingsAck()
					}
				case *http2.HeadersFrame:
					fields, _ := dec.DecodeFull(v.HeaderBlockFragment())
					for _, hf := range fields {
						if hf.Name == ":status" {
							ev <- hf.Value
							return
						}
					}
				case *http2.RSTStreamFrame:
					ev <- "reset"
					return
				}
			}
		}()
		deadline := time.After(4 * time.Second)
		for {
			select {
			case e := <-ev:
				if e == "200" {
					t.Fatalf("OPTIONS * answered 200, want 405, reset or close")
				}
				return
			case <-deadline:
				t.Fatal("OPTIONS * with a dripped body held the stream past the body deadline")
			case <-time.After(100 * time.Millisecond):
				_ = fr.WriteData(1, false, []byte("x"))
			}
		}
	})
}

type bytesBuf struct{ b []byte }

func (b *bytesBuf) Write(p []byte) (int, error) { b.b = append(b.b, p...); return len(p), nil }
