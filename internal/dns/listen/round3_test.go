package listen

// Tests of review round 3 (p4n-W6-r3-*): a reply that panics while it is
// packed, TLS resumption and the unrecognized_name rule, and the bytes that
// DoQ, DoH and DoH3 hold for a peer that does not read.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// A reply that panics in Pack answers SERVFAIL for its query on every
// transport, and the node lives on (p4n-W6-r3-1, -4). The handler's own
// recover does not reach the packing, which runs afterwards.
func TestReplyThatPanicsWhilePackedAnswersServFail(t *testing.T) {
	f := newFixture(t)
	for _, tr := range limits6() {
		t.Run(tr.String(), func(t *testing.T) {
			c := f.mustDial(tr)
			r, err := ask(c, "badpack-x.example.org.", dns.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			if r.Rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode %d, want SERVFAIL", r.Rcode)
			}
			if r, err = ask(c, "www.example.org.", dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("the next query: %v %v", r, err)
			}
		})
	}
	f.obs.mu.Lock()
	defer f.obs.mu.Unlock()
	for _, tr := range limits6() {
		if f.obs.panics[tr] != 1 {
			t.Errorf("%s: %d panics counted, want 1", tr, f.obs.panics[tr])
		}
	}
}

// ---- resumption

// anyKeyCache is a client session cache that hands the ticket it holds to any
// connection, whatever the name: the client an attacker would write.
type anyKeyCache struct {
	mu   sync.Mutex
	cs   *tls.ClientSessionState
	puts int
}

func (c *anyKeyCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}

func (c *anyKeyCache) Put(_ string, cs *tls.ClientSessionState) {
	if cs == nil {
		return
	}
	c.mu.Lock()
	c.cs = cs
	c.puts++
	c.mu.Unlock()
}

func (c *anyKeyCache) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts
}

// dialResume opens one connection of a transport with the given name and cache,
// without checking the certificate, and reports whether it resumed a session.
func dialResume(f *fixture, tr Transport, sni string, cache tls.ClientSessionCache, maxVer uint16) (resumed bool, err error) {
	conf := f.tlsConf(sni)
	conf.InsecureSkipVerify = true
	conf.ClientSessionCache = cache
	if maxVer != 0 {
		conf.MaxVersion = maxVer
	}
	switch tr {
	case DoT, DoH:
		addr := f.addr(DoT)
		if tr == DoH {
			addr = f.addr(DoH)
			conf.NextProtos = []string{"h2"}
		}
		c, err := tls.Dial("tcp", addr, conf)
		if err != nil {
			return false, err
		}
		defer c.Close()
		// The client takes a TLS 1.3 ticket in on its first read.
		_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		_, _ = c.Read(make([]byte, 1))
		return c.ConnectionState().DidResume, nil
	}
	conf.NextProtos = []string{"doq"}
	addr := f.addr(DoQ)
	if tr == DoH3 {
		conf.NextProtos = []string{"h3"}
		addr = f.addr(DoH3)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, conf, nil)
	if err != nil {
		return false, err
	}
	defer conn.CloseWithError(0, "")
	// The ticket arrives after the handshake.
	if ac, ok := cache.(*anyKeyCache); ok {
		for i := 0; i < 40 && ac.count() == 0; i++ {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return conn.ConnectionState().TLS.DidResume, nil
}

// A session ticket is good for the name it was issued for. Resuming it under
// another name must give a full handshake, so the certificate provider decides
// again and its unrecognized_name refusal holds (SC 3.3 R7; p4n-W6-r3-2).
func TestResumptionIsBoundToTheName(t *testing.T) {
	const unknown = "nope.dns.test"
	const other = "other.dns.test"
	f := newFixture(t, withRefusedName(unknown))
	cases := []struct {
		tr  Transport
		ver uint16
	}{
		{DoT, 0}, {DoT, tls.VersionTLS12}, {DoH, 0}, {DoQ, 0}, {DoH3, 0},
	}
	for _, c := range cases {
		name := c.tr.String()
		if c.ver == tls.VersionTLS12 {
			name += "-tls12"
		}
		t.Run(name, func(t *testing.T) {
			cache := &anyKeyCache{}
			if _, err := dialResume(f, c.tr, testSNI, cache, c.ver); err != nil {
				t.Fatal(err)
			}
			if cache.count() == 0 {
				t.Fatal("the server issued no session ticket: the test measured nothing")
			}
			// Same name: the session resumes.
			if resumed, err := dialResume(f, c.tr, testSNI, cache, c.ver); err != nil || !resumed {
				t.Fatalf("same name: resumed=%v err=%v", resumed, err)
			}
			// Another name the provider accepts: a full handshake, not a resumption.
			if resumed, err := dialResume(f, c.tr, other, cache, c.ver); err != nil || resumed {
				t.Fatalf("another name: resumed=%v err=%v", resumed, err)
			}
			// A name the provider refuses: the alert, with the ticket in hand.
			_, err := dialResume(f, c.tr, unknown, cache, c.ver)
			if err == nil {
				t.Fatal("a ticket carried a refused name through the handshake")
			}
			if !strings.Contains(err.Error(), "unrecognized name") && !strings.Contains(err.Error(), "0x170") {
				t.Fatalf("want the unrecognized_name alert, got: %v", err)
			}
		})
	}
}

// ---- reply bytes held for a peer that does not read

// holdQueries is how many queries a non-reading peer sends at once; their
// replies (about 9.7 KiB each) are more than the 256 KiB a connection may hold.
const holdQueries = 40

// A peer with a tiny flow-control window sends many queries for large answers
// and reads nothing. The replies must not all be held: past the per-connection
// bound the rest are SERVFAIL, a few dozen bytes each (p4n-W6-r3-3). Before the
// fix all forty were held, 390 KiB on one connection, and a few hundred
// connections of one address held gigabytes.
func TestHeldReplyBytesAreBoundedOnQUICAndHTTP2(t *testing.T) {
	set, _ := limits.SettingsFor(limits.Listeners(), DoQ)
	cases := []struct {
		tr  Transport
		run func(f *fixture) (full, servfail int, err error)
	}{
		{DoQ, holdDoQ},
		{DoH3, holdDoH3},
		{DoH, holdDoH2},
	}
	for _, c := range cases {
		t.Run(c.tr.String(), func(t *testing.T) {
			f := newFixture(t, withHandler(&slowBig{delay: 100 * time.Millisecond}))
			full, sf, err := c.run(f)
			if err != nil {
				t.Fatal(err)
			}
			if full+sf != holdQueries {
				t.Fatalf("%d full replies and %d SERVFAIL of %d queries", full, sf, holdQueries)
			}
			if sf == 0 {
				t.Fatalf("all %d replies were held for a peer that reads nothing", full)
			}
			if held := full * 9000; held > set.MaxQueuedBytes+9800 {
				t.Fatalf("%d full replies held, about %d bytes, bound %d", full, held, set.MaxQueuedBytes)
			}
			if full == 0 {
				t.Fatal("no reply at all came in full: the first reply always fits")
			}
		})
	}
}

func bigQuery(i int) *dns.Msg { return mkq(fmt.Sprintf("q%d.example.org.", i), dns.TypeTXT) }

func holdDoQ(f *fixture) (full, servfail int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, f.addr(DoQ), f.tlsConf("", "doq"),
		&quic.Config{MaxIdleTimeout: 30 * time.Second, InitialStreamReceiveWindow: 1000, MaxStreamReceiveWindow: 1000})
	if err != nil {
		return 0, 0, err
	}
	defer conn.CloseWithError(0, "")
	var strs []*quic.Stream
	for i := 0; i < holdQueries; i++ {
		str, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return 0, 0, err
		}
		m := bigQuery(i)
		m.Id = 0
		b, _ := m.Pack()
		if _, err := str.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
			return 0, 0, err
		}
		_ = str.Close()
		strs = append(strs, str)
	}
	time.Sleep(800 * time.Millisecond) // every handler has answered and every write is parked
	for _, str := range strs {
		_ = str.SetReadDeadline(time.Now().Add(20 * time.Second))
		all, err := io.ReadAll(str)
		if err != nil {
			return 0, 0, err
		}
		if len(all) > 2000 {
			full++
		} else {
			servfail++
		}
	}
	return full, servfail, nil
}

// holdHTTP sends the queries through cl, waits until every response has its
// headers, then reads every body. A response is full or a short SERVFAIL by its
// Content-Length.
func holdHTTP(cl *http.Client, base string) (full, servfail int, err error) {
	var wg sync.WaitGroup
	resps := make([]*http.Response, holdQueries)
	errs := make([]error, holdQueries)
	for i := 0; i < holdQueries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resps[i], errs[i] = dohDo(cl, base, bigQuery(i), "POST", nil)
		}()
	}
	wg.Wait()
	for i, r := range resps {
		if errs[i] != nil {
			return 0, 0, errs[i]
		}
		if r.ContentLength > 2000 {
			full++
		} else {
			servfail++
		}
	}
	for _, r := range resps {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	return full, servfail, nil
}

func holdDoH3(f *fixture) (full, servfail int, err error) {
	tr := &http3.Transport{TLSClientConfig: f.tlsConf("", "h3"),
		QUICConfig: &quic.Config{InitialStreamReceiveWindow: 1000, MaxStreamReceiveWindow: 1000}}
	defer tr.Close()
	return holdHTTP(&http.Client{Transport: tr, Timeout: 40 * time.Second}, "https://"+f.addr(DoH3)+"/dns-query")
}

func holdDoH2(f *fixture) (full, servfail int, err error) {
	tr := &http.Transport{TLSClientConfig: f.tlsConf("", "h2"), ForceAttemptHTTP2: true,
		HTTP2: &http.HTTP2Config{MaxReceiveBufferPerStream: 1000}}
	defer tr.CloseIdleConnections()
	return holdHTTP(&http.Client{Transport: tr, Timeout: 40 * time.Second}, "https://"+f.addr(DoH)+"/dns-query")
}

// The count itself: the first reply of a connection always fits, one that would
// pass a bound is replaced, and what is released is given back to the listener.
func TestHeldCountBounds(t *testing.T) {
	var node atomic.Int64
	a, b := newHeld(&node), newHeld(&node)
	big := func(n int) []byte { return make([]byte, n) }
	alt := func() []byte { return make([]byte, 10) }

	got := a.hold(big(300), 100, 1000, alt) // the first always fits
	if len(got) != 300 {
		t.Fatalf("first reply replaced: %d bytes", len(got))
	}
	got2 := a.hold(big(50), 100, 1000, alt) // 350 > 100: replaced
	if len(got2) != 10 {
		t.Fatalf("a reply past the connection bound was kept: %d bytes", len(got2))
	}
	if node.Load() != 310 {
		t.Fatalf("listener count %d, want 310", node.Load())
	}
	// A connection that holds nothing is never over the listener bound, however
	// full the listener is (p4n-W6-r6-1)...
	gb := b.hold(big(900), 5000, 1000, alt)
	if len(gb) != 900 {
		t.Fatalf("an empty connection was turned away by the listener bound: %d bytes", len(gb))
	}
	// ...but a connection that now holds bytes meets it.
	gb2 := b.hold(big(900), 5000, 1000, alt)
	if len(gb2) != 10 {
		t.Fatalf("a reply past the listener bound was kept: %d bytes", len(gb2))
	}
	a.release(len(got))
	a.release(len(got2))
	b.release(len(gb))
	b.release(len(gb2))
	if node.Load() != 0 {
		t.Fatalf("listener count %d after every release, want 0", node.Load())
	}
	if g := b.hold(big(900), 5000, 1000, alt); len(g) != 900 {
		t.Fatalf("a reply under the bounds was replaced: %d bytes", len(g))
	}
	var nilHeld *held
	if g := nilHeld.hold(big(5), 1, 1, alt); len(g) != 5 {
		t.Fatal("a nil held changed a reply")
	}
	nilHeld.release(5)
}
