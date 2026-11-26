package querypath_test

// The drain rule of SC 8a.6 on a real node: the hub withdraws the node, the agent
// computes drain_since over the table it applied and tells dns, and dns closes its
// DoT, DoH, DoH3 and DoQ connections gracefully over the window while Plain DNS is
// never touched; a push that makes the node advertised again cancels it. The rule's
// 60 s and 360 s are shortened by dnsrole.Config.Drain, which is the only thing a
// test changes.

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
)

// closeLog records every close the listeners report, by transport.
type closeLog struct {
	mu sync.Mutex
	at map[listen.Transport][]time.Time
}

func (l *closeLog) observer() listen.Observer {
	return listen.Observer{Closed: func(t listen.Transport, _ listen.CloseReason) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.at == nil {
			l.at = map[listen.Transport][]time.Time{}
		}
		l.at[t] = append(l.at[t], time.Now())
	}}
}

func (l *closeLog) of(t listen.Transport) []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.at[t]...)
}

// persistent is one client that keeps its connection between queries and, when the
// server closes it, opens another and repeats the query once (RFC 7766 6.2.4).
type persistent struct {
	name    string
	tr      listen.Transport
	c       *clients
	dial    func() (func(m *dns.Msg) (*dns.Msg, error), func(), error)
	exch    func(m *dns.Msg) (*dns.Msg, error)
	closeFn func()
	redials int
	fails   int
	asked   int
}

func (p *persistent) connect() error {
	if p.closeFn != nil {
		p.closeFn()
	}
	e, cl, err := p.dial()
	if err != nil {
		return err
	}
	p.exch, p.closeFn = e, cl
	return nil
}

// ask sends the query of Endpoint 1 and counts a failure only when a second try on a
// new connection fails too.
func (p *persistent) ask() {
	p.asked++
	m := q(allowedName, dns.TypeA)
	if p.exch != nil {
		if r, err := p.exch(m); err == nil && hasA(r, ipV1) {
			return
		}
	}
	p.redials++
	if err := p.connect(); err != nil {
		p.fails++
		return
	}
	if r, err := p.exch(m); err != nil || !hasA(r, ipV1) {
		p.fails++
	}
}

func persistentClients(t *testing.T, f *fnode) []*persistent {
	c := f.c
	const src = "127.0.0.1"
	mk := func(name string, tr listen.Transport, dial func() (func(m *dns.Msg) (*dns.Msg, error), func(), error)) *persistent {
		return &persistent{name: name, tr: tr, c: c, dial: dial}
	}
	return []*persistent{
		mk("tcp", listen.TCP, func() (func(*dns.Msg) (*dns.Msg, error), func(), error) {
			cn, err := (&net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}).Dial("tcp", c.addr(listen.TCP))
			if err != nil {
				return nil, nil, err
			}
			return func(m *dns.Msg) (*dns.Msg, error) { return framedAsk(cn, m) }, func() { _ = cn.Close() }, nil
		}),
		mk("dot", listen.DoT, func() (func(*dns.Msg) (*dns.Msg, error), func(), error) {
			cn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", c.addr(listen.DoT), c.tlsConf(rid(1)+"."+zoneName))
			if err != nil {
				return nil, nil, err
			}
			return func(m *dns.Msg) (*dns.Msg, error) { return framedAsk(cn, m) }, func() { _ = cn.Close() }, nil
		}),
		mk("doq", listen.DoQ, func() (func(*dns.Msg) (*dns.Msg, error), func(), error) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, c.addr(listen.DoQ), c.tlsConf(rid(1)+"."+zoneName, "doq"), &quic.Config{MaxIdleTimeout: 20 * time.Second})
			if err != nil {
				return nil, nil, err
			}
			return func(m *dns.Msg) (*dns.Msg, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				str, err := conn.OpenStreamSync(ctx)
				if err != nil {
					return nil, err
				}
				m = m.Copy()
				m.Id = 0
				b, _ := m.Pack()
				_ = str.SetDeadline(time.Now().Add(4 * time.Second))
				if _, err := str.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
					return nil, err
				}
				_ = str.Close()
				all, err := io.ReadAll(str)
				if err != nil || len(all) < 2 {
					return nil, fmt.Errorf("doq: %v", err)
				}
				r := new(dns.Msg)
				return r, r.Unpack(all[2:])
			}, func() { _ = conn.CloseWithError(0, "") }, nil
		}),
		mk("doh-h2", listen.DoH, func() (func(*dns.Msg) (*dns.Msg, error), func(), error) {
			tr := &http.Transport{TLSClientConfig: c.tlsConf("x."+zoneName, "h2", "http/1.1"), ForceAttemptHTTP2: true}
			return dohExchange(tr, c.addr(listen.DoH)), tr.CloseIdleConnections, nil
		}),
		mk("doh3", listen.DoH3, func() (func(*dns.Msg) (*dns.Msg, error), func(), error) {
			tr := &http3.Transport{TLSClientConfig: c.tlsConf("x."+zoneName, "h3"), QUICConfig: &quic.Config{}}
			return dohExchange(tr, c.addr(listen.DoH3)), func() { _ = tr.Close() }, nil
		}),
	}
}

func dohExchange(rt http.RoundTripper, addr string) func(*dns.Msg) (*dns.Msg, error) {
	cl := &http.Client{Transport: rt, Timeout: 6 * time.Second}
	return func(m *dns.Msg) (*dns.Msg, error) {
		b, _ := m.Pack()
		req, err := http.NewRequest("POST", "https://"+addr+"/"+tok(1), bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Host = rid(1) + "." + zoneName
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("http %d", resp.StatusCode)
		}
		r := new(dns.Msg)
		return r, r.Unpack(body)
	}
}

// shortDrain is the rule at a tenth of its size: closes from 2 s, done by 7 s, and a
// query in flight is waited for up to 1 s.
var shortDrain = dnsrole.DrainTimes{From: 2 * time.Second, Done: 7 * time.Second, Wait: time.Second}

func TestW8DrainClosesRealConnectionsAndSparesPlainDNS(t *testing.T) {
	var cl closeLog
	f := upNode(t, 0, upOpts{adjust: func(c *dnsrole.Config) { c.Drain = &shortDrain; c.Observer = cl.observer() }})
	f.fresh()
	f.push(50)
	f.wantAddr("advertised", primaryIP)
	cs := persistentClients(t, f)
	for _, p := range cs {
		p.ask()
		if p.fails != 0 {
			t.Fatalf("%s: the first query failed", p.name)
		}
		defer p.closeFn()
	}
	base := map[listen.Transport]int{}
	for _, p := range cs {
		base[p.tr] = len(cl.of(p.tr))
		p.redials = 0
	}

	// The hub withdraws this node: the answer moves, the node drains.
	t0 := time.Now()
	f.push(51, 0)
	f.wantAddr("withdrawn", fallbackIP)
	for time.Since(t0) < 10*time.Second {
		for _, p := range cs {
			p.ask()
		}
		time.Sleep(80 * time.Millisecond)
	}
	for _, p := range cs {
		if p.fails != 0 {
			t.Errorf("%s: %d of %d queries failed during the drain", p.name, p.fails, p.asked)
		}
		closes := cl.of(p.tr)[base[p.tr]:]
		switch p.tr {
		case listen.TCP:
			if len(closes) != 0 || p.redials != 0 {
				t.Errorf("Plain TCP was drained: %d closes, %d redials", len(closes), p.redials)
			}
			continue
		}
		if len(closes) == 0 {
			t.Errorf("%s: the connection was never closed", p.name)
			continue
		}
		// DrainSince is in whole seconds and the push came after t0, so no close comes
		// before t0 plus the 2 s, less the second the stamp loses.
		if first := closes[0].Sub(t0); first < time.Second {
			t.Errorf("%s: closed after %v, before the window of 2 s opened", p.name, first)
		}
		if last := closes[len(closes)-1].Sub(t0); last > 7500*time.Millisecond {
			t.Errorf("%s: closed after %v, past the 7 s of the rule", p.name, last)
		}
		if p.tr != listen.DoH && p.tr != listen.DoH3 && p.redials == 0 { // an HTTP client redials by itself
			t.Errorf("%s: closed by the server and never reconnected", p.name)
		}
	}
	// The drain is over; a client that uses the node by address connects and stays.
	for _, p := range cs {
		p.redials = 0
		base[p.tr] = len(cl.of(p.tr))
		p.ask()
	}
	time.Sleep(3 * time.Second)
	for _, p := range cs {
		p.ask()
		if p.fails != 0 || len(cl.of(p.tr)) != base[p.tr] {
			t.Errorf("%s: a connection opened after the drain was closed (%d closes)", p.name, len(cl.of(p.tr))-base[p.tr])
		}
	}
}

// A push that makes the node advertised again before its connections go cancels the
// drain: no connection is closed.
func TestW8AReadvertisementCancelsTheDrain(t *testing.T) {
	var cl closeLog
	f := upNode(t, 0, upOpts{adjust: func(c *dnsrole.Config) { c.Drain = &shortDrain; c.Observer = cl.observer() }})
	f.fresh()
	f.push(50)
	f.wantAddr("advertised", primaryIP)
	cs := persistentClients(t, f)
	for _, p := range cs {
		p.ask()
		defer p.closeFn()
	}
	base := map[listen.Transport]int{}
	for _, p := range cs {
		base[p.tr] = len(cl.of(p.tr))
		p.redials = 0
	}
	f.push(51, 0)
	f.wantAddr("withdrawn", fallbackIP)
	time.Sleep(600 * time.Millisecond) // inside the first 2 s
	f.push(52)                         // the hub clears the withdrawal
	f.wantAddr("advertised again", primaryIP)
	t0 := time.Now()
	for time.Since(t0) < 9*time.Second {
		for _, p := range cs {
			p.ask()
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, p := range cs {
		if n := len(cl.of(p.tr)) - base[p.tr]; n != 0 || p.redials != 0 || p.fails != 0 {
			t.Errorf("%s: %d closes, %d redials, %d failures after the drain was cancelled", p.name, n, p.redials, p.fails)
		}
	}
}
