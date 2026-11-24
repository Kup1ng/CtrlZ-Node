package listen

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/cookie"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// core is what every listener shares: the settings, the step-1 gate, the
// handler call with its recovery, and the in-flight count.
type core struct {
	cfg *Config
	t   Transport
	set limits.ListenerSettings
	ctx context.Context // ends when the Server closes

	inflight atomic.Int64
}

func newCore(ctx context.Context, cfg *Config, t Transport) (*core, error) {
	set, err := cfg.settings(t)
	if err != nil {
		return nil, err
	}
	return &core{cfg: cfg, t: t, set: set, ctx: ctx}, nil
}

// question returns the one question of a query, if it has exactly one.
func question(m *dns.Msg) (name string, qtype uint16, ok bool) {
	if len(m.Question) != 1 {
		return "", 0, false
	}
	return m.Question[0].Name, m.Question[0].Qtype, true
}

// exempt is the name-form exemption: it runs after the question is read and
// before any limit is consulted (L13).
func (c *core) exempt(m *dns.Msg) bool {
	name, qt, ok := question(m)
	return ok && c.cfg.Exempt.Exempt(name, qt)
}

// gate runs the limits of step 1 for a query that is not exempt and returns
// what a stopped query gets. An exempt query is never given to a limit, so no
// limit can count, drop, truncate or change the answer of it.
func (c *core) gate(exempt bool, src netip.Addr) limits.Answer {
	if exempt {
		return limits.AnswerNone
	}
	ans := c.cfg.Limits.Query(c.t, src)
	if ans != limits.AnswerNone && c.cfg.Observer.Stopped != nil {
		c.cfg.Observer.Stopped(c.t)
	}
	return ans
}

// enter counts a query into the query path. It refuses a query that is not
// exempt when the listener is at MaxInFlight: overload, which is not a limit
// of step 1, so the exemption bypasses it.
func (c *core) enter(exempt bool) bool {
	n := c.inflight.Add(1)
	if !exempt && c.set.MaxInFlight > 0 && n > int64(c.set.MaxInFlight) {
		c.inflight.Add(-1)
		return false
	}
	return true
}

func (c *core) exit() { c.inflight.Add(-1) }

// call runs the handler. A panic or a reply with nothing in it becomes
// SERVFAIL for this query; the connection is never touched (T-549). The panic
// value is dropped, not logged: it can hold request data.
func (c *core) call(req *Request) (rep Reply) {
	ctx := c.ctx
	if c.set.HandlerTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.set.HandlerTimeout)
		defer cancel()
	}
	defer func() {
		if recover() != nil {
			if c.cfg.Observer.Panic != nil {
				c.cfg.Observer.Panic(c.t)
			}
			rep = Reply{Msg: ServFail(req.Msg)}
		}
	}()
	rep = c.cfg.Handler.ServeDNS(ctx, req)
	// Status feeds http.ResponseWriter.WriteHeader, which panics outside
	// 100..999, and a 1xx is no final answer. A handler bug of that kind is a
	// SERVFAIL for this query, like a panic, never a panic in the transport
	// (p4n-W6-r8-1).
	if rep.Status != 0 && (rep.Status < 200 || rep.Status > 599) {
		rep = Reply{Msg: ServFail(req.Msg)}
	}
	if rep.Msg == nil && !rep.Drop && rep.Status == 0 {
		rep = Reply{Msg: ServFail(req.Msg)}
	}
	return rep
}

// answerCookie adds the cookie option to a Plain DNS reply (L14): whatever the
// server cookie of the query was, the reply carries a fresh one. Never
// BADCOOKIE.
func (c *core) answerCookie(reply *dns.Msg, p cookie.Parsed, src netip.Addr) {
	if c.cfg.Cookies != nil && p.Present && reply != nil {
		c.cfg.Cookies.Attach(reply, p, src)
	}
}

// parseCookie reads the cookie of a Plain DNS query and says whether it proves
// the source (a server cookie this node made for this address).
func (c *core) parseCookie(m *dns.Msg, src netip.Addr) (cookie.Parsed, bool) {
	if c.cfg.Cookies == nil {
		return cookie.Parsed{}, false
	}
	p := cookie.Parse(m)
	return p, p.Present && len(p.Server) > 0 && c.cfg.Cookies.Verify(p.Client, p.Server, src)
}

func (c *core) closed(why CloseReason) {
	if c.cfg.Observer.Closed != nil {
		c.cfg.Observer.Closed(c.t, why)
	}
}

func (c *core) refused() {
	if c.cfg.Observer.Refused != nil {
		c.cfg.Observer.Refused(c.t)
	}
}

func (c *core) dropped() {
	if c.cfg.Observer.Dropped != nil {
		c.cfg.Observer.Dropped(c.t)
	}
}

// guardPack runs the post-processing of a reply (the cookie, truncation and
// packing) and turns a panic in it into SERVFAIL for the query. call recovers
// only the handler; the reply the handler returns is used afterwards, on a
// goroutine nothing else recovers, and miekg/dns panics on a typed nil RR. An
// unrecovered panic ends the whole process, so a defect in what W7 builds
// would take every tenant's DNS down with it (p4n-W6-r3-1, -4). A nil result
// means not even the SERVFAIL could be packed.
func (c *core) guardPack(q *dns.Msg, fn func() []byte) (b []byte) {
	defer func() {
		if recover() != nil {
			if c.cfg.Observer.Panic != nil {
				c.cfg.Observer.Panic(c.t)
			}
			b = servFailWire(q)
		}
	}()
	return fn()
}

// servFailWire packs SERVFAIL for q. The query was parsed from the wire, so it
// cannot hold what makes Pack panic, but the recover costs nothing.
func servFailWire(q *dns.Msg) (b []byte) {
	defer func() {
		if recover() != nil {
			b = nil
		}
	}()
	b, err := ServFail(q).Pack()
	if err != nil {
		return nil
	}
	return b
}

// packFrame packs m as a stream message, length first. A message above 65535
// bytes is truncated; one that cannot be packed, or panics while packing, is
// replaced by SERVFAIL for the same query. pre runs first, under the same guard
// (the cookie option is added to the reply there).
func (c *core) packFrame(m, q *dns.Msg, pre func()) []byte {
	b := c.guardPack(q, func() []byte {
		if pre != nil {
			pre()
		}
		b, err := m.Pack()
		if err == nil && len(b) > limits.MaxDNSMessage {
			m.Truncate(limits.MaxDNSMessage)
			b, err = m.Pack()
		}
		if err != nil || len(b) > limits.MaxDNSMessage {
			return servFailWire(q)
		}
		return b
	})
	if b == nil {
		return nil
	}
	out := make([]byte, 2+len(b))
	out[0], out[1] = byte(len(b)>>8), byte(len(b))
	copy(out[2:], b)
	return out
}

// addrPort turns a connection's remote address into the source of a query.
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.TCPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ap.IsValid()
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// cookieOpt is the COOKIE option of a query, as cookie.Parse read it.
type cookieOpt = cookie.Parsed

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }

// readBody reads exactly n bytes without allocating n bytes first. A peer
// declares the length of a frame in two bytes and could then send nothing, so a
// buffer sized from the declaration costs the node 64 KiB for each 2 bytes the
// peer sends (p4n-W6-r1-3). bytes.Buffer grows as the data arrives.
func readBody(r io.Reader, n int) ([]byte, error) {
	var b bytes.Buffer
	if _, err := io.CopyN(&b, r, int64(n)); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b.Bytes(), nil
}
