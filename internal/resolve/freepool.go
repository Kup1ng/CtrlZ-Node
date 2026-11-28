package resolve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
)

// The connection pools of the free path (SC 5.2a, Free resolver, W9).
//
// A free miss that goes to an upstream never uses a connection that an identified
// query or a health check uses, and it never opens a connection beyond a fixed
// pool, so a flood of free misses cannot fill the host's ports or its
// connection-tracking table with closed connections. A pool belongs to one
// upstream row and is built apart from the identified client of the same row.
//
// The numbers are the ones of 5.2a and provisional (D31): 4 persistent TCP
// connections with pipelining (RFC 7766) for a udp upstream, 2 connections for
// dot, doh and doq, 64 free misses in flight on one connection, and a slot
// that replaces a closed connection at most 10 times a second.
const (
	FreeTCPConns   = 4
	FreeTLSConns   = 2
	FreeStreamCap  = 64
	FreeRedialRate = 10 // per second, for one connection slot
)

// Errors a pool returns. ErrFreePoolFull is the one the free path turns into
// REFUSED (7: "every free connection of its upstream full").
var (
	ErrFreePoolFull = errors.New("resolve: every free connection of the upstream is full")
	errSlotFull     = errors.New("resolve: free connection full")
	errRedial       = errors.New("resolve: free connection was closed a moment ago")
	errConnClosed   = errors.New("resolve: free connection closed")
)

// slot is one connection of a pool, or one stand-in for it.
type slot interface {
	// exchange sends req and waits for the reply. It never blocks for room: a
	// slot with no room returns errSlotFull at once, and one that closed its
	// connection too recently to open another returns errRedial.
	exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	Close() error
}

// FreePool is the set of connections of one upstream row for free misses. It
// implements Exchanger.
type FreePool struct {
	kind      commonv1.UpstreamKind
	bootstrap netip.Addr
	timeout   time.Duration
	slots     []slot
	rr        atomic.Uint32
	full      atomic.Uint64
}

// NewFreePool builds the pool of an upstream row. It takes the same Config as
// NewUpstream and refuses what NewUpstream refuses (it calls the same address
// rules), and dials only the bootstrap address.
func NewFreePool(cfg Config) (*FreePool, error) {
	return newFreePool(cfg, time.Second/FreeRedialRate)
}

func newFreePool(cfg Config, redialGap time.Duration) (*FreePool, error) {
	if cfg.Timeout <= 0 {
		return nil, ErrNoTimeout
	}
	if cfg.Timeout > maxUpstreamTimeout {
		return nil, fmt.Errorf("%w: timeout above %s", ErrBadAddress, maxUpstreamTimeout)
	}
	rawURL, bootstrap, err := upstreamURL(cfg)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: url", ErrBadAddress)
	}
	p := &FreePool{kind: cfg.Kind, bootstrap: bootstrap, timeout: cfg.Timeout}
	switch cfg.Kind {
	case commonv1.UpstreamKind_UPSTREAM_KIND_UDP:
		// A free miss to a udp upstream goes over TCP, so an off-path forger has no
		// UDP reply to race (SC 11).
		target := u.Host
		for i := 0; i < FreeTCPConns; i++ {
			p.slots = append(p.slots, newConnSlot(func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", target)
			}, cfg.Timeout, redialGap))
		}
	case commonv1.UpstreamKind_UPSTREAM_KIND_DOT:
		target := net.JoinHostPort(bootstrap.String(), u.Port())
		tc := tlsConfig(u.Hostname(), cfg.RootCAs)
		for i := 0; i < FreeTLSConns; i++ {
			p.slots = append(p.slots, newConnSlot(func(ctx context.Context) (net.Conn, error) {
				d := tls.Dialer{Config: tc}
				return d.DialContext(ctx, "tcp", target)
			}, cfg.Timeout, redialGap))
		}
	case commonv1.UpstreamKind_UPSTREAM_KIND_DOH:
		c, err := newDoHClient(rawURL, bootstrap, cfg.RootCAs, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		// One Transport, never replaced (D66), with the pool's two connections as its
		// bound and a limit on how fast it may dial.
		c.tr.MaxConnsPerHost, c.tr.MaxIdleConnsPerHost, c.tr.MaxIdleConns = FreeTLSConns, FreeTLSConns, FreeTLSConns
		inner := c.tr.DialContext
		lim := newDialLimit(redialGap/time.Duration(FreeTLSConns), FreeTLSConns)
		// net/http dials again for a request it cannot place while the connections it has
		// are busy, whatever MaxConnsPerHost says of HTTP/2, so the pool holds the bound
		// itself: no dial while it has its connections, and a replacement only at the
		// redial rate. A request that is refused a dial is tried again (limitedSlot).
		c.tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if c.poolOpen() >= FreeTLSConns || !lim.allow() {
				return nil, errRedial
			}
			return inner(ctx, network, addr)
		}
		p.slots = append(p.slots, &limitedSlot{x: c, cap: FreeStreamCap * FreeTLSConns, closer: c, retryDial: true})
	case commonv1.UpstreamKind_UPSTREAM_KIND_DOQ:
		// Our own client, not dnsproxy's: see freedoq.go.
		tc := tlsConfig(u.Hostname(), cfg.RootCAs)
		for i := 0; i < FreeTLSConns; i++ {
			p.slots = append(p.slots, newDoQSlot(bootstrap, u.Port(), tc, cfg.Timeout, redialGap))
		}
	default:
		return nil, fmt.Errorf("%w: %d", ErrBadKind, cfg.Kind)
	}
	return p, nil
}

func tlsConfig(name string, roots *x509.CertPool) *tls.Config {
	return &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12}
}

// Exchange sends req on a free connection of the upstream. It returns
// ErrFreePoolFull when every connection is at its in-flight limit, and never
// opens a connection beyond the pool. Like Upstream.Exchange it sends a fresh
// ID, checks the question of the reply and puts the caller's ID back.
func (p *FreePool) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) != 1 {
		return nil, ErrBadQuery
	}
	out := req.Copy()
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	var err error
	start := int(p.rr.Add(1))
	sawFull := false
	for i := 0; i < len(p.slots); i++ {
		s := p.slots[(start+i)%len(p.slots)]
		var resp *dns.Msg
		resp, err = s.exchange(ctx, out)
		switch {
		case err == nil:
			if len(resp.Question) != 1 || !sameQuestion(resp.Question[0], req.Question[0]) {
				return nil, ErrBadReply
			}
			resp.Id = req.Id
			return resp, nil
		case errors.Is(err, errSlotFull):
			sawFull = true
		case errors.Is(err, errRedial):
			// Another slot may be open.
		default:
			return nil, err
		}
	}
	if sawFull {
		p.full.Add(1)
		markFull(ctx)
		return nil, ErrFreePoolFull
	}
	return nil, err
}

// Full counts the calls that found every connection full.
func (p *FreePool) Full() uint64 { return p.full.Load() }

// BootstrapIP is the only address the pool dials.
func (p *FreePool) BootstrapIP() netip.Addr { return p.bootstrap }

// Close ends every connection.
func (p *FreePool) Close() error {
	for _, s := range p.slots {
		_ = s.Close()
	}
	return nil
}

// ---- a connection that pipelines (RFC 7766)

// connSlot is one persistent TCP or TLS connection with up to FreeStreamCap
// queries in flight on it, each under its own ID, answered in any order.
type connSlot struct {
	dial        func(context.Context) (net.Conn, error)
	dialTimeout time.Duration
	gap         time.Duration

	mu       sync.Mutex
	cn       *pipeConn
	dialing  chan struct{}
	lastDial time.Time
	inflight int
	closed   bool
}

func newConnSlot(dial func(context.Context) (net.Conn, error), dialTimeout, gap time.Duration) *connSlot {
	return &connSlot{dial: dial, dialTimeout: dialTimeout, gap: gap}
}

func (s *connSlot) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errConnClosed
	}
	if s.inflight >= FreeStreamCap {
		s.mu.Unlock()
		return nil, errSlotFull
	}
	s.inflight++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}()
	pc, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	return pc.exchange(ctx, req)
}

// conn returns the live connection, dialling one when there is none and the last
// dial is old enough. Queries that arrive while a dial is out wait for it, so a
// cold start with many queries is one dial, and queries that find a failed dial
// get errRedial at once instead of each trying again.
func (s *connSlot) conn(ctx context.Context) (*pipeConn, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, errConnClosed
		}
		if pc := s.cn; pc != nil && !pc.dead() {
			s.mu.Unlock()
			return pc, nil
		}
		if d := s.dialing; d != nil {
			s.mu.Unlock()
			select {
			case <-d:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("resolve: free connection: %w", ctx.Err())
			}
		}
		if time.Since(s.lastDial) < s.gap {
			s.mu.Unlock()
			return nil, errRedial
		}
		d := make(chan struct{})
		s.dialing, s.lastDial = d, time.Now()
		s.mu.Unlock()

		// The dial belongs to the slot, not to the query that started it.
		dctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
		c, err := s.dial(dctx)
		cancel()

		s.mu.Lock()
		if err == nil && !s.closed {
			s.cn = newPipeConn(c, 2*s.dialTimeout)
		} else if err == nil {
			_ = c.Close()
			err = errConnClosed
		}
		s.dialing = nil
		close(d)
		s.mu.Unlock()
		if err != nil {
			if errors.Is(err, errConnClosed) {
				return nil, err
			}
			return nil, fmt.Errorf("resolve: free connection: dial: %w", err)
		}
	}
}

func (s *connSlot) Close() error {
	s.mu.Lock()
	s.closed = true
	pc := s.cn
	s.mu.Unlock()
	if pc != nil {
		pc.fail()
	}
	return nil
}

// pipeConn is a framed DNS connection with a reader that hands each reply to the
// query that asked for it.
type pipeConn struct {
	c  net.Conn
	dc *dns.Conn

	wmu sync.Mutex // one writer at a time

	mu      sync.Mutex
	pending map[uint16]chan *dns.Msg
	isDead  bool
	// lastRead is the time of the last reply. A query that times out on a
	// connection that has read nothing for deadAfter ends the connection: it may be
	// dead without the kernel knowing. A connection that is still answering other
	// queries is kept, so a name whose servers never reply costs only its own query.
	lastRead  atomic.Int64
	deadAfter time.Duration
}

func newPipeConn(c net.Conn, deadAfter time.Duration) *pipeConn {
	pc := &pipeConn{c: c, dc: &dns.Conn{Conn: c}, pending: map[uint16]chan *dns.Msg{}, deadAfter: deadAfter}
	pc.lastRead.Store(time.Now().UnixNano())
	go pc.read()
	return pc
}

func (pc *pipeConn) dead() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.isDead
}

// fail closes the connection and wakes every query waiting on it.
func (pc *pipeConn) fail() {
	pc.mu.Lock()
	if pc.isDead {
		pc.mu.Unlock()
		return
	}
	pc.isDead = true
	waiting := pc.pending
	pc.pending = map[uint16]chan *dns.Msg{}
	pc.mu.Unlock()
	_ = pc.c.Close()
	for _, ch := range waiting {
		close(ch)
	}
}

func (pc *pipeConn) read() {
	for {
		m, err := pc.dc.ReadMsg()
		if err != nil {
			pc.fail()
			return
		}
		pc.lastRead.Store(time.Now().UnixNano())
		pc.mu.Lock()
		ch, ok := pc.pending[m.Id]
		if ok {
			delete(pc.pending, m.Id)
		}
		pc.mu.Unlock()
		if ok {
			ch <- m // buffered
		}
	}
}

func (pc *pipeConn) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Copy()
	ch := make(chan *dns.Msg, 1)
	pc.mu.Lock()
	if pc.isDead {
		pc.mu.Unlock()
		return nil, errConnClosed
	}
	// A fresh ID that no query waiting on this connection has, so two replies
	// can never be mixed up.
	for {
		q.Id = uint16(rand.Uint32())
		if _, taken := pc.pending[q.Id]; !taken {
			break
		}
	}
	id := q.Id
	pc.pending[id] = ch
	pc.mu.Unlock()
	forget := func() {
		pc.mu.Lock()
		delete(pc.pending, id)
		pc.mu.Unlock()
	}
	pc.wmu.Lock()
	if dl, ok := ctx.Deadline(); ok {
		_ = pc.c.SetWriteDeadline(dl)
	}
	err := pc.dc.WriteMsg(q)
	pc.wmu.Unlock()
	if err != nil {
		forget()
		pc.fail()
		return nil, errConnClosed
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return nil, errConnClosed
		}
		return m, nil
	case <-ctx.Done():
		forget()
		if time.Since(time.Unix(0, pc.lastRead.Load())) > pc.deadAfter {
			pc.fail()
		}
		return nil, fmt.Errorf("resolve: free exchange: %w", ctx.Err())
	}
}

// ---- a bound in front of another client

// limitedSlot puts a bound on the queries in flight in front of an Exchanger. The
// redial rate of its client is held by the client's own dial limit (DoH), never by
// a pause after an error: an error of one query says nothing of the connection
// the others ride on (p4n-W9-r1-1).
type limitedSlot struct {
	x      Exchanger
	cap    int
	closer interface{ Close() error }
	// retryDial is for a client whose dial the pool refuses while it still has a
	// connection to give the request: the request is tried again, briefly.
	retryDial bool

	n atomic.Int64
}

func (s *limitedSlot) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if s.n.Add(1) > int64(s.cap) {
		s.n.Add(-1)
		return nil, errSlotFull
	}
	defer s.n.Add(-1)
	resp, err := s.x.Exchange(ctx, req)
	for try := 0; s.retryDial && errors.Is(err, errRedial) && try < 4; try++ {
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		resp, err = s.x.Exchange(ctx, req)
	}
	return resp, err
}

func (s *limitedSlot) Close() error { return s.closer.Close() }

// dialLimit is a token bucket for connection attempts.
type dialLimit struct {
	mu     sync.Mutex
	every  time.Duration
	burst  int
	tokens float64
	at     time.Time
}

func newDialLimit(every time.Duration, burst int) *dialLimit {
	return &dialLimit{every: every, burst: burst, tokens: float64(burst), at: time.Now()}
}

func (l *dialLimit) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.every > 0 {
		l.tokens = min(float64(l.burst), l.tokens+float64(now.Sub(l.at))/float64(l.every))
	}
	l.at = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// poolOpen is how many connections the client holds right now.
func (c *dohClient) poolOpen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

// ---- which lookup met a full pool

type fullMarkKey struct{}

// FullMark records, for one lookup, that a free pool it used was full. The free
// path needs it to answer REFUSED instead of SERVFAIL for exactly the lookup that
// was turned away, and a counter of the whole node cannot say that: another
// query's full pool, or a health probe's, would move it too (p4n-W9-r1-3).
type FullMark struct{ v atomic.Bool }

// Full says whether a pool of the lookup was full.
func (m *FullMark) Full() bool { return m.v.Load() }

// WithFullMark returns a context whose pools mark m when they turn a call away.
func WithFullMark(ctx context.Context) (context.Context, *FullMark) {
	m := new(FullMark)
	return context.WithValue(ctx, fullMarkKey{}, m), m
}

func markFull(ctx context.Context) {
	if m, ok := ctx.Value(fullMarkKey{}).(*FullMark); ok {
		m.v.Store(true)
	}
}
