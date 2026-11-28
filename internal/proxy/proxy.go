// Package proxy is the process of the unit ctrlz-proxy (p4b-proxy 5): the ports 80
// and 443 on PROXY_IP. It reads the first bytes of a connection, asks dns what to do
// with it, and either splices it to the active Xray slot over a SOCKS inbound or
// hands it to the block process.
//
// The proxy holds no key, no policy and no Grant (5.1). Every decision is dns's, and
// the node is never an open proxy: a connection goes on only to a target that a
// verdict named for this name and this source. Nothing here logs a name, an address
// or a source; a refusal is a count by reason.
package proxy

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Sys is what the proxy asks of the kernel. The real one is Linux's (TCP_INFO,
// SIOCINQ, memory.stat); tests give their own, so the choice of whom to close
// runs on every platform.
type Sys interface {
	// Moved is the bytes a TCP socket has carried in both directions (tcpi_bytes_acked
	// and tcpi_bytes_received), and false when the connection is not a TCP one.
	Moved(c net.Conn) (uint64, bool)
	// Waiting is the bytes that wait in the socket's receive queue (SIOCINQ).
	Waiting(c net.Conn) (int, bool)
	// SockMem is the `sock` line of a memory.stat file.
	SockMem(path string) (uint64, error)
}

// Options are what differs between production and a test.
type Options struct {
	// DialLink opens proxy.sock. DialTarget opens a SOCKS inbound by its ip:port.
	// DialServe opens serve.sock. Listen opens one listener.
	DialLink   func(ctx context.Context) (net.Conn, error)
	DialTarget func(ctx context.Context, addr string) (net.Conn, error)
	DialServe  func(ctx context.Context) (net.Conn, error)
	Listen     func(addr string) (net.Listener, error)
	// Ports are the ports to bind for the logical ports 80 and 443; zero means the
	// logical port itself.
	Ports [2]int
	Sys   Sys
	// MemUnit is the memory.stat of this unit, MemSlots those of both Xray slots.
	MemUnit  string
	MemSlots []string
	// Logf is for events by place only: it is never given a name, an address, a
	// source or an error text that could hold one.
	Logf func(format string, args ...any)
	// Retry is the wait before the link is dialled again.
	Retry time.Duration
	// Sweep is the pass of the memory check, 1 s by default.
	Sweep time.Duration
}

// The reasons of a refusal, as counted and reported in `state` (5.2 step 7).
const (
	rRate = iota
	rEvict
	rSource
	rSniff
	rName
	rLookup
	rLink
	rNone
	rIran
	rDial
	rServe
	rMem
	rIdle
	rAge
	rListen
	nReasons
)

var reasonNames = [nReasons]string{"rate", "evicted", "source", "sniff", "name", "lookup_cap", "link", "none", "iran", "dial", "serve", "mem", "idle", "age", "listen"}

// Proxy is the process's state. Make one with New and run it with Run.
type Proxy struct {
	o   Options
	run uint64

	ctx    context.Context
	nextID atomic.Uint64

	refused [nReasons]atomic.Uint64

	main, other *pool
	rate        *rate
	looks       *counter

	mu    sync.Mutex
	conns map[uint64]*conn
	lk    *link
	cfg   *sock.ProxyConfig
	// closed notices wait here for the flusher (at most 100 ms, 2.1).
	closedIDs     []uint64
	closedPending []sock.Pending
	// moved notices wait in the same lock as the closed ones and go out before them,
	// so a connection that was ended never sends a moved after its closed (5.5).
	movedQ    []*sock.LinkMoved
	flushWake chan struct{}

	lmu       sync.Mutex
	lns       []net.Listener
	lnIP      string
	listening atomic.Bool
	stateWake chan struct{}
}

// Pre-grant defaults until dns sends a config: the proxy listens on nothing before
// it has one, so these only size the structures.
func New(o Options) *Proxy {
	if o.Retry == 0 {
		o.Retry = time.Second
	}
	if o.Sweep == 0 {
		o.Sweep = time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	var b [8]byte
	_, _ = cryptorand.Read(b[:])
	return &Proxy{
		o:         o,
		run:       binary.BigEndian.Uint64(b[:]),
		main:      newPool(1, 1),
		other:     newPool(1, 1),
		rate:      newRate(1, 1),
		looks:     newCounter(1, 1),
		conns:     map[uint64]*conn{},
		stateWake: make(chan struct{}, 1),
		flushWake: make(chan struct{}, 1),
	}
}

func (p *Proxy) count(reason int) { p.refused[reason].Add(1) }

// Run keeps a link to dns and serves while it is up. It returns when ctx ends.
func (p *Proxy) Run(ctx context.Context) error {
	p.ctx = ctx
	go p.sweepLoop(ctx)
	for ctx.Err() == nil {
		c, err := p.o.DialLink(ctx)
		if err != nil {
			p.o.Logf("proxy: the link to dns could not be opened")
		} else {
			p.session(ctx, c)
		}
		select {
		case <-ctx.Done():
		case <-time.After(p.o.Retry):
		}
	}
	p.closeListeners()
	p.mu.Lock()
	all := make([]*conn, 0, len(p.conns))
	for _, c := range p.conns {
		all = append(all, c)
	}
	p.mu.Unlock()
	for _, c := range all {
		c.kill()
	}
	return ctx.Err()
}

// session is one life of the link: hello, the open list, then everything else. It
// returns when the link has ended.
func (p *Proxy) session(ctx context.Context, c net.Conn) {
	l := newLink(c)
	l.onConfig = func(c *sock.ProxyConfig) { p.applyConfig(l, c) }
	l.onEnd = p.end
	defer l.close()

	p.mu.Lock()
	p.lk = l
	p.cfg = nil
	items := make([]sock.OpenItem, 0, len(p.conns))
	for _, cn := range p.conns {
		if it, ok := cn.openItem(); ok {
			items = append(items, it)
		}
	}
	// The open list is a snapshot: a close that came before it is in it by its
	// absence, and a notice for one would only confuse dns.
	p.closedIDs, p.closedPending = nil, nil
	// A moved of the old link is not replayed: the list above already names the
	// connection at the exit it moved to.
	p.movedQ = nil
	p.mu.Unlock()

	go l.read()
	go func() {
		select {
		case <-ctx.Done():
			l.close()
		case <-l.done:
		}
	}()

	if err := l.send(&sock.LinkMsg{Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: p.run}}); err != nil {
		return
	}
	parts, err := sock.SplitList(items)
	if err != nil {
		p.o.Logf("proxy: the open list does not fit the link")
		return
	}
	for i, part := range parts {
		m := &sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: part, Last: i == len(parts)-1}}
		if err := l.send(m); err != nil {
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.stateLoop(l) }()
	go func() { defer wg.Done(); p.flushLoop(l) }()
	<-l.done
	wg.Wait()

	// Link down: close both listeners so a client gets a refused connection and tries
	// the other address; open connections go on (5.1). The link and the listeners go
	// under lmu, which ensureListening holds from its check to its bind: a bind that
	// began on this link can then not land after the close.
	p.lmu.Lock()
	p.mu.Lock()
	if p.lk == l {
		p.lk = nil
		p.cfg = nil
	}
	p.mu.Unlock()
	p.closeListenersLocked()
	p.lmu.Unlock()
}

// sendMoved queues the move of cn to its next exit for the link that is the proxy's
// now. The dead check, the new SOCKS address and the queueing are one step under
// p.mu, the lock kill takes (after cn.mu) to queue the closed of the same connection:
// a connection that was ended is never queued, and one that is queued is queued
// before any closed of its own. False means the connection must stop: it was ended,
// or no link is up to tell dns where it went.
func (p *Proxy) sendMoved(cn *conn, mv *sock.LinkMoved) bool {
	p.mu.Lock()
	if p.lk == nil {
		p.mu.Unlock()
		return false
	}
	cn.mu.Lock()
	if cn.dead {
		cn.mu.Unlock()
		p.mu.Unlock()
		return false
	}
	cn.socks = mv.Socks
	cn.mu.Unlock()
	p.movedQ = append(p.movedQ, mv)
	p.mu.Unlock()
	select {
	case p.flushWake <- struct{}{}:
	default:
	}
	return true
}

func (p *Proxy) noteClosedID(id uint64) {
	p.mu.Lock()
	p.closedIDs = append(p.closedIDs, id)
	p.mu.Unlock()
}

func (p *Proxy) link() *link {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lk
}

// applyConfig takes the limits of 12 and starts listening. It is called on the link's
// reader goroutine and returns fast. A config read on a link that is no longer the
// proxy's is dropped: the reader of an old link may decode one after the next
// session began, and the listeners must open only on the config of the link dns has
// judged the open list of (5.1).
func (p *Proxy) applyConfig(l *link, c *sock.ProxyConfig) {
	if p.link() != l {
		return
	}
	cp := *c
	p.main.setLimits(int(cp.MainPerSource), int(cp.MainNode))
	p.other.setLimits(int(cp.OtherPerSource), int(cp.OtherNode))
	p.rate.setLimits(int(cp.NewRate), int(cp.NewBurst))
	p.looks.setLimits(int(cp.LookupPerSource), int(cp.LookupNode))
	p.mu.Lock()
	if p.lk != l {
		p.mu.Unlock()
		return
	}
	p.cfg = &cp
	p.mu.Unlock()
	p.ensureListening()
}

func (p *Proxy) config() *sock.ProxyConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg
}

// ensureListening opens the listeners when the link is up and a config is held,
// and moves them when the bind address changed. A bind that fails is tried again
// by the state loop.
func (p *Proxy) ensureListening() {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	// Read under lmu: session's cleanup clears the link and closes the listeners
	// under it too, so what is read here is still true when the bind is done.
	p.mu.Lock()
	cfg, lk := p.cfg, p.lk
	p.mu.Unlock()
	if cfg == nil || lk == nil {
		return
	}
	if p.listening.Load() && p.lnIP == cfg.BindIP {
		return
	}
	p.closeListenersLocked()
	var lns []net.Listener
	for i, logical := range [2]uint16{80, 443} {
		port := p.o.Ports[i]
		if port == 0 {
			port = int(logical)
		}
		ln, err := p.o.Listen(net.JoinHostPort(cfg.BindIP, strconv.Itoa(port)))
		if err != nil {
			for _, o := range lns {
				_ = o.Close()
			}
			p.count(rListen)
			return
		}
		lns = append(lns, ln)
		go p.accept(ln, logical)
	}
	p.lns, p.lnIP = lns, cfg.BindIP
	p.listening.Store(true)
	p.wakeState()
}

func (p *Proxy) closeListeners() {
	p.lmu.Lock()
	p.closeListenersLocked()
	p.lmu.Unlock()
}

func (p *Proxy) closeListenersLocked() {
	for _, ln := range p.lns {
		_ = ln.Close()
	}
	p.lns, p.lnIP = nil, ""
	if p.listening.Swap(false) {
		p.wakeState()
	}
}

func (p *Proxy) wakeState() {
	select {
	case p.stateWake <- struct{}{}:
	default:
	}
}

func (p *Proxy) accept(ln net.Listener, logical uint16) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Out of descriptors or a reset in the queue: wait a moment so a
			// permanent error is not a hot loop.
			time.Sleep(5 * time.Millisecond)
			continue
		}
		go p.handle(c, logical)
	}
}

// stateLoop sends `state` every 10 s and when listening changes, and tries the bind
// again while a config is held and nothing listens.
func (p *Proxy) stateLoop(l *link) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	retry := time.NewTicker(5 * time.Second)
	defer retry.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-retry.C:
			p.ensureListening()
		case <-tick.C:
		case <-p.stateWake:
		}
		if err := l.send(&sock.LinkMsg{Type: sock.TLinkState, State: p.stateMsg()}); err != nil {
			return
		}
	}
}

func (p *Proxy) stateMsg() *sock.LinkState {
	p.mu.Lock()
	open := 0
	for _, c := range p.conns {
		if c.held() {
			open++
		}
	}
	p.mu.Unlock()
	st := &sock.LinkState{Listening: p.listening.Load(), Open: uint32(open)}
	for i := range p.refused {
		if n := p.refused[i].Load(); n > 0 {
			st.Refused = append(st.Refused, sock.Refusal{Reason: reasonNames[i], Count: n})
		}
	}
	return st
}

// flushLoop sends the `moved` notices at once and the `closed` ones at most 100 ms
// after the close, each drain with the moved first.
func (p *Proxy) flushLoop(l *link) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-tick.C:
		case <-p.flushWake:
		}
		p.mu.Lock()
		moved, ids, pend := p.movedQ, p.closedIDs, p.closedPending
		p.movedQ, p.closedIDs, p.closedPending = nil, nil, nil
		p.mu.Unlock()
		for _, mv := range moved {
			if err := l.send(&sock.LinkMsg{Type: sock.TLinkMoved, Moved: mv}); err != nil {
				return
			}
		}
		for len(ids) > 0 || len(pend) > 0 {
			n, m := min(len(ids), sock.MaxIDsPerMsg), min(len(pend), sock.MaxIDsPerMsg)
			msg := &sock.LinkMsg{Type: sock.TLinkClosed, Closed: &sock.LinkClosed{IDs: ids[:n], Pending: pend[:m]}}
			ids, pend = ids[n:], pend[m:]
			if err := l.send(msg); err != nil {
				return
			}
		}
	}
}

// end closes the connections dns names: by id, or all of those to a SOCKS address.
func (p *Proxy) end(e *sock.LinkEnd) {
	var victims []*conn
	p.mu.Lock()
	for _, id := range e.IDs {
		if c := p.conns[id]; c != nil {
			victims = append(victims, c)
		}
	}
	if len(e.Socks) > 0 {
		want := make(map[string]struct{}, len(e.Socks))
		for _, s := range e.Socks {
			want[s] = struct{}{}
		}
		for _, c := range p.conns {
			if _, ok := want[c.socksAddr()]; ok {
				victims = append(victims, c)
			}
		}
	}
	p.mu.Unlock()
	for _, c := range victims {
		c.kill()
	}
}

// Open is the number of connections the proxy holds (a verdict, not closed).
func (p *Proxy) Open() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.conns {
		if c.held() {
			n++
		}
	}
	return n
}

// Listening reports whether the listeners are open.
func (p *Proxy) Listening() bool { return p.listening.Load() }
