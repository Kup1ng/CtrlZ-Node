package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// conn is one client connection from accept to close (5.2).
type conn struct {
	p  *Proxy
	id uint64
	// ctx ends when the connection does: kill cancels it, so a dial or a wait for
	// a first byte stops at once and nothing more is sent to an exit (5.2).
	ctx    context.Context
	cancel context.CancelFunc
	c      net.Conn
	src    []byte
	key    srcKey
	port   uint16
	opened time.Time

	mu      sync.Mutex
	target  net.Conn
	serve   net.Conn
	socks   string // the current SOCKS target of a kind 1 connection from its verdict on, "" for kind 2
	dialed  bool   // a dial to socks has been started, so a close leaves one behind (5.5)
	tag     []byte
	kind    uint8 // 0 until a kind 1 or 2 verdict: dns holds a place only after it
	verdAt  time.Time
	dialMS  uint32 // start of the current dial, ms after the verdict
	dead    bool
	entry   *poolEntry
	entryIn *pool

	gotByte atomic.Bool

	// Samples of the sweeper (mem.go): the bytes both sockets carried, when that
	// total last changed, and what the client socket moved in the last pass.
	sampMu     sync.Mutex
	lastTotal  uint64
	lastMove   time.Time
	prevClient uint64
	delta      uint64
}

// remoteSource returns the client's address as 4 or 16 raw bytes.
func remoteSource(c net.Conn) ([]byte, bool) {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return nil, false
	}
	a := ap.Addr().Unmap()
	if a.Is4() {
		b := a.As4()
		return b[:], true
	}
	b := a.As16()
	return b[:], true
}

func (cn *conn) held() bool {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.kind != 0 && !cn.dead
}

func (cn *conn) isDead() bool {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.dead
}

func (cn *conn) socksAddr() string {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.socks
}

// openItem is the connection's line of the `open` list; only a connection with a
// verdict is in it.
func (cn *conn) openItem() (sock.OpenItem, bool) {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	if cn.kind == 0 || cn.dead {
		return sock.OpenItem{}, false
	}
	return sock.OpenItem{ID: cn.id, Source: cn.src, Socks: cn.socks, Tag: cn.tag}, true
}

// kill closes the connection and everything it holds. It is safe to call twice and
// from any goroutine; the first call reports the close to dns.
func (cn *conn) kill() {
	cn.mu.Lock()
	if cn.dead {
		cn.mu.Unlock()
		return
	}
	cn.dead = true
	kind, startMS, dialed := cn.kind, cn.dialMS, cn.dialed
	target, serve, entry, inPool := cn.target, cn.serve, cn.entry, cn.entryIn
	cn.mu.Unlock()

	// Before the sockets are closed: a dial in flight holds a SOCKS leg that is
	// not in cn.target yet, and the cancel is what closes it.
	if cn.cancel != nil {
		cn.cancel()
	}
	_ = cn.c.Close()
	if target != nil {
		_ = target.Close()
	}
	if serve != nil {
		_ = serve.Close()
	}
	if entry != nil {
		inPool.release(entry)
	}
	p := cn.p
	p.mu.Lock()
	delete(p.conns, cn.id)
	if kind != 0 {
		// A kind 1 connection that had no byte from its current target leaves a dial
		// behind that dns keeps counted for dial_hold (5.5). One that never dialled
		// left nothing behind and frees its place at once.
		if kind == sock.VerdictProxy && dialed && !cn.gotByte.Load() {
			p.closedPending = append(p.closedPending, sock.Pending{ID: cn.id, StartMS: startMS})
		} else {
			p.closedIDs = append(p.closedIDs, cn.id)
		}
	}
	p.mu.Unlock()
}

// handle is the whole life of an accepted connection.
func (p *Proxy) handle(c net.Conn, port uint16) {
	src, ok := remoteSource(c)
	if !ok {
		_ = c.Close()
		return
	}
	tuneClient(c)
	cn := &conn{p: p, id: p.nextID.Add(1), c: c, src: src, key: keyOf(src), port: port, opened: time.Now(), lastMove: time.Now()}
	if !p.rate.allow(cn.key, cn.opened) {
		p.count(rRate)
		_ = c.Close()
		return
	}
	cn.ctx, cn.cancel = context.WithCancel(p.ctx)
	p.mu.Lock()
	lk, cfg := p.lk, p.cfg
	if lk == nil || cfg == nil {
		p.mu.Unlock()
		p.count(rLink)
		cn.cancel()
		_ = c.Close()
		return
	}
	p.conns[cn.id] = cn
	p.mu.Unlock()
	defer cn.kill()

	ctx := cn.ctx

	// Which pool: asked before anything is read, so a source with no Grant never
	// holds a place of the main pool (5.4).
	askCtx, askCancel := context.WithTimeout(ctx, time.Duration(cfg.MainSniffMS)*time.Millisecond)
	known, err := lk.askSource(askCtx, cn.id, src)
	askCancel()
	if err != nil {
		p.count(rSource)
		return
	}
	pl, within := p.other, time.Duration(cfg.OtherFirstMS)*time.Millisecond
	if known {
		pl, within = p.main, time.Duration(cfg.MainSniffMS)*time.Millisecond
	}
	entry := pl.admit(cn.key, func() { p.count(rEvict); cn.kill() })
	cn.mu.Lock()
	cn.entry, cn.entryIn = entry, pl
	dead := cn.dead
	cn.mu.Unlock()
	if dead {
		return
	}

	var (
		name     string
		recorded []byte
		movable  = true
	)
	deadline := time.Now().Add(within)
	if port == 443 {
		name, recorded, err = sniffTLS(c, deadline)
	} else {
		var h *httpFirst
		h, err = sniffHTTP(c, deadline)
		if err == nil {
			name, recorded, movable = h.Host, h.Recorded, h.Movable
		}
	}
	if err != nil {
		p.count(rSniff)
		return
	}
	wire, text, err := normalize(name)
	if err != nil {
		p.count(rName)
		return
	}

	if !p.looks.take(cn.key) {
		p.count(rLookup)
		return
	}
	lctx, lcancel := context.WithTimeout(ctx, within+5*time.Second)
	v, err := lk.lookup(lctx, cn.id, src, wire, port)
	lcancel()
	p.looks.put(cn.key)
	if err != nil {
		p.count(rLink)
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			// dns may still have answered and charged a place for it (or the
			// connection was ended while it waited): tell it the connection is
			// gone. An id it does not know is ignored there.
			p.noteClosedID(cn.id)
		}
		return
	}

	// The verdict ends the pre-grant state: the connection leaves the pool (5.4).
	cn.mu.Lock()
	cn.entry = nil
	cn.mu.Unlock()
	pl.release(entry)

	switch v.Kind {
	case sock.VerdictProxy:
		if !cn.setVerdict(lk, v) {
			return
		}
		// The built-in check of D42 repeats the backend's: it runs after the verdict
		// because a block page for such a name is allowed.
		if iranian(text) {
			p.count(rIran)
			return
		}
		cn.runProxy(ctx, cfg, v, recorded, movable)
	case sock.VerdictBlock:
		if !cn.setVerdict(lk, v) {
			return
		}
		cn.runBlock(ctx, cfg, v, text, recorded)
	default:
		p.count(rNone)
	}
}

// setVerdict records what dns decided. A connection that was closed while it waited
// (evicted, ended) still has a place charged in dns, so its close is reported here,
// where kill could not know it.
//
// lk is the link the lookup went out on. The comparison with the proxy's link and
// the write of kind are one step under p.mu, as is the snapshot of a new session's
// open list: a verdict is either in that list (kind set before it) or refused here.
// A verdict from an older link is refused because the new dns holds no place for the
// connection and would never end it.
//
// socks is set here for a kind 1 connection, before the built-in check and the first
// dial: with "" in it the open list reads the connection as kind 2 (5.4), and an
// `end` for its exit would not find it.
func (cn *conn) setVerdict(lk *link, v *sock.LinkVerdict) bool {
	p := cn.p
	p.mu.Lock()
	if p.lk != lk {
		p.mu.Unlock()
		return false
	}
	cn.mu.Lock()
	if cn.dead {
		cn.mu.Unlock()
		p.mu.Unlock()
		p.noteClosedID(cn.id)
		return false
	}
	cn.kind = v.Kind
	cn.tag = v.Tag
	cn.verdAt = time.Now()
	if v.Kind == sock.VerdictProxy && len(v.Targets) > 0 {
		cn.socks = v.Targets[0].Socks
	}
	cn.mu.Unlock()
	p.mu.Unlock()
	return true
}

// runBlock hands the connection to ctrlz-block (5.2 step 5): the serve frame, the
// bytes already read, then both ways.
func (cn *conn) runBlock(ctx context.Context, cfg *sock.ProxyConfig, v *sock.LinkVerdict, name string, recorded []byte) {
	p := cn.p
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	sc, err := p.o.DialServe(dctx)
	if err != nil {
		p.count(rServe)
		return
	}
	tuneServe(sc)
	cn.mu.Lock()
	if cn.dead {
		cn.mu.Unlock()
		_ = sc.Close()
		return
	}
	cn.serve = sc
	cn.mu.Unlock()
	_ = sc.SetWriteDeadline(time.Now().Add(2 * time.Second))
	f := &sock.ServeFrame{Name: name, Port: cn.port, Endpoint: v.Endpoint, Account: v.Account, Source: cn.src, PageHash: v.PageHash}
	if err := sock.ServeCodec.Write(sc, f); err != nil {
		p.count(rServe)
		return
	}
	if _, err := sc.Write(recorded); err != nil {
		p.count(rServe)
		return
	}
	_ = sc.SetWriteDeadline(time.Time{})
	cn.pipe(sc, nil)
}

// runProxy dials the targets in order (5.2 step 6). A target that fails before its
// first byte hands the connection to the next one, with the recorded bytes sent
// again; after a first byte there is no failover.
func (cn *conn) runProxy(ctx context.Context, cfg *sock.ProxyConfig, v *sock.LinkVerdict, recorded []byte, movable bool) {
	p := cn.p
	firstByte := time.Duration(cfg.DialFirstByteMS) * time.Millisecond
	targets := v.Targets
	if !movable {
		// A request that is not a bodiless GET or HEAD may have had an effect at
		// the first target, so it stays there.
		targets = targets[:1]
	}
	for i, t := range targets {
		// A connection that dns ended, or the sweeper, goes to no further exit and
		// moves nowhere: dns has been told it is closed.
		if cn.isDead() || ctx.Err() != nil {
			return
		}
		start := time.Now()
		startMS := uint32(start.Sub(cn.verdAt) / time.Millisecond)
		cn.mu.Lock()
		cn.socks, cn.dialMS, cn.dialed = t.Socks, startMS, true
		cn.mu.Unlock()
		cn.gotByte.Store(false)

		sc, first, left, err := cn.dialTarget(ctx, t, recorded, start.Add(firstByte), movable)
		if err == nil {
			cn.mu.Lock()
			if cn.dead {
				cn.mu.Unlock()
				_ = sc.Close()
				return
			}
			cn.target = sc
			cn.mu.Unlock()
			if len(first) > 0 {
				cn.gotByte.Store(true)
				if _, err := cn.c.Write(first); err != nil {
					return
				}
			}
			cn.pipe(sc, first2(first, movable))
			return
		}
		if cn.isDead() || ctx.Err() != nil {
			return
		}
		if i+1 >= len(targets) {
			p.count(rDial)
			return
		}
		mv := &sock.LinkMoved{ID: cn.id, Socks: targets[i+1].Socks}
		if left {
			mv.Left = &sock.Left{Socks: t.Socks, StartMS: startMS}
		}
		if !p.sendMoved(cn, mv) {
			return
		}
	}
}

// first2 says whether the target→client copy must read the first bytes itself:
// only when nothing has been read yet, which is a request that cannot move on.
func first2(first []byte, movable bool) *firstRead {
	if len(first) > 0 || movable {
		return nil
	}
	return &firstRead{}
}

// firstRead marks a connection whose first byte from the target is read inside the
// splice (a request that cannot move on has no first-byte wait).
type firstRead struct{}

var errNoByte = errors.New("proxy: no byte from the target")

// dialTarget opens the SOCKS leg and sends the recorded bytes. For a request that
// may move on it also waits for the first byte; left reports that the failure was
// 5 s of silence, after which the exit's own dial goes on (5.5), and not an error or
// an end that finished it.
func (cn *conn) dialTarget(ctx context.Context, t sock.Target, recorded []byte, deadline time.Time, movable bool) (sc net.Conn, first []byte, left bool, err error) {
	p := cn.p
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	sc, err = p.o.DialTarget(dctx, t.Socks)
	if err != nil {
		return nil, nil, false, err
	}
	// The leg is not in cn.target until the wait is over, so the end of the
	// connection closes it through the context: that is what interrupts the
	// first-byte read.
	stop := context.AfterFunc(ctx, func() { _ = sc.Close() })
	defer func() {
		if err != nil {
			stop()
		} else if !stop() {
			// The end came as the first byte did: the connection is over.
			_ = sc.Close()
			sc, first, left, err = nil, nil, false, context.Canceled
		}
	}()
	fail := func(e error, silent bool) (net.Conn, []byte, bool, error) {
		_ = sc.Close()
		return nil, nil, silent, e
	}
	if err = socksConnect(sc, t.Host, t.Port, deadline); err != nil {
		return fail(err, false)
	}
	_ = sc.SetWriteDeadline(deadline.Add(5 * time.Second))
	if _, err = sc.Write(recorded); err != nil {
		return fail(err, false)
	}
	_ = sc.SetWriteDeadline(time.Time{})
	if !movable {
		return sc, nil, false, nil
	}
	buf := make([]byte, 4096)
	_ = sc.SetReadDeadline(deadline)
	n, rerr := sc.Read(buf)
	_ = sc.SetReadDeadline(time.Time{})
	if n > 0 {
		return sc, buf[:n], false, nil
	}
	var ne net.Error
	if errors.As(rerr, &ne) && ne.Timeout() {
		return fail(errNoByte, true)
	}
	return fail(errNoByte, false)
}

// pipe copies both ways between the client and t until both are done or one fails.
// With first non-nil the first bytes of t are read here, so the connection knows
// when the target has answered (the place of the connection is freed at once, and
// a close after it leaves no pending dial, 5.5).
func (cn *conn) pipe(t net.Conn, first *firstRead) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(t, cn.c)
		if err != nil {
			cn.kill()
			return
		}
		closeWrite(t)
	}()
	go func() {
		defer wg.Done()
		if first != nil {
			buf := make([]byte, 4096)
			n, err := t.Read(buf)
			if n > 0 {
				cn.gotByte.Store(true)
				if _, werr := cn.c.Write(buf[:n]); werr != nil {
					cn.kill()
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					closeWrite(cn.c)
				} else {
					cn.kill()
				}
				return
			}
		}
		_, err := io.Copy(cn.c, t)
		if err != nil {
			cn.kill()
			return
		}
		closeWrite(cn.c)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// serveBuf is the buffer of the proxy's end of serve.sock (10.2): the block
// process sets the same on its end, so a stalled reader of block pages holds 32 KiB
// per connection and not the kernel default, which is what the memory limits of
// both units were sized around.
const serveBuf = 32 << 10

// tuneServe sets the buffers on a connection that has the setters (a unix or TCP
// socket); any other conn is left as it is.
func tuneServe(c net.Conn) {
	b, ok := c.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	})
	if !ok {
		return
	}
	_ = b.SetReadBuffer(serveBuf)
	_ = b.SetWriteBuffer(serveBuf)
}
