package listen

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// streamServer is Plain DNS on TCP 53 and DoT on 853: a length-prefixed
// stream (RFC 1035 4.2.2, RFC 7858) with one goroutine per query and replies
// written out of order, so a slow query never holds the ones behind it
// (T-549, L13 round 51). DoT is the same loop under TLS.
type streamServer struct {
	*core
	ln     net.Listener
	tlsCfg *tls.Config // nil for Plain TCP
	wg     sync.WaitGroup

	mu    sync.Mutex
	conns map[*sconn]struct{}

	// queued is the bytes of replies waiting for the wire on every connection of
	// this listener, against MaxQueuedBytesNode.
	queued atomic.Int64
}

func newStream(c *core, ln net.Listener, tlsCfg *tls.Config) *streamServer {
	return &streamServer{core: c, ln: ln, tlsCfg: tlsCfg, conns: map[*sconn]struct{}{}}
}

func (s *streamServer) start() {
	s.wg.Add(1)
	go s.acceptLoop()
}

func (s *streamServer) close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		c.fail(CloseShutdown)
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *streamServer) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || isClosed(err) {
				return
			}
			// A temporary failure (out of descriptors): wait, do not spin.
			time.Sleep(5 * time.Millisecond)
			continue
		}
		src, ok := addrPort(c.RemoteAddr())
		if !ok {
			_ = c.Close()
			continue
		}
		// The TCP handshake has finished, so the source is validated and the
		// connection limits may count it (L13 (3)).
		slot, ok := s.cfg.Limits.Admit(s.t, src.Addr())
		if !ok {
			// Refused before it is accepted: closed at once.
			s.refused()
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go s.serveConn(c, src, slot)
	}
}

// sconn is one accepted connection.
type sconn struct {
	// raw is the TCP connection, fixed for the life of the connection, so a
	// shutdown can close it from another goroutine without racing the
	// assignment of conn. conn is raw, or the TLS connection over it once the
	// handshake is done, and is used only by the goroutines that start after that.
	raw    net.Conn
	conn   net.Conn
	reason atomic.Uint32

	// The replies that are ready and wait for the wire, written by one writer
	// goroutine in the order they became ready.
	//
	// pending counts every query read and not yet written or dropped: the
	// handler still running, the reply queued, the reply being written. While
	// MaxQueuedReplies of them wait and the peer is behind (a reply queued or a
	// write under way), the reader stops reading new frames, so a peer that does
	// not read its answers is held back by TCP flow control (p4n-W6-r1-1, -5,
	// p4n-W6-r2-1, -5). A peer that reads is never behind for long, so nothing
	// waits on a healthy connection and there is no query cap (L13 (2)).
	//
	// The reader cannot know that a slow handler's reply will be large or that
	// the peer will not take it, so the queue is also bounded in bytes: past the
	// cap a reply is replaced by a short SERVFAIL for the same query, which still
	// answers it and costs the node a few dozen bytes instead of up to 64 KiB.
	omu     sync.Mutex
	out     []outFrame
	qbytes  int  // bytes in out, plus the frame the writer has in hand
	handLen int  // bytes of the frame the writer has in hand (counted in qbytes)
	pending int  // queries read and not yet written or dropped
	writing bool // the writer has a frame in hand
	node    *atomic.Int64
	wake    chan struct{} // the writer has work (capacity 1)
	space   chan struct{} // pending or the queue shrank (capacity 1)
	dead    chan struct{} // closed when the connection is over
	once    sync.Once
}

type outFrame struct {
	id uint64
	b  []byte
}

func newSconn(raw net.Conn, node *atomic.Int64) *sconn {
	return &sconn{raw: raw, conn: raw, node: node, wake: make(chan struct{}, 1), space: make(chan struct{}, 1), dead: make(chan struct{})}
}

// fail records why the connection ends (the first reason wins) and closes it.
func (c *sconn) fail(why CloseReason) {
	c.reason.CompareAndSwap(0, uint32(why))
	_ = c.raw.Close()
	c.kill()
}

// kill wakes everything that waits on the connection.
func (c *sconn) kill() { c.once.Do(func() { close(c.dead) }) }

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// reserve counts a query read, before its handler starts.
func (c *sconn) reserve() {
	c.omu.Lock()
	c.pending++
	c.omu.Unlock()
}

// release ends the claim of a query that gets no reply on the wire.
func (c *sconn) release() {
	c.omu.Lock()
	c.pending--
	c.omu.Unlock()
	signal(c.space)
}

// push queues a reply. A reply that would pass the per-connection cap or the
// listener-wide cap is replaced by alt(). A small reply (up to firstReplyFree)
// on a connection that holds nothing always fits, so the listener-wide cap
// lands on the connections that hold bytes and never turns away a client that
// holds nothing (an exempt name included, L13) because other peers do not read
// (p4n-W6-r6-1). The exemption stops at firstReplyFree: without that, every
// connection's first reply escaped the listener cap and the node held up to
// connections x 64 KiB for peers that read nothing (p4n-W6-r7-1, -2). A cap of
// 0 is no cap.
func (c *sconn) push(f outFrame, connCap, nodeCap int, alt func() []byte) {
	c.omu.Lock()
	select {
	case <-c.dead:
		// The connection is over and drop has run or will: queueing now would
		// leave bytes counted against the listener for good.
		c.omu.Unlock()
		return
	default:
	}
	if overCaps(c.qbytes, len(f.b), c.node, connCap, nodeCap) {
		if b := alt(); b != nil {
			f.b = b
		}
	}
	c.out = append(c.out, f)
	c.qbytes += len(f.b)
	c.node.Add(int64(len(f.b)))
	c.omu.Unlock()
	signal(c.wake)
}

// firstReplyFree is the size up to which the first reply of a connection ignores
// the listener-wide byte cap: it covers every answer to an exempt name and an
// ordinary answer to a healthy client, and bounds what a connection that holds
// nothing can add to the listener to a few KiB.
const firstReplyFree = 4096

// overCaps says whether a reply of n bytes must be replaced, for a connection
// that holds `holds` bytes. The per-connection cap always admits a connection's
// first reply (a lone reply fits it by CheckListeners); the listener cap admits
// it only when it is small.
func overCaps(holds, n int, node *atomic.Int64, connCap, nodeCap int) bool {
	if nodeCap > 0 && (holds > 0 || n > firstReplyFree) && node.Load()+int64(n) > int64(nodeCap) {
		return true
	}
	return holds > 0 && connCap > 0 && holds+n > connCap
}

func (c *sconn) pop() (outFrame, bool) {
	c.omu.Lock()
	if len(c.out) == 0 {
		c.omu.Unlock()
		return outFrame{}, false
	}
	f := c.out[0]
	c.out[0] = outFrame{}
	c.out = c.out[1:]
	// The frame stays counted until its write ends: a peer that does not read
	// holds it in the writer's hand, and the next reply must see that bytes are
	// held (p4n-W6-r7-2).
	c.handLen = len(f.b)
	c.writing = true
	c.omu.Unlock()
	return f, true
}

// wrote ends the claim of the reply the writer had in hand.
func (c *sconn) wrote() {
	c.omu.Lock()
	c.writing = false
	c.qbytes -= c.handLen
	c.node.Add(-int64(c.handLen))
	c.handLen = 0
	c.pending--
	c.omu.Unlock()
	signal(c.space)
}

// drop gives back to the listener what the queue still holds when the
// connection is over.
func (c *sconn) drop() {
	c.omu.Lock()
	c.node.Add(-int64(c.qbytes))
	c.qbytes, c.handLen, c.out = 0, 0, nil
	c.omu.Unlock()
}

// waitSpace blocks while max queries wait and the peer is behind. It returns
// false when the connection is over. A max of 0 never blocks.
func (c *sconn) waitSpace(max int) bool {
	for {
		c.omu.Lock()
		blocked := max > 0 && c.pending >= max && (len(c.out) > 0 || c.writing)
		c.omu.Unlock()
		if !blocked {
			return true
		}
		select {
		case <-c.space:
		case <-c.dead:
			return false
		}
	}
}

// waitDrained blocks until every query read has been answered on the wire or
// dropped, the connection ends, or limit passes. A peer that half-closes after
// its queries (a pipelining client, a probe) still gets its answers (L13 (2):
// no connection is closed while a query is unanswered); the stall deadline
// covers a peer that then does not read, and limit a handler that never ends.
func (c *sconn) waitDrained(limit time.Duration) {
	var timeout <-chan time.Time
	if limit > 0 {
		t := time.NewTimer(limit)
		defer t.Stop()
		timeout = t.C
	}
	for {
		c.omu.Lock()
		n := c.pending
		c.omu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-c.space:
		case <-c.dead:
			return
		case <-timeout:
			return
		}
	}
}

// writeLoop is the one writer of the connection. Each write is registered with
// quiet, which closes the connection when the oldest one has run for the
// write-stall time.
func (s *streamServer) writeLoop(sc *sconn, q *quiet) {
	defer s.wg.Done()
	for {
		f, ok := sc.pop()
		if !ok {
			select {
			case <-sc.wake:
			case <-sc.dead:
				return
			}
			continue
		}
		q.writeBegin(f.id)
		_, err := sc.conn.Write(f.b)
		q.writeEnd(f.id)
		sc.wrote()
		if err != nil {
			if isTimeout(err) {
				sc.fail(CloseStall)
			} else {
				sc.fail(ClosePeer)
			}
			return
		}
	}
}

func (s *streamServer) serveConn(raw net.Conn, src netip.AddrPort, slot *limits.Conn) {
	defer s.wg.Done()
	sc := newSconn(raw, &s.queued)
	s.mu.Lock()
	s.conns[sc] = struct{}{}
	s.mu.Unlock()
	// A connection accepted just before close() may have missed its loop over
	// s.conns. Server.Close cancels the context before it calls close(), so a
	// live context here means the loop comes later and finds this connection,
	// and a cancelled one means it may already have run (p4n-W6-r4-1).
	if s.ctx.Err() != nil {
		sc.fail(CloseShutdown)
	}
	defer func() {
		s.mu.Lock()
		delete(s.conns, sc)
		s.mu.Unlock()
		_ = sc.raw.Close()
		sc.kill()
		sc.drop()
		slot.Release()
		why := CloseReason(sc.reason.Load())
		if why == 0 {
			why = ClosePeer
		}
		s.closed(why)
	}()

	sni := ""
	if s.tlsCfg != nil {
		tc := tls.Server(raw, s.tlsCfg)
		_ = raw.SetDeadline(time.Now().Add(s.set.HandshakeTimeout))
		if err := tc.Handshake(); err != nil {
			sc.reason.CompareAndSwap(0, uint32(CloseHandshake))
			return
		}
		_ = raw.SetDeadline(time.Time{})
		sni = tc.ConnectionState().ServerName
		sc.conn = tc
	}
	conn := sc.conn

	// Idle is a read deadline. The stall closes the connection: the write it
	// must end may be one that no socket write is blocked in.
	q := newQuiet(s.set.IdleTimeout, s.set.WriteStall,
		connAlarm{set: conn.SetReadDeadline}, &timerAlarm{fire: func() { sc.fail(CloseStall) }})
	defer q.stop()
	s.wg.Add(1)
	go s.writeLoop(sc, q)

	br := bufio.NewReaderSize(conn, 4096)
	for {
		// A full queue of replies the peer has not taken: stop reading.
		if !sc.waitSpace(s.set.MaxQueuedReplies) {
			return
		}
		// Waiting for the first byte of a frame is the idle state: the deadline
		// here is the one quiet armed, and only when nothing is unread or
		// unanswered.
		if _, err := br.Peek(1); err != nil {
			switch {
			case isTimeout(err) && q.idleArmed():
				sc.fail(CloseIdle)
				return
			case isTimeout(err):
				continue // disarmed an instant before the timeout was delivered
			case errors.Is(err, io.EOF):
				// The peer will send no more (a FIN, or a TLS close_notify) and may
				// still read: answer what it asked, then close (p4n-W6-r2-3).
				sc.waitDrained(s.set.HandlerTimeout + s.set.WriteStall)
			}
			return
		}
		// A frame is under way: from here until it is answered, the connection
		// is not quiet, and the frame has BodyTimeout to arrive (a slowloris peer
		// holds its own connection for that long, no one else's).
		id := q.begin()
		_ = conn.SetReadDeadline(time.Now().Add(s.set.BodyTimeout))
		m, ok := readFrame(br)
		if !ok {
			// Length below 12, a frame that did not arrive, or one that does
			// not parse: a protocol error that ends this connection. It is not a
			// limit of step 1 (D52).
			sc.fail(CloseProtocol)
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		if m.Response {
			q.abort(id) // a response on a query stream is not answered
			continue
		}
		s.dispatch(sc, q, id, m, src, sni)
	}
}

// readFrame reads one length-prefixed message.
func readFrame(br *bufio.Reader) (*dns.Msg, bool) {
	var lb [2]byte
	if _, err := io.ReadFull(br, lb[:]); err != nil {
		return nil, false
	}
	n := int(lb[0])<<8 | int(lb[1])
	if n < 12 {
		return nil, false
	}
	buf, err := readBody(br, n)
	if err != nil {
		return nil, false
	}
	m := new(dns.Msg)
	if m.Unpack(buf) != nil {
		return nil, false
	}
	return m, true
}

// dispatch applies step 1 to a query read and starts its goroutine. The query
// is open in q as id.
func (s *streamServer) dispatch(sc *sconn, q *quiet, id uint64, m *dns.Msg, src netip.AddrPort, sni string) {
	sc.reserve() // the query is counted from its read until its reply is written
	exempt := s.exempt(m)
	stop := s.gate(exempt, src.Addr())
	var ck cookieOpt
	validated := true // a finished TCP or TLS handshake
	if s.t == TCP {
		ck, _ = s.parseCookie(m, src.Addr())
	}
	go func() {
		var rep Reply
		switch {
		case stop != limits.AnswerNone:
			// The limit acts on this query only: it gets REFUSED on its own
			// answer and the connection stays open (L13 (2)).
			rep = Reply{Msg: Refused(m)}
		case !s.enter(exempt):
			rep = Reply{Msg: ServFail(m)}
		default:
			rep = s.call(&Request{Msg: m, Transport: s.t, Source: src, Validated: validated, SNI: sni})
			s.exit()
		}
		if rep.Drop && s.t == TCP {
			q.abort(id) // Plain DNS silent drop: the connection stays open
			sc.release()
			return
		}
		if rep.Msg == nil {
			rep.Msg = ServFail(m)
		}
		frame := s.packFrame(rep.Msg, m, func() { s.answerCookie(rep.Msg, ck, src.Addr()) })
		if frame == nil {
			q.abort(id)
			sc.release()
			return
		}
		// The query is answered. From here the peer must take the reply, and the
		// stall time counts from the moment the writer starts it.
		q.queue(id)
		sc.push(outFrame{id: id, b: frame}, s.set.MaxQueuedBytes, s.set.MaxQueuedBytesNode,
			func() []byte { return s.packFrame(ServFail(m), m, nil) })
	}()
}
