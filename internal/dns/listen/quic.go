package listen

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// handshakes counts QUIC handshakes in progress whose source address is not
// validated, across DoQ and DoH3 on this node. Above limits.RetryUnderLoad the
// node asks new sources for a Retry (QUIC source-address verification, RFC
// 9000 8.1.2), which costs one round trip and is therefore kept for a node
// under load (D52). The same Retry is asked of one source that already has
// limits.RetryPerSource handshakes in progress, or that is over a connection
// limit: the limits count a connection only after its handshake, so these are
// what keeps one real host from making the node run TLS handshakes without
// bound (p4n-W6-r4-4).
type handshakes struct {
	pending    atomic.Int64
	retried    atomic.Int64 // Retry packets asked for, for tests
	forceRetry bool

	// bySrc counts the unvalidated handshakes in progress per source (an IPv4
	// address or an IPv6 /64). Its size is bounded by pending, which cannot pass
	// RetryUnderLoad by more than the Initials that arrive between two checks:
	// above it every new source is asked for a Retry and counts nothing.
	mu    sync.Mutex
	bySrc map[netip.Prefix]int
}

// srcKey is the key of the per-source handshake count.
func srcKey(a net.Addr) (netip.Prefix, bool) {
	if a == nil {
		return netip.Prefix{}, false
	}
	ap, ok := addrPort(a)
	if !ok {
		return netip.Prefix{}, false
	}
	bits := 64
	if ap.Addr().Is4() {
		bits = 32
	}
	p, err := ap.Addr().Prefix(bits)
	return p, err == nil
}

// verify is quic-go's VerifySourceAddress: true asks the source for a Retry.
// refuse says whether the source is over a connection limit; it counts
// nothing, so an Initial with a spoofed address costs its victim only a Retry.
func (h *handshakes) verify(a net.Addr, refuse func(netip.Addr) bool) bool {
	retry := h.forceRetry || h.pending.Load() > limits.RetryUnderLoad
	if !retry {
		if k, ok := srcKey(a); ok {
			h.mu.Lock()
			retry = h.bySrc[k] >= limits.RetryPerSource
			h.mu.Unlock()
		}
	}
	if !retry && refuse != nil && a != nil {
		if ap, ok := addrPort(a); ok {
			retry = refuse(ap.Addr())
		}
	}
	if retry {
		h.retried.Add(1)
	}
	return retry
}

// connState rides on the context of a QUIC connection from its first Initial
// to its last packet.
type connState struct {
	h       *handshakes
	counted bool
	key     netip.Prefix // the source it is counted under; invalid when not tracked
	// pend is the claim of this handshake on the connection limits, for the Retry
	// decision only (p4n-W6-r5-4). It ends with the handshake, like the count.
	pend *limits.Pending
	once sync.Once
	// slot is the claim on the connection limits of a connection whose address
	// was validated before its handshake (a Retry token). It is taken in
	// ConnContext, so a source over a limit is refused before any TLS work, and
	// the accept loop uses it instead of admitting again.
	slot *limits.Conn
}

type connStateKey struct{}

// uncount takes the connection out of the handshakes in progress. It is
// called when the handshake completes and, through the context, when it fails
// or the connection ends, whichever comes first.
func (c *connState) uncount() {
	c.once.Do(func() {
		if !c.counted {
			return
		}
		c.h.pending.Add(-1)
		c.pend.End()
		if c.key.IsValid() {
			c.h.mu.Lock()
			if c.h.bySrc[c.key]--; c.h.bySrc[c.key] <= 0 {
				delete(c.h.bySrc, c.key)
			}
			c.h.mu.Unlock()
		}
	})
}

// connContext is quic-go's hook for a connection attempt that has passed the
// Retry decision. A source with no validated address is counted while its
// handshake runs.
//
// begin, when not nil, records the handshake on the connection limits (see
// limits.Set.BeginPending); it is called before the end of the handshake is
// armed, so the claim cannot outlive or miss it.
func (h *handshakes) connContext(ctx context.Context, ci *quic.ClientInfo, begin func(netip.Addr) *limits.Pending) (context.Context, error) {
	cs := &connState{h: h, counted: !ci.AddrVerified}
	if cs.counted {
		if begin != nil && ci.RemoteAddr != nil {
			if ap, ok := addrPort(ci.RemoteAddr); ok {
				cs.pend = begin(ap.Addr())
			}
		}
		h.pending.Add(1)
		if k, ok := srcKey(ci.RemoteAddr); ok {
			cs.key = k
			h.mu.Lock()
			if h.bySrc == nil {
				h.bySrc = map[netip.Prefix]int{}
			}
			h.bySrc[k]++
			h.mu.Unlock()
		}
		context.AfterFunc(ctx, cs.uncount)
	}
	return context.WithValue(ctx, connStateKey{}, cs), nil
}

var errRefusedConn = errors.New("listen: connection refused by a connection limit")

// Application error codes of the QUIC listeners. DoQ: RFC 9250 section 4.3.
// DoH3: RFC 9114 section 8.1.
const (
	doqNoError         quic.ApplicationErrorCode = 0x0
	doqProtocolError   quic.ApplicationErrorCode = 0x2
	doqRequestCanceled quic.ApplicationErrorCode = 0x3
	doqExcessiveLoad   quic.ApplicationErrorCode = 0x4

	h3NoError        quic.ApplicationErrorCode = 0x100
	h3ExcessiveLoad  quic.ApplicationErrorCode = 0x107
	h3RequestCancled quic.StreamErrorCode      = 0x10c
)

// qconn is one accepted QUIC connection.
type qconn struct {
	c      *quic.Conn
	reason atomic.Uint32
	q      *quiet
	hdr    *hdrQueue                 // DoH3 only: request streams whose headers are not read
	noErr  quic.ApplicationErrorCode // code for a close that is not an error
	held   *held                     // reply bytes this connection holds for the peer (p4n-W6-r3-3)
}

// fail records why the connection ends (first reason wins) and closes it.
func (c *qconn) fail(why CloseReason, code quic.ApplicationErrorCode) {
	c.reason.CompareAndSwap(0, uint32(why))
	_ = c.c.CloseWithError(code, "")
}

// quicBase is the part of DoQ and DoH3 that is the same: the UDP socket, the
// QUIC transport with its Retry rule, the accept loop with the connection
// limits, and shutdown.
type quicBase struct {
	*core
	hs  *handshakes
	udp *net.UDPConn
	tr  *quic.Transport
	ln  *quic.Listener
	h3  bool
	// nodeHeld is the reply bytes all connections of this listener hold for peers
	// that do not read them.
	nodeHeld atomic.Int64

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[*quic.Conn]*qconn
}

func newQUICBase(c *core, hs *handshakes, udp *net.UDPConn, tlsCfg *tls.Config, h3 bool) (*quicBase, error) {
	b := &quicBase{core: c, hs: hs, udp: udp, h3: h3, conns: map[*quic.Conn]*qconn{}}
	uni := int64(-1) // DoQ uses no unidirectional stream
	if h3 {
		uni = 10 // control and QPACK streams, with room
	}
	qconf := &quic.Config{
		// quic-go also ends a handshake at twice this value whatever progress
		// the peer makes, so half of the setting makes the setting the absolute
		// limit, as it is for the TLS handshake of the TCP transports
		// (p4n-W6-r5-1).
		HandshakeIdleTimeout: c.set.HandshakeTimeout / 2,
		// The transport's own idle timer stays far above ours: ours is armed
		// only while nothing is unread or unanswered (quiet), and a query that
		// waits on a slow answer must not be cut by a timer that counts
		// silence. The keep-alive keeps the path open while it waits, and a dead
		// peer still ends the connection by the missing acknowledgements.
		MaxIdleTimeout:                 c.set.QUICMaxIdle,
		KeepAlivePeriod:                c.set.QUICKeepAlive,
		MaxIncomingStreams:             int64(c.set.MaxStreams),
		MaxIncomingUniStreams:          uni,
		Allow0RTT:                      false, // 0-RTT is off in version 1 (D51, D52)
		EnableDatagrams:                false,
		InitialStreamReceiveWindow:     uint64(c.set.QUICStreamWindow),
		MaxStreamReceiveWindow:         uint64(c.set.QUICStreamWindow),
		InitialConnectionReceiveWindow: uint64(c.set.QUICConnWindow) / 2,
		MaxConnectionReceiveWindow:     uint64(c.set.QUICConnWindow),
	}
	b.tr = &quic.Transport{
		Conn: udp,
		// A token from an earlier connection (NEW_TOKEN, which quic-go sends after
		// every handshake) is bound to the address only and works for any number
		// of Initials for as long as it is valid, so a peer that holds one can
		// make a spoofed Initial look address-validated: it would take its
		// victim's connection slots in ConnContext and never answer
		// (p4n-W6-r5-3). A negative age makes every such token invalid, so only a
		// Retry token validates an address. A Retry token is bound to the source IP
		// (not the port, and not a connection ID: quic-go never compares the
		// Initial's destination ID with it) and lives 2 x the handshake idle
		// timeout, 5 s. It can be reused for that time, which is safe because only a
		// host that receives the IP's packets gets one and every use is Admitted
		// against the per-source limits in ConnContext before any TLS work
		// (p4n-W6-r6-3).
		MaxTokenAge: -1,
		VerifySourceAddress: func(a net.Addr) bool {
			return hs.verify(a, func(ip netip.Addr) bool { return c.cfg.Limits.WouldRefuse(c.t, ip) })
		},
		ConnContext: b.connContext,
	}
	ln, err := b.tr.Listen(tlsCfg, qconf)
	if err != nil {
		return nil, err
	}
	b.ln = ln
	return b, nil
}

// acceptLoop takes connections whose handshake has completed (or whose Retry
// token was valid: quic-go has no other way to hand one over), counts them on
// the connection limits only then (L13 (3)), and serves each on a goroutine.
func (b *quicBase) acceptLoop(serve func(*qconn, netip.AddrPort, *limits.Conn)) {
	defer b.wg.Done()
	for {
		conn, err := b.ln.Accept(b.ctx)
		if err != nil {
			return
		}
		var slot *limits.Conn // set when ConnContext admitted the connection already
		if cs, ok := conn.Context().Value(connStateKey{}).(*connState); ok {
			cs.uncount()
			slot = cs.slot
		}
		src, ok := addrPort(conn.RemoteAddr())
		if !ok {
			slot.Release()
			_ = conn.CloseWithError(doqNoError, "")
			continue
		}
		if slot == nil {
			// A handshake that finished without a validated address (no Retry was
			// asked): the connection is counted now.
			var admitted bool
			slot, admitted = b.cfg.Limits.Admit(b.t, src.Addr())
			if !admitted {
				b.refused()
				code := doqExcessiveLoad
				if b.h3 {
					code = h3ExcessiveLoad
				}
				_ = conn.CloseWithError(code, "")
				continue
			}
		}
		qc := &qconn{c: conn, noErr: doqNoError, held: newHeld(&b.nodeHeld)}
		if b.h3 {
			qc.noErr = h3NoError
		}
		b.mu.Lock()
		b.conns[conn] = qc
		b.mu.Unlock()
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() {
				b.mu.Lock()
				delete(b.conns, conn)
				b.mu.Unlock()
				slot.Release()
				why := CloseReason(qc.reason.Load())
				if why == 0 {
					why = ClosePeer
				}
				b.closed(why)
			}()
			serve(qc, src, slot)
		}()
	}
}

// connContext runs for every connection attempt that passed the Retry decision.
// One whose address is already validated (it answered a Retry, or presented a
// token from an earlier connection) is counted on the connection limits here,
// before quic-go runs its TLS handshake, so a source that is over a limit costs
// the node a Retry and no signature or key exchange (p4n-W6-r4-4). One that
// is not validated counts nothing (L13 (3)) and is admitted by the accept loop
// once its handshake is done.
func (b *quicBase) connContext(ctx context.Context, ci *quic.ClientInfo) (context.Context, error) {
	ctx, err := b.hs.connContext(ctx, ci, func(a netip.Addr) *limits.Pending { return b.cfg.Limits.BeginPending(b.t, a) })
	if err != nil || !ci.AddrVerified {
		return ctx, err
	}
	ap, ok := addrPort(ci.RemoteAddr)
	if !ok {
		return nil, errRefusedConn
	}
	slot, ok := b.cfg.Limits.Admit(b.t, ap.Addr())
	if !ok {
		b.refused()
		return nil, errRefusedConn
	}
	ctx.Value(connStateKey{}).(*connState).slot = slot
	// A handshake that never finishes, or a connection that ends, gives the slot
	// back; the serving goroutine releases it too, and Release is idempotent.
	context.AfterFunc(ctx, slot.Release)
	return ctx, nil
}

func (b *quicBase) lookup(c *quic.Conn) *qconn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conns[c]
}

// newAlarms builds the idle and stall alarms of a connection: after their time
// they close it, but only if they are still armed (timerAlarm checks).
func (c *qconn) newQuiet(set limits.ListenerSettings) *quiet {
	idle := &timerAlarm{fire: func() { c.fail(CloseIdle, c.noErr) }}
	stall := &timerAlarm{fire: func() { c.fail(CloseStall, c.noErr) }}
	c.q = newQuiet(set.IdleTimeout, set.WriteStall, idle, stall)
	return c.q
}

func (b *quicBase) close() {
	_ = b.ln.Close()
	b.mu.Lock()
	for _, qc := range b.conns {
		qc.fail(CloseShutdown, qc.noErr)
	}
	b.mu.Unlock()
	_ = b.tr.Close()
	_ = b.udp.Close()
	b.wg.Wait()
}
