package listen

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// doh3Server is DoH on HTTP/3 over UDP 443: the DoH handler, served by
// quic-go's http3 on connections this loop has accepted. It is a transport of
// its own with its own limits, and takes every QUIC rule of L13 as DoQ does:
// a connection counts only once its handshake is done, no limit closes it,
// every connection has the stream cap. 0-RTT is off, and there is no Alt-Svc
// and no HTTPS record with alpn=h3 (D51): a client reaches it only by a
// configured address.
//
// The request streams are accepted by our own loop and handed to quic-go's
// RawServerConn, because http3.Server has no header deadline and no way to see
// a stream whose headers are still arriving. Our loop gives each stream the
// header deadline and counts it as a query under way until its handler starts
// (p4n-W6-r1-4, -8).
type doh3Server struct {
	*quicBase
	srv *http3.Server
}

func newDoH3(b *quicBase, verify VerifyHandler) *doh3Server {
	h := &dohHandler{core: b.core, verify: verify}
	s := &doh3Server{quicBase: b}
	s.srv = &http3.Server{
		Handler:         h,
		MaxHeaderBytes:  b.set.MaxHeaderBytes,
		EnableDatagrams: false,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			if qc := b.lookup(c); qc != nil {
				ctx = context.WithValue(ctx, heldKey{}, qc.held)
			}
			if qc := b.lookup(c); qc != nil && qc.q != nil {
				ctx = context.WithValue(ctx, quietKey{}, qc.q)
				if qc.hdr != nil {
					ctx = context.WithValue(ctx, hdrKey{}, qc.hdr)
				}
			}
			return ctx
		},
	}
	return s
}

func (s *doh3Server) start() {
	s.wg.Add(1)
	go s.acceptLoop(s.serveConn)
}

func (s *doh3Server) serveConn(qc *qconn, _ netip.AddrPort, _ *limits.Conn) {
	q := qc.newQuiet(s.set)
	defer q.stop()
	defer s.attachDrain(qc)()
	qc.hdr = newHdrQueue(q, s.set.ReadHeaderTimeout)
	qc.hdr.max = s.set.MaxStreams
	defer qc.hdr.stop()
	// The source of every request is the connection's address (the handler
	// reads r.RemoteAddr).
	hconn, err := s.srv.NewRawServerConn(qc.c)
	if err != nil {
		_ = qc.c.CloseWithError(qc.noErr, "")
		return
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		for {
			us, err := qc.c.AcceptUniStream(s.ctx)
			if err != nil {
				return
			}
			go hconn.HandleUnidirectionalStream(us)
		}
	})
	// The loop ends when the peer closes the connection or the server does.
	defer func() { _ = qc.c.CloseWithError(qc.noErr, "") }()
	for {
		str, err := qc.c.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		tok := qc.hdr.add(str.StreamID())
		if qc.refusing.Load() {
			// H3_REQUEST_REJECTED says nothing was processed, so the client may send the
			// request on a new connection (RFC 9114 8.1). quic-go's RawServerConn has no
			// GOAWAY of its own, so this is how the client learns.
			qc.hdr.end(tok)
			str.CancelRead(h3RequestRejected)
			str.CancelWrite(h3RequestRejected)
			continue
		}
		if d := s.set.ReadHeaderTimeout; d > 0 {
			_ = str.SetReadDeadline(time.Now().Add(d))
		}
		wg.Go(func() {
			hconn.HandleRequestStream(str)
			// Whatever happened to the stream, its header wait is over: this is what
			// keeps the tokens at the stream cap under a peer that opens and closes
			// streams (p4n-W6-r4-2).
			qc.hdr.end(tok)
		})
	}
}

func (s *doh3Server) close() {
	_ = s.srv.Close()
	s.quicBase.close()
}

// hdrQueue counts the request streams of one connection whose headers have
// not been read as queries under way, so the idle deadline cannot close the
// connection while a request is arriving, and the hold-off of the stall
// deadline sees them. A stream ends this state when its handler starts
// (endStream, by the stream's own ID), when quic-go has finished with the
// stream whether or not a handler ran (the serve loop calls end), or at the
// header deadline, whichever is first. Each token is tied to its own stream, so
// one stream's end never takes another stream's token (p4n-W6-r5-6).
//
// A stream that quic-go ends before any handler runs (a FIN with no HEADERS, an
// immediate reset) gives its stream credit back at once, so a peer can open
// streams as fast as it can close them. The token must go with the stream, not
// with its timer, or the live tokens are the churn rate times the header
// deadline (p4n-W6-r4-2). The tokens are a map by stream ID, so add, end and
// endStream are O(1) and there are never more than the stream cap of them.
type hdrQueue struct {
	q *quiet
	d time.Duration
	// max bounds the tokens: quic-go gives a stream's credit back when the stream
	// is closed, which is a moment before the serve loop's goroutine for it gets to
	// call end, so a peer that opens and closes streams as fast as it can sees more
	// tokens than the cap for as long as the scheduler lags. At max a new token
	// takes the place of one other token; the streams really waiting are at most
	// the cap, so the tokens left still say that something is arriving. Zero is
	// no bound (tests).
	max int

	mu   sync.Mutex
	toks map[quic.StreamID]*hdrTok
	gone bool
	peak int // most tokens held at once, for tests
}

type hdrTok struct {
	id  uint64
	sid quic.StreamID
	t   *time.Timer
	in  bool // still in the map
}

func newHdrQueue(q *quiet, d time.Duration) *hdrQueue {
	if d <= 0 {
		d = 5 * time.Second
	}
	return &hdrQueue{q: q, d: d, toks: map[quic.StreamID]*hdrTok{}}
}

// add opens the header wait of the stream sid and returns its token, nil when
// the connection is already over. The caller hands the token to end when the
// stream is finished with.
func (h *hdrQueue) add(sid quic.StreamID) *hdrTok {
	id := h.q.begin()
	tok := &hdrTok{id: id, sid: sid}
	h.mu.Lock()
	if h.gone {
		h.mu.Unlock()
		h.q.abort(id)
		return nil
	}
	var victim *hdrTok
	if h.max > 0 && len(h.toks) >= h.max {
		for _, v := range h.toks {
			victim = v
			break
		}
		delete(h.toks, victim.sid)
		victim.in = false
	}
	tok.t = time.AfterFunc(h.d, func() { h.end(tok) })
	tok.in = true
	h.toks[sid] = tok
	if n := len(h.toks); n > h.peak {
		h.peak = n
	}
	h.mu.Unlock()
	if victim != nil {
		victim.t.Stop()
		h.q.abort(victim.id)
	}
	return tok
}

// end takes tok out of the waiting streams, once. A nil tok is no stream.
func (h *hdrQueue) end(tok *hdrTok) {
	if tok == nil {
		return
	}
	h.mu.Lock()
	found := tok.in
	if found {
		delete(h.toks, tok.sid)
		tok.in = false
	}
	h.mu.Unlock()
	if found {
		tok.t.Stop()
		h.q.abort(tok.id)
	}
}

// endStream is called when the handler of stream sid starts: that stream's
// headers are read.
func (h *hdrQueue) endStream(sid quic.StreamID) {
	h.mu.Lock()
	tok := h.toks[sid]
	h.mu.Unlock()
	h.end(tok)
}

func (h *hdrQueue) stop() {
	h.mu.Lock()
	h.gone = true
	toks := make([]*hdrTok, 0, len(h.toks))
	for _, t := range h.toks {
		t.in = false // under the lock: end must not remove from the emptied map
		toks = append(toks, t)
	}
	clear(h.toks)
	h.mu.Unlock()
	for _, t := range toks {
		t.t.Stop()
	}
}

// maxHeld reports the most tokens the queue held at once.
func (h *hdrQueue) maxHeld() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.peak
}

var _ http.Handler = (*dohHandler)(nil)
