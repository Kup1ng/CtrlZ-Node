package listen

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

const dnsMessageType = "application/dns-message"

type quietKey struct{}

// hdrKey carries the DoH3 connection's queue of request streams whose headers
// have not been read yet.
type hdrKey struct{}

// reqTrack follows one request in the connection's quiet state: an item from
// the moment the handler starts, a write from the moment the reply starts, so
// a reply the peer does not take (a zero flow-control window, a small receive
// buffer) is a write that the stall deadline can see, whether or not a socket
// write is blocked (p4n-W6-r1-2, -6). Nil when the connection has no quiet.
type reqTrack struct {
	q       *quiet
	id      uint64
	replied bool
}

func newTrack(q *quiet) *reqTrack {
	if q == nil {
		return nil
	}
	return &reqTrack{q: q, id: q.begin()}
}

// reply marks the start of the response write; it is called before the first
// byte of any response, error statuses included.
func (t *reqTrack) reply() {
	if t != nil && !t.replied {
		t.replied = true
		t.q.reply(t.id)
	}
}

func (t *reqTrack) finish() {
	if t == nil {
		return
	}
	if t.replied {
		t.q.writeEnd(t.id)
	} else {
		t.q.abort(t.id)
	}
}

// dohHandler is RFC 8484 over a net/http handler, for DoH (HTTP/1.1 and
// HTTP/2) and for DoH3 (HTTP/3): the same handler, the same caps, the same
// answers. It is where the size caps of 7.4 live.
type dohHandler struct {
	*core
	verify VerifyHandler
}

func (h *dohHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q, _ := r.Context().Value(quietKey{}).(*quiet)
	tr := newTrack(q)
	defer tr.finish()
	if hq, ok := r.Context().Value(hdrKey{}).(*hdrQueue); ok {
		// This request's headers are read. quic-go's request body knows its stream;
		// without it the token ends with the stream or at the header deadline.
		if sb, ok := r.Body.(interface{ StreamID() quic.StreamID }); ok {
			hq.endStream(sb.StreamID())
		}
	}
	// The body deadline covers the whole request, whatever its method and
	// however it ends: a body this handler never reads (a GET with one, a POST
	// answered 415 or 413) is read and thrown away by net/http, and must not be
	// able to take longer than a body we do read (p4n-W6-r1-7). It is cleared
	// once the request is read, or a handler that runs on would meet it as a
	// timeout of the connection read net/http keeps open to see the peer go.
	rc := http.NewResponseController(w)
	if h.set.BodyTimeout > 0 {
		if err := rc.SetReadDeadline(time.Now().Add(h.set.BodyTimeout)); err != nil && r.Body != nil && r.Body != http.NoBody {
			t := time.AfterFunc(h.set.BodyTimeout, func() { _ = r.Body.Close() })
			defer t.Stop()
		}
	}
	readDone := func() { _ = rc.SetReadDeadline(time.Time{}) }
	sni := ""
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	// GET /v on a verify host is the `verify` page's request (P4 7.6). The hook
	// is W7's and owns its headers, CORS included. CORS exists for that host and
	// path only: everything below answers OPTIONS with 405 and sends no
	// Access-Control-Allow-Origin.
	if h.verify != nil && r.URL.Path == "/v" && h.verify.VerifyHost(sni) {
		// A GET has no body to use, but one that is declared must still arrive
		// under the body deadline: net/http throws away what the handler left, and
		// does it with no deadline of its own once ours is cleared (p4n-W6-r2-6).
		if status := drainBody(r, h.maxBody()); status != 0 {
			plain(w, tr, status)
			return
		}
		readDone()
		tr.reply()
		h.serveVerify(w, tr, r)
		// The hook's reply is buffered until the handler returns, and HTTP/2 and
		// HTTP/3 then wait for the peer's window outside this function. Flush it
		// inside the write reqTrack follows, as the DoH path below does
		// (p4n-W6-r2-2).
		_ = rc.Flush()
		return
	}
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")

	var wire []byte
	switch r.Method {
	case http.MethodGet:
		var status int
		if wire, status = h.fromQuery(r); status == 0 {
			// A body on a GET is read under the deadline before it is cleared
			// (p4n-W6-r2-6).
			status = drainBody(r, h.maxBody())
		}
		if status != 0 {
			plain(w, tr, status)
			return
		}
	case http.MethodPost:
		var status int
		if wire, status = h.fromBody(w, r); status != 0 {
			plain(w, tr, status)
			return
		}
	default: // OPTIONS and the rest: no CORS, no preflight answer
		hdr.Set("Allow", "GET, POST")
		plain(w, tr, http.StatusMethodNotAllowed)
		return
	}

	readDone()
	m := new(dns.Msg)
	if m.Unpack(wire) != nil || m.Response {
		plain(w, tr, http.StatusBadRequest)
		return
	}
	// The source is the address of the connection, never a header (D52).
	src, ok := addrPort(addrString(r.RemoteAddr))
	if !ok {
		plain(w, tr, http.StatusBadRequest)
		return
	}

	exempt := h.exempt(m)
	stop := h.gate(exempt, src.Addr())
	var rep Reply
	switch {
	case stop != limits.AnswerNone:
		// HTTP 200 with a REFUSED message: the request ends, the connection
		// stays (L13 (2)).
		rep = Reply{Msg: Refused(m)}
	case !h.enter(exempt):
		rep = Reply{Msg: ServFail(m)}
	default:
		rep = h.call(&Request{
			Msg: m, Transport: h.t, Source: src, Validated: true, SNI: sni,
			HTTP: &HTTPInfo{
				Path:            r.URL.Path,
				Authority:       r.Host,
				Method:          r.Method,
				ContentType:     r.Header.Get("Content-Type"),
				HasOrigin:       len(r.Header.Values("Origin")) > 0,
				HasReferer:      len(r.Header.Values("Referer")) > 0,
				HasSecFetchSite: len(r.Header.Values("Sec-Fetch-Site")) > 0,
			},
		})
		h.exit()
	}
	if rep.Status != 0 && rep.Status != http.StatusOK {
		plain(w, tr, rep.Status)
		return
	}
	if rep.Msg == nil { // Drop has no meaning here: a request must be answered
		rep.Msg = ServFail(m)
	}
	b := h.guardPack(m, func() []byte {
		b, err := rep.Msg.Pack()
		if err == nil && len(b) > limits.MaxDNSMessage {
			rep.Msg.Truncate(limits.MaxDNSMessage)
			b, err = rep.Msg.Pack()
		}
		if err != nil {
			return servFailWire(m)
		}
		return b
	})
	if b == nil {
		plain(w, tr, http.StatusInternalServerError)
		return
	}
	// A peer that does not take its replies is not allowed to make the node hold
	// them (p4n-W6-r3-3): past the connection or listener bound the reply is a
	// SERVFAIL.
	hd, _ := r.Context().Value(heldKey{}).(*held)
	b = hd.hold(b, h.set.MaxQueuedBytes, h.set.MaxQueuedBytesNode, func() []byte { return servFailWire(m) })
	defer hd.release(len(b))
	hdr.Set("Content-Type", dnsMessageType)
	hdr.Set("Content-Length", strconv.Itoa(len(b)))
	tr.reply()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	// A small reply stays in net/http's buffer until the handler returns, and
	// HTTP/2 then waits for the peer's flow-control window outside this
	// function, where no deadline can see it. Flushing here keeps that wait
	// inside the write that reqTrack follows (p4n-W6-r1-2).
	_ = rc.Flush()
}

func (h *dohHandler) maxBody() int64 {
	if h.set.MaxBodyBytes > 0 {
		return int64(h.set.MaxBodyBytes)
	}
	return int64(limits.MaxDNSMessage)
}

// drainBody reads the body of a request whose handler has no use for it, up to
// max bytes, so that it arrives under the request deadline ServeHTTP set. It
// returns 0 when the body is gone (or there was none). When it cannot finish
// (the deadline, a body above max) it returns the status to answer, and the
// caller leaves the deadline in force: what net/http then throws away runs
// under it and ends the connection when it passes.
func drainBody(r *http.Request, max int64) int {
	if r.Body == nil || r.Body == http.NoBody {
		return 0
	}
	n, err := io.Copy(io.Discard, io.LimitReader(r.Body, max+1))
	switch {
	case err != nil && isTimeout(err):
		return http.StatusRequestTimeout
	case err != nil:
		return http.StatusBadRequest
	case n > max:
		return http.StatusRequestEntityTooLarge
	}
	return 0
}

// serveVerify runs W7's hook under a recover. net/http ends an HTTP/1.1
// connection on a handler panic and resets the stream on HTTP/2 and HTTP/3; the
// rule of T-549 is that a handler bug never closes a connection, so the panic
// becomes a 500 (a no-op if the hook had already sent its header) and is
// counted. The value is dropped: it can hold request data (p4n-W6-r8-1).
func (h *dohHandler) serveVerify(w http.ResponseWriter, tr *reqTrack, r *http.Request) {
	defer func() {
		if recover() != nil {
			if h.cfg.Observer.Panic != nil {
				h.cfg.Observer.Panic(h.t)
			}
			plain(w, tr, http.StatusInternalServerError)
		}
	}()
	h.verify.ServeHTTP(w, r)
}

func plain(w http.ResponseWriter, tr *reqTrack, status int) {
	tr.reply()
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

// fromQuery reads the dns= parameter of a GET. A parameter that decodes to
// more than 65535 bytes gets 413. (A request line so long that it passes
// 16 KiB never reaches this handler: net/http, HTTP/2 and HTTP/3 refuse it
// first with 431. The check is here for the case where the header cap is
// raised, and it is what the unit test drives.)
func (h *dohHandler) fromQuery(r *http.Request) ([]byte, int) {
	vals := r.URL.Query()["dns"]
	if len(vals) != 1 {
		return nil, http.StatusBadRequest
	}
	enc := vals[0]
	max := limits.MaxDNSMessage
	if h.set.MaxBodyBytes > 0 {
		max = h.set.MaxBodyBytes
	}
	if len(enc) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, http.StatusRequestEntityTooLarge
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, http.StatusBadRequest
	}
	if len(b) > max {
		return nil, http.StatusRequestEntityTooLarge
	}
	return b, 0
}

// fromBody reads the body of a POST. A POST with no Content-Length, or above
// the cap, gets 413 before a byte is read; the read itself runs through
// MaxBytesReader and the request deadline ServeHTTP set, so a slow body costs
// its own stream and nothing else.
func (h *dohHandler) fromBody(w http.ResponseWriter, r *http.Request) ([]byte, int) {
	max := int64(limits.MaxDNSMessage)
	if h.set.MaxBodyBytes > 0 {
		max = int64(h.set.MaxBodyBytes)
	}
	if r.ContentLength < 0 || r.ContentLength > max {
		return nil, http.StatusRequestEntityTooLarge
	}
	// RFC 8484 4.2.1 allows 415 for another media type. A browser can send a
	// cross-origin POST of another type with no preflight, which the proof rule
	// of 7.6 must never count, so the type is checked here as well as passed on.
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != dnsMessageType {
		return nil, http.StatusUnsupportedMediaType
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			return nil, http.StatusRequestEntityTooLarge
		case isTimeout(err):
			return nil, http.StatusRequestTimeout
		}
		return nil, http.StatusBadRequest
	}
	return b, 0
}

// addrString lets addrPort take the "ip:port" string net/http gives.
type addrString string

func (a addrString) Network() string { return "tcp" }
func (a addrString) String() string  { return string(a) }

// dohServer is DoH on TCP 443. net/http serves HTTP/1.1 and HTTP/2 on
// connections this loop has accepted, admitted through the connection limits
// and handshaken with their own deadline, so net/http meets only connections
// that are validated and carry a finished TLS handshake. HTTP/1.1 requests on
// one connection are served in order, as net/http does; HTTP/2 streams are
// capped at MaxStreams.
//
// The connections are spread over dohShards http.Servers, each with its own feed,
// and that is for the drain rule (SC 8a.6): net/http can end one connection
// gracefully only by shutting the Server that holds it down (HTTP/2 GOAWAY, an
// HTTP/1.1 connection closed when idle), never one connection alone. A drain shuts
// a shard down at a random moment of its window and puts a fresh shard in its
// place, so the connections close in dohShards steps over the window and the node
// goes on serving every new connection.
type dohServer struct {
	*core
	ln     net.Listener
	tlsCfg *tls.Config
	h      *dohHandler
	// nodeHeld is the bytes of replies all connections hold for peers that do not
	// read them (p4n-W6-r3-3).
	nodeHeld atomic.Int64
	wg       sync.WaitGroup

	mu      sync.Mutex
	shards  []*dohShard
	stopped bool
	rng     func(n int) int // the shard a connection goes to; replaced by a test
}

// dohShards is how many http.Servers carry the DoH connections: the steps a drain
// closes them in.
const dohShards = 32

// dohShard is one http.Server and the feed it takes connections from.
type dohShard struct {
	srv  *http.Server
	feed *feedListener
	// item is the shard's place in the drain; give reads it.
	item *drainItem
	// drained is set when the drain retires the shard: a connection of it that then
	// closes is reported as CloseDrain, not as net/http's own close (p4n-W8-r3-2).
	drained atomic.Bool
}

func newDoH(c *core, ln net.Listener, tlsCfg *tls.Config, verify VerifyHandler) *dohServer {
	s := &dohServer{core: c, ln: ln, tlsCfg: tlsCfg, h: &dohHandler{core: c, verify: verify}, rng: rand.IntN}
	for i := 0; i < dohShards; i++ {
		s.shards = append(s.shards, s.newShard())
	}
	return s
}

func (s *dohServer) newShard() *dohShard {
	h := s.h
	c := s.core
	sh := &dohShard{feed: newFeedListener(s.ln.Addr())}
	sh.srv = &http.Server{
		Handler:   h,
		TLSConfig: s.tlsCfg, // names h2, so Serve enables HTTP/2
		// net/http would answer OPTIONS * itself, reading its body with no deadline
		// and never reaching dohHandler: no BodyTimeout, no 405 (p4n-W6-r8-2).
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            c.set.ReadHeaderTimeout,
		IdleTimeout:                  c.set.IdleTimeout,
		MaxHeaderBytes:               c.set.MaxHeaderBytes,
		// A sanitised ErrorLog (R21): net/http writes request lines and peer
		// addresses to it, which must reach no sink.
		ErrorLog: log.New(io.Discard, "", 0),
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          c.set.MaxStreams,
			MaxReadFrameSize:              c.set.H2MaxFrame,
			MaxReceiveBufferPerStream:     c.set.H2StreamWindow,
			MaxReceiveBufferPerConnection: c.set.H2ConnWindow,
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if gc, ok := tc.NetConn().(*guardedConn); ok && gc.q != nil {
					ctx = context.WithValue(ctx, heldKey{}, gc.held)
					return context.WithValue(ctx, quietKey{}, gc.q)
				}
			}
			return ctx
		},
	}
	return sh
}

func (s *dohServer) start() {
	s.mu.Lock()
	for _, sh := range s.shards {
		s.serveShard(sh)
	}
	s.mu.Unlock()
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.acceptLoop() }()
}

// serveShard starts a shard's Serve loop and registers it with the drain rule. A
// replacement is registered like any shard, so a plan whose window is open schedules
// it: the clients that arrive during the window go to it as often as to an original
// shard (p4n-W8-r1-1). The caller holds s.mu.
func (s *dohServer) serveShard(sh *dohShard) {
	s.wg.Add(1)
	go func() { defer s.wg.Done(); _ = sh.srv.Serve(sh.feed) }()
	// A plan in force schedules the shard inside attach, and a moment of 0 can fire
	// before attach has returned the detach function: close waits for it.
	var detach func()
	ready := make(chan struct{})
	closeWith := func(wait time.Duration) {
		<-ready
		detach()
		s.retire(sh, wait)
	}
	sh.item = &drainItem{
		close:     func() { closeWith(s.set.HandlerTimeout) },
		closeWait: closeWith,
	}
	detach = s.dr.attach(sh.item)
	close(ready)
}

// retire puts a fresh shard in the place of sh and shuts sh down gracefully: the
// connections it holds get GOAWAY (HTTP/2) or are closed when idle (HTTP/1.1), the
// requests under way are answered first, for at most wait (never longer than the
// handler timeout), and the node goes on accepting new connections into the fresh
// shard.
func (s *dohServer) retire(sh *dohShard, wait time.Duration) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	for i, x := range s.shards {
		if x == sh {
			n := s.newShard()
			s.shards[i] = n
			s.serveShard(n)
			break
		}
	}
	s.mu.Unlock()
	if wait > s.set.HandlerTimeout {
		wait = s.set.HandlerTimeout
	}
	// Set before the shutdown so the connections it ends are counted as drained.
	sh.drained.Store(true)
	sh.shutdownWithin(wait)
}

// give hands a handshaken connection to one of the shards. A shard that was shut
// down between the choice and the hand-over refuses it, and the next try finds its
// replacement.
func (s *dohServer) give(tc net.Conn, on *atomic.Pointer[dohShard]) bool {
	for try := 0; try < 3; try++ {
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			return false
		}
		sh := s.pick()
		s.mu.Unlock()
		on.Store(sh)
		if sh.feed.put(tc) {
			return true
		}
	}
	return false
}

// pick chooses the shard for a new connection: a random one, but after a drain's
// window has ended, one that has no close still to come, so that a connection that
// opens after the window is never drained (p4n-W8-r3-3). When every shard has one (a
// plan that began at 340 s closes all of them within milliseconds) any shard will do.
// The caller holds s.mu.
func (s *dohServer) pick() *dohShard {
	n := len(s.shards)
	i := s.rng(n)
	for k := 0; k < n; k++ {
		if sh := s.shards[(i+k)%n]; !s.dr.pendingClose(sh.item) {
			return sh
		}
	}
	return s.shards[i]
}

func (s *dohServer) close() {
	_ = s.ln.Close()
	s.mu.Lock()
	s.stopped = true
	shards := append([]*dohShard(nil), s.shards...)
	s.mu.Unlock()
	for _, sh := range shards {
		_ = sh.srv.Close()
		sh.feed.close()
	}
	s.wg.Wait()
}

func (s *dohServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || isClosed(err) {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		src, ok := addrPort(c.RemoteAddr())
		if !ok {
			_ = c.Close()
			continue
		}
		slot, ok := s.cfg.Limits.Admit(DoH, src.Addr())
		if !ok {
			s.refused()
			_ = c.Close()
			continue
		}
		go s.handshake(c, slot)
	}
}

// handshake runs the TLS handshake under its own deadline, then hands the
// connection to net/http. The wrapper under the TLS layer releases the
// connection's claim when net/http closes it, and tells quiet about each
// write so the write-stall deadline runs only while nothing is unread or
// unanswered.
func (s *dohServer) handshake(raw net.Conn, slot *limits.Conn) {
	gc := &guardedConn{Conn: raw, release: slot.Release, held: newHeld(&s.nodeHeld)}
	var why atomic.Uint32
	var shard atomic.Pointer[dohShard]
	gc.onClose = func() {
		w := CloseReason(why.Load())
		switch {
		case w != 0:
		case s.ctx.Err() != nil:
			w = CloseShutdown
		case gc.peerGone.Load():
			w = ClosePeer
		default:
			w = CloseHTTP
			if sh := shard.Load(); sh != nil && sh.drained.Load() {
				w = CloseDrain
			}
		}
		s.closed(w)
	}
	tc := tls.Server(gc, s.tlsCfg)
	_ = raw.SetDeadline(time.Now().Add(s.set.HandshakeTimeout))
	if err := tc.Handshake(); err != nil {
		why.Store(uint32(CloseHandshake))
		_ = tc.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})
	// The write-stall tracking starts after the handshake. Its alarm closes the
	// connection: the write it ends may be a reply held in net/http's flow
	// control, with no socket write blocked for a deadline to cut.
	gc.q = newQuiet(0, s.set.WriteStall, nil, &timerAlarm{fire: func() {
		why.CompareAndSwap(0, uint32(CloseStall))
		_ = gc.Close()
	}})
	prev := gc.onClose
	gc.onClose = func() { gc.q.stop(); prev() }
	if !s.give(tc, &shard) {
		_ = tc.Close()
	}
}

// feedListener hands connections to http.Server.Serve.
type feedListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newFeedListener(a net.Addr) *feedListener {
	return &feedListener{addr: a, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (f *feedListener) put(c net.Conn) bool {
	select {
	case f.ch <- c:
		return true
	case <-f.done:
		return false
	}
}

func (f *feedListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.ch:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *feedListener) close()         { f.once.Do(func() { close(f.done) }) }
func (f *feedListener) Close() error   { f.close(); return nil }
func (f *feedListener) Addr() net.Addr { return f.addr }
