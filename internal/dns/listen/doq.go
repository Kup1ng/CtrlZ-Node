package listen

import (
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// doqServer is DNS over QUIC (RFC 9250) on UDP 853. Each query is one
// bidirectional stream: a two-byte length, the message, and a FIN; the reply
// goes back on the same stream. The stream cap is the QUIC stream limit of the
// connection (100). 0-RTT is off.
type doqServer struct {
	*quicBase
}

func newDoQ(b *quicBase) *doqServer { return &doqServer{b} }

func (s *doqServer) start() {
	s.wg.Add(1)
	go s.acceptLoop(s.serveConn)
}

func (s *doqServer) serveConn(qc *qconn, acceptSrc netip.AddrPort, _ *limits.Conn) {
	q := qc.newQuiet(s.set)
	defer q.stop()
	defer s.attachDrain(qc)()
	sni := qc.c.ConnectionState().TLS.ServerName
	for {
		str, err := qc.c.AcceptStream(s.ctx)
		if err != nil {
			return // the peer closed, or we did
		}
		// A stream whose query is not whole yet is unread: the connection is not
		// quiet, so neither the idle nor the stall deadline can run.
		id := q.begin()
		if qc.refusing.Load() {
			// The drain has begun on this connection: the query is not taken, and the
			// client sends it on a new connection. The begin comes first so a stream
			// accepted as the flag is set is either refused here or held and finished.
			q.abort(id)
			str.CancelRead(quic.StreamErrorCode(doqRequestCanceled))
			str.CancelWrite(quic.StreamErrorCode(doqRequestCanceled))
			continue
		}
		// The source is read per stream: quic-go follows a client that migrates
		// once the new path is validated, and a connection lives as long as it
		// keeps asking. The slot of the connection limits stays on the address
		// it was admitted for (p4n-W6-r4-5).
		src := acceptSrc
		if a, ok := addrPort(qc.c.RemoteAddr()); ok {
			src = a
		}
		go s.stream(qc, q, id, str, src, sni)
	}
}

func (s *doqServer) stream(qc *qconn, q *quiet, id uint64, str *quic.Stream, src netip.AddrPort, sni string) {
	m, why := s.readQuery(str)
	switch why {
	case readOK:
	case readCancel: // this stream only, the connection goes on
		q.abort(id)
		str.CancelRead(quic.StreamErrorCode(doqRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(doqRequestCanceled))
		return
	default: // a malformed message: a protocol error ends the connection
		q.abort(id)
		qc.fail(CloseProtocol, doqProtocolError)
		return
	}
	if m.Response {
		q.abort(id)
		str.CancelRead(quic.StreamErrorCode(doqRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(doqRequestCanceled))
		return
	}
	exempt := s.exempt(m)
	stop := s.gate(exempt, src.Addr())
	var rep Reply
	switch {
	case stop != limits.AnswerNone:
		// REFUSED on its own stream: the stream ends, the connection stays, and
		// the stream's slot is free again (L13 Open).
		rep = Reply{Msg: Refused(m)}
	case !s.enter(exempt):
		rep = Reply{Msg: ServFail(m)}
	default:
		rep = s.call(&Request{Msg: m, Transport: DoQ, Source: src, Validated: true, SNI: sni})
		s.exit()
	}
	if rep.Msg == nil {
		rep.Msg = ServFail(m)
	}
	frame := s.packFrame(rep.Msg, m, nil)
	if frame == nil {
		q.abort(id)
		str.CancelWrite(quic.StreamErrorCode(doqRequestCanceled))
		return
	}
	// A peer that does not take its replies is not allowed to make the node hold
	// them: past the connection or listener bound the reply is a SERVFAIL.
	frame = qc.held.hold(frame, s.set.MaxQueuedBytes, s.set.MaxQueuedBytesNode,
		func() []byte { return s.packFrame(ServFail(m), m, nil) })
	defer qc.held.release(len(frame))
	q.reply(id)
	_, err := str.Write(frame)
	if err == nil {
		err = str.Close() // the FIN
	}
	q.writeEnd(id)
	if err != nil {
		str.CancelWrite(quic.StreamErrorCode(doqRequestCanceled))
	}
}

type readResult uint8

const (
	readOK readResult = iota
	readCancel
	readBad
)

// readQuery reads the whole query of a stream, with BodyTimeout for it to
// arrive. A stream that stalls or is reset by the peer is cancelled alone. A
// length below 12, a message that does not parse, or data after the message is
// a protocol error (RFC 9250 4.3.3), which the caller turns into a closed
// connection: not a limit of step 1 (D52).
func (s *doqServer) readQuery(str *quic.Stream) (*dns.Msg, readResult) {
	_ = str.SetReadDeadline(time.Now().Add(s.set.BodyTimeout))
	var lb [2]byte
	if _, err := io.ReadFull(str, lb[:]); err != nil {
		return nil, classify(err)
	}
	n := int(lb[0])<<8 | int(lb[1])
	if n < 12 {
		return nil, readBad
	}
	buf, err := readBody(str, n)
	if err != nil {
		return nil, classify(err)
	}
	// The client must FIN after its query. Anything after the message is an
	// error; a missing FIN is waited for only as long as the body deadline.
	var one [1]byte
	if k, err := str.Read(one[:]); k > 0 {
		return nil, readBad
	} else if !errors.Is(err, io.EOF) {
		return nil, classify(err)
	}
	_ = str.SetReadDeadline(time.Time{})
	m := new(dns.Msg)
	if m.Unpack(buf) != nil {
		return nil, readBad
	}
	return m, readOK
}

// classify maps a stream read error: a deadline or a reset is the stream's
// own trouble; an early end of the stream is a malformed message.
func classify(err error) readResult {
	var se *quic.StreamError
	if isTimeout(err) || errors.As(err, &se) {
		return readCancel
	}
	var ae *quic.ApplicationError
	var ie *quic.IdleTimeoutError
	if errors.As(err, &ae) || errors.As(err, &ie) || errors.Is(err, quic.ErrServerClosed) {
		return readCancel // the connection is already gone
	}
	return readBad
}
