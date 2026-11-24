package resolve

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// The free path's own DoQ client (RFC 9250), one per slot of the pool.
//
// dnsproxy's DoQ upstream closes the whole QUIC connection after any error of one
// query, a read timeout included, and redials on the next call. For the free pool
// that is a flood amplifier: one name whose servers never answer would tear down
// the connection every other free miss rides on, and every such name would make
// the next query dial again, whatever rate the pool promises (p4n-W9-r1-1 and
// p4n-W9-r1-5). So, as for DoH (D66), the free pool has its own client: a query
// that times out ends its own stream and nothing else, and a slot dials again only
// when its connection is gone, no oftener than gap.

// doqCodeCancelled is DOQ_REQUEST_CANCELLED (RFC 9250 section 4.3.3).
const doqCodeCancelled = quic.StreamErrorCode(0x3)

// doqCodeNoError is DOQ_NO_ERROR, the code of a connection we close ourselves.
const doqCodeNoError = quic.ApplicationErrorCode(0x0)

// doqSlot is one QUIC connection with up to FreeStreamCap queries in flight on it,
// one stream each.
type doqSlot struct {
	addr    string // bootstrap address and port: the only thing it dials
	tc      *tls.Config
	timeout time.Duration
	gap     time.Duration
	// dialHook is for tests: it runs before each dial.
	dialHook func()

	mu       sync.Mutex
	conn     *quic.Conn
	dialing  chan struct{}
	lastDial time.Time
	inflight int
	closed   bool
}

func newDoQSlot(bootstrap netip.Addr, port string, tc *tls.Config, timeout, gap time.Duration) *doqSlot {
	tc = tc.Clone()
	tc.NextProtos = []string{"doq"}
	tc.MinVersion = tls.VersionTLS13
	return &doqSlot{addr: net.JoinHostPort(bootstrap.String(), port), tc: tc, timeout: timeout, gap: gap}
}

func (s *doqSlot) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
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

	c, err := s.connection(ctx)
	if err != nil {
		return nil, err
	}
	// The message ID is 0 on a QUIC stream (RFC 9250 section 4.2.1); the stream
	// itself pairs the reply with the query.
	q := req.Copy()
	q.Id = 0
	wire, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("resolve: free doq: %w", ErrBadQuery)
	}
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve: free doq: opening a stream: %w", err)
	}
	// An error below ends this stream only. The connection stays for the queries
	// that are still answering on it; a connection that is really gone shows in its
	// own context and is replaced by the next call, at the redial rate.
	fail := func(err error) (*dns.Msg, error) {
		st.CancelRead(doqCodeCancelled)
		st.CancelWrite(doqCodeCancelled)
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	framed := append(binary.BigEndian.AppendUint16(make([]byte, 0, len(wire)+2), uint16(len(wire))), wire...)
	if _, err := st.Write(framed); err != nil {
		return fail(fmt.Errorf("resolve: free doq: write: %w", err))
	}
	if err := st.Close(); err != nil { // FIN: no more data from us
		return fail(fmt.Errorf("resolve: free doq: write: %w", err))
	}
	var l [2]byte
	if _, err := io.ReadFull(st, l[:]); err != nil {
		return fail(fmt.Errorf("resolve: free doq: read: %w", err))
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 12 {
		return fail(ErrBadReply)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(st, buf); err != nil {
		return fail(fmt.Errorf("resolve: free doq: read: %w", err))
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf); err != nil {
		return fail(ErrBadReply)
	}
	resp.Id = req.Id
	return resp, nil
}

// connection returns the live connection, dialling one when there is none and the
// last dial is at least gap old. Queries that arrive while a dial is out wait for
// it; queries that find a failed dial inside the gap get errRedial at once.
func (s *doqSlot) connection(ctx context.Context) (*quic.Conn, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, errConnClosed
		}
		if c := s.conn; c != nil && c.Context().Err() == nil {
			s.mu.Unlock()
			return c, nil
		}
		if d := s.dialing; d != nil {
			s.mu.Unlock()
			select {
			case <-d:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("resolve: free doq: %w", ctx.Err())
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
		if s.dialHook != nil {
			s.dialHook()
		}
		dctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		c, err := quic.DialAddr(dctx, s.addr, s.tc, &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second})
		cancel()

		s.mu.Lock()
		if err == nil && !s.closed {
			s.conn = c
		} else if err == nil {
			_ = c.CloseWithError(doqCodeNoError, "")
			err = errConnClosed
		}
		s.dialing = nil
		close(d)
		s.mu.Unlock()
		if err != nil {
			if errors.Is(err, errConnClosed) {
				return nil, err
			}
			return nil, fmt.Errorf("resolve: free doq: dial: %w", err)
		}
	}
}

func (s *doqSlot) Close() error {
	s.mu.Lock()
	s.closed = true
	c := s.conn
	s.mu.Unlock()
	if c != nil {
		_ = c.CloseWithError(doqCodeNoError, "")
	}
	return nil
}
