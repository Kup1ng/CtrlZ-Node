package listen

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// udpServer is Plain DNS on UDP 53. A fixed pool of goroutines reads
// datagrams and runs step 1 inline (the drop rules, the exemption, the
// limits, the cookie), which is cheap; the query path runs on a goroutine of
// its own per query, so a slow answer never holds a reader.
type udpServer struct {
	*core
	conn *net.UDPConn
	wg   sync.WaitGroup
}

func newUDP(c *core, conn *net.UDPConn) *udpServer {
	return &udpServer{core: c, conn: conn}
}

func (s *udpServer) start() {
	n := s.set.UDPReaders
	if n <= 0 {
		n = 4
	}
	for i := 0; i < n; i++ {
		s.wg.Add(1)
		go s.readLoop()
	}
}

func (s *udpServer) close() {
	_ = s.conn.Close()
	s.wg.Wait()
}

// reflectorPorts are source ports of services that answer anything, or that
// are used to reflect traffic. A datagram from one of them is dropped unless
// it is a well-formed query that L13 names (SC 5.2 step 1). Port 53 is not in
// the list: some resolvers still query from it, and the QR=1 rule already
// stops a loop of two DNS servers' replies.
func reflectorPort(p uint16) bool {
	switch p {
	case 0, 7, 13, 17, 19, 37, 123, 1900, 11211:
		return true
	}
	return false
}

func (s *udpServer) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, limits.MaxDNSMessage)
	errs := 0
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil || isClosed(err) {
				return
			}
			// Windows reports an ICMP port-unreachable for an earlier reply as a
			// read error; skip it, and slow down only if the errors do not stop.
			if errs++; errs > 100 {
				time.Sleep(10 * time.Millisecond)
			}
			continue
		}
		errs = 0
		s.packet(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
	}
}

// packet is step 1 for one datagram.
func (s *udpServer) packet(b []byte, from netip.AddrPort) {
	// Shorter than a header, or QR=1: never answered, so two servers or a
	// server and an echo service cannot keep a loop of replies going.
	if len(b) < 12 || b[2]&0x80 != 0 {
		s.dropped()
		return
	}
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		// FORMERR only for a header parsed with QR=0, and not to a reflector
		// port, which could be anything. The reply is the 12-byte header, never
		// longer than the query.
		if reflectorPort(from.Port()) {
			s.dropped()
			return
		}
		// A reply to junk is still a packet sent to the source, which may be a
		// spoofed victim: it goes through the same per-address and per-prefix
		// limits as a query, and is dropped when they stop it, so the node is no
		// unlimited packet reflector (p4n-W6-r1-9).
		if s.gate(false, from.Addr()) != limits.AnswerNone {
			s.dropped()
			return
		}
		var h [12]byte
		copy(h[:2], b[:2])
		h[2] = 0x80 | b[2]&0x79 // QR, the opcode and RD of the query
		h[3] = byte(dns.RcodeFormatError)
		_, _ = s.conn.WriteToUDPAddrPort(h[:], from)
		return
	}
	src := from.Addr()
	exempt := s.exempt(m)
	if !exempt && reflectorPort(from.Port()) {
		s.dropped()
		return
	}
	ck, validated := s.parseCookie(m, src)
	// Whatever a limit answers, a query it stopped is not served (p4n-W6-r2-9):
	// TC=1 sends the client to TCP, where no limit keyed on a source meets it, and
	// any other answer (an entry with no source in its key may be REFUSED) is sent
	// as it is.
	switch s.gate(exempt, src) {
	case limits.AnswerNone:
	case limits.AnswerTC:
		s.send(Truncated(m), m, from, ck)
		return
	default:
		s.send(Refused(m), m, from, ck)
		return
	}
	if !s.enter(exempt) {
		s.dropped()
		return
	}
	go func() {
		defer s.exit()
		rep := s.call(&Request{Msg: m, Transport: UDP, Source: from, Validated: validated})
		if rep.Drop {
			return
		}
		if rep.Msg == nil { // a Status means nothing on Plain DNS
			rep.Msg = ServFail(m)
		}
		s.send(rep.Msg, m, from, ck)
	}()
}

// send packs a reply for a UDP client: the cookie added, and the reply cut to
// the size the client announced (512 with no EDNS, at most UDPPayload).
func (s *udpServer) send(reply, q *dns.Msg, to netip.AddrPort, ck cookieOpt) {
	size := 512
	if opt := q.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
		size = int(opt.UDPSize())
	}
	if s.set.UDPPayload > 0 && size > s.set.UDPPayload {
		size = s.set.UDPPayload
	}
	b := s.guardPack(q, func() []byte {
		s.answerCookie(reply, ck, to.Addr())
		reply.Compress = true
		b, err := reply.Pack()
		if err == nil && len(b) > size {
			reply.Truncate(size)
			b, err = reply.Pack()
		}
		if err != nil || len(b) > size {
			return servFailWire(q)
		}
		return b
	})
	if b == nil {
		return
	}
	_, _ = s.conn.WriteToUDPAddrPort(b, to)
}
