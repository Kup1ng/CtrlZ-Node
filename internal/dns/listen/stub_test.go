package listen

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Stub is a Handler for tests. It lives in a test file on purpose: it answers every
// name with the same address, and must never be linkable into the release
// binary (p4n-W6-r1-12). It answers A with 192.0.2.1 and AAAA with 2001:db8::1 for any
// name, and acts on the first label of the name so a test can ask for a
// behaviour:
//
//	panic-*   panics
//	error-*   returns an empty reply (the listener answers SERVFAIL)
//	slow-*    waits SlowFor, or until the context ends
//	big-*     answers with enough TXT data to need truncation on UDP
//	drop-*    the silent drop of Plain DNS
//	status-*  HTTP 403 with no DNS message (DoH and DoH3)
//	badpack-* a reply that panics when it is packed (a typed nil RR in Answer)
//
// It records every Request it is given.
type Stub struct {
	SlowFor time.Duration
	// Gate, when set, replaces the SlowFor timer: slow-* waits until it is
	// closed. A test that must count what a server accepted or refused uses it
	// instead of a delay, which a loaded machine can outrun (p4n-W6-r6-2).
	Gate chan struct{}

	mu   sync.Mutex
	reqs []Request

	cur, peak atomic.Int64
}

// NewStub returns a Stub that waits 300 ms for slow-* names.
func NewStub() *Stub { return &Stub{SlowFor: 300 * time.Millisecond} }

// Requests returns a copy of the requests seen so far.
func (s *Stub) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Reset forgets the requests seen.
func (s *Stub) Reset() {
	s.mu.Lock()
	s.reqs = nil
	s.mu.Unlock()
}

// ServeDNS implements Handler.
func (s *Stub) ServeDNS(ctx context.Context, req *Request) Reply {
	s.mu.Lock()
	s.reqs = append(s.reqs, *req)
	s.mu.Unlock()
	n := s.cur.Add(1)
	defer s.cur.Add(-1)
	for p := s.peak.Load(); n > p && !s.peak.CompareAndSwap(p, n); p = s.peak.Load() {
	}

	if len(req.Msg.Question) != 1 {
		return Reply{Msg: rcodeReply(req.Msg, dns.RcodeFormatError)}
	}
	qn := req.Msg.Question[0]
	first := strings.ToLower(qn.Name)
	switch {
	case strings.HasPrefix(first, "panic-"):
		panic("stub: asked to panic")
	case strings.HasPrefix(first, "error-"):
		return Reply{}
	case strings.HasPrefix(first, "slow-"):
		var wait <-chan time.Time
		if s.Gate == nil {
			wait = time.After(s.SlowFor)
		}
		select {
		case <-wait:
		case <-s.Gate:
		case <-ctx.Done():
		}
	case strings.HasPrefix(first, "drop-"):
		return Reply{Drop: true}
	case strings.HasPrefix(first, "statusbad-"):
		return Reply{Status: 1000} // http.ResponseWriter.WriteHeader panics on it
	case strings.HasPrefix(first, "statusone-"):
		return Reply{Status: 103} // a 1xx is no final answer
	case strings.HasPrefix(first, "status-"):
		return Reply{Status: 403}
	case strings.HasPrefix(first, "badpack-"):
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		m.Answer = []dns.RR{(*dns.A)(nil)} // a typed nil: Pack dereferences it
		return Reply{Msg: m}
	}
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Authoritative = true
	hdr := dns.RR_Header{Name: qn.Name, Class: dns.ClassINET, Ttl: 60}
	switch qn.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, 1)})
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")})
	case dns.TypeTXT:
		hdr.Rrtype = dns.TypeTXT
		n := 1
		if strings.HasPrefix(first, "big-") {
			n = 40
		}
		for i := 0; i < n; i++ {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{strings.Repeat("x", 200)}})
		}
	}
	return Reply{Msg: m}
}

// Peak is the most queries the stub has had in hand at once.
func (s *Stub) Peak() int { return int(s.peak.Load()) }
