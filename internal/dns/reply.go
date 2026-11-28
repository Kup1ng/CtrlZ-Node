package dns

import (
	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
)

// maxUDPPayload is the most a UDP answer may carry (SC 7, UDP size): no answer is
// fragmented.
const maxUDPPayload = 1232

// newReply starts an answer to q: the question echoed as it was sent, QR set,
// RD copied, RA as given. A client that sent EDNS gets an OPT back.
func newReply(q *dns.Msg, ra bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = ra
	m.Compress = true
	if opt := q.IsEdns0(); opt != nil {
		m.SetEdns0(maxUDPPayload, opt.Do())
	}
	return m
}

func rcodeMsg(q *dns.Msg, rcode int) *dns.Msg {
	m := newReply(q, false)
	m.Rcode = rcode
	return m
}

// rrOf builds a record for the answer or authority section from evaluator
// parts. A record that does not parse is skipped, never sent half made.
func rrOf(n names.Name, typ uint16, ttl uint32, data []byte) dns.RR {
	rr, err := policy.RRToDNS(sharedpolicy.RR{Name: n, Type: typ, Class: sharedpolicy.ClassIN, TTL: ttl, Data: data})
	if err != nil {
		return nil
	}
	return rr
}

// fromAnswer turns what the evaluator decided into a message. Owner names that
// are the qname are written as the client sent them, so a client that mixes
// the case of its question (0x20) finds it in the answer; names on a CNAME
// chain keep the folded form they have in the evaluator.
func fromAnswer(q *dns.Msg, qn names.Name, a sharedpolicy.Answer) *dns.Msg {
	m := newReply(q, true)
	m.Rcode = int(a.RCode)
	m.AuthenticatedData = a.AD
	asked := q.Question[0].Name
	conv := func(in []sharedpolicy.RR) []dns.RR {
		var out []dns.RR
		for i := range in {
			rr, err := policy.RRToDNS(in[i])
			if err != nil {
				continue
			}
			if in[i].Name.Equal(&qn) {
				rr.Header().Name = asked
			}
			out = append(out, rr)
		}
		return out
	}
	m.Answer = conv(a.Answer)
	m.Ns = conv(a.Authority)
	// RFC 7871 7.2.2: a reply carries ECS only when the query did, and it echoes
	// the client's own family, prefix and address; only the scope is ours. A
	// profile in ECS Auto or Custom mode sends ECS upstream whether or not the
	// client sent any, and that must not show up in a reply to a plain stub
	// (p4n-W7-r4-3).
	if a.ECS != nil {
		if opt := m.IsEdns0(); opt != nil {
			if cs := clientSubnet(q); cs != nil {
				opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: cs.Family, SourceNetmask: cs.SourceNetmask, SourceScope: a.ECS.Scope, Address: cs.Address})
			}
		}
	}
	return m
}

// clientSubnet is the ECS option the client's query held, or nil.
func clientSubnet(q *dns.Msg) *dns.EDNS0_SUBNET {
	if opt := q.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if cs, ok := o.(*dns.EDNS0_SUBNET); ok {
				return cs
			}
		}
	}
	return nil
}

// fitUDP applies the UDP size rule of SC 7: an answer larger than the limit is
// sent as TC=1 with no records. The limit is the client's EDNS payload size,
// raised to 512 and capped at 1232, and 512 without EDNS. The listener adds the
// server cookie after this, so a query that carries a cookie leaves room for it.
func fitUDP(q, m *dns.Msg) *dns.Msg {
	limit := 512
	if opt := q.IsEdns0(); opt != nil && int(opt.UDPSize()) > limit {
		limit = int(opt.UDPSize())
	}
	if limit > maxUDPPayload {
		limit = maxUDPPayload
	}
	if opt := q.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_COOKIE); ok {
				limit -= 32
				break
			}
		}
	}
	b, err := m.Pack()
	if err != nil || len(b) > limit {
		return listen.Truncated(q)
	}
	return m
}
