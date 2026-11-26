package dns

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// The zone answerer: SC 8a.3 over zone.Target and zone.NameServers, built as
// real DNS messages. Answers are authoritative (AA=1) and echo the question; a
// REFUSED answer is not authoritative.

// zoneSOATTL is the TTL and MINIMUM of the zone's SOA and of every negative
// answer of the zone (8a.3).
const zoneSOATTL = 30

// zoneFor finds which zone of the settings a name is in, or at.
func (s *Settings) zoneFor(n names.Name) (names.Name, bool) {
	for _, z := range s.zones {
		if n.Labels() >= z.Labels() && string(n.SuffixWire(z.Labels())) == string(z.Wire()) {
			return z, true
		}
	}
	return names.Name{}, false
}

func soaRR(zn names.Name, ttl uint32) dns.RR {
	z := NameText(zn)
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: dns.Fqdn(z), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:  "ns1." + dns.Fqdn(z), Mbox: "hostmaster." + dns.Fqdn(z),
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: zoneSOATTL,
	}
}

func authMsg(q *dns.Msg) *dns.Msg {
	m := newReply(q, false)
	m.Authoritative = true
	return m
}

func nodataMsg(q *dns.Msg, zn names.Name) *dns.Msg {
	m := authMsg(q)
	m.Ns = []dns.RR{soaRR(zn, zoneSOATTL)}
	return m
}

// addrAnswer answers an address query with a, when its family matches the
// question's type; false when it does not (the caller gives NODATA).
func addrAnswer(q *dns.Msg, ttl uint32, a netip.Addr) (*dns.Msg, bool) {
	qs := q.Question[0]
	a = a.Unmap()
	hdr := dns.RR_Header{Name: qs.Name, Class: dns.ClassINET, Ttl: ttl}
	switch {
	case a.Is4() && qs.Qtype == dns.TypeA:
		hdr.Rrtype = dns.TypeA
		m := authMsg(q)
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: a.AsSlice()}}
		return m, true
	case a.Is6() && qs.Qtype == dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		m := authMsg(q)
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: a.AsSlice()}}
		return m, true
	}
	return nil, false
}

// zoneView is the table in use for answers. Only the agent decides what that is:
// until it has called SetZoneState there is no table in use, and the names that
// need one are REFUSED (SC 8a.5, p4-nodes 7.2). image.Zone() carries no withdrawal
// flags, so answering from it would advertise a primary the hub has withdrawn.
// A ZoneState with a nil Table is the same state, said by the agent.
func (h *Handler) zoneView() (*zone.Table, zone.Local, func(string) []string) {
	if zs := h.zs.Load(); zs != nil {
		return zs.Table, zs.Local, zs.Acme
	}
	return nil, zone.Local{}, nil
}

// answerZone answers a name of the zone that step 3 answers: HostResolver,
// HostMalformed, the apex and the reserved names but myip. handled is false for
// a name this step does not answer (verify names, myip, out of zone).
func (h *Handler) answerZone(q *dns.Msg, qn names.Name, set *Settings, sv *Serving, host identity.Host) (*dns.Msg, bool) {
	zn, ok := set.zoneFor(qn)
	if !ok {
		return nil, false
	}
	qs := q.Question[0]
	table, local, acme := h.zoneView()
	refused := func() (*dns.Msg, bool) { return rcodeMsg(q, dns.RcodeRefused), true }

	switch host.Kind {
	case identity.HostApex:
		switch qs.Qtype {
		case dns.TypeSOA:
			m := authMsg(q)
			m.Answer = []dns.RR{soaRR(zn, zoneSOATTL)}
			return m, true
		case dns.TypeNS:
			if table == nil {
				return refused()
			}
			m := authMsg(q)
			for _, n := range zone.NameServers(table) {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: qs.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: zone.NSTTL},
					Ns:  fmt.Sprintf("ns%d.%s.", n.Slot, NameText(zn)),
				})
			}
			return m, true
		}
		return nodataMsg(q, zn), true

	case identity.HostMalformed:
		m := authMsg(q)
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{soaRR(zn, zoneSOATTL)}
		return m, true

	case identity.HostResolver:
		if table == nil {
			return refused()
		}
		var pair zone.PairID // zero for an unknown rid: Target uses the global pair (R29)
		if ep, ok := sv.img.ByResolverID(host.RID); ok && len(ep.Record.PairId) == 16 {
			copy(pair[:], ep.Record.PairId)
		}
		n, ok := zone.Target(table, pair, local)
		if !ok {
			return refused()
		}
		if m, ok := addrAnswer(q, zone.HostTTL, n.DNSIP); ok {
			return m, true
		}
		return nodataMsg(q, zn), true

	case identity.HostReserved:
		switch {
		case host.Name == "verify":
			return nodataMsg(q, zn), true
		case host.Name == "_acme-challenge" || host.Name == "_acme-challenge.verify":
			if qs.Qtype == dns.TypeTXT && acme != nil {
				if vals := acme(strings.TrimSuffix(strings.ToLower(qs.Name), ".")); len(vals) > 0 {
					m := authMsg(q)
					for _, v := range vals {
						m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: qs.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{v}})
					}
					return m, true
				}
			}
			return nodataMsg(q, zn), true
		case strings.HasPrefix(host.Name, "ns"):
			if table == nil {
				return refused()
			}
			for _, n := range zone.NameServers(table) {
				if host.Name == fmt.Sprintf("ns%d", n.Slot) {
					if m, ok := addrAnswer(q, zone.NSTTL, n.DNSIP); ok {
						return m, true
					}
				}
			}
			return nodataMsg(q, zn), true
		}
		// myip waits for identity (5.2 step 3).
		return nil, false
	}
	return nil, false
}
