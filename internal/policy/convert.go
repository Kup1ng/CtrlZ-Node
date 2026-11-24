package policy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
)

// The evaluator works on its own record type (a wire name, a type, a TTL and
// uncompressed RDATA) so it needs no DNS library. These are the two doors
// between it and the messages the node reads and writes.

// NameFromDNS turns the presentation name of a question into the evaluator's
// name through the wire form, so escapes (\DDD, \.) mean what they say. The
// result is case-folded.
func NameFromDNS(s string) (names.Name, error) {
	var buf [256]byte
	n, err := dns.PackDomainName(dns.Fqdn(s), buf[:], 0, nil, false)
	if err != nil {
		return names.Name{}, err
	}
	return names.FromCanonicalWire(buf[:n])
}

// NameToDNS is the presentation form of a name, with the trailing dot a DNS
// library wants.
func NameToDNS(n names.Name) string {
	s, _, err := dns.UnpackDomainName(n.Wire(), 0)
	if err != nil {
		return "."
	}
	return s
}

// RRFromDNS converts a record. The record is packed without compression, so
// the RDATA it keeps has no pointer into a message that is about to be dropped.
func RRFromDNS(rr dns.RR) (sharedpolicy.RR, bool) {
	if rr == nil || rr.Header() == nil {
		return sharedpolicy.RR{}, false
	}
	buf := make([]byte, dns.Len(rr)+16)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return sharedpolicy.RR{}, false
	}
	buf = buf[:off]
	// owner name, then type, class, ttl, rdlength, rdata
	_, nameEnd, err := dns.UnpackDomainName(buf, 0)
	if err != nil || nameEnd+10 > len(buf) {
		return sharedpolicy.RR{}, false
	}
	name, err := names.FromCanonicalWire(buf[:nameEnd])
	if err != nil {
		return sharedpolicy.RR{}, false
	}
	rdlen := int(binary.BigEndian.Uint16(buf[nameEnd+8:]))
	if nameEnd+10+rdlen != len(buf) {
		return sharedpolicy.RR{}, false
	}
	return sharedpolicy.RR{
		Name:  name,
		Type:  binary.BigEndian.Uint16(buf[nameEnd:]),
		Class: binary.BigEndian.Uint16(buf[nameEnd+2:]),
		TTL:   binary.BigEndian.Uint32(buf[nameEnd+4:]),
		Data:  append([]byte(nil), buf[nameEnd+10:]...),
	}, true
}

// RRToDNS converts a record back. A record whose RDATA does not parse for its
// type is refused, never sent.
func RRToDNS(r sharedpolicy.RR) (dns.RR, error) {
	wire := make([]byte, 0, r.Name.Len()+10+len(r.Data))
	wire = append(wire, r.Name.Wire()...)
	wire = binary.BigEndian.AppendUint16(wire, r.Type)
	wire = binary.BigEndian.AppendUint16(wire, r.Class)
	wire = binary.BigEndian.AppendUint32(wire, r.TTL)
	if len(r.Data) > 65535 {
		return nil, errors.New("policy: rdata too long")
	}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(r.Data)))
	wire = append(wire, r.Data...)
	rr, _, err := dns.UnpackRR(wire, 0)
	if err == nil && sameRData(rr, r.Data) {
		return rr, nil
	}
	// RDATA that does not parse for its type, or does not pack back to the same
	// bytes, goes out as it is, as an opaque record (RFC 3597): the evaluator
	// passes upstream data through and never repairs it, and a typed record that
	// repacked differently would change what the client is told.
	name, _, nerr := dns.UnpackDomainName(r.Name.Wire(), 0)
	if nerr != nil {
		return nil, nerr
	}
	return &dns.RFC3597{
		Hdr:   dns.RR_Header{Name: name, Rrtype: r.Type, Class: r.Class, Ttl: r.TTL},
		Rdata: hex.EncodeToString(r.Data),
	}, nil
}

// sameRData reports whether a parsed record packs back, uncompressed, to the RDATA
// it was parsed from.
func sameRData(rr dns.RR, want []byte) bool {
	buf := make([]byte, dns.Len(rr)+16)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return false
	}
	// header: owner name, type, class, ttl, rdlength
	_, nameEnd, err := dns.UnpackDomainName(buf, 0)
	if err != nil || nameEnd+10 > off {
		return false
	}
	return bytes.Equal(buf[nameEnd+10:off], want)
}

// Extended DNS Error codes that say a DNSSEC chain did not validate (RFC 8914).
// Unbound answers such a query with SERVFAIL and one of them when CD is clear.
func edeIsBogus(code uint16) bool {
	switch code {
	case 6, 7, 8, 9, 10, 11, 12, 13: // bogus, expired, not yet valid, DNSKEY or DS missing, RRSIG or NSEC missing, ...
		return true
	}
	return false
}

// TrueAnswerFromMsg turns an upstream reply for the question qname into the
// evaluator's TrueAnswer. Only NOERROR and NXDOMAIN are answers; any other
// code, SERVFAIL included, is a failure (SC 5.12). Records whose owner is not
// on the CNAME chain from the qname are dropped: an upstream that is wrong
// or hostile must not be able to add a record for another name to what a client
// is told about this one. The OPT record and the additional section are not
// carried over.
func TrueAnswerFromMsg(qname names.Name, resp *dns.Msg) *sharedpolicy.TrueAnswer {
	a := &sharedpolicy.TrueAnswer{RCode: uint16(resp.Rcode), Chain: []names.Name{qname}}
	bogus := false
	if opt := resp.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			switch v := o.(type) {
			case *dns.EDNS0_EDE:
				if edeIsBogus(v.InfoCode) {
					bogus = true
				}
			case *dns.EDNS0_SUBNET:
				a.ECSScope = v.SourceScope
			}
		}
	}
	switch {
	case bogus:
		a.Validation = sharedpolicy.Bogus
	case resp.AuthenticatedData && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError):
		// RFC 6840: AD also covers a validated denial of existence.
		a.Validation = sharedpolicy.Secure
	default:
		a.Validation = sharedpolicy.Insecure
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		a.Failed, a.RCode = true, sharedpolicy.RCodeServFail
		return a
	}

	// The CNAME chain, in order, from the qname. A loop or a branch ends it.
	cname := map[string]names.Name{}
	var conv []sharedpolicy.RR
	for _, rr := range resp.Answer {
		r, ok := RRFromDNS(rr)
		if !ok {
			continue
		}
		conv = append(conv, r)
		if r.Type == sharedpolicy.TypeCNAME {
			if t, err := names.FromCanonicalWire(r.Data); err == nil {
				if _, dup := cname[string(r.Name.Wire())]; !dup {
					cname[string(r.Name.Wire())] = t
				}
			}
		}
	}
	onChain := map[string]bool{string(qname.Wire()): true}
	cur := qname
	for i := 0; i < sharedpolicy.MaxCNAMEHops; i++ {
		next, ok := cname[string(cur.Wire())]
		if !ok || onChain[string(next.Wire())] {
			break
		}
		a.Chain = append(a.Chain, next)
		onChain[string(next.Wire())] = true
		cur = next
	}
	// A record on the chain is kept. A DNAME above the chain is kept only when
	// it explains a CNAME step of the chain, and an RRSIG above it only when it
	// signs such a DNAME: an upstream must not be able to hang a DNAME on a
	// whole ancestor zone (the TLD, say) by putting it into a reply for one name.
	keptDNAME := map[string]bool{}
	for _, r := range conv {
		if onChain[string(r.Name.Wire())] {
			a.Answer = append(a.Answer, r)
			continue
		}
		if r.Type == typeDNAME && explainsChainStep(r, a.Chain) {
			keptDNAME[string(r.Name.Wire())] = true
			a.Answer = append(a.Answer, r)
		}
	}
	for _, r := range conv {
		if r.Type == sharedpolicy.TypeRRSIG && !onChain[string(r.Name.Wire())] &&
			len(r.Data) >= 2 && binary.BigEndian.Uint16(r.Data) == typeDNAME && keptDNAME[string(r.Name.Wire())] {
			a.Answer = append(a.Answer, r)
		}
	}
	a.Authority = filterAuthority(resp.Ns, a.Chain)
	return a
}

const typeDNAME = 39

// filterAuthority applies to the authority section the rule the answer section
// has: an upstream must not tell a client about another name through it. A
// record is kept when its owner is a name of the chain or an ancestor of one
// (the SOA, NS and DS a negative answer or a referral legitimately carries). The
// denial records of the zone (NSEC, NSEC3 and the signatures over them) sit at
// other owners inside the zone, so they are kept when their owner is at or below
// the owner of a kept SOA: a DNSSEC client still gets its proof, while an NS or
// SOA for an unrelated zone is dropped (p4n-W7-r8-2). Owners are compared label
// by label for the same reason as in explainsChainStep.
func filterAuthority(ns []dns.RR, chain []names.Name) []sharedpolicy.RR {
	var conv []sharedpolicy.RR
	for _, rr := range ns {
		if r, ok := RRFromDNS(rr); ok {
			conv = append(conv, r)
		}
	}
	var kept []sharedpolicy.RR
	var zones []names.Name // owners of the kept SOA records
	var rest []sharedpolicy.RR
	for _, r := range conv {
		if ancestorOfAny(&r.Name, chain) {
			kept = append(kept, r)
			if r.Type == sharedpolicy.TypeSOA {
				zones = append(zones, r.Name)
			}
			continue
		}
		rest = append(rest, r)
	}
	for _, r := range rest {
		if !isDenial(r) {
			continue
		}
		for i := range zones {
			if r.Name.Labels() >= zones[i].Labels() &&
				string(r.Name.SuffixWire(zones[i].Labels())) == string(zones[i].Wire()) {
				kept = append(kept, r)
				break
			}
		}
	}
	return kept
}

// isDenial reports whether r is an NSEC or NSEC3 record, or an RRSIG over one.
func isDenial(r sharedpolicy.RR) bool {
	switch r.Type {
	case sharedpolicy.TypeNSEC, sharedpolicy.TypeNSEC3:
		return true
	case sharedpolicy.TypeRRSIG:
		if len(r.Data) < 2 {
			return false
		}
		c := binary.BigEndian.Uint16(r.Data)
		return c == sharedpolicy.TypeNSEC || c == sharedpolicy.TypeNSEC3
	}
	return false
}

// ancestorOfAny reports whether o is a chain name or an ancestor of one.
func ancestorOfAny(o *names.Name, chain []names.Name) bool {
	for i := range chain {
		c := &chain[i]
		if o.Labels() <= c.Labels() && string(c.SuffixWire(o.Labels())) == string(o.Wire()) {
			return true
		}
	}
	return false
}

// explainsChainStep reports whether a DNAME is the substitution behind one CNAME
// step of the chain (RFC 6672): some chain name sits strictly below the DNAME's
// owner and the next chain name is that name with the owner replaced by the
// target. Anything else is a DNAME the question did not need.
func explainsChainStep(d sharedpolicy.RR, chain []names.Name) bool {
	target, err := names.FromCanonicalWire(d.Data)
	if err != nil {
		return false
	}
	// Compared label by label: a label may hold any byte, so a byte suffix of the
	// wire form can start inside a label (the owner com. is \x03com\x00, and the
	// single label abc\003com ends in the same bytes) (p4n-W7-r7-5).
	own := &d.Name
	for i := 0; i+1 < len(chain); i++ {
		cur, next := &chain[i], &chain[i+1]
		k := cur.Labels() - own.Labels()
		if k <= 0 || next.Labels()-target.Labels() != k {
			continue
		}
		if string(cur.SuffixWire(own.Labels())) != string(own.Wire()) ||
			string(next.SuffixWire(target.Labels())) != string(target.Wire()) {
			continue
		}
		same := true
		for j := 0; j < k && same; j++ {
			same = bytes.Equal(cur.Label(j), next.Label(j))
		}
		if same {
			return true
		}
	}
	return false
}
