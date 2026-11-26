package cache

import (
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
)

// Gate is the Sanity Gate (SC 11, 5.2 step 8): an answer for a public name that
// points at an injected block-page address (10.10.34.0/24), an RFC 1918 or
// CGNAT address or loopback is not a real answer, and neither the cache nor a
// client gets it. Some Iranian networks inject such answers for filtered names,
// and a resolver that believes one would store it for every tenant.
//
// The class is read from every A and AAAA record and from the address hints of
// HTTPS and SVCB records, because a client may connect to a hint without ever
// asking for the A record (the Rebind rule reads them for the same reason).
//
// Allow holds the per-node allow entries of SC 11: prefixes whose addresses
// pass. NodeConfig carries none yet, so production builds the Gate with an empty
// list and a name that really points inside a private range needs an entry the
// hub does not send today (recorded in the notes of this package's task).
type Gate struct {
	Allow []netip.Prefix
}

// Verdict is the result of Check. It carries the class and never the address,
// so a counter or an alert built from it holds no address (SC 5.2a, No trace).
type Verdict struct {
	OK    bool
	Class netclass.Class
}

// privateSuffixes are the names that are not public: single-label names and the
// special-use and conventional intranet suffixes. A private address behind one
// is what the name is for. A name outside them that points into a private range
// is the split-horizon case SC 11 hands to an allow entry.
var privateSuffixes = []string{
	"local", "localhost", "lan", "home", "internal", "intranet", "corp", "private",
	"localdomain", "home.arpa", "in-addr.arpa", "ip6.arpa", "invalid",
}

func publicName(n names.Name) bool {
	if n.Labels() < 2 {
		return false
	}
	for _, s := range privateSuffixes {
		sn, err := names.FromString(s)
		if err != nil {
			continue
		}
		if n.Labels() >= sn.Labels() && string(n.SuffixWire(sn.Labels())) == string(sn.Wire()) {
			return false
		}
	}
	return true
}

func (g *Gate) allowed(a netip.Addr) bool {
	for _, p := range g.Allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Check judges an answer for the question named qname. Injected answers are
// rejected for every name; the other classes only for a public name.
func (g *Gate) Check(qname names.Name, a *policy.TrueAnswer) Verdict {
	public := publicName(qname)
	for _, sec := range [][]policy.RR{a.Answer, a.Authority} {
		for i := range sec {
			for _, addr := range rrAddrs(&sec[i]) {
				c := netclass.ClassOf(addr)
				bad := c == netclass.Injected || (public && (c == netclass.Private || c == netclass.CGNAT || c == netclass.Loopback))
				if bad && !g.allowed(addr) {
					return Verdict{Class: c}
				}
			}
		}
	}
	return Verdict{OK: true}
}

func rrAddrs(r *policy.RR) []netip.Addr {
	if a, ok := r.Addr(); ok {
		return []netip.Addr{a}
	}
	if r.Type == policy.TypeHTTPS || r.Type == policy.TypeSVCB {
		return svcHints(r.Data)
	}
	return nil
}

// svcHints reads the ipv4hint (key 4) and ipv6hint (key 6) parameters of an
// SVCB or HTTPS record. Anything malformed ends the scan; the hints read before
// that still count, which is the rule the Rebind scan follows (SC 6).
func svcHints(d []byte) []netip.Addr {
	if len(d) < 3 {
		return nil
	}
	off := 2
	for off < len(d) { // the target name: labels, or a two-byte pointer which ends it
		l := int(d[off])
		switch {
		case l == 0:
			off++
			goto params
		case l&0xC0 == 0xC0:
			off += 2
			goto params
		case l&0xC0 != 0:
			return nil
		}
		off += 1 + l
	}
	return nil
params:
	var out []netip.Addr
	for off+4 <= len(d) {
		key := int(d[off])<<8 | int(d[off+1])
		n := int(d[off+2])<<8 | int(d[off+3])
		off += 4
		if off+n > len(d) {
			return out
		}
		v := d[off : off+n]
		off += n
		switch {
		case key == 4 && n%4 == 0:
			for i := 0; i+4 <= n; i += 4 {
				out = append(out, netip.AddrFrom4([4]byte(v[i:i+4])))
			}
		case key == 6 && n%16 == 0:
			for i := 0; i+16 <= n; i += 16 {
				out = append(out, netip.AddrFrom16([16]byte(v[i:i+16])))
			}
		}
	}
	return out
}
