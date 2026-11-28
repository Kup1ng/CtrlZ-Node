package limits

import (
	"strings"
	"sync/atomic"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const typeNS = 2 // dns.TypeNS, kept local so this package needs no DNS library

// Exemption is the name-form exemption of L13 (7.5): a query for a
// HostResolver name (by its form alone, whatever its rid), for NS at the apex,
// or for ns1 to ns4 goes past step 1 without being given to, or counted by,
// any query limit. The listener asks it after the question is read and before
// it consults the Set, so no list of exempt names lives inside a limiter
// (round 49 of the review of L13).
//
// The zones are swapped atomically by the caller when the node's zone
// changes; with none set nothing is exempt.
type Exemption struct {
	zones atomic.Pointer[[]names.Name]
}

// NewExemption returns an Exemption with no zone.
func NewExemption() *Exemption { return &Exemption{} }

// SetZones replaces the zones (one, or two during a domain change). The slice
// is copied.
func (x *Exemption) SetZones(z []names.Name) {
	c := append([]names.Name(nil), z...)
	x.zones.Store(&c)
}

// Exempt reports whether a query for qname (presentation form, as the DNS
// library gives it) of type qtype is exempt.
func (x *Exemption) Exempt(qname string, qtype uint16) bool {
	if x == nil {
		return false
	}
	zp := x.zones.Load()
	if zp == nil || len(*zp) == 0 {
		return false
	}
	// A name too long to be a DNS name cannot be in the zone; skip the parse.
	if len(qname) > 255 || strings.ContainsRune(qname, '\\') {
		return false
	}
	h := identity.ParseHost(qname, *zp)
	switch h.Kind {
	case identity.HostResolver:
		return true
	case identity.HostApex:
		return qtype == typeNS
	case identity.HostReserved:
		switch h.Name {
		case "ns1", "ns2", "ns3", "ns4":
			return true
		}
	}
	return false
}
