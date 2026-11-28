// Package nets lists the address ranges that Unbound must never accept or send
// to (SC 11, 5.2a: private-address and do-not-query-address), derived from the
// classes of shared/netclass.
//
// netclass answers "which class is this address" and exports no list, and it
// must not be edited from the node (shared/ is canonical in the Panel
// repository). The list here is therefore a copy of its table, kept honest by
// the test in this package, which compares it with netclass.ClassOf over every
// IPv4 /24, every boundary of every listed prefix and a sample of IPv6. A change
// of netclass that this list does not follow fails that test.
//
// One deliberate difference: netclass gives an IPv6 address the class of the
// IPv4 address it embeds, and for Teredo (2001::/32) the client IPv4 address is
// stored bit-inverted in the last 32 bits with 64 free bits before it, which no
// prefix can describe. The whole of 2001::/32 is therefore listed. It is a
// superset: no host legitimately answers from Teredo space in 2026, and the cost
// of the superset is that a Teredo address with two public embedded addresses is
// refused by Unbound, which the node's own Sanity Gate (netclass, exact) would
// have let through. A test states exactly this: everything netclass calls
// non-public is covered, and the only addresses covered beyond that are in
// 2001::/32.
package nets

import (
	"net/netip"
	"sort"
)

func m(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// v4 are the non-public IPv4 ranges of netclass, as listed there.
func v4() []netip.Prefix {
	return []netip.Prefix{
		m("10.10.34.0/24"), m("10.0.0.0/8"), m("172.16.0.0/12"), m("192.168.0.0/16"),
		m("127.0.0.0/8"), m("169.254.0.0/16"), m("100.64.0.0/10"), m("224.0.0.0/4"),
		m("0.0.0.0/8"), m("192.0.0.0/24"), m("192.0.2.0/24"), m("192.88.99.0/24"),
		m("198.18.0.0/15"), m("198.51.100.0/24"), m("203.0.113.0/24"), m("240.0.0.0/4"),
	}
}

// v6 are the non-public native IPv6 ranges of netclass.
func v6() []netip.Prefix {
	return []netip.Prefix{
		m("::1/128"), m("::/128"), m("fe80::/10"), m("fc00::/7"), m("fec0::/10"),
		m("ff00::/8"), m("2001:db8::/32"), m("100::/64"),
	}
}

// embed places an IPv4 prefix inside an IPv6 base: base bits, then the IPv4
// bytes at byte offset off, giving a prefix of baseBits + p bits.
func embed(base netip.Addr, baseBits, off int, p netip.Prefix) netip.Prefix {
	b := base.As16()
	a4 := p.Addr().As4()
	copy(b[off:off+4], a4[:])
	return netip.PrefixFrom(netip.AddrFrom16(b), baseBits+p.Bits()).Masked()
}

// Embeddings returns the IPv6 prefixes that stand for an IPv4 prefix in the
// forms of SC 11: IPv4-mapped, IPv4-compatible, NAT64, 6to4 and the Teredo
// server position. The Teredo client position is covered by listing 2001::/32
// whole (package comment).
func Embeddings(p netip.Prefix) []netip.Prefix {
	return []netip.Prefix{
		embed(netip.MustParseAddr("::ffff:0:0"), 96, 12, p),
		embed(netip.MustParseAddr("::"), 96, 12, p),
		embed(netip.MustParseAddr("64:ff9b::"), 96, 12, p),
		embed(netip.MustParseAddr("2002::"), 16, 2, p),
		embed(netip.MustParseAddr("2001::"), 32, 4, p),
	}
}

// NonPublic is every prefix that Unbound's private-address must hold: all the
// non-public ranges of netclass, in IPv4 and IPv6, with every embedded form,
// sorted and without duplicates.
func NonPublic() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range v4() {
		out = append(out, p)
		out = append(out, Embeddings(p)...)
	}
	out = append(out, v6()...)
	out = append(out, m("2001::/32")) // Teredo, whole: see the package comment
	return norm(out)
}

// ForAddr is the prefixes that name one node address in every form a
// delegation could use to reach it: the address itself, and when it is IPv4 its
// embeddings as single hosts (do-not-query-address, SC 5.2a). An IPv6 address
// that itself embeds an IPv4 one is the caller's business: the admin routes
// refuse those for a node address (SC 5.2a, Loops).
func ForAddr(a netip.Addr) []netip.Prefix {
	a = a.Unmap()
	if !a.IsValid() {
		return nil
	}
	if a.Is6() {
		return []netip.Prefix{netip.PrefixFrom(a, 128)}
	}
	p := netip.PrefixFrom(a, 32)
	out := []netip.Prefix{p}
	out = append(out, Embeddings(p)...)
	return norm(out)
}

// norm sorts by address then length and drops duplicates and prefixes already
// inside a listed one, so the list Unbound reads is the smallest that covers
// the same space.
func norm(in []netip.Prefix) []netip.Prefix {
	for i := range in {
		in[i] = in[i].Masked()
	}
	sort.Slice(in, func(i, j int) bool {
		if c := in[i].Addr().Compare(in[j].Addr()); c != 0 {
			return c < 0
		}
		return in[i].Bits() < in[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range in {
		covered := false
		for _, q := range out {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

// Merge joins lists and normalises the result.
func Merge(lists ...[]netip.Prefix) []netip.Prefix {
	var all []netip.Prefix
	for _, l := range lists {
		all = append(all, l...)
	}
	return norm(all)
}

// Contains reports whether any prefix of list holds a.
func Contains(list []netip.Prefix, a netip.Addr) bool {
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CoversAddr reports whether a is one of the node addresses in any of the forms
// a delegation could use to reach it (SC 5.2a, Loops): after Unmap, with the
// embedded-IPv4 IPv6 forms compared as the IPv4 address itself.
func CoversAddr(nodes []netip.Addr, a netip.Addr) bool {
	a = a.Unmap()
	for _, n := range nodes {
		if Contains(ForAddr(n), a) {
			return true
		}
	}
	return false
}
