package peer

import (
	"net/netip"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// node is one entry of the applied PairTable as the peer code needs it.
type node struct {
	id   zone.NodeID
	addr netip.Addr // dns_ip: the address a peer is seen from (4.5)
	spki [32]byte
	// live is false for a revoked node, whose spki_sha256 is empty in the table of the
	// applied log entry (8a.4 Versions). Such a node is never trusted, never sent to and
	// never accepted from, whatever certificate it still holds.
	live bool
}

// view is the applied entry's PairTable cut to what 4.5 decides on. It is built once
// for each table the agent applies (the pointer is the version), so every check of a
// forward or a connection reads a table that cannot change under it.
//
// The table is the one of the applied log entry, never a push (SC 8a.7): a push moves
// withdrawal flags only and must not be able to make a revoked node trusted.
type view struct {
	pt   *policyv1.PairTable
	self zone.NodeID
	// byAddr holds the address of the live pair peer alone: it is what the accept check
	// admits before TLS.
	byAddr map[netip.Addr]*node
	byID   map[zone.NodeID]*node
	// peer is the pair peer of this node, nil when it has none. It can be a revoked
	// node: live says so.
	peer *node
	// pairs maps a pair id to its two members; global is the pair that an Endpoint with
	// no pair_id of its own belongs to.
	pairs  map[string][2]zone.NodeID
	global string
}

func newView(pt *policyv1.PairTable, self zone.NodeID) *view {
	v := &view{pt: pt, self: self, byAddr: map[netip.Addr]*node{}, byID: map[zone.NodeID]*node{}, pairs: map[string][2]zone.NodeID{}}
	if pt == nil {
		return v
	}
	for _, n := range pt.Nodes {
		if len(n.NodeId) != 16 {
			continue
		}
		e := &node{live: len(n.SpkiSha256) == 32}
		copy(e.id[:], n.NodeId)
		copy(e.spki[:], n.SpkiSha256)
		if ip, ok := netip.AddrFromSlice(n.DnsIp); ok {
			e.addr = ip.Unmap()
		}
		v.byID[e.id] = e
	}
	v.global = string(pt.GlobalPairId)
	for _, p := range pt.Pairs {
		if len(p.Primary) != 16 || len(p.Fallback) != 16 {
			// A pair with no fallback has no peer for either member (4.4).
			continue
		}
		var m [2]zone.NodeID
		copy(m[0][:], p.Primary)
		copy(m[1][:], p.Fallback)
		v.pairs[string(p.PairId)] = m
		if v.peer != nil {
			continue
		}
		switch self {
		case m[0]:
			v.peer = v.byID[m[1]]
		case m[1]:
			v.peer = v.byID[m[0]]
		}
	}
	// The listener admits the address of the pair peer and no other (4.5): a node of
	// another pair has nothing to say to us, and if it could finish a connection it
	// would hold one of the slots. Our own address is never a peer's.
	if p := v.peerLive(); p != nil && p.id != self && p.addr.IsValid() {
		v.byAddr[p.addr] = p
	}
	return v
}

// trusts says whether id is a live node of the table whose key is spki.
func (v *view) trusts(id zone.NodeID, spki [32]byte) bool {
	n := v.byID[id]
	return n != nil && n.live && n.spki == spki
}

// peerLive is the pair peer when it is a node that may be spoken to, else nil.
func (v *view) peerLive() *node {
	if v.peer != nil && v.peer.live {
		return v.peer
	}
	return nil
}

// inOurPair says whether the pair that an Endpoint belongs to (its pair_id, or the
// global pair when that is empty) is the pair of this node and its peer. An Endpoint
// of another pair never travels between us, so one tenant's grant cannot be placed on
// a node that does not serve it.
func (v *view) inOurPair(pairID []byte) bool {
	if v.peer == nil {
		return false
	}
	key := string(pairID)
	if len(pairID) == 0 {
		key = v.global
	}
	m, ok := v.pairs[key]
	if !ok {
		return false
	}
	return (m[0] == v.self && m[1] == v.peer.id) || (m[1] == v.self && m[0] == v.peer.id)
}
