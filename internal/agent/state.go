package agent

import (
	"net/netip"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/probe"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/telem"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// zones are the live zones of the latest NodeConfig, nil when there is none.
func (a *Agent) zones() []string {
	if c := a.nodeCfg.Load(); c != nil {
		return c.Zones
	}
	return nil
}

func addrOf(b []byte) (netip.Addr, bool) {
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// nodeAddrs are the addresses no resolver may be sent to and no upstream may
// be (SC 5.2a): this node's bind and advertised addresses, from agent.conf and
// the NodeConfig, and the dns_ip of every node of the applied PairTable.
func (a *Agent) nodeAddrs() []netip.Addr {
	return nodeAddrList(a.cfg.Conf, a.nodeCfg.Load(), a.push.Member())
}

// nodeAddrList is nodeAddrs for the inputs it is made of, so that the start before
// the agent exists (serve_pending.go) builds the same list from the same files.
func nodeAddrList(ac conf.Agent, c *hubv1.NodeConfig, m *policyv1.PairTable) []netip.Addr {
	var out []netip.Addr
	add := func(ip netip.Addr) {
		if ip.IsValid() {
			out = append(out, ip.Unmap())
		}
	}
	add(ac.DNSBindIP)
	add(ac.DNSAdvertisedIP)
	if c != nil {
		for _, b := range [][]byte{c.DnsBindIp, c.DnsAdvertisedIp} {
			if ip, ok := addrOf(b); ok {
				add(ip)
			}
		}
	}
	if m != nil {
		for _, n := range m.Nodes {
			if ip, ok := addrOf(n.DnsIp); ok {
				add(ip)
			}
		}
	}
	return out
}

// doNotQuery is the do-not-query-address list of both Unbound processes' node
// part (the non-public ranges are added by the renderer).
func (a *Agent) doNotQuery() []netip.Prefix { return doNotQueryOf(a.nodeAddrs()) }

func doNotQueryOf(addrs []netip.Addr) []netip.Prefix {
	var lists [][]netip.Prefix
	for _, ip := range addrs {
		lists = append(lists, nets.ForAddr(ip))
	}
	return nets.Merge(lists...)
}

// dnsIP is the DNS_IP the Plain listeners are bound to: the NodeConfig's bind
// address, else agent.conf's.
func (a *Agent) dnsIP() netip.Addr {
	if c := a.nodeCfg.Load(); c != nil {
		if ip, ok := addrOf(c.DnsBindIp); ok {
			return ip
		}
	}
	return a.cfg.Conf.DNSBindIP
}

// syncProbeTargets points the prober at every other node of the applied
// membership. A revoked node (empty SPKI) is not probed: it is out of every
// pair and never serves a client.
func (a *Agent) syncProbeTargets() {
	m := a.push.Member()
	var ts []probe.Target
	if m != nil {
		for _, n := range m.Nodes {
			if len(n.NodeId) != 16 || len(n.SpkiSha256) == 0 {
				continue
			}
			var id zone.NodeID
			copy(id[:], n.NodeId)
			if id == a.self {
				continue
			}
			if ip, ok := addrOf(n.DnsIp); ok {
				ts = append(ts, probe.Target{ID: id, Addr: ip})
			}
		}
	}
	a.probe.SetTargets(ts)
}

// refreshAppliedViews copies the few facts of the applied state that a
// Heartbeat or dns needs into atomics. It takes the Applier's lock, so only the
// log worker and start call it: never a Heartbeat (L11, round 42).
func (a *Agent) refreshAppliedViews() {
	a.app.Inspect(func(ap *store.Applied) {
		a.quarantined.Store(uint32(len(ap.Q.Quarantined)))
		if ap.FreeDNS != nil {
			a.freeValue.Store(proto.Clone(ap.FreeDNS).(*policyv1.FreeDns))
		} else {
			a.freeValue.Store(nil)
		}
	})
	a.facts.Applied(a.app.AppliedSeq())
}

// recordLookup is telem.Records over the applied state.
type recordLookup struct{ a *Agent }

// Lookup reads the clients and client_cap of the Endpoints of one activity flush
// under the Applier's lock, once.
func (r *recordLookup) Lookup(eps [][16]byte) map[[16]byte]telem.EndpointInfo {
	out := make(map[[16]byte]telem.EndpointInfo, len(eps))
	r.a.app.Inspect(func(ap *store.Applied) {
		for _, id := range eps {
			rec := ap.Q.Endpoints[id]
			if rec == nil {
				continue
			}
			out[id] = infoOf(rec)
		}
	})
	return out
}

func infoOf(rec *policyv1.EndpointRecord) telem.EndpointInfo {
	info := telem.EndpointInfo{Cap: rec.ClientCap, Clients: make(map[[16]byte]struct{}, len(rec.Clients))}
	for _, c := range rec.Clients {
		var h [16]byte
		copy(h[:], c.ClientHash)
		info.Clients[h] = struct{}{}
	}
	return info
}

var _ = identity.ClientHash
