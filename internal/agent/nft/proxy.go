package nft

import (
	"errors"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
)

// The chains of the proxy role (p4b-proxy 5.5). They live in the same table as the
// P4 rules, so one apply and one read-back cover both.
//
// What they must never do is judge a packet from or to a DNS_IP listener (SC 8a.11
// L13). Each rule is keyed on a port that DNS_IP does not serve on PROXY_IP's
// address, or on the uid of a process that runs no such listener. And nothing uses
// connection state: an output chain accepts first every TCP packet that is not a
// first SYN, because no connection exists without one, so only new connections are
// judged and a flood cannot fill a state table through these rules.

// The loopback SOCKS inbounds of the Xray slots (7.4): two addresses, one for each
// slot, and the port range of the exits' inbounds.
const (
	SocksAddrA  = "127.0.0.20"
	SocksAddrB  = "127.0.0.21"
	SocksPortLo = 20000
	SocksPortHi = 20255
)

// Uids are the numeric uids the chains are keyed on. A name is resolved once by the
// caller: nftables would resolve it at load time, from a file the rules do not
// control, and a uid is the thing the kernel checks.
type Uids struct {
	Xray, Proxy, Block, DNS, Agent uint32
}

// ProxyParams are what the proxy chains depend on.
type ProxyParams struct {
	// ProxyIP is proxy_bind_ip, where the proxy listens on 80 and 443.
	ProxyIP netip.Addr
	Uids    Uids
	// Unbound is the identified Unbound's listener, the one place Xray may send TCP
	// on this host (7.4: tcp+local resolution).
	Unbound netip.AddrPort
	// DenyAddrs are the addresses Xray may never reach beyond the ranges of netclass:
	// every dns_ip, proxy_ip and bind address of the table's nodes. The node's own
	// DNS_IP, PROXY_IP and the panel addresses are added from the table's Params.
	DenyAddrs []netip.Addr
}

func (q *ProxyParams) validate(dnsIP netip.Addr) error {
	if !q.ProxyIP.IsValid() || q.ProxyIP.IsUnspecified() || q.ProxyIP.IsMulticast() {
		return errors.New("nft: no PROXY_IP")
	}
	if q.ProxyIP.Unmap() == dnsIP.Unmap() {
		// A chain on PROXY_IP's ports would then judge DNS_IP's own listeners (L13).
		return errors.New("nft: PROXY_IP is DNS_IP")
	}
	u := q.Uids
	if u.Xray == 0 || u.Proxy == 0 || u.Block == 0 || u.DNS == 0 || u.Agent == 0 {
		return errors.New("nft: a uid of the proxy chains is root or unset")
	}
	if u.Xray == u.Proxy || u.Xray == u.Block || u.Proxy == u.Block || u.Xray == u.DNS || u.Xray == u.Agent {
		return errors.New("nft: the proxy chains need distinct accounts")
	}
	if !q.Unbound.IsValid() {
		return errors.New("nft: no identified Unbound address")
	}
	return nil
}

type proxyView struct {
	PFam                           string
	ProxyIP                        netip.Addr
	Xray, Proxy, Block, DNS, Agent uint32
	UnboundIP                      netip.Addr
	UnboundPort                    uint16
	Deny4, Deny6                   []netip.Prefix
	A, B                           string
	Lo, Hi                         int
}

func (q *ProxyParams) view(p Params) *proxyView {
	v := &proxyView{
		PFam: "ip", ProxyIP: q.ProxyIP.Unmap(),
		Xray: q.Uids.Xray, Proxy: q.Uids.Proxy, Block: q.Uids.Block, DNS: q.Uids.DNS, Agent: q.Uids.Agent,
		UnboundIP: q.Unbound.Addr().Unmap(), UnboundPort: q.Unbound.Port(),
		A: SocksAddrA, B: SocksAddrB, Lo: SocksPortLo, Hi: SocksPortHi,
	}
	if v.ProxyIP.Is6() {
		v.PFam = "ip6"
	}
	// One list serves Unbound, finalRules and these chains (5.5): the non-public
	// ranges of netclass with every embedded form, then the addresses of the nodes
	// and of the panel in every form a delegation could name them.
	lists := [][]netip.Prefix{nets.NonPublic(), nets.ForAddr(p.DNSIP), nets.ForAddr(q.ProxyIP)}
	for _, a := range p.PanelAddrs {
		lists = append(lists, nets.ForAddr(a))
	}
	for _, a := range q.DenyAddrs {
		lists = append(lists, nets.ForAddr(a))
	}
	for _, pf := range nets.Merge(lists...) {
		if pf.Addr().Is4() {
			v.Deny4 = append(v.Deny4, pf)
		} else {
			v.Deny6 = append(v.Deny6, pf)
		}
	}
	return v
}

// proxyTmpl holds the two blocks the table template includes. The prefixes of a
// set never overlap (nets.Merge drops what another one covers), which nftables
// requires of an anonymous interval set.
const proxyTmpl = `
{{- define "proxyraw"}}
		{{.PFam}} daddr {{.ProxyIP}} tcp dport { 80, 443 } notrack
		{{.PFam}} saddr {{.ProxyIP}} tcp sport { 80, 443 } notrack
		ip daddr { {{.A}}, {{.B}} } tcp dport {{.Lo}}-{{.Hi}} notrack
		ip saddr { {{.A}}, {{.B}} } tcp sport {{.Lo}}-{{.Hi}} notrack
{{- end}}
{{- define "proxychains"}}
	chain xray_out {
		type filter hook output priority filter; policy accept;
		meta skuid {{.Xray}} tcp flags & (fin | syn | rst | ack) != syn accept
		meta skuid {{.Xray}} ip daddr {{.UnboundIP}} tcp dport {{.UnboundPort}} accept
		meta skuid {{.Xray}} fib daddr type { local, broadcast, anycast, multicast } drop
{{- if .Deny4}}
		meta skuid {{.Xray}} ip daddr { {{range $i, $p := .Deny4}}{{if $i}}, {{end}}{{$p}}{{end}} } drop
{{- end}}
{{- if .Deny6}}
		meta skuid {{.Xray}} ip6 daddr { {{range $i, $p := .Deny6}}{{if $i}}, {{end}}{{$p}}{{end}} } drop
{{- end}}
		meta skuid {{.Xray}} accept
	}
	chain proxy_out {
		type filter hook output priority filter; policy accept;
		meta skuid {{.Proxy}} tcp flags & (fin | syn | rst | ack) != syn accept
		meta skuid {{.Proxy}} ip daddr { {{.A}}, {{.B}} } tcp dport {{.Lo}}-{{.Hi}} accept
		meta skuid {{.Proxy}} drop
	}
	chain block_out {
		type filter hook output priority filter; policy accept;
		meta skuid {{.Block}} drop
	}
	chain socks_guard {
		type filter hook output priority filter; policy accept;
		tcp flags & (fin | syn | rst | ack) != syn accept
		ip daddr { {{.A}}, {{.B}} } meta l4proto tcp meta skuid { {{.Proxy}}, {{.DNS}}, {{.Agent}} } accept
		ip daddr { {{.A}}, {{.B}} } meta l4proto tcp drop
	}
{{- end}}
`
