// Package nft renders the agent's one nftables table and applies it through
// `nft -f` (p4-nodes 7.3, SC 5.2a Connection tracking, 8a.11 L13 clause 1,
// 7.10).
//
// What the table holds, and what it never holds:
//   - notrack for UDP and TCP to port 53 of DNS_IP and their replies, and for the
//     UDP queries the free Unbound sends from its outgoing port range and their
//     replies, so neither a spoofed flood to port 53 nor the fan-out of a free miss
//     adds an entry to the connection-tracking table;
//   - NTP (UDP 123) and NTS-KE (TCP 4460) out only to the panel host (7.10);
//   - never a rate, a meter, a quota, a connection count, a set that grows with
//     traffic or a per-source match on packets to DNS_IP. L13 clause 1 says the
//     product installs no such rule, and a test of this package fails the text
//     of any rendering that holds one.
//
// The text is rendered here and handed to nft by an interface, so the tests read
// the exact rules and a Windows development machine needs no nftables.
package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"text/template"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
)

// Table is the name of the agent's table. Nothing else in the node touches it.
const Table = "ctrlz_agent"

// Params are what the table depends on.
type Params struct {
	// DNSIP is DNS_IP, the address of the Plain DNS listeners.
	DNSIP netip.Addr
	// PanelAddrs are the addresses of the panel host: the only place NTP and NTS-KE
	// may go. The caller resolves the host (4.2 gives it as an address or a name).
	PanelAddrs []netip.Addr
	// FreePortLo and FreePortHi are the free Unbound's outgoing-port-permit range.
	FreePortLo, FreePortHi int
}

// Validate refuses what cannot be rendered.
func (p Params) Validate() error {
	if !p.DNSIP.IsValid() || p.DNSIP.IsUnspecified() || p.DNSIP.IsMulticast() {
		return errors.New("nft: no DNS_IP")
	}
	if len(p.PanelAddrs) == 0 {
		return errors.New("nft: no panel address for NTP and NTS-KE")
	}
	for _, a := range p.PanelAddrs {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			return errors.New("nft: bad panel address")
		}
	}
	if p.FreePortLo < 1024 || p.FreePortHi < p.FreePortLo || p.FreePortHi > 65535 {
		return errors.New("nft: bad free port range")
	}
	return nil
}

type view struct {
	Fam            string // ip or ip6, for DNS_IP
	DNSIP          netip.Addr
	Lo, Hi         int
	Panel4, Panel6 []netip.Addr
	Table          string
}

// The table is deleted and recreated in one transaction (add, delete, define),
// so applying it twice, or over an older rendering, never leaves two copies and
// never leaves a moment with no table.
const tmpl = `add table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {
	chain raw_in {
		type filter hook prerouting priority raw; policy accept;
		{{.Fam}} daddr {{.DNSIP}} udp dport 53 notrack
		{{.Fam}} daddr {{.DNSIP}} tcp dport 53 notrack
		udp sport 53 udp dport {{.Lo}}-{{.Hi}} notrack
	}
	chain raw_out {
		type filter hook output priority raw; policy accept;
		{{.Fam}} saddr {{.DNSIP}} udp sport 53 notrack
		{{.Fam}} saddr {{.DNSIP}} tcp sport 53 notrack
		udp sport {{.Lo}}-{{.Hi}} udp dport 53 notrack
	}
	chain time_out {
		type filter hook output priority filter; policy accept;
{{- if .Panel4}}
		udp dport 123 ip daddr != { {{range $i, $a := .Panel4}}{{if $i}}, {{end}}{{$a}}{{end}} } drop
		tcp dport 4460 ip daddr != { {{range $i, $a := .Panel4}}{{if $i}}, {{end}}{{$a}}{{end}} } drop
{{- else}}
		udp dport 123 meta nfproto ipv4 drop
		tcp dport 4460 meta nfproto ipv4 drop
{{- end}}
{{- if .Panel6}}
		udp dport 123 ip6 daddr != { {{range $i, $a := .Panel6}}{{if $i}}, {{end}}{{$a}}{{end}} } drop
		tcp dport 4460 ip6 daddr != { {{range $i, $a := .Panel6}}{{if $i}}, {{end}}{{$a}}{{end}} } drop
{{- else}}
		udp dport 123 meta nfproto ipv6 drop
		tcp dport 4460 meta nfproto ipv6 drop
{{- end}}
	}
}
`

var parsed = template.Must(template.New("nft").Parse(tmpl))

// Render returns the script for nft -f.
func Render(p Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	v := view{Fam: "ip", DNSIP: p.DNSIP.Unmap(), Lo: p.FreePortLo, Hi: p.FreePortHi, Table: Table}
	if v.DNSIP.Is6() {
		v.Fam = "ip6"
	}
	for _, a := range p.PanelAddrs {
		a = a.Unmap()
		if a.Is4() {
			v.Panel4 = append(v.Panel4, a)
		} else {
			v.Panel6 = append(v.Panel6, a)
		}
	}
	var b bytes.Buffer
	if err := parsed.Execute(&b, v); err != nil {
		return "", fmt.Errorf("nft: render: %w", err)
	}
	return b.String(), nil
}

// Apply renders the table, has nft check it (-c) and then applies it. A script
// nft refuses changes nothing.
func Apply(ctx context.Context, r sysx.Runner, p Params) error {
	s, err := Render(p)
	if err != nil {
		return err
	}
	if _, err := r.Run(ctx, []byte(s), "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft: check: %w", err)
	}
	if _, err := r.Run(ctx, []byte(s), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft: apply: %w", err)
	}
	return nil
}
