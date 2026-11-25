// Package unbound renders, checks and supervises the node's two Unbound
// processes, the identified one and the free one (p4-nodes 7.3 and 7.7, SC 11
// and 5.2a, Plan T-026, T-031, T-559, T-561).
//
// Both configurations come from one template and differ only in the keys that
// SC 5.2a and T-559 name for the free resolver, so the local root, the DNSSEC
// trust anchor, private-address and the refusal of the injected range hold for
// both and one test covers both. The agent writes the files; it refuses to
// start either process when the version is under the floor, when a pinned
// setting of an existing file is not what the template gives, when the
// private-address list is not the one derived from netclass, or when the free
// process's port range overlaps another socket's.
package unbound

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"text/template"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
)

// Kind is which of the two processes.
type Kind uint8

const (
	// Identified serves the identified query path and the resolve check.
	Identified Kind = iota + 1
	// Free serves free misses only (SC 5.2a, Free resolver).
	Free
)

func (k Kind) String() string {
	if k == Free {
		return "free"
	}
	return "identified"
}

// Fixed numbers. Each is provisional (D31) except where the contract gives it.
const (
	// UnwantedThresholdIdentified is SC 11's value: a threshold that a flood of
	// spoofed replies can trip is acceptable only where replies pass connection
	// tracking, which is the identified process only.
	UnwantedThresholdIdentified = 10_000_000
	// RateLimitFree and RateLimitDomainFree are the per-zone limits of queries
	// toward authoritative servers (SC 5.2a), for every zone and for com, net, org.
	RateLimitFree       = 200
	RateLimitDomainFree = 50
	// FreeThreads and FreeQueriesPerThread give the free request list. free_inflight
	// (256, SC 5.2a) may not exceed it.
	FreeThreads          = 2
	FreeQueriesPerThread = 512
	// FreeInflightCap is the node's miss cap for free queries.
	FreeInflightCap = 256
	// MaxSentCount, DiscardTimeoutMS and WaitLimit are Unbound's own work bounds,
	// pinned at the values of the version floor's documentation so that a drift of
	// a package default cannot change what one free miss costs.
	MaxSentCount     = 32
	DiscardTimeoutMS = 1900
	WaitLimit        = 1000
	WaitLimitCookie  = 10000
)

// FreeRequestList is the free Unbound's request list size, the upper bound of
// the miss cap.
func FreeRequestList() int { return FreeThreads * FreeQueriesPerThread }

// Params is what differs between hosts and processes. DefaultParams fills the
// production values.
type Params struct {
	Kind Kind
	// Listen is the loopback address and port the process answers on.
	Listen netip.AddrPort
	// Dir is the working directory, Pid and Control are under RunDir.
	Dir, RunDir string
	// User is the unprivileged user the process drops to.
	User string
	// TrustAnchor and RootHints come from the bundle's dns-root-data package.
	TrustAnchor, RootHints string
	Threads                int
	IPv6                   bool
	// PortLo and PortHi are the outgoing-port-permit range. They must not overlap
	// the other Unbound's range or the host's ephemeral range (SC 5.2a).
	PortLo, PortHi int
	// OutgoingInterface, valid only for the free process, is the T-561 option: an
	// address in another /24 that is not DNS_IP, PROXY_IP or the identified
	// Unbound's, so authoritative servers that limit per address see two sources.
	OutgoingInterface netip.Addr
	// DoNotQuery are the node addresses (with their embedded forms) that no
	// delegation may send the resolver to: every node of the applied PairTable
	// and the node's own bind and advertised addresses (SC 5.2a).
	DoNotQuery []netip.Prefix
}

// DefaultParams are the production values of a kind.
func DefaultParams(k Kind) Params {
	p := Params{
		Kind:        k,
		Dir:         "/var/lib/ctrlz-unbound",
		User:        "ctrlz-unbound",
		TrustAnchor: "/usr/share/dns/root.key",
		RootHints:   "/usr/share/dns/root.hints",
		Threads:     2,
		IPv6:        true,
	}
	if k == Free {
		p.Listen = netip.MustParseAddrPort("127.0.0.11:5300")
		p.RunDir = "/run/ctrlz-unbound-free"
		p.User = "ctrlz-unbound-free"
		p.Dir = "/var/lib/ctrlz-unbound-free"
		p.Threads = FreeThreads
		p.PortLo, p.PortHi = FreePortLo, FreePortHi
	} else {
		p.Listen = netip.MustParseAddrPort("127.0.0.10:5300")
		p.RunDir = "/run/ctrlz-unbound"
		p.PortLo, p.PortHi = IdentifiedPortLo, IdentifiedPortHi
	}
	return p
}

// The outgoing port ranges. The host's ephemeral range must end below
// FreePortLo (the install script sets net.ipv4.ip_local_port_range to 32768
// 39999), so the notrack rule that accepts the free Unbound's replies without
// state reaches no other socket (SC 5.2a, Connection tracking).
const (
	FreePortLo       = 40000
	FreePortHi       = 40999
	IdentifiedPortLo = 41000
	IdentifiedPortHi = 41999
)

var errText = errors.New("unbound: a setting holds a character that does not belong in a config value")

func clean(s string) bool { return !strings.ContainsAny(s, "\"\n\r\x00#") }

// Validate refuses a Params that cannot be rendered safely.
func (p Params) Validate() error {
	if p.Kind != Identified && p.Kind != Free {
		return errors.New("unbound: unknown kind")
	}
	if !p.Listen.IsValid() || !p.Listen.Addr().IsLoopback() || p.Listen.Port() == 0 {
		return errors.New("unbound: the listen address must be a loopback address with a port")
	}
	for _, s := range []string{p.Dir, p.RunDir, p.User, p.TrustAnchor, p.RootHints} {
		if s == "" || !clean(s) {
			return errText
		}
	}
	if p.Threads < 1 || p.Threads > 64 {
		return errors.New("unbound: threads out of range")
	}
	if p.PortLo < 1024 || p.PortHi > 65535 || p.PortHi < p.PortLo {
		return errors.New("unbound: bad outgoing port range")
	}
	if p.OutgoingInterface.IsValid() && p.Kind != Free {
		return errors.New("unbound: outgoing-interface is an option of the free process only")
	}
	return nil
}

// tmpl is the one template of both processes. The branches on .Free are exactly
// the keys SC 5.2a and T-559 list for the free process; everything outside them
// is the same text.
const tmpl = `# Written by ctrlz-agent. Do not edit: the agent refuses to start this
# process when a pinned setting differs, and rewrites the file on change.
server:
    verbosity: 0
    use-syslog: no
    logfile: "/dev/null"
    log-queries: no
    log-replies: no
    log-servfail: no
    log-local-actions: no
    log-tag-queryreply: no
    val-log-level: 0
    statistics-interval: 0
    extended-statistics: no
    directory: "{{.Dir}}"
    chroot: ""
    username: "{{.User}}"
    pidfile: "{{.RunDir}}/unbound.pid"
    interface: {{.Listen.Addr}}@{{.Listen.Port}}
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    do-ip4: yes
    do-ip6: {{yesno .IPv6}}
    do-udp: yes
    do-tcp: yes
    num-threads: {{.Threads}}
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-below-nxdomain: yes
    qname-minimisation: yes
    use-caps-for-id: yes
    trust-anchor-file: "{{.TrustAnchor}}"
    root-hints: "{{.RootHints}}"
    do-not-query-localhost: yes
    unwanted-reply-threshold: {{.Unwanted}}
    outgoing-port-avoid: 0-65535
    outgoing-port-permit: {{.PortLo}}-{{.PortHi}}
    outgoing-range: {{.OutgoingRange}}
    max-sent-count: {{.MaxSent}}
    discard-timeout: {{.Discard}}
    wait-limit: {{.WaitLimit}}
    wait-limit-cookie: {{.WaitLimitCookie}}
{{- if .Free}}
    serve-expired: no
    num-queries-per-thread: {{.QueriesPerThread}}
    ratelimit: {{.RateLimit}}
    ratelimit-for-domain: com {{.RateLimitDomain}}
    ratelimit-for-domain: net {{.RateLimitDomain}}
    ratelimit-for-domain: org {{.RateLimitDomain}}
{{- if .OutIf}}
    outgoing-interface: {{.OutIf}}
{{- end}}
{{- else}}
    serve-expired: yes
    serve-expired-ttl: 86400
    num-queries-per-thread: 1024
{{- end}}
{{range .Private}}    private-address: {{.}}
{{end}}{{range .DoNotQueryAddr}}    do-not-query-address: {{.}}
{{end}}
remote-control:
    control-enable: yes
    control-interface: {{.RunDir}}/control.sock
    control-use-cert: no
`

type view struct {
	Params
	Free             bool
	Unwanted         int
	OutgoingRange    int
	MaxSent          int
	Discard          int
	WaitLimit        int
	WaitLimitCookie  int
	QueriesPerThread int
	RateLimit        int
	RateLimitDomain  int
	OutIf            string
	Private          []netip.Prefix
	DoNotQueryAddr   []netip.Prefix
}

var parsed = template.Must(template.New("unbound").Funcs(template.FuncMap{
	"yesno": func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	},
}).Parse(tmpl))

// Render returns the configuration file of p.
func Render(p Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	v := view{
		Params:           p,
		Free:             p.Kind == Free,
		Unwanted:         UnwantedThresholdIdentified,
		OutgoingRange:    p.PortHi - p.PortLo + 1,
		MaxSent:          MaxSentCount,
		Discard:          DiscardTimeoutMS,
		WaitLimit:        WaitLimit,
		WaitLimitCookie:  WaitLimitCookie,
		QueriesPerThread: FreeQueriesPerThread,
		RateLimit:        RateLimitFree,
		RateLimitDomain:  RateLimitDomainFree,
		Private:          nets.NonPublic(),
		// do-not-query-address holds the node addresses and every non-public
		// range, which is what keeps a delegation out of the provider's network.
		DoNotQueryAddr: nets.Merge(nets.NonPublic(), p.DoNotQuery),
	}
	if p.OutgoingInterface.IsValid() {
		v.OutIf = p.OutgoingInterface.String()
	}
	if v.Free {
		v.Unwanted = 0 // a threshold would let anyone clear the free cache at will (SC 11)
	}
	var b bytes.Buffer
	if err := parsed.Execute(&b, v); err != nil {
		return "", fmt.Errorf("unbound: render: %w", err)
	}
	return b.String(), nil
}
