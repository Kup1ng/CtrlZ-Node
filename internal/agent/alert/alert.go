// Package alert is where the agent says that something on the node needs the
// owner. The proto has no alert message in P4 (the hub raises its alerts from
// Heartbeats and QuarantineReports), so an alert is a line in the agent's
// journal and a counter that the Heartbeat and a later hub intake can read.
//
// An alert has a code from a fixed list and a detail that is chosen by the
// caller from words it wrote itself: never a query name, an address, a
// resolver ID or an error string taken from a command. That keeps the no-trace
// rule of SC 5.2a true for everything the agent says.
package alert

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Codes. Each is a condition of the node, not an event.
const (
	UnboundDown         = "unbound_down"          // an Unbound unit is not running and was restarted
	UnboundRefused      = "unbound_refused"       // an Unbound was not started: version floor, a pinned setting, or ranges
	UnboundReloadFail   = "unbound_reload_fail"   // reload_keep_cache failed
	CorePattern         = "core_pattern"          // kernel.core_pattern can leave a core of a node process
	HostResolver        = "host_resolver"         // the host's resolver names a node's DNS_IP (T-561)
	ConntrackLow        = "conntrack_low"         // nf_conntrack_max below the measured value
	SyncookiesOff       = "syncookies_off"        // net.ipv4.tcp_syncookies is 0 or unreadable: a SYN flood fills the half-open queue (T-017)
	NftFailed           = "nft_failed"            // the nftables table could not be applied
	SysctlOff           = "sysctl_off"            // a kernel setting of the proxy role (p4b-proxy 5.5) is not the installed one
	ChronyFailed        = "chrony_failed"         // chrony's file or unit could not be updated
	UpstreamLoop        = "upstream_loop"         // an upstream of the NodeConfig is a node's own address (SC 5.2a, Loops)
	QuarantineTwoNodes  = "quarantine"            // an entry was refused and reported
	PushRefused         = "push_refused"          // a pushed table was refused
	StateDamaged        = "state_damaged"         // the applied state had to be repaired at start
	ConfigFallback      = "config_fallback"       // the node serves from a previous or no NodeConfig
	UnboundUnwanted     = "unbound_unwanted"      // the unwanted.replies counter of the identified Unbound rose
	UnboundUnsupervised = "unbound_unsupervised"  // an Unbound unit is running that the agent refused to take over: it is not supervised
	UnboundStale        = "unbound_stale"         // an Unbound ran from a binary or library that was replaced; it was restarted
	CertBundleRefused   = "cert_bundle_refused"   // a CertBundle did not open or did not match
	Skew                = "clock_skew"            // the node clock differs from the hub's by more than 2 s
	HubUnreachable      = "hub_unreachable"       // the Control stream has been down for a while
	RevocationOverflow  = "revocation_overflow"   // more revocation ids than the node holds: the oldest were dropped
	DNSRestartFailed    = "dns_restart_failed"    // ctrlz-dns could not be restarted onto a new NodeConfig
	ImagePublishFailed  = "image_publish_failed"  // the image of an applied state could not be published (disk fault)
	ChainMismatch       = "chain_mismatch"        // the entries the hub serves do not reach its signed head
	RevocationsNotSaved = "revocations_not_saved" // the revocation file could not be written: a restart now starts with none
)

// Alert is one condition.
type Alert struct {
	Code   string
	Detail string
}

// Alerter receives alerts. Alert must not block and must be safe to call from
// any goroutine.
type Alerter interface {
	Alert(a Alert)
}

// Discard drops every alert.
type Discard struct{}

// Alert implements Alerter.
func (Discard) Alert(Alert) {}

// Memory keeps a count per code, for tests and for the Heartbeat.
type Memory struct {
	mu     sync.Mutex
	counts map[string]int
	last   map[string]string
}

// Alert implements Alerter.
func (m *Memory) Alert(a Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts, m.last = map[string]int{}, map[string]string{}
	}
	m.counts[a.Code]++
	m.last[a.Code] = a.Detail
}

// Count is how many times code was raised.
func (m *Memory) Count(code string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[code]
}

// Last is the detail of the last alert of code.
func (m *Memory) Last(code string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last[code]
}

// Codes lists the codes raised so far, sorted.
func (m *Memory) Codes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.counts))
	for c := range m.counts {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Log writes an alert as one line, at most once a minute for one code, so a
// condition that is checked every minute is one line an hour, not sixty.
//
// The write is not made on the caller's goroutine. Alert is called from the Control
// receive loop (a clock skew) and other places that must never wait (L11), and W is
// the journal's pipe, which stops draining when journald stalls. Lines go through a
// bounded queue to one writer goroutine and are dropped when it is full; they are
// only diagnostics, and the Heartbeat does not depend on them.
type Log struct {
	W   io.Writer
	Now func() time.Time

	mu   sync.Mutex
	last map[string]time.Time

	once    sync.Once
	q       chan string
	dropped atomic.Uint64
}

// logQueue is how many lines wait for a slow writer.
const logQueue = 256

// Alert implements Alerter.
func (l *Log) Alert(a Alert) {
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	l.mu.Lock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	t := now()
	if p, ok := l.last[a.Code]; ok && t.Sub(p) < time.Minute {
		l.mu.Unlock()
		return
	}
	l.last[a.Code] = t
	l.mu.Unlock()
	l.once.Do(func() {
		l.q = make(chan string, logQueue)
		go func() {
			for line := range l.q {
				_, _ = io.WriteString(l.W, line)
			}
		}()
	})
	select {
	case l.q <- fmt.Sprintf("ctrlz-agent alert code=%s detail=%q\n", a.Code, a.Detail):
	default:
		l.dropped.Add(1)
	}
}

// Multi sends an alert to every Alerter.
type Multi []Alerter

// Alert implements Alerter.
func (m Multi) Alert(a Alert) {
	for _, x := range m {
		x.Alert(a)
	}
}
