// Package hostcheck holds the checks the agent runs on the host it lives on
// (p4-nodes 7.3, SC 5.2a, Plan T-555, T-559, T-561): that a crash of a node
// process cannot leave a core dump with a cache in it, that the host's own
// resolver does not point at a node's DNS_IP, and that the connection-tracking
// table is as large as the load test measured.
//
// Each check reads through sysx and returns a Finding with an alert code, or
// nothing. A finding never carries an address or a path from the host in its
// detail text.
package hostcheck

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
)

// Paths on the host.
const (
	CorePatternPath = "/proc/sys/kernel/core_pattern"
	SelfLimitsPath  = "/proc/self/limits"
	CoredumpDropIn  = "/etc/systemd/coredump.conf.d/ctrlz.conf"
	ResolvConf      = "/etc/resolv.conf"
	ResolvedConf    = "/run/systemd/resolve/resolv.conf"
	ConntrackMax    = "/proc/sys/net/netfilter/nf_conntrack_max"
	SyncookiesPath  = "/proc/sys/net/ipv4/tcp_syncookies"
)

// DefaultConntrackMax is the value used until the load test (T-374) measures
// one. P4b raised it from 262,144 to hold the tracked entries of the proxy
// (p4b-proxy 5.5); provisional (D31).
const DefaultConntrackMax = 524288

// Finding is a failed check.
type Finding struct {
	Code   string
	Detail string
}

// Alerts raises every finding.
func Alerts(a alert.Alerter, fs []Finding) {
	for _, f := range fs {
		a.Alert(alert.Alert{Code: f.Code, Detail: f.Detail})
	}
}

// CoreDumps checks the three things that keep a node process from leaving a
// core (SC 5.2a, No trace): the agent's own core limit is 0 (the units set
// LimitCORE=0, so the agent's limit stands for all of them), kernel.core_pattern
// is the systemd-coredump pipe or a plain file pattern, which the limit covers
// (another pipe handler may ignore the limit), and the systemd-coredump drop-in
// says Storage=none and ProcessSizeMax=0.
func CoreDumps(files sysx.Files) []Finding {
	var out []Finding
	bad := func(d string) { out = append(out, Finding{Code: alert.CorePattern, Detail: d}) }

	if b, err := files.ReadFile(SelfLimitsPath); err != nil {
		bad("core limit unreadable")
	} else if !coreLimitZero(b) {
		bad("core limit is not 0")
	}

	if b, err := files.ReadFile(CorePatternPath); err != nil {
		bad("core_pattern unreadable")
	} else if !coreOK(strings.TrimSpace(string(b))) {
		bad("core_pattern is a pipe other than systemd-coredump")
	}

	if b, err := files.ReadFile(CoredumpDropIn); err != nil {
		bad("systemd-coredump drop-in missing")
	} else if !dropInOK(b) {
		bad("systemd-coredump drop-in does not say Storage=none and ProcessSizeMax=0")
	}
	return out
}

func coreLimitZero(b []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Max core file size") {
			f := strings.Fields(strings.TrimPrefix(line, "Max core file size"))
			return len(f) >= 2 && f[0] == "0" && f[1] == "0"
		}
	}
	return false
}

func coreOK(p string) bool {
	if p == "" {
		return false
	}
	if !strings.HasPrefix(p, "|") {
		return true // a plain file pattern: the limit applies
	}
	f := strings.Fields(strings.TrimPrefix(p, "|"))
	if len(f) == 0 {
		return false
	}
	switch f[0] {
	case "/lib/systemd/systemd-coredump", "/usr/lib/systemd/systemd-coredump":
		return true
	}
	return false
}

func dropInOK(b []byte) bool {
	storage, size := false, false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := strings.ReplaceAll(strings.TrimSpace(sc.Text()), " ", "")
		switch l {
		case "Storage=none":
			storage = true
		case "ProcessSizeMax=0":
			size = true
		}
	}
	return storage && size
}

// HostResolver reports when the host's resolver configuration names one of the
// node addresses (T-561): condition (b) of SC 5.2a drops the queries that leave
// a node from its DNS_IP, so a host that resolves through it breaks itself.
// Both files are read, because with systemd-resolved /etc/resolv.conf holds only
// the stub and the real servers are in the second.
func HostResolver(files sysx.Files, nodeAddrs []netip.Addr) []Finding {
	set := map[netip.Addr]bool{}
	for _, a := range nodeAddrs {
		set[a.Unmap()] = true
	}
	for _, p := range []string{ResolvConf, ResolvedConf} {
		b, err := files.ReadFile(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 2 || f[0] != "nameserver" {
				continue
			}
			ns, _, _ := strings.Cut(f[1], "%")
			if a, err := netip.ParseAddr(ns); err == nil && set[a.Unmap()] {
				return []Finding{{Code: alert.HostResolver, Detail: "the host resolver names a node DNS_IP"}}
			}
		}
	}
	return nil
}

// EnsureConntrack raises nf_conntrack_max to want when it is lower, through
// sysctl, and reports a finding when it is still lower afterwards (SC 5.2a,
// Connection tracking). A host without the module has no such file; that is a
// finding too, because the notrack rules assume a tracking table exists to be
// kept small.
func EnsureConntrack(ctx context.Context, files sysx.Files, run sysx.Runner, want int) []Finding {
	read := func() (int, error) {
		b, err := files.ReadFile(ConntrackMax)
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(strings.TrimSpace(string(b)))
	}
	have, err := read()
	if err != nil {
		return []Finding{{Code: alert.ConntrackLow, Detail: "nf_conntrack_max unreadable"}}
	}
	if have >= want {
		return nil
	}
	if _, err := run.Run(ctx, nil, "sysctl", "-w", fmt.Sprintf("net.netfilter.nf_conntrack_max=%d", want)); err == nil {
		if have, err = read(); err == nil && have >= want {
			return nil
		}
	}
	return []Finding{{Code: alert.ConntrackLow, Detail: "nf_conntrack_max below the measured value"}}
}

// Syncookies checks that net.ipv4.tcp_syncookies is on (T-017, SC 5.2 step 1).
// The node serves DNS over TCP, DoT and DoH to anyone, and a spoofed SYN flood
// fills the host half-open queue unless cookies answer once it is full. The
// install sets the value (packaging/sysctl/60-ctrlz.conf) but another unit or an
// operator can change it later, and a distribution default is not a guarantee, so
// the agent reads it every round instead of trusting the file. 1 (cookies only
// when the queue is full) and 2 (always) both hold; 0 and an unreadable or
// unparsable file do not.
func Syncookies(files sysx.Files) []Finding {
	b, err := files.ReadFile(SyncookiesPath)
	if err != nil {
		return []Finding{{Code: alert.SyncookiesOff, Detail: "tcp_syncookies unreadable"}}
	}
	if v := strings.TrimSpace(string(b)); v != "1" && v != "2" {
		return []Finding{{Code: alert.SyncookiesOff, Detail: "tcp_syncookies is off"}}
	}
	return nil
}

// ProxySysctl is the table of p4b-proxy 5.5 (D31): the keys the install sets for the
// proxy role, with the value each must have. nf_conntrack_max and the port range have
// checks of their own (EnsureConntrack, unbound.CheckRanges). The agent cannot write
// /proc/sys, so a key that differs is an alert and an operator's fix.
var ProxySysctl = [][2]string{
	{"net.ipv4.tcp_tw_reuse", "1"},
	{"net.ipv4.tcp_rmem", "4096 131072 2097152"},
	{"net.ipv4.tcp_wmem", "4096 16384 2097152"},
	{"net.ipv4.tcp_notsent_lowat", "131072"},
	{"net.ipv4.tcp_mem", "786432 1048576 1572864"},
	{"net.netfilter.nf_conntrack_tcp_timeout_syn_sent", "10"},
	{"net.netfilter.nf_conntrack_tcp_timeout_last_ack", "10"},
	{"net.netfilter.nf_conntrack_tcp_timeout_fin_wait", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_close_wait", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_time_wait", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_unacknowledged", "30"},
	{"net.netfilter.nf_conntrack_tcp_timeout_max_retrans", "30"},
}

// ProxyKernel reads those keys and reports each one that is unreadable or differs.
// The detail names the key, never a value.
func ProxyKernel(files sysx.Files) []Finding {
	var out []Finding
	for _, k := range ProxySysctl {
		b, err := files.ReadFile("/proc/sys/" + strings.ReplaceAll(k[0], ".", "/"))
		if err != nil || strings.Join(strings.Fields(string(b)), " ") != k[1] {
			out = append(out, Finding{Code: alert.SysctlOff, Detail: "a kernel setting of the proxy role is not the one of the install: " + k[0]})
		}
	}
	return out
}
