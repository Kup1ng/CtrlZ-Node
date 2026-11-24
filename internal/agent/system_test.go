package agent_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func systemLab(t *testing.T) *lab {
	l := newLab(t, func(l *lab) { l.cfg.NoSystem, l.cfg.SkipHostChecks = false, false })
	keys := filepath.Join(l.cfg.Root, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "node_ca.pem"), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return l
}

func lines(l *lab) string { return strings.Join(l.runner.Lines(), "\n") }

func TestSystemStartsUnboundNftablesAndChrony(t *testing.T) {
	l := systemLab(t)
	l.start()
	eventually(t, "both Unbound units started", func() bool {
		s := lines(l)
		return strings.Contains(s, "systemctl start ctrlz-unbound.service") && strings.Contains(s, "systemctl start ctrlz-unbound-free.service") &&
			strings.Contains(s, "nft -f -") && strings.Contains(s, "systemctl restart chrony.service")
	})
	for _, p := range []string{"/etc/ctrlz/unbound/identified.conf", "/etc/ctrlz/unbound/free.conf", "/etc/ctrlz/chrony/ctrlz.sources", "/etc/ctrlz/chrony/node_ca.pem"} {
		if l.files.Get(p) == "" {
			t.Errorf("%s not written", p)
		}
	}
	if !strings.Contains(l.files.Get("/etc/ctrlz/chrony/ctrlz.sources"), "server 127.0.0.1 iburst nts") {
		t.Error("chrony does not use the panel host as its only server")
	}
	var script string
	for _, c := range l.runner.Calls() {
		if c.Name == "nft" && len(c.Args) == 2 && c.Args[0] == "-f" {
			script = string(c.Stdin)
		}
	}
	for _, want := range []string{"ip daddr 10.0.0.5 udp dport 53 notrack", "udp dport 123 ip daddr != { 127.0.0.1 } drop"} {
		if !strings.Contains(script, want) {
			t.Errorf("the nftables script lacks %q", want)
		}
	}
	if !strings.Contains(l.files.Get("/etc/ctrlz/unbound/free.conf"), "unwanted-reply-threshold: 0") {
		t.Error("the free Unbound is not the free configuration")
	}
	// A node with no NodeConfig yet runs Plain-only and says so (7.2); nothing else.
	for _, c := range l.alerts.Codes() {
		if c != alert.ConfigFallback {
			t.Errorf("alert on a healthy host: %v", c)
		}
	}
	// the applied PairTable changes the do-not-query list, which both processes reload
	b1 := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "reload with the new list", func() bool {
		return strings.Contains(l.files.Get("/etc/ctrlz/unbound/identified.conf"), "do-not-query-address: 1.1.1.1/32") &&
			strings.Count(lines(l), "reload_keep_cache") >= 2
	})
	if strings.Contains(lines(l), "systemctl restart ctrlz-unbound") {
		t.Error("a list change restarted an Unbound instead of reloading it")
	}
}

func TestSystemRefusals(t *testing.T) {
	t.Run("unbound below the floor", func(t *testing.T) {
		l := systemLab(t)
		l.runner.Reply = func(c fake.Call) ([]byte, error) {
			if c.Name == "unbound" {
				return []byte("Version 1.10.0\n"), nil
			}
			return nil, nil
		}
		l.start()
		eventually(t, "the refusal", func() bool { return l.alerts.Count(alert.UnboundRefused) >= 2 })
		time.Sleep(100 * time.Millisecond)
		if strings.Contains(lines(l), "systemctl start ctrlz-unbound") {
			t.Error("an Unbound under the floor was started")
		}
	})
	t.Run("a core pattern that can leave a core", func(t *testing.T) {
		l := systemLab(t)
		l.files.Set("/proc/sys/kernel/core_pattern", "|/usr/share/apport/apport %p\n")
		l.start()
		eventually(t, "the alerts", func() bool {
			return l.alerts.Count(alert.CorePattern) >= 1 && l.alerts.Count(alert.UnboundRefused) >= 1
		})
		time.Sleep(100 * time.Millisecond)
		if strings.Contains(lines(l), "systemctl start ctrlz-unbound") {
			t.Error("an Unbound was started while core dumps were not ruled out")
		}
	})
	t.Run("a pinned limit changed on disk", func(t *testing.T) {
		l := systemLab(t)
		l.files.Set("/etc/ctrlz/unbound/free.conf", "server:\n    ratelimit: 99999\n")
		l.start()
		eventually(t, "refused free", func() bool { return l.alerts.Count(alert.UnboundRefused) >= 1 })
		time.Sleep(100 * time.Millisecond)
		if strings.Contains(lines(l), "systemctl start ctrlz-unbound-free") {
			t.Error("the free Unbound started with a changed limit")
		}
		if !strings.Contains(lines(l), "systemctl start ctrlz-unbound.service") {
			t.Error("the identified Unbound should still start")
		}
	})
	t.Run("a host resolver naming DNS_IP and a low conntrack", func(t *testing.T) {
		l := systemLab(t)
		l.files.Set("/etc/resolv.conf", "nameserver 10.0.0.5\n")
		l.files.Set("/proc/sys/net/netfilter/nf_conntrack_max", "1000\n")
		l.runner.Reply = func(c fake.Call) ([]byte, error) {
			if c.Name == "unbound" {
				return []byte("Version 1.20.0\n"), nil
			}
			if c.Name == "systemctl" && c.Args[0] == "is-active" {
				return []byte("active\n"), nil
			}
			return nil, nil // sysctl succeeds but changes nothing
		}
		l.start()
		eventually(t, "both alerts", func() bool { return l.alerts.Count(alert.HostResolver) >= 1 && l.alerts.Count(alert.ConntrackLow) >= 1 })
	})
}

func TestUpstreamThatIsANodeAddressAlerts(t *testing.T) {
	l := newLab(t)
	l.start()
	s := l.session()
	_ = s.Send(serverTime())
	id := func(n byte) []byte { b := make([]byte, 16); b[0] = n; return b }
	nc := testNodeConfig(2, storetest.RandomSecret(t, 32))
	nc.Mode = commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM
	nc.Upstreams = []*hubv1.Upstream{
		{Id: id(1), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "9.9.9.9:53", TimeoutMs: 1000},
		{Id: id(2), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "[::ffff:8.8.8.8]:53", TimeoutMs: 1000},
		{Id: id(3), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: "dns.example.org", BootstrapIp: []byte{8, 8, 8, 8}, TimeoutMs: 1000},
	}
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: nc}})
	// the node's own advertised address, in its mapped form and as a bootstrap IP
	eventually(t, "the loop alerts", func() bool { return l.alerts.Count(alert.UpstreamLoop) == 2 })
	if l.alerts.Last(alert.UpstreamLoop) == "" || strings.Contains(l.alerts.Last(alert.UpstreamLoop), "8.8.8.8") {
		t.Errorf("detail %q", l.alerts.Last(alert.UpstreamLoop))
	}
}

// An Unbound whose start failed (or was refused by the core-dump gate) is started
// again by the supervision pass once the cause is gone, with no agent restart.
func TestSystemRetriesAnUnboundThatNeverStarted(t *testing.T) {
	fast := func(l *lab) {
		l.cfg.UnboundEvery, l.cfg.UnboundStartRetry, l.cfg.HostEvery = 20*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond
	}
	count := func(l *lab, unit string) int {
		n := 0
		for _, s := range l.runner.Lines() {
			if s == "systemctl start "+unit {
				n++
			}
		}
		return n
	}
	t.Run("a systemctl start that failed once", func(t *testing.T) {
		l := systemLab(t)
		fast(l)
		var failed atomic.Bool
		base := l.runner.Reply
		l.runner.Reply = func(c fake.Call) ([]byte, error) {
			if c.Name == "systemctl" && len(c.Args) == 2 && c.Args[0] == "start" && c.Args[1] == "ctrlz-unbound-free.service" && failed.CompareAndSwap(false, true) {
				return nil, errors.New("polkit not ready")
			}
			return base(c)
		}
		l.start()
		eventually(t, "the free unit started again", func() bool { return count(l, "ctrlz-unbound-free.service") >= 2 })
		time.Sleep(150 * time.Millisecond)
		if n := count(l, "ctrlz-unbound-free.service"); n != 2 {
			t.Errorf("start calls = %d: a started unit must not be started again", n)
		}
		if n := count(l, "ctrlz-unbound.service"); n != 1 {
			t.Errorf("the identified unit was started %d times", n)
		}
	})
	t.Run("a core pattern fixed while the agent runs", func(t *testing.T) {
		l := systemLab(t)
		fast(l)
		l.files.Set("/proc/sys/kernel/core_pattern", "|/usr/share/apport/apport %p\n")
		l.start()
		eventually(t, "the refusal", func() bool { return l.alerts.Count(alert.UnboundRefused) >= 1 })
		time.Sleep(150 * time.Millisecond)
		if count(l, "ctrlz-unbound.service") != 0 {
			t.Fatal("started while core dumps were not ruled out")
		}
		l.files.Set("/proc/sys/kernel/core_pattern", "|/lib/systemd/systemd-coredump %P\n")
		eventually(t, "both units started", func() bool {
			return count(l, "ctrlz-unbound.service") == 1 && count(l, "ctrlz-unbound-free.service") == 1
		})
	})
}

// A chrony restart that failed is made again on the host tick.
func TestSystemRetriesAFailedChronyRestart(t *testing.T) {
	l := systemLab(t)
	l.cfg.HostEvery = 30 * time.Millisecond
	var failed atomic.Bool
	base := l.runner.Reply
	l.runner.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "systemctl" && len(c.Args) == 2 && c.Args[0] == "restart" && c.Args[1] == "chrony.service" && failed.CompareAndSwap(false, true) {
			return nil, errors.New("unit not active")
		}
		return base(c)
	}
	l.start()
	restarts := func() int {
		n := 0
		for _, s := range l.runner.Lines() {
			if s == "systemctl restart chrony.service" {
				n++
			}
		}
		return n
	}
	eventually(t, "chrony restarted again", func() bool { return restarts() >= 2 })
	time.Sleep(150 * time.Millisecond)
	if n := restarts(); n != 2 {
		t.Errorf("chrony restarts = %d, want 2", n)
	}
}
