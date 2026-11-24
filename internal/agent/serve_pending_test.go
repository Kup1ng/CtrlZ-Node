package agent

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/unbound"
)

// unboundHost is a fake host where Unbound is installed and the units answer systemctl.
func unboundHost() (*fake.Runner, *fake.Files) {
	units := &fake.Units{}
	r := &fake.Runner{Reply: func(c fake.Call) ([]byte, error) {
		if out, err, ok := units.Handle(c); ok {
			return out, err
		}
		switch c.Name {
		case "unbound":
			return []byte("Version 1.19.2\n"), nil
		case "dpkg-query":
			return []byte(unbound.DistroFloor), nil
		}
		return nil, nil
	}}
	return r, fake.NewFiles(map[string]string{unbound.EphemeralPath: "32768 39999\n"})
}

// p4n-MC-r2-3: a node that is still enrolling has its two Unbound processes started,
// with the node's own addresses in the do-not-query list, before any identity exists
// and without a word to the hub. This runs on the host side only, so it needs no Linux.
func TestServePendingStartsBothUnboundsWithoutAnIdentity(t *testing.T) {
	r, files := unboundHost()
	al := &alert.Memory{}
	cfg := Config{Root: filepath.Join(t.TempDir(), "ctrlz"), ConfPath: filepath.Join(t.TempDir(), "agent.conf"),
		Runner: r, Files: files, Alert: al, SkipHostChecks: true, UnboundEvery: 10 * time.Millisecond}
	ac := conf.Agent{Hub: "hub.test", DNSBindIP: netip.MustParseAddr("1.2.3.4"), DNSAdvertisedIP: netip.MustParseAddr("5.6.7.8")}
	stop := servePending(context.Background(), cfg, ac)
	defer stop()
	eventually := func(what string, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(10 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("%s; calls: %v", what, r.Lines())
			}
		}
	}
	eventually("both units started", func() bool {
		s := strings.Join(r.Lines(), "\n")
		return strings.Contains(s, "systemctl start ctrlz-unbound.service") && strings.Contains(s, "systemctl start ctrlz-unbound-free.service")
	})
	for _, p := range []string{"/etc/ctrlz/unbound/identified.conf", "/etc/ctrlz/unbound/free.conf"} {
		c := files.Get(p)
		if c == "" {
			t.Fatalf("%s not written", p)
		}
		for _, want := range []string{"do-not-query-address: 1.2.3.4/32", "do-not-query-address: 5.6.7.8/32"} {
			if !strings.Contains(c, want) {
				t.Errorf("%s lacks %q", p, want)
			}
		}
	}
	stop()
	for _, c := range r.Calls() {
		if c.Name == "systemctl" && len(c.Args) > 0 && c.Args[0] == "stop" {
			t.Errorf("the units were stopped when the supervision ended: %v", c)
		}
	}
}

// p4n-MC-r3-1 and p4n-MC-r3-2: the clean-up of temporary files that opening the store makes
// is finished before servePending returns, so it can never take a file the enrolment is
// writing (the enrolment makes ".tmp-enroll-*" in keys/ and renames it).
func TestServePendingCleansTheStoreBeforeItReturns(t *testing.T) {
	r, files := unboundHost()
	root := filepath.Join(t.TempDir(), "ctrlz")
	keys := filepath.Join(root, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(keys, ".tmp-enroll-old")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Root: root, ConfPath: filepath.Join(t.TempDir(), "agent.conf"), Runner: r, Files: files,
		Alert: &alert.Memory{}, SkipHostChecks: true, UnboundEvery: 5 * time.Millisecond}
	stop := servePending(context.Background(), cfg, conf.Agent{Hub: "hub.test"})
	defer stop()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("the clean-up had not run when servePending returned: %v", err)
	}
	// what the enrolment writes from here on is never touched, however long the supervision runs
	live := filepath.Join(keys, ".tmp-enroll-live")
	if err := os.WriteFile(live, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(10 * time.Second); !strings.Contains(strings.Join(r.Lines(), "\n"), "systemctl start ctrlz-unbound-free.service"); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("units not started: %v", r.Lines())
		}
	}
	time.Sleep(50 * time.Millisecond)
	stop()
	if _, err := os.Stat(live); err != nil {
		t.Errorf("a temporary file of the enrolment was removed: %v", err)
	}
}

// p4n-MC-r3-5: the nftables table (notrack, the NTP restriction) and the host checks do
// not wait for an identity: after a reboot they are what stands between the open port 53
// and a spoofed flood.
func TestServePendingAppliesTheNftTableAndRunsTheHostChecks(t *testing.T) {
	r, files := unboundHost()
	al := &alert.Memory{}
	cfg := Config{Root: filepath.Join(t.TempDir(), "ctrlz"), ConfPath: filepath.Join(t.TempDir(), "agent.conf"),
		Runner: r, Files: files, Alert: al, UnboundEvery: 10 * time.Millisecond}
	ac := conf.Agent{Hub: "hub.test", DNSBindIP: netip.MustParseAddr("1.2.3.4"), PanelAddrs: []netip.Addr{netip.MustParseAddr("198.51.100.20")}}
	stop := servePending(context.Background(), cfg, ac)
	defer stop()
	for end := time.Now().Add(10 * time.Second); al.Count(alert.CorePattern) == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("the host checks did not run; alerts %v", al.Codes())
		}
	}
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		var script string
		for _, c := range r.Calls() {
			if c.Name == "nft" && len(c.Args) == 2 && c.Args[0] == "-f" {
				script = string(c.Stdin)
			}
		}
		if strings.Contains(script, "ip daddr 1.2.3.4 udp dport 53 notrack") {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("the nftables table was not applied: %v", r.Lines())
		}
	}
}

// The lab and most tests run with NoSystem: nothing is touched.
func TestServePendingLeavesTheHostAloneWithNoSystem(t *testing.T) {
	r, files := unboundHost()
	cfg := Config{Root: t.TempDir(), Runner: r, Files: files, NoSystem: true}
	servePending(context.Background(), cfg, conf.Agent{})()
	if len(r.Calls()) != 0 {
		t.Errorf("calls: %v", r.Lines())
	}
}
