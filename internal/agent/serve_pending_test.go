package agent

import (
	"context"
	"net/netip"
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

// The lab and most tests run with NoSystem: nothing is touched.
func TestServePendingLeavesTheHostAloneWithNoSystem(t *testing.T) {
	r, files := unboundHost()
	cfg := Config{Root: t.TempDir(), Runner: r, Files: files, NoSystem: true}
	servePending(context.Background(), cfg, conf.Agent{})()
	if len(r.Calls()) != 0 {
		t.Errorf("calls: %v", r.Lines())
	}
}
