package chrony

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
)

func TestRender(t *testing.T) {
	s, err := Render("panel.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(s, "\nserver "); n != 1 {
		t.Errorf("sources = %d, the panel must be the only one", n)
	}
	if !strings.Contains(s, "server panel.example.net iburst nts") {
		t.Errorf("no NTS source line in %q", s)
	}
	// chronyd parses this directory as root: the file the agent writes may hold a
	// source line and comments, and no other directive (R16).
	for _, l := range strings.Split(s, "\n") {
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "server ") {
			continue
		}
		t.Errorf("the agent's file holds a directive that is not a source: %q", l)
	}
	if strings.Contains(s, "pool") {
		t.Error("a pool is a second source")
	}
	if !strings.HasSuffix(ConfName, ".sources") {
		t.Error("chronyd reads only *.sources files from a sourcedir")
	}
}

func TestHostIsValidated(t *testing.T) {
	for _, h := range []string{"198.51.100.20", "2001:db8::1", "panel.example.net", "a"} {
		if !ValidHost(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{"", "x\nserver evil iburst", "a b", "-a", "a..b", "a;b", "host/with/slash", strings.Repeat("a", 300)} {
		if ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
		if _, err := Render(h); err == nil {
			t.Errorf("Render accepted %q", h)
		}
	}
}

func TestUpdateRestartsOnlyOnChange(t *testing.T) {
	f := fake.NewFiles(nil)
	r := &fake.Runner{}
	ctx := context.Background()
	ca := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	changed, err := Update(ctx, f, r, "198.51.100.20", ca)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !strings.Contains(f.Get("/etc/ctrlz/chrony/ctrlz.sources"), "server 198.51.100.20 iburst nts") || f.Get("/etc/ctrlz/chrony/node_ca.pem") != string(ca) {
		t.Error("files")
	}
	if got := r.Lines(); len(got) != 1 || got[0] != "systemctl restart chrony.service" {
		t.Errorf("calls %v", got)
	}
	changed, err = Update(ctx, f, r, "198.51.100.20", ca)
	if err != nil || changed || len(r.Calls()) != 1 {
		t.Errorf("a repeat did work: %v %v %v", changed, err, r.Lines())
	}
	if _, err := Update(ctx, f, r, "198.51.100.21", ca); err != nil || len(r.Calls()) != 2 {
		t.Error("a new host did not restart")
	}
	if _, err := Update(ctx, f, r, "198.51.100.21", nil); err == nil {
		t.Error("no CA accepted")
	}
	f.WriteErr = errors.New("disk")
	if _, err := Update(ctx, f, r, "198.51.100.30", ca); err == nil {
		t.Error("write error swallowed")
	}
}

// A restart that failed after the files were written is owed: the next Update
// finds the files as they should be and must still restart chrony, or chrony
// never reads the drop-in (the first start of a node, with the unit not up yet).
func TestFailedRestartIsRetried(t *testing.T) {
	f := fake.NewFiles(nil)
	fail := true
	r := &fake.Runner{Reply: func(fake.Call) ([]byte, error) {
		if fail {
			return nil, errors.New("unit not active")
		}
		return nil, nil
	}}
	ctx := context.Background()
	ca := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	if _, err := Update(ctx, f, r, "198.51.100.20", ca); err == nil {
		t.Fatal("a failed restart was not reported")
	}
	fail = false
	// a new Update (an agent restart is the same: the debt is on disk) restarts
	if changed, err := Update(ctx, f, r, "198.51.100.20", ca); err != nil || !changed {
		t.Fatalf("the owed restart was not made: changed=%v err=%v", changed, err)
	}
	if n := len(r.Calls()); n != 2 {
		t.Errorf("restart calls = %d, want 2", n)
	}
	// and once it has succeeded it is not repeated
	if changed, err := Update(ctx, f, r, "198.51.100.20", ca); err != nil || changed || len(r.Calls()) != 2 {
		t.Errorf("a settled state did work: %v %v %v", changed, err, r.Lines())
	}
}
