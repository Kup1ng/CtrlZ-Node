package pkgcheck_test

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/chrony"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/unbound"
	"github.com/Kup1ng/CtrlZ-Node/internal/enroll"
	"github.com/Kup1ng/CtrlZ-Node/internal/pkgcheck"
	"github.com/Kup1ng/CtrlZ-Node/internal/upgrade"
)

// These tests tie the packaging to the code that runs under it (merge C): every path,
// user, group and role the code names is the one the units, the directory list and the
// install script give it. pkgcheck.Check judges the packaging by itself; this is the
// other half, so a rename on either side fails here and not on the first host.

const pk = "../../packaging"

func read(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{pk}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func unit(t *testing.T, name string) pkgcheck.Unit {
	t.Helper()
	return pkgcheck.ParseUnit(read(t, "systemd", name+".service"))
}

func one(t *testing.T, u pkgcheck.Unit, key string) string {
	t.Helper()
	v, ok := u.One(key)
	if !ok || v == "" {
		t.Fatalf("%s is unset or set twice", key)
	}
	return v
}

func TestUnitsRunTheRolesTheBinaryHas(t *testing.T) {
	main, err := os.ReadFile("../../cmd/ctrlz-node/main.go")
	if err != nil {
		t.Fatal(err)
	}
	apply := read(t, "install", "apply.sh")
	const bin = "/usr/local/bin/ctrlz-node"
	if !strings.Contains(apply, bin+" 0755") {
		t.Errorf("apply.sh does not install the binary at %s", bin)
	}
	for _, role := range []string{"dns", "agent", "proxy"} {
		u := unit(t, "ctrlz-"+role)
		if got, want := one(t, u, "Service.ExecStart"), bin+" "+role; got != want {
			t.Errorf("ctrlz-%s ExecStart %q, want %q", role, got, want)
		}
		if !regexp.MustCompile(`case "` + role + `":`).Match(main) {
			t.Errorf("ctrlz-node has no role %q", role)
		}
	}
	if !strings.Contains(string(main), `"upgrade"`) {
		t.Error("ctrlz-node has no upgrade subcommand")
	}
}

func TestUnitsMatchTheAccountsTheCodeUses(t *testing.T) {
	acc, err := pkgcheck.ParseAccounts(read(t, "accounts.conf"))
	if err != nil {
		t.Fatal(err)
	}
	agentU, dnsU := unit(t, "ctrlz-agent"), unit(t, "ctrlz-dns")
	if got := one(t, dnsU, "Service.User"); got != agent.DNSUser {
		t.Errorf("ctrlz-dns runs as %s, the agent checks the peer is %s", got, agent.DNSUser)
	}
	if _, ok := acc.Users[agent.DNSUser]; !ok {
		t.Errorf("accounts.conf has no user %s", agent.DNSUser)
	}
	for _, u := range []pkgcheck.Unit{agentU, dnsU} {
		if got := one(t, u, "Service.Group"); got != agent.SockGroup {
			t.Errorf("a unit has group %s, the socket's group is %s", got, agent.SockGroup)
		}
	}
	if !slices.Contains(acc.Groups, agent.SockGroup) {
		t.Errorf("accounts.conf has no group %s", agent.SockGroup)
	}
	for _, name := range []string{"ctrlz-unbound", "ctrlz-unbound-free"} {
		u := unit(t, name)
		user := one(t, u, "Service.User")
		kind := unbound.Identified
		if name == "ctrlz-unbound-free" {
			kind = unbound.Free
		}
		p := unbound.DefaultParams(kind)
		if p.User != user {
			t.Errorf("%s runs as %s, the config names %s", name, user, p.User)
		}
		if got, want := "/run/"+one(t, u, "Service.RuntimeDirectory"), p.RunDir; got != want {
			t.Errorf("%s runtime directory %s, the config's RunDir is %s", name, got, want)
		}
		if got, want := "/var/lib/"+one(t, u, "Service.StateDirectory"), p.Dir; got != want {
			t.Errorf("%s state directory %s, the config's Dir is %s", name, got, want)
		}
		conf := unbound.ConfIdentified
		if kind == unbound.Free {
			conf = unbound.ConfFree
		}
		if got, want := one(t, u, "Service.ExecStart"), "/usr/sbin/unbound -d -c "+path.Join(agent.UnboundConfDir, conf); got != want {
			t.Errorf("%s ExecStart %q, want %q", name, got, want)
		}
	}
}

func TestStatePathsAreWritableAndOwnedAsTheCodeNeeds(t *testing.T) {
	agentU := unit(t, "ctrlz-agent")
	rw := agentU.Words("Service.ReadWritePaths")
	for _, p := range []string{agent.DefaultRoot, agent.UnboundConfDir, chrony.Dir} {
		if !slices.Contains(rw, p) {
			t.Errorf("the agent unit cannot write %s (ReadWritePaths %v)", p, rw)
		}
	}
	// The socket directory is the unit's runtime directory.
	if got, want := "/run/"+one(t, agentU, "Service.RuntimeDirectory"), path.Dir(agent.DefaultSock); got != want {
		t.Errorf("runtime directory %s, the socket is in %s", got, want)
	}
	dirs, err := pkgcheck.ParseDirs(read(t, "dirs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]pkgcheck.Dir{}
	for _, d := range dirs {
		have[d.Path] = d
	}
	for _, p := range []string{
		agent.DefaultRoot, agent.DefaultRoot + "/keys", agent.DefaultRoot + "/bundles", agent.UnboundConfDir, chrony.Dir,
		filepath.ToSlash(path.Dir(upgrade.DefaultVersion)),
	} {
		if _, ok := have[p]; !ok {
			t.Errorf("dirs.conf does not make %s", p)
		}
	}
	if d := have[agent.DefaultRoot+"/bundles"]; d.Path != "" && path.Join(agent.DefaultRoot, "bundles") != upgrade.DefaultBundles {
		t.Errorf("upgrade reads bundles from %s, the install makes %s", upgrade.DefaultBundles, d.Path)
	}
	if d := have[agent.DefaultRoot+"/keys"]; d.Owner != "ctrlz-agent" || d.Mode != "0700" {
		t.Errorf("keys directory: %+v", d)
	}
}

func TestInstallWritesWhatTheCodeReads(t *testing.T) {
	apply := read(t, "install", "apply.sh")
	node := read(t, "install", "node.sh")
	for _, want := range []string{
		agent.DefaultConf,           // agent.conf
		upgrade.DefaultRoot,         // the root-owned copy of root.json
		upgrade.DefaultVersion,      // the versions file
		upgrade.DefaultVerify,       // ctrlz-verify
		"$K/" + hubconn.NodeCAFile,  // the node CA
		"$K/" + hubconn.HubPinFile,  // the pin
		"$K/" + hubconn.RootFile,    // the agent's root
		"$K/" + enroll.TokenFile,    // the enrolment token
		"$K/" + enroll.PendingFile,  // cleared by a repeat install
		"$K/" + hubconn.NodeKeyFile, // cleared by a repeat install
		"$K/" + hubconn.NodeCertFile,
	} {
		if !strings.Contains(apply, want) {
			t.Errorf("apply.sh never names %s", want)
		}
	}
	if !strings.Contains(node, "ctrlz-verify") {
		t.Error("node.sh does not use ctrlz-verify")
	}
	if got := filepath.ToSlash(upgrade.DefaultStage); got != "/var/lib" {
		t.Errorf("upgrade stages in %s", got)
	}
}
