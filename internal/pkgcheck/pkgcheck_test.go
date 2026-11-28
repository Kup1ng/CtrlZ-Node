package pkgcheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const realPackaging = "../../packaging"

var (
	treeOnce  sync.Once
	treeFiles map[string][]byte
	treeErr   error
)

// packagingFiles reads packaging/ once; every mutant case then copies from memory,
// which matters where the repository is on a slow mount.
func packagingFiles() (map[string][]byte, error) {
	treeOnce.Do(func() {
		treeFiles = map[string][]byte{}
		treeErr = filepath.WalkDir(realPackaging, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(realPackaging, p)
			b, err := os.ReadFile(p)
			treeFiles[rel] = b
			return err
		})
	})
	return treeFiles, treeErr
}

func copyTree(t *testing.T) string {
	t.Helper()
	files, err := packagingFiles()
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	for rel, b := range files {
		p := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func mutate(t *testing.T, root, rel, from, to string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), from) {
		t.Fatalf("%s does not contain %q: the mutant would test nothing", rel, from)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), from, to, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasFinding(fs []Finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(string(f), sub) {
			return true
		}
	}
	return false
}

// The real files are clean. This is N11's install-layout half: group ctrlz holds
// only ctrlz-dns and ctrlz-agent; the agent's polkit actions and writable paths
// are exactly those of 7.1.
func TestRealPackagingIsClean(t *testing.T) {
	if fs := Check(realPackaging); len(fs) != 0 {
		t.Fatalf("findings:\n%s", strings.Join(toStrings(fs), "\n"))
	}
}

func toStrings(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = string(f)
	}
	return out
}

func TestParsedValuesAreTheSpec(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(realPackaging, "polkit/50-ctrlz-agent.rules"))
	if err != nil {
		t.Fatal(err)
	}
	p := ParsePolkit(string(b))
	if p.User != "ctrlz-agent" || !sameSet(p.Units, AgentUnits) || !sameSet(p.Verbs, AgentVerbs) || p.Yes != 1 || !p.DefaultNo {
		t.Fatalf("polkit parsed as %+v", p)
	}
	ab, _ := os.ReadFile(filepath.Join(realPackaging, "accounts.conf"))
	a, err := ParseAccounts(string(ab))
	if err != nil {
		t.Fatal(err)
	}
	if !sameSet(a.Members["ctrlz"], []string{"ctrlz-dns", "ctrlz-agent"}) {
		t.Fatalf("group ctrlz members %v", a.Members["ctrlz"])
	}
	ub, _ := os.ReadFile(filepath.Join(realPackaging, "systemd/ctrlz-agent.service"))
	u := ParseUnit(string(ub))
	if !sameSet(u.Words("Service.ReadWritePaths"), []string{"/var/lib/ctrlz", "/etc/ctrlz/unbound", "/etc/ctrlz/chrony"}) {
		t.Fatalf("agent ReadWritePaths %v", u.Words("Service.ReadWritePaths"))
	}
}

// Each case is a change to the packaging that widens a right or loses a rule; the
// check must name it. The first two are the mutants N11 lists.
func TestMutantsAreFound(t *testing.T) {
	cases := []struct {
		name, file, from, to, want string
	}{
		{"manage-units for every unit", "polkit/50-ctrlz-agent.rules", `units.indexOf(action.lookup("unit")) >= 0 &&`, ``, "not conditioned"},
		{"manage-units for every unit (grant by user only)", "polkit/50-ctrlz-agent.rules", `if (action.id === "org.freedesktop.systemd1.manage-units" &&`, `if (action.id === "org.freedesktop.systemd1.manage-units" ||`, "not conditioned"},
		{"agent may run apt: a writable path", "systemd/ctrlz-agent.service", `ReadWritePaths=/var/lib/ctrlz `, `ReadWritePaths=/var/lib/dpkg /var/lib/ctrlz `, "ReadWritePaths"},
		{"agent may run apt: a capability", "systemd/ctrlz-agent.service", `CapabilityBoundingSet=CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE`, "CAP_NET_ADMIN only"},
		{"agent may run apt: a privileged pre-start", "systemd/ctrlz-agent.service", "[Service]\n", "[Service]\nExecStartPre=+/usr/bin/apt-get update\n", "ExecStartPre"},
		{"agent may run apt: no NoNewPrivileges", "systemd/ctrlz-agent.service", `NoNewPrivileges=yes`, `NoNewPrivileges=no`, "NoNewPrivileges"},
		{"agent may run apt: a polkit action", "polkit/50-ctrlz-agent.rules", `action.id === "org.freedesktop.systemd1.manage-units" &&`, `(action.id === "org.freedesktop.systemd1.manage-units" || action.id === "org.freedesktop.systemd1.manage-unit-files") &&`, "actions are"},
		{"polkit: another unit", "polkit/50-ctrlz-agent.rules", `"chrony.service"`, `"chrony.service", "apt-daily.service"`, "units are"},
		{"polkit: reload verb", "polkit/50-ctrlz-agent.rules", `["start", "stop", "restart"]`, `["start", "stop", "restart", "reload"]`, "verbs are"},
		{"polkit: another user", "polkit/50-ctrlz-agent.rules", `subject.user !== "ctrlz-agent"`, `subject.user !== "ctrlz-dns"`, "the rule is for user"},
		{"polkit: no default refusal", "polkit/50-ctrlz-agent.rules", "    return polkit.Result.NO;\n", "    return polkit.Result.NOT_HANDLED;\n", "refuse everything else"},
		{"polkit: a second grant", "polkit/50-ctrlz-agent.rules", "    return polkit.Result.NO;\n", "    return polkit.Result.YES;\n", "grants in 2 places"},
		{"proxy in group ctrlz", "accounts.conf", "member ctrlz-dns ctrlz\n", "member ctrlz-dns ctrlz\nmember ctrlz-proxy ctrlz\n", "group ctrlz has members"},
		{"unbound in group ctrlz", "accounts.conf", "member ctrlz-dns ctrlz\n", "member ctrlz-dns ctrlz\nmember ctrlz-unbound ctrlz\n", "must not be in group ctrlz"},
		{"agent leaves group ctrlz", "accounts.conf", "member ctrlz-agent ctrlz\n", "", "group ctrlz has members"},
		{"unbound primary is ctrlz", "accounts.conf", "user ctrlz-unbound ctrlz-unbound /var/lib/ctrlz-unbound", "user ctrlz-unbound ctrlz /var/lib/ctrlz-unbound", "primary group"},
		{"blobs without setgid", "dirs.conf", "/var/lib/ctrlz/blobs ctrlz-agent ctrlz 2750", "/var/lib/ctrlz/blobs ctrlz-agent ctrlz 0750", "setgid"},
		{"keys open to the group", "dirs.conf", "/var/lib/ctrlz/keys ctrlz-agent ctrlz 0700", "/var/lib/ctrlz/keys ctrlz-agent ctrlz 0750", "0700"},
		{"a unit forgotten by files.conf", "files.conf", "systemd/ctrlz-proxy.service /etc/systemd/system/ctrlz-proxy.service 0644\n", "", "in no list"},
		{"no core limit", "systemd/ctrlz-dns.service", "LimitCORE=0\n", "", "LimitCORE"},
		{"dns with a second capability", "systemd/ctrlz-dns.service", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE only"},
		{"unbound restarts itself", "systemd/ctrlz-unbound.service", "Restart=no", "Restart=always", "Restart must be no"},
		{"unbound enabled", "systemd/ctrlz-unbound-free.service", "UMask=0027\n", "UMask=0027\n[Install]\nWantedBy=multi-user.target\n", "must not be enabled"},
		{"free unbound without a memory ceiling", "systemd/ctrlz-unbound-free.service", "MemoryMax=512M\n", "", "MemoryMax"},
		{"free unbound with a per-cpu quota", "systemd/ctrlz-unbound-free.service", "MemoryMax=512M\n", "MemoryMax=512M\nCPUQuota=25%\n", "CPUQuota"},
		{"agent writes to the whole of /etc", "systemd/ctrlz-agent.service", "/etc/ctrlz/unbound /etc/ctrlz/chrony", "/etc", "ReadWritePaths"},
		{"agent with RestrictSUIDSGID", "systemd/ctrlz-agent.service", "RestrictRealtime=yes\n", "RestrictRealtime=yes\nRestrictSUIDSGID=yes\n", "RestrictSUIDSGID"},
		{"chronyd may read all of /etc", "apparmor/local-usr.sbin.chronyd", "/etc/ctrlz/chrony/** r,", "/etc/** r,", "apparmor chronyd"},
		{"chronyd may write the drop-in", "apparmor/local-usr.sbin.chronyd", "/etc/ctrlz/chrony/** r,", "/etc/ctrlz/chrony/** rw,", "must be read-only"},
		{"chronyd profile forgotten by files.conf", "files.conf", "apparmor/local-usr.sbin.chronyd /etc/apparmor.d/local/usr.sbin.chronyd 0644\n", "", "in no list"},
		{"core dumps kept", "coredump/ctrlz.conf", "Storage=none", "Storage=external", "Storage must be none"},
		{"ephemeral range reaches the free ports", "sysctl/60-ctrlz.conf", "32768 39999", "32768 60999", "ip_local_port_range"},
		{"syn cookies off", "sysctl/60-ctrlz.conf", "net.ipv4.tcp_syncookies = 1", "net.ipv4.tcp_syncookies = 0", "tcp_syncookies"},
		{"apport's core pattern left in place", "sysctl/60-ctrlz.conf", "kernel.core_pattern = |/usr/lib/systemd/systemd-coredump", "kernel.core_pattern = |/usr/share/apport/apport", "core_pattern"},
		{"no core pattern", "sysctl/60-ctrlz.conf", "kernel.core_pattern", "#kernel.core_pattern", "core_pattern"},
		{"small socket buffer", "sysctl/60-ctrlz.conf", "net.core.rmem_max = 7500000", "net.core.rmem_max = 212992", "quic-go wants"},
		{"chrony names a pool", "chrony/chrony.conf", "rtcsync\n", "rtcsync\npool ntp.ubuntu.com\n", "only source"},
		{"chrony without sourcedir", "chrony/chrony.conf", "sourcedir /etc/ctrlz/chrony", "", "sourcedir"},
		{"chrony reads the agent directory as a confdir", "chrony/chrony.conf", "sourcedir /etc/ctrlz/chrony", "confdir /etc/ctrlz/chrony", "confdir"},
		{"chrony leaves nosystemcert to the agent", "chrony/chrony.conf", "nosystemcert\n", "", "fix user"},
		{"chrony without its fixed user", "chrony/chrony.conf", "user _chrony\n", "", "fix user"},
		{"token in an argument", "install/node.sh", "--token-stdin is required", "--token X is required", "stdin only"},
		{"token to curl in an argument", "install/node.sh", `-H "@$TOK/token.hdr"`, `-H "Authorization: Bearer x"`, "-H @file"},
		{"apt with its sources", "install/apply.sh", "-o Dir::Etc::sourcelist=/dev/null ", "", "network sources off"},
		{"no restore on failure", "install/apply.sh", "trap cleanup EXIT", "trap : EXIT", "failure restore"},
		{"no dpkg lock wait in the real run", "install/apply.sh", " -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300 \\\n\t\t\tinstall", " -o Dpkg::Options::=--force-confold \\\n\t\t\tinstall", "wait for the dpkg lock"},
		{"no dpkg lock wait in the dry run", "install/apply.sh", " -o DPkg::Lock::Timeout=300 install", " install", "wait for the dpkg lock"},
		{"apt with --no-download", "install/apply.sh", "apt-get -y --no-install-recommends \\", "apt-get -y --no-download --no-install-recommends \\", "--no-download"},
		{"timesyncd purged by hand", "install/apply.sh", "set -- \"$@\" systemd-timesyncd-", "dpkg --purge systemd-timesyncd", "systemd-timesyncd"},
		{"services may start during apt", "install/apply.sh", "\thold_services\n", "", "hold_services"},
		{"distribution chrony config during apt", "install/apply.sh", "\tput_chrony_conf\n", "", "put_chrony_conf"},
		{"apt update in the install", "install/apply.sh", "\tset -- \"$STAGE\"/debs/*.deb\n", "\tapt-get update\n\tset -- \"$STAGE\"/debs/*.deb\n", "network or the package index"},
	}
	for _, c := range cases {
		root := copyTree(t)
		mutate(t, root, c.file, c.from, c.to)
		fs := Check(root)
		if !hasFinding(fs, c.want) {
			t.Errorf("%s: no finding mentioning %q; got %v", c.name, c.want, toStrings(fs))
		}
	}
}

func TestParsersRefuseBadLines(t *testing.T) {
	if _, err := ParseAccounts("user a b\n"); err == nil {
		t.Error("short user line accepted")
	}
	if _, err := ParseAccounts("wat x\n"); err == nil {
		t.Error("unknown line accepted")
	}
	if _, err := ParseDirs("/a b c\n"); err == nil {
		t.Error("short dirs line accepted")
	}
	if _, err := ParseFiles("a b\n"); err == nil {
		t.Error("short files line accepted")
	}
	u := ParseUnit("[Service]\nCapabilityBoundingSet=CAP_A\nCapabilityBoundingSet=\n")
	if len(u.Words("Service.CapabilityBoundingSet")) != 0 {
		t.Error("an empty assignment must reset, as systemd does")
	}
	if _, ok := ParseUnit("[Service]\nUser=a\nUser=b\n").One("Service.User"); ok {
		t.Error("a key set twice must be reported")
	}
}

func TestApparmorAdditionsAreNarrow(t *testing.T) {
	for _, c := range []struct{ name, from, to, want string }{
		{"the whole of /etc", "/etc/ctrlz/unbound/free.conf r,\n", "/etc/ctrlz/unbound/free.conf r,\n/etc/** r,\n", "paths are"},
		{"execute", "/usr/share/dns/root.key r,", "/usr/share/dns/root.key rix,", "permissions"},
		{"write the config", "/etc/ctrlz/unbound/identified.conf r,", "/etc/ctrlz/unbound/identified.conf rw,", "read-only"},
		{"a missing directory", "/run/ctrlz-unbound-free/ rw,\n", "", "paths are"},
		{"not a rule", "/usr/share/dns/root.hints r,", "/usr/share/dns/root.hints", "is not"},
	} {
		root := copyTree(t)
		mutate(t, root, "apparmor/local-usr.sbin.unbound", c.from, c.to)
		if fs := Check(root); !hasFinding(fs, c.want) {
			t.Errorf("%s: no finding mentioning %q; got %v", c.name, c.want, toStrings(fs))
		}
	}
}
