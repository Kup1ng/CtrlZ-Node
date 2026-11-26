// Package pkgcheck is the structural check of the node packaging (p4-nodes 11.2,
// N11): it reads the rendered files of packaging/ and fails on anything that
// widens what the node's processes may do.
//
// Why a parser and not a lint: N11 names two mutants (a polkit rule that allows
// manage-units for every unit, and an agent that may run apt or dpkg) and a test
// must see them. The check reads the same files the install copies, so the
// install and the test cannot drift apart, and it runs on every platform, which
// the container install test does not.
package pkgcheck

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one failed rule.
type Finding string

// Unit is a parsed systemd unit: every key's values in file order, per section.
type Unit map[string][]string

// ParseUnit reads a unit file. Comments and blank lines are skipped; a key
// repeated gathers its values; an empty assignment (`CapabilityBoundingSet=`)
// resets in systemd, which Values reflects by clearing earlier values.
func ParseUnit(text string) Unit {
	u := Unit{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if l[0] == '[' && strings.HasSuffix(l, "]") {
			section = l[1 : len(l)-1]
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		key := section + "." + strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if v == "" {
			u[key] = nil
			continue
		}
		u[key] = append(u[key], v)
	}
	return u
}

// One returns the single value of a key, "" when unset, and false when it is set
// more than once (a second assignment could undo the first).
func (u Unit) One(key string) (string, bool) {
	v := u[key]
	switch len(v) {
	case 0:
		return "", true
	case 1:
		return v[0], true
	}
	return "", false
}

// Words returns the space-separated words of all values of a key.
func (u Unit) Words(key string) []string {
	var out []string
	for _, v := range u[key] {
		out = append(out, strings.Fields(v)...)
	}
	return out
}

// Polkit is what a rules file grants.
type Polkit struct {
	User  string
	Units []string
	Verbs []string
	// Actions are the polkit action ids compared with action.id.
	Actions []string
	// Yes counts the `polkit.Result.YES` returns; the rule has one.
	Yes int
	// UnitFilter and VerbFilter say the YES is conditioned on the arrays.
	UnitFilter, VerbFilter bool
	// Or is true when the rule has an alternative (||) anywhere: a grant is a chain of
	// conditions that must all hold.
	Or bool
	// DefaultNo is true when the rule ends by refusing everything it did not grant.
	DefaultNo bool
}

var (
	reArray  = regexp.MustCompile(`var\s+(\w+)\s*=\s*\[([^\]]*)\]`)
	reStr    = regexp.MustCompile(`"([^"]*)"`)
	reUser   = regexp.MustCompile(`subject\.user\s*!==\s*"([^"]*)"`)
	reAction = regexp.MustCompile(`action\.id\s*===\s*"([^"]*)"`)
)

// ParsePolkit reads the rule text.
func ParsePolkit(text string) Polkit {
	var p Polkit
	var noComments []string
	for _, l := range strings.Split(text, "\n") {
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		noComments = append(noComments, l)
	}
	t := strings.Join(noComments, "\n")
	if m := reUser.FindStringSubmatch(t); m != nil {
		p.User = m[1]
	}
	for _, m := range reArray.FindAllStringSubmatch(t, -1) {
		var vals []string
		for _, s := range reStr.FindAllStringSubmatch(m[2], -1) {
			vals = append(vals, s[1])
		}
		switch m[1] {
		case "units":
			p.Units = vals
		case "verbs":
			p.Verbs = vals
		}
	}
	for _, m := range reAction.FindAllStringSubmatch(t, -1) {
		p.Actions = append(p.Actions, m[1])
	}
	p.Yes = strings.Count(t, "polkit.Result.YES")
	p.Or = strings.Contains(t, "||")
	p.UnitFilter = strings.Contains(t, "units.indexOf(action.lookup(\"unit\"))")
	p.VerbFilter = strings.Contains(t, "verbs.indexOf(action.lookup(\"verb\"))")
	trim := strings.TrimSpace(t)
	p.DefaultNo = strings.Contains(trim, "return polkit.Result.NO;\n});") || strings.HasSuffix(strings.Join(strings.Fields(trim), " "), "return polkit.Result.NO; });")
	return p
}

// Account lists.
type Accounts struct {
	Groups  []string
	Users   map[string]User
	Members map[string][]string // group -> supplementary members
}

// User is a line `user NAME PRIMARY HOME`.
type User struct{ Name, Primary, Home string }

// ParseAccounts reads accounts.conf.
func ParseAccounts(text string) (Accounts, error) {
	a := Accounts{Users: map[string]User{}, Members: map[string][]string{}}
	for _, f := range lines(text) {
		switch f[0] {
		case "group":
			if len(f) != 2 {
				return a, fmt.Errorf("accounts: bad group line %q", strings.Join(f, " "))
			}
			a.Groups = append(a.Groups, f[1])
		case "user":
			if len(f) != 4 {
				return a, fmt.Errorf("accounts: bad user line %q", strings.Join(f, " "))
			}
			a.Users[f[1]] = User{f[1], f[2], f[3]}
		case "member":
			if len(f) != 3 {
				return a, fmt.Errorf("accounts: bad member line %q", strings.Join(f, " "))
			}
			a.Members[f[2]] = append(a.Members[f[2]], f[1])
		default:
			return a, fmt.Errorf("accounts: unknown line %q", f[0])
		}
	}
	return a, nil
}

// Dir is a line of dirs.conf.
type Dir struct {
	Path, Owner, Group, Mode string
}

// ParseDirs reads dirs.conf.
func ParseDirs(text string) ([]Dir, error) {
	var out []Dir
	for _, f := range lines(text) {
		if len(f) != 4 {
			return nil, fmt.Errorf("dirs: bad line %q", strings.Join(f, " "))
		}
		out = append(out, Dir{f[0], f[1], f[2], f[3]})
	}
	return out, nil
}

// File is a line of files.conf.
type File struct{ Src, Dest, Mode string }

// ParseFiles reads files.conf.
func ParseFiles(text string) ([]File, error) {
	var out []File
	for _, f := range lines(text) {
		if len(f) != 3 {
			return nil, fmt.Errorf("files: bad line %q", strings.Join(f, " "))
		}
		out = append(out, File{f[0], f[1], f[2]})
	}
	return out, nil
}

func lines(text string) [][]string {
	var out [][]string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' {
			continue
		}
		out = append(out, strings.Fields(l))
	}
	return out
}

// What 7.1 fixes, in one place. A change here is a change of the design.
var (
	unitNames = []string{"ctrlz-dns", "ctrlz-agent", "ctrlz-proxy", "ctrlz-unbound", "ctrlz-unbound-free"}
	// AgentUnits are the units the agent may start, stop and restart.
	AgentUnits = []string{"chrony.service", "ctrlz-dns.service", "ctrlz-unbound-free.service", "ctrlz-unbound.service"}
	// AgentVerbs are the verbs it may use on them.
	AgentVerbs = []string{"restart", "start", "stop"}
	// AgentWritable are the agent unit's ReadWritePaths.
	AgentWritable = []string{"/etc/ctrlz/chrony", "/etc/ctrlz/unbound", "/var/lib/ctrlz"}
	// ctrlzMembers are the only members of group ctrlz.
	ctrlzMembers = []string{"ctrlz-agent", "ctrlz-dns"}
	// groupShared are the directories of /var/lib/ctrlz that dns reads: group ctrlz and setgid.
	groupShared = []string{"/var/lib/ctrlz", "/var/lib/ctrlz/blobs", "/var/lib/ctrlz/image", "/var/lib/ctrlz/config"}
	// installInputs are packaging files that are not copied by files.conf.
	installInputs = map[string]bool{
		"accounts.conf": true, "dirs.conf": true, "files.conf": true,
		"install/node.sh": true, "install/apply.sh": true,
	}
)

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

// Check reads the packaging directory at root and returns every failed rule.
func Check(root string) []Finding {
	var out []Finding
	bad := func(format string, a ...any) { out = append(out, Finding(fmt.Sprintf(format, a...))) }
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			bad("%s: %v", rel, err)
			return ""
		}
		return string(b)
	}

	acc, err := ParseAccounts(read("accounts.conf"))
	if err != nil {
		bad("%v", err)
	}
	dirs, err := ParseDirs(read("dirs.conf"))
	if err != nil {
		bad("%v", err)
	}
	files, err := ParseFiles(read("files.conf"))
	if err != nil {
		bad("%v", err)
	}

	checkAccounts(acc, bad)
	checkDirs(dirs, acc, bad)
	checkFiles(root, files, bad)

	units := map[string]Unit{}
	for _, n := range unitNames {
		units[n] = ParseUnit(read("systemd/" + n + ".service"))
	}
	checkUnits(units, acc, dirs, bad)
	checkPolkit(ParsePolkit(read("polkit/50-ctrlz-agent.rules")), bad)
	checkHost(read("coredump/ctrlz.conf"), read("sysctl/60-ctrlz.conf"), read("chrony/chrony.conf"), bad)
	checkApparmor("unbound", read("apparmor/local-usr.sbin.unbound"), apparmorPaths, bad)
	checkApparmor("chronyd", read("apparmor/local-usr.sbin.chronyd"), apparmorChronyPaths, bad)
	checkScripts(read("install/node.sh"), read("install/apply.sh"), bad)
	return out
}

func checkAccounts(a Accounts, bad func(string, ...any)) {
	if !sameSet(a.Members["ctrlz"], ctrlzMembers) {
		bad("group ctrlz has members %v, want exactly %v", a.Members["ctrlz"], ctrlzMembers)
	}
	have := map[string]bool{}
	for _, g := range a.Groups {
		have[g] = true
	}
	own := map[string]string{}
	for n, u := range a.Users {
		if !have[u.Primary] {
			bad("user %s: primary group %s is not declared", n, u.Primary)
		}
		if u.Primary == "ctrlz" {
			bad("user %s has group ctrlz as its primary group; it is for the two members only", n)
		}
		if prev, dup := own[u.Primary]; dup {
			bad("users %s and %s share the primary group %s", prev, n, u.Primary)
		}
		own[u.Primary] = n
		if strings.Contains(u.Home, " ") {
			bad("user %s: bad home", n)
		}
	}
	// ctrlz-proxy and the Unbound users have groups of their own (R16): none of
	// them may be in ctrlz, or in the other Unbound's group.
	for g, ms := range a.Members {
		for _, m := range ms {
			if _, ok := a.Users[m]; !ok {
				bad("member %s of %s is not a declared user", m, g)
			}
			if g == "ctrlz" && (m == "ctrlz-proxy" || strings.HasPrefix(m, "ctrlz-unbound")) {
				bad("%s must not be in group ctrlz", m)
			}
		}
	}
	for _, g := range []string{"ctrlz-unbound", "ctrlz-unbound-free"} {
		if !sameSet(a.Members[g], []string{"ctrlz-agent"}) {
			bad("group %s has members %v, want only ctrlz-agent (its control socket)", g, a.Members[g])
		}
	}
}

func checkDirs(dirs []Dir, a Accounts, bad func(string, ...any)) {
	by := map[string]Dir{}
	for _, d := range dirs {
		by[d.Path] = d
		if _, ok := a.Users[d.Owner]; !ok && d.Owner != "root" {
			bad("directory %s: owner %s is not a declared user", d.Path, d.Owner)
		}
		if len(d.Mode) != 4 || strings.ContainsAny(d.Mode, "89") {
			bad("directory %s: mode %s", d.Path, d.Mode)
			continue
		}
		if d.Mode[3] != '0' && d.Mode[3] != '5' {
			bad("directory %s: mode %s is open to others", d.Path, d.Mode)
		}
	}
	for _, p := range groupShared {
		d, ok := by[p]
		if !ok {
			bad("directory %s is missing", p)
			continue
		}
		if d.Group != "ctrlz" || d.Mode[0] != '2' {
			bad("directory %s: want group ctrlz and setgid, have %s %s", p, d.Group, d.Mode)
		}
	}
	for _, p := range []string{"/var/lib/ctrlz/keys", "/var/lib/ctrlz/state", "/var/lib/ctrlz/bundles"} {
		if d, ok := by[p]; !ok || d.Mode != "0700" {
			bad("directory %s must exist and be 0700", p)
		}
	}
	for _, p := range AgentWritable {
		d, ok := by[p]
		if !ok || d.Owner != "ctrlz-agent" {
			bad("the agent's writable path %s must be made and owned by ctrlz-agent", p)
		}
	}
}

func checkFiles(root string, files []File, bad func(string, ...any)) {
	listed := map[string]bool{}
	for _, f := range files {
		listed[f.Src] = true
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f.Src))); err != nil {
			bad("files.conf names %s, which does not exist", f.Src)
		}
		if f.Mode != "0644" && f.Mode != "0755" {
			bad("files.conf: %s has the mode %s", f.Dest, f.Mode)
		}
		if !strings.HasPrefix(f.Dest, "/etc/") {
			bad("files.conf: %s is outside /etc", f.Dest)
		}
	}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if !listed[rel] && !installInputs[rel] {
			bad("packaging/%s is in no list: it would never be installed", rel)
		}
		return nil
	})
}

func checkUnits(units map[string]Unit, acc Accounts, dirs []Dir, bad func(string, ...any)) {
	for name, u := range units {
		one := func(key string) string {
			v, ok := u.One(key)
			if !ok {
				bad("%s: %s is set more than once", name, key)
			}
			return v
		}
		if one("Service.LimitCORE") != "0" {
			bad("%s: LimitCORE must be 0", name)
		}
		if one("Service.NoNewPrivileges") != "yes" {
			bad("%s: NoNewPrivileges must be yes", name)
		}
		if one("Service.ProtectSystem") != "strict" {
			bad("%s: ProtectSystem must be strict", name)
		}
		if one("Service.PrivateTmp") != "yes" {
			bad("%s: PrivateTmp must be yes", name)
		}
		user := one("Service.User")
		if _, ok := acc.Users[user]; !ok {
			bad("%s: User=%s is not a declared user", name, user)
		}
		if exec := one("Service.ExecStart"); strings.HasPrefix(exec, "+") || strings.HasPrefix(exec, "!") || strings.HasPrefix(exec, "-") {
			bad("%s: ExecStart has a privilege prefix", name)
		}
		for _, k := range []string{"Service.ExecStartPre", "Service.ExecStartPost", "Service.ExecStop", "Service.ExecReload", "Service.PermissionsStartOnly"} {
			if len(u[k]) > 0 {
				bad("%s: %s is not part of the design", name, k)
			}
		}
		if g := one("Service.Group"); g == "" {
			bad("%s: Group must be set", name)
		}
		if len(u.Words("Service.SupplementaryGroups")) > 0 {
			bad("%s: groups come from accounts.conf, not SupplementaryGroups", name)
		}
	}

	dns := units["ctrlz-dns"]
	if v, _ := dns.One("Service.User"); v != "ctrlz-dns" {
		bad("ctrlz-dns runs as %q", v)
	}
	if !sameSet(dns.Words("Service.CapabilityBoundingSet"), []string{"CAP_NET_BIND_SERVICE"}) || !sameSet(dns.Words("Service.AmbientCapabilities"), []string{"CAP_NET_BIND_SERVICE"}) {
		bad("ctrlz-dns: capabilities must be CAP_NET_BIND_SERVICE only")
	}
	if len(dns.Words("Service.ReadWritePaths")) > 0 {
		bad("ctrlz-dns writes nowhere")
	}

	agent := units["ctrlz-agent"]
	if v, _ := agent.One("Service.User"); v != "ctrlz-agent" {
		bad("ctrlz-agent runs as %q", v)
	}
	if g, _ := agent.One("Service.Group"); g != "ctrlz" {
		bad("ctrlz-agent runs in group %q, want ctrlz (it owns /run/ctrlz)", g)
	}
	if !sameSet(agent.Words("Service.CapabilityBoundingSet"), []string{"CAP_NET_ADMIN"}) || !sameSet(agent.Words("Service.AmbientCapabilities"), []string{"CAP_NET_ADMIN"}) {
		bad("ctrlz-agent: capabilities must be CAP_NET_ADMIN only")
	}
	if !sameSet(agent.Words("Service.ReadWritePaths"), AgentWritable) {
		bad("ctrlz-agent: ReadWritePaths is %v, want exactly %v", agent.Words("Service.ReadWritePaths"), AgentWritable)
	}
	for _, k := range []string{"Service.ReadOnlyPaths", "Service.InaccessiblePaths", "Service.BindPaths", "Service.BindReadOnlyPaths", "Service.TemporaryFileSystem"} {
		if len(agent[k]) > 0 {
			bad("ctrlz-agent: %s changes the sandbox of 7.1", k)
		}
	}
	if v, _ := agent.One("Service.RestrictSUIDSGID"); v == "yes" {
		bad("ctrlz-agent: RestrictSUIDSGID=yes makes the store's chmod of a setgid directory fail with EPERM, so the agent would never start")
	}
	if len(agent["Service.AmbientCapabilities"]) == 0 {
		bad("ctrlz-agent: no ambient capability, so its nft child has none")
	}

	for _, n := range []string{"ctrlz-unbound", "ctrlz-unbound-free"} {
		u := units[n]
		if v, _ := u.One("Service.Restart"); v != "no" {
			bad("%s: Restart must be no (the agent supervises, after its start checks)", n)
		}
		if v, _ := u.One("Service.StandardOutput"); v != "null" {
			bad("%s: StandardOutput must be null", n)
		}
		if v, _ := u.One("Service.StandardError"); v != "null" {
			bad("%s: StandardError must be null", n)
		}
		if len(u.Words("Service.CapabilityBoundingSet")) != 0 || len(u["Service.AmbientCapabilities"]) != 0 {
			bad("%s: no capability", n)
		}
		if len(u["Install.WantedBy"]) != 0 {
			bad("%s: must not be enabled; only the agent starts it", n)
		}
		if _, ok := u["Service.RuntimeDirectory"]; !ok {
			bad("%s: no RuntimeDirectory for pid and control.sock", n)
		}
	}
	if v, _ := units["ctrlz-unbound"].One("Service.User"); v != "ctrlz-unbound" {
		bad("ctrlz-unbound runs as %q", v)
	}
	free := units["ctrlz-unbound-free"]
	if v, _ := free.One("Service.User"); v != "ctrlz-unbound-free" {
		bad("ctrlz-unbound-free runs as %q", v)
	}
	if v, _ := free.One("Service.MemoryMax"); v == "" {
		bad("ctrlz-unbound-free: MemoryMax is required")
	}
	if len(free["Service.CPUQuota"]) != 0 {
		bad("ctrlz-unbound-free: CPUQuota is per CPU; the install writes the host's share to a drop-in")
	}
	for _, n := range []string{"ctrlz-unbound", "ctrlz-unbound-free"} {
		ex, _ := units[n].One("Service.ExecStart")
		conf := map[string]string{"ctrlz-unbound": "identified.conf", "ctrlz-unbound-free": "free.conf"}[n]
		if ex != "/usr/sbin/unbound -d -c /etc/ctrlz/unbound/"+conf {
			bad("%s: ExecStart is %q", n, ex)
		}
	}
	proxy := units["ctrlz-proxy"]
	if v, _ := proxy.One("Service.User"); v != "ctrlz-proxy" {
		bad("ctrlz-proxy runs as %q", v)
	}
	if g, _ := proxy.One("Service.Group"); g != "ctrlz-proxy" {
		bad("ctrlz-proxy must have a group of its own, has %q", g)
	}
	for _, n := range []string{"ctrlz-unbound", "ctrlz-unbound-free"} {
		if g, _ := units[n].One("Service.Group"); g != n {
			bad("%s must run in a group of its own, has %q", n, g)
		}
	}
	// The ReadWritePaths of the agent must be directories the install makes.
	made := map[string]bool{}
	for _, d := range dirs {
		made[d.Path] = true
	}
	for _, p := range agent.Words("Service.ReadWritePaths") {
		if !made[p] {
			bad("ReadWritePaths %s is not made by dirs.conf; the unit would not start", p)
		}
	}
}

func checkPolkit(p Polkit, bad func(string, ...any)) {
	if p.User != "ctrlz-agent" {
		bad("polkit: the rule is for user %q, want ctrlz-agent", p.User)
	}
	if !sameSet(p.Units, AgentUnits) {
		bad("polkit: units are %v, want exactly %v", p.Units, AgentUnits)
	}
	if !sameSet(p.Verbs, AgentVerbs) {
		bad("polkit: verbs are %v, want exactly %v", p.Verbs, AgentVerbs)
	}
	if !sameSet(p.Actions, []string{"org.freedesktop.systemd1.manage-units"}) {
		bad("polkit: actions are %v, want only manage-units", p.Actions)
	}
	if p.Yes != 1 {
		bad("polkit: the rule grants in %d places, want 1", p.Yes)
	}
	if !p.UnitFilter || !p.VerbFilter || p.Or {
		bad("polkit: the grant is not conditioned on the unit and the verb")
	}
	if !p.DefaultNo {
		bad("polkit: the rule does not refuse everything else for the agent")
	}
}

var reSysctlRange = regexp.MustCompile(`(?m)^net\.ipv4\.ip_local_port_range\s*=\s*32768\s+39999\s*$`)
var reSyncookies = regexp.MustCompile(`(?m)^net\.ipv4\.tcp_syncookies\s*=\s*[12]\s*$`)
var reBuf = regexp.MustCompile(`(?m)^net\.core\.(rmem_max|wmem_max)\s*=\s*(\d+)\s*$`)

// The agent accepts a plain pattern or systemd-coredump's pipe; apport's pipe (the stock
// Ubuntu Server value) keeps both Unbound units from starting, so the install must set one.
var reCorePattern = regexp.MustCompile(`(?m)^kernel\.core_pattern\s*=\s*\|/usr/lib/systemd/systemd-coredump(\s.*)?$`)

func checkHost(coredump, sysctl, chrony string, bad func(string, ...any)) {
	u := ParseUnit(coredump)
	if v, _ := u.One("Coredump.Storage"); v != "none" {
		bad("coredump drop-in: Storage must be none")
	}
	if v, _ := u.One("Coredump.ProcessSizeMax"); v != "0" {
		bad("coredump drop-in: ProcessSizeMax must be 0")
	}
	if !reSysctlRange.MatchString(sysctl) {
		bad("sysctl: net.ipv4.ip_local_port_range must be 32768 39999")
	}
	if !reSyncookies.MatchString(sysctl) {
		bad("sysctl: net.ipv4.tcp_syncookies must be 1 (T-017)")
	}
	seen := 0
	for _, m := range reBuf.FindAllStringSubmatch(sysctl, -1) {
		seen++
		var n int
		fmt.Sscan(m[2], &n)
		if n < 7_500_000 {
			bad("sysctl: %s is %d, quic-go wants about 7.5 MB", m[1], n)
		}
	}
	if seen != 2 {
		bad("sysctl: rmem_max and wmem_max must both be set")
	}
	if !reCorePattern.MatchString(sysctl) {
		bad("sysctl: kernel.core_pattern must be the systemd-coredump pipe (apport's pipe stops both Unbound units)")
	}
	if !strings.Contains(sysctl, "nf_conntrack_max") {
		bad("sysctl: nf_conntrack_max is not set")
	}
	// chronyd parses chrony.conf as root and the agent writes into the sourcedir, so
	// everything that is not a source line must be fixed here (R16) and the agent's
	// directory must be read as a sourcedir, never as a confdir or an include.
	hasSourcedir, hasUser, hasNoSys, hasCerts := false, false, false, false
	for _, f := range lines(chrony) {
		switch f[0] {
		case "sourcedir":
			hasSourcedir = len(f) == 2 && f[1] == "/etc/ctrlz/chrony"
		case "user":
			hasUser = len(f) == 2 && f[1] == "_chrony"
		case "nosystemcert":
			hasNoSys = len(f) == 1
		case "ntstrustedcerts":
			hasCerts = len(f) == 2 && f[1] == "/etc/ctrlz/chrony/node_ca.pem"
		case "confdir", "include", "pool", "server", "peer", "allow", "refclock":
			bad("chrony.conf holds %q; the panel is the only source and the agent writes it as a sourcedir file", f[0])
		}
	}
	if !hasSourcedir {
		bad("chrony.conf must say sourcedir /etc/ctrlz/chrony")
	}
	if !hasUser || !hasNoSys || !hasCerts {
		bad("chrony.conf must fix user _chrony, nosystemcert and ntstrustedcerts /etc/ctrlz/chrony/node_ca.pem itself, not leave them to the agent's directory")
	}
}

// checkScripts holds the greppable half of the install rules; the container test
// holds the rest by running the script.
func checkScripts(node, apply string, bad func(string, ...any)) {
	node, apply = code(node), code(apply)
	if strings.Contains(node, "--token ") || strings.Contains(node, "--token=") {
		bad("node.sh takes the token on stdin only")
	}
	if !regexp.MustCompile(`-H\s+"?@`).MatchString(node) {
		bad("node.sh must hand the token to curl with -H @file")
	}
	if !strings.Contains(node, "--pinnedpubkey") {
		bad("node.sh must fetch under the pin")
	}
	for _, s := range []string{"Dir::Etc::sourcelist=/dev/null", "Dir::Etc::sourceparts=/dev/null"} {
		if !strings.Contains(apply, s) {
			bad("apply.sh: apt must run with the network sources off (%s missing)", s)
		}
	}
	// The install must not leave a node down when it fails and must not let a package
	// start a service (the container test runs these paths).
	for _, s := range []string{"trap cleanup EXIT", "\n\thold_services\n", "\n\tput_chrony_conf\n"} {
		if !strings.Contains(apply, s) {
			bad("apply.sh: %q is missing (failure restore, no service starts or distribution chrony during apt)", strings.TrimSpace(s))
		}
	}
	// The dry run and the real run both wait for the dpkg lock, and the real run takes
	// systemd-timesyncd out in the transaction that installs chrony (r5-1, r5-3, r5-8).
	if strings.Count(apply, "DPkg::Lock::Timeout=300") < 2 {
		bad("apply.sh: the dry run and the real apt run must both wait for the dpkg lock (DPkg::Lock::Timeout=300)")
	}
	if !strings.Contains(apply, "systemd-timesyncd-") {
		bad("apply.sh: systemd-timesyncd must be removed inside the apt transaction that installs chrony")
	}
	// Real apt refuses --no-download together with local .deb files, and a purge by
	// hand runs without the dpkg lock wait and cannot be undone: with no package
	// source, apt cannot find a purged package again.
	for _, s := range []string{"--no-download", "APT::Get::Remove=false", "dpkg --purge"} {
		if strings.Contains(apply, s) {
			bad("apply.sh must not use %q", s)
		}
	}
	for _, l := range strings.Split(apply, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "apt-get update") || strings.Contains(l, "apt update") || strings.Contains(l, "curl ") || strings.Contains(l, "wget ") {
			bad("apply.sh reaches for the network or the package index: %q", l)
		}
	}
}

// code drops the comment lines of a shell script, so a rule that looks for a
// construct is not satisfied by the comment that explains it.
func code(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// apparmorPaths are the only paths the local AppArmor additions may name: the two
// units' own directories, their two config files and the DNS root data. Anything
// wider would give the Unbound processes more of the host than 7.1 does.
var apparmorPaths = []string{
	"/etc/ctrlz/unbound/identified.conf", "/etc/ctrlz/unbound/free.conf",
	"/run/ctrlz-unbound/", "/run/ctrlz-unbound/**", "/run/ctrlz-unbound-free/", "/run/ctrlz-unbound-free/**",
	"/var/lib/ctrlz-unbound/", "/var/lib/ctrlz-unbound/**", "/var/lib/ctrlz-unbound-free/", "/var/lib/ctrlz-unbound-free/**",
	"/usr/share/dns/root.key", "/usr/share/dns/root.hints",
}

func checkApparmor(name, text string, want []string, bad func(string, ...any)) {
	var have []string
	for _, f := range lines(text) {
		if len(f) != 2 || !strings.HasSuffix(f[1], ",") {
			bad("apparmor %s: line %q is not `PATH PERMISSIONS,`", name, strings.Join(f, " "))
			continue
		}
		have = append(have, f[0])
		perms := strings.TrimSuffix(f[1], ",")
		if strings.Trim(perms, "rwk") != "" || strings.Contains(perms, "x") {
			bad("apparmor %s: %s has the permissions %s", name, f[0], perms)
		}
		if strings.HasPrefix(f[0], "/etc/ctrlz/") && perms != "r" || strings.HasPrefix(f[0], "/usr/share/dns/") && perms != "r" {
			bad("apparmor %s: %s must be read-only", name, f[0])
		}
	}
	if !sameSet(have, want) {
		bad("apparmor %s: the paths are %v, want exactly %v", name, have, want)
	}
}

// apparmorChronyPaths is the one directory chronyd reads from the node: the agent's
// time-source drop-in and the panel CA beside it, read-only.
var apparmorChronyPaths = []string{"/etc/ctrlz/chrony/", "/etc/ctrlz/chrony/**"}
