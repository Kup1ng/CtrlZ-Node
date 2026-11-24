package unbound

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
)

func render(t *testing.T, k Kind, mut ...func(*Params)) string {
	t.Helper()
	p := DefaultParams(k)
	for _, m := range mut {
		m(&p)
	}
	s, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func listOf(conf, key string) []netip.Prefix {
	var out []netip.Prefix
	for _, line := range strings.Split(conf, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+": "); ok {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				panic(err)
			}
			out = append(out, p)
		}
	}
	return out
}

// T-031: the private-address list of both processes is derived from netclass.
// Every address that netclass calls non-public is in both lists; the only
// addresses the lists hold beyond that are the Teredo block (nets package).
func TestPrivateAddressMatchesNetclassOnBoth(t *testing.T) {
	id, fr := render(t, Identified), render(t, Free)
	li, lf := listOf(id, "private-address"), listOf(fr, "private-address")
	if len(li) == 0 || len(li) != len(lf) {
		t.Fatalf("lists differ in length: %d and %d", len(li), len(lf))
	}
	for i := range li {
		if li[i] != lf[i] {
			t.Fatalf("private-address differs between the two processes at %d", i)
		}
	}
	teredo := netip.MustParsePrefix("2001::/32")
	rng := rand.New(rand.NewSource(3))
	probe := func(a netip.Addr) {
		want := netclass.ClassOf(a) != netclass.Public
		for name, l := range map[string][]netip.Prefix{"identified": li, "free": lf} {
			got := nets.Contains(l, a)
			if want && !got {
				t.Fatalf("%s: %s is non-public for netclass and not in private-address", name, a)
			}
			if got && !want && !teredo.Contains(a) {
				t.Fatalf("%s: %s is in private-address and public for netclass", name, a)
			}
		}
	}
	for _, s := range []string{
		"10.1.2.3", "172.16.0.1", "172.32.0.1", "192.168.5.5", "127.0.0.1", "169.254.1.1", "100.64.0.1", "100.128.0.1",
		"224.0.0.1", "0.1.2.3", "240.0.0.1", "255.255.255.255", "10.10.34.7", "8.8.8.8", "1.1.1.1", "198.18.0.1", "198.20.0.1",
		"::1", "::", "fe80::1", "fd00::1", "fec0::1", "ff02::1", "2001:db8::1", "2001:4860:4860::8888",
		"::ffff:10.0.0.1", "::ffff:8.8.8.8", "64:ff9b::192.168.1.1", "64:ff9b::8.8.8.8", "2002:c0a8:0101::1", "2002:0808:0808::1",
	} {
		probe(netip.MustParseAddr(s))
	}
	for i := 0; i < 50000; i++ {
		var b [4]byte
		rng.Read(b[:])
		probe(netip.AddrFrom4(b))
		var b6 [16]byte
		rng.Read(b6[:])
		probe(netip.AddrFrom16(b6))
	}
}

// The free process is the identified one with only the keys of SC 5.2a and
// T-559 changed.
func TestFreeDiffersOnlyInItsKeys(t *testing.T) {
	a, b := settings(render(t, Identified)), settings(render(t, Free))
	keyOf := func(s string) string { k, _, _ := strings.Cut(s, ":"); return k }
	count := func(l []string) map[string]string {
		m := map[string]string{}
		for _, s := range l {
			m[s] = keyOf(s)
		}
		return m
	}
	ma, mb := count(a), count(b)
	differing := map[string]bool{}
	for s, k := range ma {
		if _, ok := mb[s]; !ok {
			differing[k] = true
		}
	}
	for s, k := range mb {
		if _, ok := ma[s]; !ok {
			differing[k] = true
		}
	}
	allowed := map[string]bool{
		"interface": true, "pidfile": true, "username": true, "directory": true, "control-interface": true,
		"unwanted-reply-threshold": true, "serve-expired": true, "serve-expired-ttl": true, "num-queries-per-thread": true,
		"ratelimit": true, "ratelimit-for-domain": true, "outgoing-port-permit": true, "outgoing-range": true, "num-threads": true,
	}
	for k := range differing {
		if !allowed[k] {
			t.Errorf("key %q differs between the two processes but is not a key of SC 5.2a", k)
		}
	}
	for _, k := range []string{"unwanted-reply-threshold", "serve-expired", "ratelimit", "ratelimit-for-domain", "outgoing-port-permit"} {
		if !differing[k] {
			t.Errorf("key %q should differ", k)
		}
	}
}

func TestPinnedValues(t *testing.T) {
	id, fr := render(t, Identified), render(t, Free)
	for name, conf := range map[string]string{"identified": id, "free": fr} {
		for _, want := range []string{
			"verbosity: 0", "use-syslog: no", `logfile: "/dev/null"`, "log-queries: no", "log-replies: no", "log-servfail: no",
			"log-local-actions: no", "log-tag-queryreply: no", "val-log-level: 0", "use-caps-for-id: yes",
			"max-sent-count: 32", "discard-timeout: 1900", "wait-limit: 1000", `trust-anchor-file: "/usr/share/dns/root.key"`,
		} {
			if !strings.Contains(conf, "\n    "+want+"\n") {
				t.Errorf("%s: missing %q", name, want)
			}
		}
		if strings.Contains(conf, "dnstap") || strings.Contains(conf, "include") {
			t.Errorf("%s: dnstap or include present", name)
		}
	}
	if !strings.Contains(id, "unwanted-reply-threshold: 10000000") || !strings.Contains(id, "serve-expired: yes") {
		t.Error("identified: threshold or serve-expired wrong")
	}
	for _, want := range []string{"unwanted-reply-threshold: 0", "serve-expired: no", "ratelimit: 200",
		"ratelimit-for-domain: com 50", "ratelimit-for-domain: net 50", "ratelimit-for-domain: org 50"} {
		if !strings.Contains(fr, want) {
			t.Errorf("free: missing %q", want)
		}
	}
	if strings.Contains(id, "ratelimit") {
		t.Error("identified process must not carry the free rate limits")
	}
	if FreeInflightCap > FreeRequestList() {
		t.Error("free_inflight exceeds the free request list")
	}
}

func TestDoNotQueryHoldsNodesAndNonPublic(t *testing.T) {
	node := netip.MustParseAddr("203.0.114.9")
	for _, k := range []Kind{Identified, Free} {
		conf := render(t, k, func(p *Params) { p.DoNotQuery = nets.ForAddr(node) })
		l := listOf(conf, "do-not-query-address")
		for _, s := range []string{"203.0.114.9", "::ffff:203.0.114.9", "64:ff9b::203.0.114.9", "2002:cb00:7209::1", "10.1.1.1", "fe80::1"} {
			if !nets.Contains(l, netip.MustParseAddr(s)) {
				t.Errorf("%s: %s not in do-not-query-address", k, s)
			}
		}
	}
}

func TestOutgoingInterfaceOnlyForFree(t *testing.T) {
	addr := netip.MustParseAddr("198.51.101.7")
	fr := render(t, Free, func(p *Params) { p.OutgoingInterface = addr })
	if !strings.Contains(fr, "outgoing-interface: 198.51.101.7") {
		t.Error("free process lacks the T-561 outgoing interface")
	}
	if strings.Contains(render(t, Free), "outgoing-interface") {
		t.Error("outgoing-interface set without the option")
	}
	p := DefaultParams(Identified)
	p.OutgoingInterface = addr
	if _, err := Render(p); err == nil {
		t.Error("identified process accepted an outgoing interface")
	}
}

func TestRenderRefusesBadInput(t *testing.T) {
	for _, m := range []func(*Params){
		func(p *Params) { p.Listen = netip.MustParseAddrPort("10.0.0.1:53") },
		func(p *Params) { p.Dir = "a\"b" },
		func(p *Params) { p.User = "x\nserver:" },
		func(p *Params) { p.Threads = 0 },
		func(p *Params) { p.PortLo, p.PortHi = 5000, 100 },
	} {
		p := DefaultParams(Identified)
		m(&p)
		if _, err := Render(p); err == nil {
			t.Error("Render accepted bad parameters")
		}
	}
}

func TestVersionFloor(t *testing.T) {
	v, err := ParseVersion([]byte("Version 1.19.2\n\nConfigure line: ...\n"))
	if err != nil || v != "1.19.2" {
		t.Fatalf("ParseVersion = %q, %v", v, err)
	}
	for v, want := range map[string]bool{"1.19.2": false, "1.19.10": false, "1.20.0": true, "1.20.1": true, "2.0": true, "1.19.1": false, "1.18.9": false, "0.9": false, "garbage": false, "": false} {
		if got := AtLeast(v, VersionFloor); got != want {
			t.Errorf("AtLeast(%q) = %v", v, got)
		}
	}
	if _, err := ParseVersion([]byte("nothing here")); err == nil {
		t.Error("no version accepted")
	}
	if err := CheckVersion("1.10.0"); !errors.Is(err, ErrBelowFloor) {
		t.Error("floor not enforced")
	}
}

func TestVerifyRefusesChangedPinned(t *testing.T) {
	p := DefaultParams(Free)
	good := render(t, Free)
	if err := Verify(good, p); err != nil {
		t.Fatalf("a fresh file does not verify: %v", err)
	}
	for name, mut := range map[string]func(string) string{
		"limit changed": func(s string) string { return strings.Replace(s, "ratelimit: 200", "ratelimit: 2000", 1) },
		"limit removed": func(s string) string { return strings.Replace(s, "    max-sent-count: 32\n", "", 1) },
		"logging on":    func(s string) string { return strings.Replace(s, "log-queries: no", "log-queries: yes", 1) },
		"verbosity":     func(s string) string { return strings.Replace(s, "verbosity: 0", "verbosity: 2", 1) },
		"include": func(s string) string {
			return strings.Replace(s, "server:\n", "include: \"/tmp/x.conf\"\nserver:\n", 1)
		},
		"extra key":         func(s string) string { return strings.Replace(s, "server:\n", "server:\n    dnstap-enable: yes\n", 1) },
		"private-address":   func(s string) string { return strings.Replace(s, "    private-address: 10.0.0.0/8\n", "", 1) },
		"serve-expired":     func(s string) string { return strings.Replace(s, "serve-expired: no", "serve-expired: yes", 1) },
		"dnq loses a range": func(s string) string { return strings.Replace(s, "    do-not-query-address: 10.0.0.0/8\n", "", 1) },
	} {
		if err := Verify(mut(good), p); !errors.Is(err, ErrPinned) {
			t.Errorf("%s: Verify = %v", name, err)
		}
	}
	// The do-not-query list is the agent's to change.
	more := good + "    do-not-query-address: 203.0.114.9/32\n"
	if err := Verify(more, p); err != nil {
		t.Errorf("a longer do-not-query list was refused: %v", err)
	}
	// The error never names a value.
	err := Verify(strings.Replace(good, "ratelimit: 200", "ratelimit: 2000", 1), p)
	if err == nil || strings.Contains(err.Error(), "2000") {
		t.Errorf("error holds the value: %v", err)
	}
}

func TestRangesMustBeDisjoint(t *testing.T) {
	fr, id := DefaultParams(Free), DefaultParams(Identified)
	if err := CheckRanges(fr, id, 32768, 39999); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	if err := CheckRanges(fr, id, 32768, 60999); !errors.Is(err, ErrRanges) {
		t.Error("the stock ephemeral range overlaps the free range and was accepted")
	}
	id.PortLo = 40500
	if err := CheckRanges(fr, id, 32768, 39999); !errors.Is(err, ErrRanges) {
		t.Error("overlapping unbound ranges accepted")
	}
	if lo, hi, err := ParseEphemeral([]byte("32768\t60999\n")); err != nil || lo != 32768 || hi != 60999 {
		t.Errorf("ParseEphemeral = %d %d %v", lo, hi, err)
	}
}

func newSup(t *testing.T, version string, eph string) (*Supervisor, *fake.Runner, *fake.Files, *alert.Memory) {
	t.Helper()
	units := &fake.Units{}
	r := &fake.Runner{Reply: func(c fake.Call) ([]byte, error) {
		if out, err, ok := units.Handle(c); ok {
			return out, err
		}
		switch {
		case c.Name == "unbound":
			return []byte("Version " + version + "\n"), nil
		case c.Name == "dpkg-query":
			return []byte(DistroFloor), nil
		}
		return nil, nil
	}}
	f := fake.NewFiles(map[string]string{EphemeralPath: eph})
	al := &alert.Memory{}
	s := New(Config{Runner: r, Files: f, Alert: al, ConfDir: "/etc/ctrlz/unbound",
		Identified: DefaultParams(Identified), Free: DefaultParams(Free)})
	return s, r, f, al
}

func TestSupervisorStartsBothAndWritesFiles(t *testing.T) {
	s, r, f, al := newSup(t, "1.19.2", "32768 39999\n")
	ctx := context.Background()
	for _, k := range []Kind{Identified, Free} {
		if err := s.Start(ctx, k, nil); err != nil {
			t.Fatal(err)
		}
	}
	if f.Get("/etc/ctrlz/unbound/identified.conf") == "" || f.Get("/etc/ctrlz/unbound/free.conf") == "" {
		t.Fatal("configuration not written")
	}
	lines := strings.Join(r.Lines(), "\n")
	for _, want := range []string{"systemctl start ctrlz-unbound.service", "systemctl start ctrlz-unbound-free.service"} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in %s", want, lines)
		}
	}
	if len(al.Codes()) != 0 {
		t.Errorf("alerts: %v", al.Codes())
	}
	if f.Modes["/etc/ctrlz/unbound/free.conf"] != 0o640 {
		t.Error("mode of the configuration")
	}
}

func TestSupervisorRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("version under the floor starts neither", func(t *testing.T) {
		s, r, _, al := newSup(t, "1.18.0", "32768 39999")
		for _, k := range []Kind{Identified, Free} {
			if err := s.Start(ctx, k, nil); !errors.Is(err, ErrBelowFloor) {
				t.Errorf("%s: %v", k, err)
			}
		}
		for _, l := range r.Lines() {
			if strings.HasPrefix(l, "systemctl start") {
				t.Errorf("started: %s", l)
			}
		}
		if al.Count(alert.UnboundRefused) != 2 {
			t.Errorf("alerts = %d", al.Count(alert.UnboundRefused))
		}
	})
	t.Run("a changed limit on disk", func(t *testing.T) {
		s, r, f, al := newSup(t, "1.19.2", "32768 39999")
		f.Set("/etc/ctrlz/unbound/free.conf", strings.Replace(render(t, Free), "max-sent-count: 32", "max-sent-count: 3200", 1))
		if err := s.Start(ctx, Free, nil); !errors.Is(err, ErrPinned) {
			t.Fatalf("Start = %v", err)
		}
		if strings.Contains(strings.Join(r.Lines(), "\n"), "systemctl start") || al.Count(alert.UnboundRefused) != 1 {
			t.Error("started or no alert")
		}
		if !strings.Contains(f.Get("/etc/ctrlz/unbound/free.conf"), "max-sent-count: 3200") {
			t.Error("the changed file was overwritten without a word")
		}
	})
	t.Run("ephemeral range overlaps the free range", func(t *testing.T) {
		s, _, _, al := newSup(t, "1.19.2", "32768 60999")
		if err := s.Start(ctx, Free, nil); !errors.Is(err, ErrRanges) {
			t.Fatalf("Start = %v", err)
		}
		if al.Count(alert.UnboundRefused) != 1 {
			t.Error("no alert")
		}
		// the identified process does not depend on the range
		if err := s.Start(ctx, Identified, nil); err != nil {
			t.Errorf("identified refused: %v", err)
		}
	})
}

func TestSupervisorRestartsDeadUnitAndAlerts(t *testing.T) {
	s, r, _, al := newSup(t, "1.19.2", "32768 39999")
	ctx := context.Background()
	_ = s.Start(ctx, Identified, nil)
	_ = s.Start(ctx, Free, nil)
	dead := true
	r.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "systemctl" && c.Args[0] == "is-active" && c.Args[1] == UnitFree && dead {
			return []byte("failed\n"), errors.New("exit 3")
		}
		if c.Name == "systemctl" && c.Args[0] == "is-active" {
			return []byte("active\n"), nil
		}
		return nil, nil
	}
	s.Check(ctx)
	if al.Count(alert.UnboundDown) != 1 || al.Last(alert.UnboundDown) != "free" {
		t.Errorf("alerts: %v", al.Codes())
	}
	if !strings.Contains(strings.Join(r.Lines(), "\n"), "systemctl restart ctrlz-unbound-free.service") {
		t.Error("not restarted")
	}
	if strings.Contains(strings.Join(r.Lines(), "\n"), "systemctl restart ctrlz-unbound.service") {
		t.Error("restarted the healthy one")
	}
}

func TestDoNotQueryChangeReloadsKeepingCache(t *testing.T) {
	s, r, f, _ := newSup(t, "1.19.2", "32768 39999")
	ctx := context.Background()
	_ = s.Start(ctx, Identified, nil)
	_ = s.Start(ctx, Free, nil)
	list := nets.ForAddr(netip.MustParseAddr("203.0.114.9"))
	if err := s.SetDoNotQuery(ctx, list); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Get("/etc/ctrlz/unbound/identified.conf"), "do-not-query-address: 203.0.114.9/32") {
		t.Error("identified file not updated")
	}
	n := 0
	for _, l := range r.Lines() {
		if strings.HasSuffix(l, "reload_keep_cache") {
			n++
		}
		if strings.Contains(l, " restart ") && strings.Contains(l, "unbound") {
			t.Errorf("restart instead of reload: %s", l)
		}
	}
	if n != 2 {
		t.Errorf("reloads = %d", n)
	}
	before := len(r.Calls())
	if err := s.SetDoNotQuery(ctx, list); err != nil || len(r.Calls()) != before {
		t.Error("an unchanged list caused work")
	}
}

func TestUnwantedRepliesAlert(t *testing.T) {
	s, r, _, al := newSup(t, "1.19.2", "32768 39999")
	ctx := context.Background()
	_ = s.Start(ctx, Identified, nil)
	n := "0"
	r.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "unbound-control" {
			return []byte("total.num.queries=5\nunwanted.replies=" + n + "\n"), nil
		}
		return []byte("active\n"), nil
	}
	s.Check(ctx)
	if al.Count(alert.UnboundUnwanted) != 0 {
		t.Fatal("alert at zero")
	}
	n = "7"
	s.Check(ctx)
	s.Check(ctx)
	if al.Count(alert.UnboundUnwanted) != 1 {
		t.Errorf("alerts = %d", al.Count(alert.UnboundUnwanted))
	}
}

// p4n-W5b-r1-5: a reload that failed is retried, so the running process is never left
// on the old do-not-query list with the new one only in the file.
func TestFailedReloadIsRetriedOnTheNextPass(t *testing.T) {
	s, r, _, al := newSup(t, "1.19.2", "32768 39999")
	ctx := context.Background()
	_ = s.Start(ctx, Identified, nil)
	failing := true
	r.Reply = func(c fake.Call) ([]byte, error) {
		switch {
		case c.Name == "systemctl" && c.Args[0] == "is-active":
			return []byte("active\n"), nil
		case len(c.Args) > 0 && c.Args[len(c.Args)-1] == "reload_keep_cache" && failing:
			return nil, errors.New("control socket busy")
		}
		return nil, nil
	}
	list := nets.ForAddr(netip.MustParseAddr("203.0.114.9"))
	if err := s.SetDoNotQuery(ctx, list); err == nil {
		t.Fatal("the failed reload was not reported")
	}
	if al.Count(alert.UnboundReloadFail) != 1 {
		t.Errorf("alerts: %v", al.Codes())
	}
	// the same list again: it must try again, since the process never got it
	failing = false
	s.Check(ctx)
	n := 0
	for _, l := range r.Lines() {
		if strings.HasSuffix(l, "reload_keep_cache") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("reloads = %d, want the failed one and its retry", n)
	}
	s.Check(ctx)
	m := 0
	for _, l := range r.Lines() {
		if strings.HasSuffix(l, "reload_keep_cache") {
			m++
		}
	}
	if m != 2 {
		t.Errorf("a list the process holds was reloaded again (%d)", m)
	}
}

// p4n-W5b-r1-19: a unit that died is not brought back into a host that fails a start
// check, and comes back when the host is right again.
func TestDeadUnitIsNotRestartedWhileAStartCheckFails(t *testing.T) {
	s, r, f, al := newSup(t, "1.19.2", "32768 39999")
	ctx := context.Background()
	_ = s.Start(ctx, Identified, nil)
	gate := errors.New("core dumps are not ruled out")
	s.cfg.Gate = func() error { return gate }
	r.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "systemctl" && c.Args[0] == "is-active" {
			return []byte("failed\n"), errors.New("exit 3")
		}
		return nil, nil
	}
	s.Check(ctx)
	if strings.Contains(strings.Join(r.Lines(), "\n"), "systemctl restart") {
		t.Fatal("restarted although cores are not ruled out")
	}
	if al.Count(alert.UnboundRefused) == 0 {
		t.Error("no refusal alert")
	}
	// the host is right again: the next pass restarts it
	gate = nil
	s.Check(ctx)
	if !strings.Contains(strings.Join(r.Lines(), "\n"), "systemctl restart ctrlz-unbound.service") {
		t.Error("not restarted once the check holds")
	}
	// a pinned setting changed on disk is a refusal as well
	before := strings.Count(strings.Join(r.Lines(), "\n"), "systemctl restart")
	const path = "/etc/ctrlz/unbound/identified.conf"
	f.M[path] = []byte(strings.Replace(string(f.M[path]), "log-queries: no", "log-queries: yes", 1))
	s.Check(ctx)
	if strings.Count(strings.Join(r.Lines(), "\n"), "systemctl restart") != before {
		t.Error("restarted with a changed configuration file")
	}
}

// outgoing-port-permit only adds to the set Unbound starts from (every unassigned
// port above 1024), so without an avoid line before it neither process is confined
// to its range, and the notrack rule and the ephemeral-range check rest on nothing
// (p4n-W5b-r2-6). The avoid line must come first, in both processes.
func TestOutgoingPortsAreConfinedToTheRange(t *testing.T) {
	for _, k := range []Kind{Identified, Free} {
		conf := render(t, k)
		avoid := strings.Index(conf, "\n    outgoing-port-avoid: 0-65535\n")
		permit := strings.Index(conf, "\n    outgoing-port-permit: ")
		if avoid < 0 || permit < 0 || avoid > permit {
			t.Errorf("%s: the avoid line (at %d) must come before the permit line (at %d)", k, avoid, permit)
		}
		// Verify keeps the order too: a file whose lines are swapped is not the template.
		swapped := strings.Replace(conf, "    outgoing-port-avoid: 0-65535\n", "", 1)
		swapped = strings.Replace(swapped, "\n    outgoing-range:", "\n    outgoing-port-avoid: 0-65535\n    outgoing-range:", 1)
		if err := Verify(swapped, DefaultParams(k)); !errors.Is(err, ErrPinned) {
			t.Errorf("%s: a file with the avoid line after the permit line verified: %v", k, err)
		}
	}
}

// A kind whose start did not happen is tried again by Check, once the cause is gone
// and StartRetry has passed; a kind that is running is not started again.
func TestCheckStartsAKindThatNeverStarted(t *testing.T) {
	s, r, _, _ := newSup(t, "1.19.2", "32768 39999\n")
	s.cfg.StartRetry = time.Nanosecond
	ctx := context.Background()
	fail := true
	base := r.Reply
	r.Reply = func(c fake.Call) ([]byte, error) {
		if fail && c.Name == "systemctl" && len(c.Args) > 0 && c.Args[0] == "start" {
			return nil, errors.New("not yet")
		}
		if base != nil {
			return base(c)
		}
		return nil, nil
	}
	if err := s.Start(ctx, Identified, nil); err == nil {
		t.Fatal("the start should have failed")
	}
	// StartRetry is a nanosecond, which a coarse clock (the container's, the Windows host's)
	// can show as no time passed between two calls: let a clock tick pass before each Check.
	tick := func() { time.Sleep(5 * time.Millisecond) }
	tick()
	s.Check(ctx) // still failing: tried, refused again
	fail = false
	tick()
	s.Check(ctx)
	n := 0
	for _, l := range r.Lines() {
		if l == "systemctl start ctrlz-unbound.service" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("start calls = %d, want 3 (the first, a failed retry, a good retry)", n)
	}
	s.Check(ctx)
	s.Check(ctx)
	for _, l := range r.Lines() {
		if l == "systemctl start ctrlz-unbound.service" {
			n--
		}
	}
	if n != 0 {
		t.Error("a running unit was started again")
	}
	// the free kind was never asked for, so Check leaves it alone
	for _, l := range r.Lines() {
		if strings.Contains(l, "ctrlz-unbound-free") {
			t.Errorf("an unwanted kind was started: %s", l)
		}
	}
}

// The floor is the first release with all four fixes, DNSBomb's (1.20.0) among them.
// The one build below it that is accepted is Ubuntu's 1.19.2, from the package
// revision that carries the DNSBomb patch, and only when dpkg says so (p4n-W5b-r2-8).
func TestFloorAcceptsOnlyThePatchedDistroBuild(t *testing.T) {
	ctx := context.Background()
	mk := func(version, pkg string, compareOK bool) (*Supervisor, *fake.Runner) {
		s, r, _, _ := newSup(t, version, "32768 39999\n")
		r.Reply = func(c fake.Call) ([]byte, error) {
			switch {
			case c.Name == "unbound":
				return []byte("Version " + version + "\n"), nil
			case c.Name == "dpkg-query":
				return []byte(pkg), nil
			case c.Name == "dpkg":
				if !compareOK {
					return nil, errors.New("exit status 1")
				}
			}
			return nil, nil
		}
		return s, r
	}
	// an unpatched 1.19.2 (dpkg says the revision is below) is refused, so is one whose
	// package cannot be read, and so is a 1.19.3, which has no distribution patch
	for name, c := range map[string]struct {
		v, pkg string
		cmp    bool
	}{
		"revision below the patched one":         {"1.19.2", "1.19.2-1ubuntu3", false},
		"no package":                             {"1.19.2", "", true},
		"a package string that is not a version": {"1.19.2", "1.19.2; rm -rf /", true},
		"1.19.3 upstream":                        {"1.19.3", "1.19.3-1", true},
	} {
		s, r := mk(c.v, c.pkg, c.cmp)
		if err := s.Start(ctx, Identified, nil); !errors.Is(err, ErrBelowFloor) {
			t.Errorf("%s: Start = %v", name, err)
		}
		for _, l := range r.Lines() {
			if strings.HasPrefix(l, "systemctl start") {
				t.Errorf("%s: started", name)
			}
		}
	}
	// the patched revision starts, and a dead unit may be restarted afterwards
	s, _ := mk("1.19.2", DistroFloor, true)
	if err := s.Start(ctx, Identified, nil); err != nil {
		t.Fatalf("the patched distribution build was refused: %v", err)
	}
	if err := s.guard(Identified); err != nil {
		t.Errorf("guard refuses the patched build: %v", err)
	}
	// and 1.20.0 needs no package at all
	s, r := mk("1.20.0", "", false)
	if err := s.Start(ctx, Identified, nil); err != nil {
		t.Fatalf("1.20.0 refused: %v", err)
	}
	for _, l := range r.Lines() {
		if strings.HasPrefix(l, "dpkg") {
			t.Error("dpkg asked about a release that is above the floor")
		}
	}
}

// runningHost answers every unit as already running (an agent restart on a host whose
// Unbounds kept running) and records a reload_keep_cache as failing while failReload.
func runningHost(r *fake.Runner, version string, failReload *bool) {
	r.Reply = func(c fake.Call) ([]byte, error) {
		switch {
		case c.Name == "unbound":
			return []byte("Version " + version + "\n"), nil
		case c.Name == "systemctl" && c.Args[0] == "is-active":
			return []byte("active\n"), nil
		case len(c.Args) > 0 && c.Args[len(c.Args)-1] == "reload_keep_cache" && failReload != nil && *failReload:
			return nil, errors.New("control socket busy")
		}
		return nil, nil
	}
}

func reloads(r *fake.Runner) int {
	n := 0
	for _, l := range r.Lines() {
		if strings.HasSuffix(l, "reload_keep_cache") {
			n++
		}
	}
	return n
}

// p4n-W5b-r3-5: Start on a unit that is already running does not start it, so the
// process still has the list it had; it is told to reload, and a reload that fails is
// retried, never taken for done.
func TestStartOnARunningUnitReloadsItsList(t *testing.T) {
	s, r, f, al := newSup(t, "1.20.0", "32768 39999")
	failing := true
	runningHost(r, "1.20.0", &failing)
	ctx := context.Background()
	list := nets.ForAddr(netip.MustParseAddr("203.0.114.9"))
	if err := s.Start(ctx, Identified, list); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.Lines(), "\n"), "systemctl start") {
		t.Error("`systemctl start` on a unit that is running")
	}
	if !strings.Contains(f.Get("/etc/ctrlz/unbound/identified.conf"), "do-not-query-address: 203.0.114.9/32") {
		t.Error("the file does not hold the list")
	}
	if reloads(r) != 1 || al.Count(alert.UnboundReloadFail) != 1 {
		t.Fatalf("reloads %d, reload alerts %d", reloads(r), al.Count(alert.UnboundReloadFail))
	}
	// the process never got the list: the next pass tries again, once
	failing = false
	s.Check(ctx)
	if reloads(r) != 2 {
		t.Fatalf("reloads after the pass = %d, want the failed one and its retry", reloads(r))
	}
	s.Check(ctx)
	if reloads(r) != 2 {
		t.Errorf("a list the process holds was reloaded again (%d)", reloads(r))
	}
}

// The same with an empty list: the file differs from what the old process read for
// other reasons (a changed template), and nothing in `reloaded` would show it.
func TestStartOnARunningUnitReloadsEvenAnEmptyList(t *testing.T) {
	s, r, _, _ := newSup(t, "1.20.0", "32768 39999")
	runningHost(r, "1.20.0", nil)
	if err := s.Start(context.Background(), Identified, nil); err != nil {
		t.Fatal(err)
	}
	if reloads(r) != 1 {
		t.Errorf("reloads = %d", reloads(r))
	}
}

// A refused file under a unit that is running leaves an unsupervised process, which
// is a different thing to tell the owner than a refusal to start.
func TestRefusedFileUnderARunningUnitAlertsAsUnsupervised(t *testing.T) {
	s, r, f, al := newSup(t, "1.20.0", "32768 39999")
	runningHost(r, "1.20.0", nil)
	_ = f.WriteFile("/etc/ctrlz/unbound/identified.conf", []byte("server:\n    ratelimit: 99999\n"), 0o640)
	if err := s.Start(context.Background(), Identified, nil); err == nil {
		t.Fatal("a changed pinned setting was accepted")
	}
	if al.Count(alert.UnboundRefused) != 1 || al.Count(alert.UnboundUnsupervised) != 1 {
		t.Errorf("alerts: %v", al.Codes())
	}
	// not running: the refusal alone
	s2, _, f2, al2 := newSup(t, "1.20.0", "32768 39999")
	_ = f2.WriteFile("/etc/ctrlz/unbound/identified.conf", []byte("server:\n    ratelimit: 99999\n"), 0o640)
	_ = s2.Start(context.Background(), Identified, nil)
	if al2.Count(alert.UnboundRefused) != 1 || al2.Count(alert.UnboundUnsupervised) != 0 {
		t.Errorf("alerts with the unit down: %v", al2.Codes())
	}
}

// p4n-W5b-r5-3: a do-not-query change must not put a changed pinned limit back
// silently. The file keeps what the operator wrote, nothing is reloaded, and the
// owner is told the process is not supervised.
func TestDoNotQueryChangeRefusesAChangedPinnedSetting(t *testing.T) {
	s, r, f, al := newSup(t, "1.19.2", "32768 39999")
	ctx := context.Background()
	_ = s.Start(ctx, Identified, nil)
	_ = s.Start(ctx, Free, nil)
	path := "/etc/ctrlz/unbound/free.conf"
	edited := strings.Replace(f.Get(path), "ratelimit: 200", "ratelimit: 99999", 1)
	if edited == f.Get(path) {
		t.Fatal("the test's edit changed nothing")
	}
	_ = f.WriteFile(path, []byte(edited), 0o640)
	before := reloads(r)
	if err := s.SetDoNotQuery(ctx, nets.ForAddr(netip.MustParseAddr("203.0.114.9"))); err == nil {
		t.Fatal("a changed pinned setting was accepted")
	}
	if f.Get(path) != edited {
		t.Error("the operator's file was overwritten")
	}
	if al.Count(alert.UnboundUnsupervised) < 1 || al.Count(alert.UnboundRefused) < 1 {
		t.Errorf("alerts: %v", al.Codes())
	}
	// the identified process, whose file is untouched, still follows the list
	if reloads(r) != before+1 || !strings.Contains(f.Get("/etc/ctrlz/unbound/identified.conf"), "203.0.114.9/32") {
		t.Errorf("the untouched process did not follow the list (reloads %d, before %d)", reloads(r), before)
	}
}

// p4n-MC-r1-1: a package update does not restart a unit that is masked or not
// enabled, and the agent only reloads a running Unbound, so the process that keeps
// serving from a replaced binary or library must be found and restarted. The agent
// cannot read /proc/<pid>/exe of another user's process; it compares the process's
// start with the change time of the files it runs from.
func TestAReplacedBinaryOrLibraryRestartsTheUnit(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	// the process started 1000 s after boot (100000 ticks of 10 ms, the stat field below)
	started := boot.Add(1000 * time.Second)
	now := started.Add(time.Hour)
	setup := func(change map[string]time.Time) (*Supervisor, *fake.Runner, *fake.Files, *alert.Memory) {
		s, r, f, al := newSup(t, "1.19.2", "32768 39999\n")
		base := r.Reply
		r.Reply = func(c fake.Call) ([]byte, error) {
			if c.Name == "systemctl" && len(c.Args) > 1 && c.Args[0] == "show" {
				return []byte("4242\n"), nil
			}
			return base(c)
		}
		// a command name with a space and a ")" in it, as the kernel prints it
		f.M["/proc/4242/stat"] = []byte("4242 (unbound (x) y) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 " + "100000" + " 1000 1000 18446744073709551615\n")
		f.M["/proc/stat"] = []byte("cpu  1 2 3\nbtime 1700000000\nprocesses 5\n")
		s.cfg.Now = func() time.Time { return now }
		s.cfg.ChangeTime = func(p string) (time.Time, error) {
			if t, ok := change[p]; ok {
				return t, nil
			}
			return time.Time{}, errors.New("no such file")
		}
		for _, k := range []Kind{Identified, Free} {
			if err := s.Start(context.Background(), k, nil); err != nil {
				t.Fatal(err)
			}
		}
		return s, r, f, al
	}
	restarts := func(r *fake.Runner) int {
		n := 0
		for _, l := range r.Lines() {
			if strings.HasPrefix(l, "systemctl restart ctrlz-unbound") {
				n++
			}
		}
		return n
	}
	ctx := context.Background()

	t.Run("the binary replaced after the start", func(t *testing.T) {
		s, r, _, al := setup(map[string]time.Time{BinaryPath: started.Add(10 * time.Minute)})
		s.Check(ctx)
		if restarts(r) != 2 || al.Count(alert.UnboundStale) != 2 {
			t.Fatalf("restarts %d, stale alerts %d: %v", restarts(r), al.Count(alert.UnboundStale), r.Lines())
		}
		// a second pass inside the rate limit does nothing, whatever the clocks say
		s.Check(ctx)
		if restarts(r) != 2 {
			t.Errorf("restarted again at once: %d", restarts(r))
		}
	})
	t.Run("a library package replaced after the start, found by the dpkg status file", func(t *testing.T) {
		s, r, _, _ := setup(map[string]time.Time{BinaryPath: started.Add(-time.Hour), DpkgStatus: started.Add(time.Minute)})
		s.Check(ctx)
		if restarts(r) != 2 {
			t.Fatalf("restarts %d: %v", restarts(r), r.Lines())
		}
	})
	t.Run("files older than the process leave it alone", func(t *testing.T) {
		s, r, _, al := setup(map[string]time.Time{BinaryPath: started.Add(-time.Hour), DpkgStatus: started.Add(-time.Minute)})
		s.Check(ctx)
		if restarts(r) != 0 || al.Count(alert.UnboundStale) != 0 {
			t.Fatalf("restarted a current process: %v", r.Lines())
		}
	})
	t.Run("a change time in the future is not believed, so a stepped clock cannot loop", func(t *testing.T) {
		s, r, _, _ := setup(map[string]time.Time{BinaryPath: now.Add(24 * time.Hour)})
		s.Check(ctx)
		if restarts(r) != 0 {
			t.Fatalf("restarted for a file from the future: %v", r.Lines())
		}
	})
	t.Run("a host that cannot say (no pid, no files) is left alone", func(t *testing.T) {
		s, r, f, _ := setup(map[string]time.Time{BinaryPath: started.Add(time.Hour)})
		delete(f.M, "/proc/stat")
		s.Check(ctx)
		if restarts(r) != 0 {
			t.Fatalf("restarted without knowing the process start: %v", r.Lines())
		}
	})
	t.Run("the restart waits for the same checks as a dead unit's", func(t *testing.T) {
		s, r, _, al := setup(map[string]time.Time{BinaryPath: started.Add(time.Minute)})
		s.cfg.Gate = func() error { return errors.New("core dumps are not ruled out") }
		s.Check(ctx)
		if restarts(r) != 0 || al.Count(alert.UnboundRefused) == 0 {
			t.Fatalf("restarted past the host gate: %v", r.Lines())
		}
	})
}

// p4n-MC-r1-6: a repeat install with a new --free-outgoing-ip is an authorised
// change that looks like a tampered file to the agent (the old free.conf has no
// outgoing-interface line). The install removes the rendered file; the agent then
// starts the unit from a fresh one. The refusal itself stays for any other change.
func TestStartAfterTheInstallRemovedARenderedFileOfAnotherConfiguration(t *testing.T) {
	ctx := context.Background()
	old := render(t, Free)
	s, _, f, al := newSup(t, "1.19.2", "32768 39999")
	s.cfg.Free.OutgoingInterface = netip.MustParseAddr("198.51.101.7")
	if err := f.WriteFile("/etc/ctrlz/unbound/free.conf", []byte(old), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, Free, nil); err == nil {
		t.Fatal("the agent took a file of another configuration over silently")
	}
	if al.Count(alert.UnboundRefused) != 1 {
		t.Fatalf("alerts: %v", al.Codes())
	}
	// what apply.sh does: remove the rendered file
	delete(f.M, "/etc/ctrlz/unbound/free.conf")
	if err := s.Start(ctx, Free, nil); err != nil {
		t.Fatalf("the start after the install removed the file: %v", err)
	}
	if !strings.Contains(f.Get("/etc/ctrlz/unbound/free.conf"), "outgoing-interface: 198.51.101.7") {
		t.Error("the new file lacks the outgoing interface")
	}
}
