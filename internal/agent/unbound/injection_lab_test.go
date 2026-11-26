//go:build unboundlab

package unbound

// T-031 (p4-nodes 7.7 and 11.5): the injection test with a real Unbound.
//
// The other tests of this package compare the rendered private-address list
// with netclass. This one runs the real Unbound with the configuration the node
// renders for each of its two processes (the identified and the free one) and
// asks what a client of that process would be given when the authority is hostile:
// answers in 10.10.34.0/24 (the injected redirect range), private, loopback,
// CGNAT and embedded-IPv4 addresses for a public name, and the shapes a censor's
// fast fake reply takes (an address mixed into a real set, a CNAME chain that ends
// in one, records that do not belong to the question). Neither process may hand
// out any of them. Public answers must pass in the same run, so the test can fail:
// a resolver that never reached the server, or one that refuses everything, is
// red on the controls, and a third process rendered without private-address shows
// that the injected answer does reach a client when the list is missing.
//
// The lab fixture root. The authority is one miekg/dns server that is also the root
// of the lab: the root hints name it, it answers `. NS`, and it answers every name
// below the root itself, so no delegation or real root is involved and nothing
// leaves the machine. Unbound refuses to query a non-public address (that is the
// point of do-not-query-address), so the server cannot sit on loopback: it listens
// on a public-class address that the job adds to the loopback interface, which is
// why the build tag and the job exist (.github/ci/unbound.sh in the workspace
// overlay, scripts/conformance.sh). The trust anchor is a fixture key for the name
// "invalid.", so the file is a real one that unbound parses and no name under
// test is validated.
//
// The tag makes the test a statement that a real Unbound is there: a missing
// binary or a port that cannot be bound fails, it never skips.

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// rootAddr is the lab root's address: public for netclass (so the Unbounds will
// query it) and added to lo by the job.
const rootAddr = "11.0.0.53"

// labAnswer is what the hostile root answers for one name.
type labAnswer struct {
	a, aaaa []string
	// cname makes the name an alias; the reply carries the target's records inline,
	// as an authoritative server does.
	cname string
	// strayAnswer and strayExtra are records the reply carries that do not belong
	// to the question: what a fast fake reply stuffs into a real answer.
	strayAnswer, strayExtra []string
}

func mustRR(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(fmt.Sprintf("bad fixture record %q: %v", s, err))
	}
	return r
}

type hostile struct {
	zone map[string]labAnswer
	// which maps the source port of a query to the process that sent it.
	which func(port int) string

	mu   sync.Mutex
	seen map[string]map[string]bool // lower-case name -> process -> asked
}

func (h *hostile) note(name string, port int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen[name] == nil {
		h.seen[name] = map[string]bool{}
	}
	h.seen[name][h.which(port)] = true
}

func (h *hostile) asked(name, proc string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seen[strings.ToLower(name)][proc]
}

const labSOA = ". 3600 IN SOA a.root-servers.net. hostmaster.root-servers.net. 1 1800 900 604800 86400"

func (h *hostile) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r) // keeps the question byte for byte, so use-caps-for-id sees its own case
	m.Authoritative = true
	if r.IsEdns0() != nil {
		m.SetEdns0(1232, false)
	}
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	if ua, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		h.note(name, ua.Port)
	}
	switch {
	case name == "." && q.Qtype == dns.TypeNS:
		m.Answer = []dns.RR{mustRR(". 3600 IN NS A.ROOT-SERVERS.NET.")}
		m.Extra = []dns.RR{mustRR("A.ROOT-SERVERS.NET. 3600 IN A " + rootAddr)}
	case q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA:
		h.answer(m, q, name)
	default:
		m.Ns = []dns.RR{mustRR(labSOA)}
	}
	_ = w.WriteMsg(m)
}

// answer fills m for an A or AAAA question. A name that is not in the zone gets a
// NODATA reply and never NXDOMAIN, so a minimised query for a parent label cannot
// make the resolver believe everything below it is gone.
func (h *hostile) answer(m *dns.Msg, q dns.Question, name string) {
	first, ok := h.zone[name]
	if !ok {
		m.Ns = []dns.RR{mustRR(labSOA)}
		return
	}
	f, owner := first, q.Name
	for hops := 0; f.cname != "" && hops < 4; hops++ {
		m.Answer = append(m.Answer, mustRR(fmt.Sprintf("%s 300 IN CNAME %s", owner, f.cname)))
		owner = f.cname
		f = h.zone[strings.ToLower(f.cname)]
	}
	switch q.Qtype {
	case dns.TypeA:
		for _, a := range f.a {
			m.Answer = append(m.Answer, mustRR(fmt.Sprintf("%s 300 IN A %s", owner, a)))
		}
	case dns.TypeAAAA:
		for _, a := range f.aaaa {
			m.Answer = append(m.Answer, mustRR(fmt.Sprintf("%s 300 IN AAAA %s", owner, a)))
		}
	}
	for _, s := range first.strayAnswer {
		m.Answer = append(m.Answer, mustRR(s))
	}
	for _, s := range first.strayExtra {
		m.Extra = append(m.Extra, mustRR(s))
	}
	if len(m.Answer) == 0 {
		m.Ns = []dns.RR{mustRR(labSOA)}
	}
}

func (h *hostile) start(t *testing.T) {
	t.Helper()
	addr := net.JoinHostPort(rootAddr, "53")
	hint := "the job adds the address to lo and lowers net.ipv4.ip_unprivileged_port_start (.github/ci/unbound.sh of the overlay, scripts/conformance.sh)"
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the lab root cannot bind udp %s: %v; %s", addr, err, hint)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		t.Fatalf("the lab root cannot bind tcp %s: %v; %s", addr, err, hint)
	}
	started := make(chan struct{}, 2)
	us := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: func() { started <- struct{}{} }}
	ts := &dns.Server{Listener: ln, Handler: h, NotifyStartedFunc: func() { started <- struct{}{} }}
	go func() { _ = us.ActivateAndServe() }()
	go func() { _ = ts.ActivateAndServe() }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("the lab root did not start")
		}
	}
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
}

// syncBuf is the process's output, read while it still writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// labBinary copies the installed unbound next to the test files. The distribution's
// AppArmor profile is attached to the path /usr/sbin/unbound and would deny a
// configuration in a temporary directory; a copy is not confined by it and is the
// same binary.
func labBinary(t *testing.T, dir string) string {
	t.Helper()
	src, err := exec.LookPath("unbound")
	if err != nil {
		if _, e := os.Stat("/usr/sbin/unbound"); e != nil {
			t.Fatal("no unbound binary: this test is built with the tag unboundlab to run against a real one (apt-get install unbound)")
		}
		src = "/usr/sbin/unbound"
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	dst := filepath.Join(dir, "unbound")
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(dst, "-V").CombinedOutput(); err == nil {
		t.Logf("unbound under test: %s", strings.SplitN(string(out), "\n", 2)[0])
	} else {
		t.Logf("unbound -V failed: %v", err)
	}
	return dst
}

// labParams are the production parameters of a kind with only what a lab host
// cannot share changed: the directories, the user, the root files and, for the
// third process, the listen address and the port range. The resolver settings
// (every key of the template) are the node's own.
func labParams(t *testing.T, k Kind, dir, name, usr string) Params {
	t.Helper()
	p := DefaultParams(k)
	p.Dir = filepath.Join(dir, name, "lib")
	p.RunDir = filepath.Join(dir, name, "run")
	for _, d := range []string{p.Dir, p.RunDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p.User = usr
	p.TrustAnchor = filepath.Join(dir, "anchor.key")
	p.RootHints = filepath.Join(dir, "root.hints")
	// The lab root is IPv4 only; without IPv6 the process does not try a family the
	// runner may not have.
	p.IPv6 = false
	return p
}

// stderrLogging turns the node's silent logging (logfile /dev/null, verbosity 0) into
// errors on stderr, so a lame mark, a failed query or an anchor problem leaves a trace
// in the output the test prints when it fails. Logging is not a setting under test: it
// changes no answer. Every line it replaces must be present, so a template change that
// moves one fails here and not silently.
func stderrLogging(t *testing.T, conf string) string {
	t.Helper()
	for _, r := range [][2]string{
		{"verbosity: 0", "verbosity: 1"},
		{"logfile: \"/dev/null\"", "logfile: \"\""},
		{"log-servfail: no", "log-servfail: yes"},
	} {
		if !strings.Contains(conf, r[0]) {
			t.Fatalf("the rendered configuration has no %q: the lab cannot route Unbound's log to stderr", r[0])
		}
		conf = strings.Replace(conf, r[0], r[1], 1)
	}
	return conf
}

// startUnbound renders p (edit may change the text), starts the real process in
// the foreground and waits until it answers. Its stderr is printed when the test
// fails (see stderrLogging).
func startUnbound(t *testing.T, bin, dir, name string, p Params, edit func(string) string) {
	t.Helper()
	conf, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	conf = stderrLogging(t, conf)
	if edit != nil {
		conf = edit(conf)
	}
	path := filepath.Join(dir, name+".conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-d", "-c", path)
	out := &syncBuf{}
	cmd.Stdout, cmd.Stderr = out, out
	// Registered before the kill below, so it runs after it and sees the whole output.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		o := out.String()
		if len(o) > 16000 {
			o = "...\n" + o[len(o)-16000:]
		}
		t.Logf("unbound %s output:\n%s", name, o)
	})
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: start: %v", name, err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })

	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("good.example.", dns.TypeA)
	for deadline := time.Now().Add(40 * time.Second); time.Now().Before(deadline); {
		select {
		case <-done:
			t.Fatalf("%s: unbound exited at start:\n%s", name, out.String())
		default:
		}
		if _, _, err := c.Exchange(m, p.Listen.String()); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s: unbound did not answer on %s:\n%s", name, p.Listen, out.String())
}

func ask(t *testing.T, at netip.AddrPort, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: "udp", Timeout: 8 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	var last error
	for i := 0; i < 3; i++ {
		r, _, err := c.Exchange(m, at.String())
		if err == nil {
			return r
		}
		last = err
	}
	t.Fatalf("%s %s: no reply from %s: %v", name, dns.TypeToString[qtype], at, last)
	return nil
}

func addrOf(rr dns.RR) (netip.Addr, bool) {
	switch v := rr.(type) {
	case *dns.A:
		a, ok := netip.AddrFromSlice(v.A.To4())
		return a, ok
	case *dns.AAAA:
		a, ok := netip.AddrFromSlice(v.AAAA.To16())
		return a, ok
	}
	return netip.Addr{}, false
}

// answerAddrs are the addresses in the answer section: what a client would connect to.
func answerAddrs(m *dns.Msg) []netip.Addr {
	var out []netip.Addr
	for _, rr := range m.Answer {
		if a, ok := addrOf(rr); ok {
			out = append(out, a)
		}
	}
	return out
}

// leaked are the non-public addresses in any section of the reply.
func leaked(m *dns.Msg) []netip.Addr {
	var out []netip.Addr
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if a, ok := addrOf(rr); ok && !netclass.IsPublic(a) {
				out = append(out, a)
			}
		}
	}
	return out
}

func zoneOfTheLab() map[string]labAnswer {
	z := map[string]labAnswer{
		// Controls: what a real authority answers.
		"good.example.":       {a: []string{"11.0.0.80"}},
		"good6.example.":      {aaaa: []string{"2001:4860:4860::8888"}},
		"chain-good.example.": {cname: "good.example."},
		"poisoned.example.":   {a: []string{"11.0.0.81"}},
		// A real answer stuffed with records that do not belong to the question, the
		// way a censor's fast fake reply carries its own addresses.
		"fastfake.example.": {
			a:           []string{"11.0.0.80"},
			strayAnswer: []string{"poisoned.example. 300 IN A 10.10.34.34", "other.example. 300 IN A 10.10.34.35"},
			strayExtra:  []string{"ns.fastfake.example. 300 IN A 10.10.34.34", "poisoned.example. 300 IN A 10.10.34.36"},
		},
		// An injected address in the same set as a real one.
		"mixed.example.": {a: []string{"11.0.0.80", "10.10.34.34"}},
		// A chain whose end is an injected or a private address.
		"chain-inj.example.":    {cname: "inj-target.example."},
		"inj-target.example.":   {a: []string{"10.10.34.34"}},
		"chain-priv.example.":   {cname: "priv-target.example."},
		"priv-target.example.":  {a: []string{"192.168.1.1"}},
		"chain-priv6.example.":  {cname: "priv6-target.example."},
		"priv6-target.example.": {aaaa: []string{"fd00::1"}},
		// The injected range.
		"inj1.example.": {a: []string{"10.10.34.34"}},
		"inj2.example.": {a: []string{"10.10.34.35", "10.10.34.36"}},
	}
	return z
}

// hostileV4 and hostileV6 are one name per address: every address is a name's whole
// answer, so a drop of one range cannot hide behind another.
var hostileV4 = []string{
	"10.0.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1", "0.0.0.0", "169.254.169.254",
	"100.64.0.1", "224.0.0.1", "198.18.0.1", "240.0.0.1", "192.0.2.1", "10.10.34.36",
}

var hostileV6 = []string{
	"::1", "fc00::1", "fe80::1", "fec0::1",
	"::ffff:10.10.34.34", "::ffff:192.168.1.1", "64:ff9b::a0a:2222", "2002:a0a:2222::1",
}

func labName(prefix string, i int) string { return fmt.Sprintf("%s%d.example.", prefix, i) }

// TestInjectionLab is T-031's injection case. It needs the lab root address on lo
// and a real unbound (see the comment at the top of the file).
func TestInjectionLab(t *testing.T) {
	dir := t.TempDir()
	zone := zoneOfTheLab()
	for i, a := range hostileV4 {
		zone[labName("v4-", i)] = labAnswer{a: []string{a}}
	}
	for i, a := range hostileV6 {
		zone[labName("v6-", i)] = labAnswer{aaaa: []string{a}}
	}
	if !netclass.IsPublic(netip.MustParseAddr(rootAddr)) || !netclass.IsPublic(netip.MustParseAddr("11.0.0.80")) {
		t.Fatal("the lab's public addresses are not public for netclass: the Unbounds would not query them")
	}

	// The control process listens beside the two real ones, with its own ports, and
	// is rendered without private-address.
	const ctlLo, ctlHi = 42000, 42999
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	idP := labParams(t, Identified, dir, "identified", u.Username)
	frP := labParams(t, Free, dir, "free", u.Username)
	ctP := labParams(t, Identified, dir, "control", u.Username)
	ctP.Listen = netip.MustParseAddrPort("127.0.0.12:5300")
	ctP.PortLo, ctP.PortHi = ctlLo, ctlHi

	h := &hostile{zone: zone, seen: map[string]map[string]bool{}, which: func(port int) string {
		switch {
		case port >= idP.PortLo && port <= idP.PortHi:
			return "identified"
		case port >= frP.PortLo && port <= frP.PortHi:
			return "free"
		case port >= ctlLo && port <= ctlHi:
			return "control"
		}
		return fmt.Sprintf("port %d", port)
	}}
	h.start(t)

	anchor := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "invalid.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	if _, err := anchor.Generate(256); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor.key"), []byte(anchor.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hints := ". 3600000 IN NS A.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET. 3600000 IN A " + rootAddr + "\n"
	if err := os.WriteFile(filepath.Join(dir, "root.hints"), []byte(hints), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := labBinary(t, dir)
	startUnbound(t, bin, dir, "identified", idP, nil)
	startUnbound(t, bin, dir, "free", frP, nil)
	startUnbound(t, bin, dir, "control", ctP, func(conf string) string {
		var keep []string
		for _, l := range strings.Split(conf, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "private-address:") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	})

	// The controls and the fake-reply case come first and the pure injections last, so
	// nothing the resolver learns about the lab root from refused answers can colour a
	// control.
	for _, proc := range []struct {
		name string
		at   netip.AddrPort
	}{{"identified", idP.Listen}, {"free", frP.Listen}} {
		t.Run(proc.name, func(t *testing.T) {
			wantA := func(name string, qtype uint16, want string) {
				t.Helper()
				m := ask(t, proc.at, name, qtype)
				got := answerAddrs(m)
				if len(got) != 1 || got[0] != netip.MustParseAddr(want) {
					t.Fatalf("control %s: want %s, got %v (rcode %s): the test cannot tell a refusal from a broken lab", name, want, got, dns.RcodeToString[m.Rcode])
				}
				if !h.asked(name, proc.name) {
					t.Fatalf("control %s: the lab root never saw this process ask", name)
				}
			}
			wantA("good.example.", dns.TypeA, "11.0.0.80")
			wantA("good6.example.", dns.TypeAAAA, "2001:4860:4860::8888")
			// An alias to a public name passes too, the chain included.
			wantA("chain-good.example.", dns.TypeA, "11.0.0.80")

			// The fast fake reply: whatever Unbound does with the reply, no non-public
			// address may reach the client from any section, and the names the reply tried
			// to plant are still answered by the authority afterwards.
			m := ask(t, proc.at, "fastfake.example.", dns.TypeA)
			if l := leaked(m); len(l) != 0 {
				t.Fatalf("fastfake.example.: non-public addresses reached the client: %v", l)
			}
			wantA("poisoned.example.", dns.TypeA, "11.0.0.81")

			// Only the first hostile name must be seen by the lab root. A reply stripped
			// of every address may leave Unbound marking the lab root (its only server)
			// lame, so a later name can be answered with no query sent; that is still a
			// refusal, and demanding a query for it would turn a setup effect into a
			// failed refusal. The first name and the controls prove the lab is reached.
			firstHostile := true
			refused := func(name string, qtype uint16, mixed bool) {
				t.Helper()
				m := ask(t, proc.at, name, qtype)
				if l := leaked(m); len(l) != 0 {
					t.Errorf("%s: a non-public address reached the client: %v (rcode %s)", name, l, dns.RcodeToString[m.Rcode])
				}
				// A name whose whole answer is hostile gives no address at all. A set that
				// mixes a real address with an injected one may lose the whole set or only the
				// injected one; the rule there is the one above.
				if got := answerAddrs(m); !mixed && len(got) != 0 {
					t.Errorf("%s: the client was given %v (rcode %s)", name, got, dns.RcodeToString[m.Rcode])
				}
				if firstHostile && !h.asked(name, proc.name) {
					t.Errorf("%s: the lab root never saw this process ask, so the refusal proves nothing", name)
				}
				firstHostile = false
			}
			refused("mixed.example.", dns.TypeA, true)
			for _, n := range []string{"inj1.example.", "inj2.example.", "chain-inj.example.", "chain-priv.example."} {
				refused(n, dns.TypeA, false)
			}
			refused("chain-priv6.example.", dns.TypeAAAA, false)
			for i := range hostileV4 {
				refused(labName("v4-", i), dns.TypeA, false)
			}
			for i := range hostileV6 {
				refused(labName("v6-", i), dns.TypeAAAA, false)
			}
		})
	}

	// Without the rendered private-address list the same injected answer reaches the
	// client, so the refusals above are the list's doing and the test can fail.
	t.Run("control without private-address", func(t *testing.T) {
		at := ctP.Listen
		m := ask(t, at, "inj1.example.", dns.TypeA)
		got := answerAddrs(m)
		if len(got) != 1 || got[0] != netip.MustParseAddr("10.10.34.34") {
			t.Fatalf("an Unbound rendered without private-address gave %v (rcode %s), not the injected 10.10.34.34: the lab does not show what the list prevents",
				got, dns.RcodeToString[m.Rcode])
		}
	})
}
