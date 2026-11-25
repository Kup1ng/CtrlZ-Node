package querypath_test

// W8, the node side of failover (p4-nodes 7.8, SC 8a.2, 8a.3, 8a.5, 8a.6, 8a.10),
// end to end: a real agent against the in-process fake hub (the hub is a stand-in
// built from the shared proto, as the plan says), the real dns role with the query
// path joined, and real clients. The node's clock is a test clock, so the 30 s and
// 90 s of SC 8a.5 are crossed by moving it, never by waiting. What the hub's
// evaluator would decide is not here (Panel side): each test sends the push the
// hub would have signed.
//
// Linux only, like the merge B end-to-end tests. Host ports 5400 to 5499 (not 5500 to 5599: internal/dns/listen binds there in the same go test run).

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// testClock is a node's clock. It runs with real time, and a test slows it (the 30 s
// in which a restarted node has no table in use then do not depend on how fast the
// machine is: a clock that stops altogether stalls the agent's own loops, so it is
// slowed a hundredfold instead) or moves it on.
type testClock struct {
	mu   sync.Mutex
	base time.Time // the clock's reading at ref
	ref  time.Time // the real time of base
	rate float64   // 0 is read as 1
}

func (c *testClock) now() time.Time {
	r := c.rate
	if r == 0 {
		r = 1
	}
	if c.ref.IsZero() {
		return time.Now()
	}
	return c.base.Add(time.Duration(float64(time.Since(c.ref)) * r))
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now()
}

// Slow makes the clock run a hundred times slower than real time.
func (c *testClock) Slow() { c.setRate(0.01) }

// Thaw puts the clock back at real speed, where it stands.
func (c *testClock) Thaw() { c.setRate(1) }

func (c *testClock) setRate(r float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.base, c.ref, c.rate = c.now(), time.Now(), r
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.base, c.ref = c.now().Add(d), time.Now()
	if c.rate == 0 {
		c.rate = 1
	}
}

// The two Endpoints of two tenants: each blocks a name the other lets through.
const (
	blockedByOne = "blocked-one.example.com"
	blockedByTwo = "blocked-two.example.com"
)

// The addresses storetest.Table gives its nodes: node 0 is the primary of the global
// pair and node 1 its fallback.
const (
	primaryIP  = "8.8.8.8"
	fallbackIP = "8.8.4.4"
)

// fnode is one node of a failover test: the agent, its fake hub and session, the
// Unbound stand-in, and the dns role.
type fnode struct {
	*node
	t   *testing.T
	fu  *fakeUnbound
	s   *fakehub.Session
	c   *clients
	ver uint64 // the last version this test pushed
}

type upOpts struct {
	freeze       bool // the clock is frozen from before the agent starts
	probes       bool // the agent probes its peers every 100 ms, and every probe fails
	noServerTime bool // no ServerTime is sent: the node judges by its own clock
	clockAhead   time.Duration
	adjust       func(*dnsrole.Config)
	unboundPort  int
}

// failingProbes makes every probe of a peer fail at once: nothing answers there.
func failingProbes(n *node) {
	n.cfg.ProbeEvery = 100 * time.Millisecond
	n.cfg.ProbeTimeout = 200 * time.Millisecond
	n.cfg.ProbeDial = func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: syscallRefused{}}
	}
}

type syscallRefused struct{}

func (syscallRefused) Error() string { return "connection refused" }

// entry is the log entry both nodes get: two tenants with their own profiles and a
// Plain DNS claim each, and the table of three nodes.
func twoTenantEntry(t *testing.T) ([][]byte, *policyv1.ConfigEntry) {
	d1, h1 := profile(t, blockedByOne)
	d2, h2 := profile(t, blockedByTwo)
	ep1, cl1 := endpoint(1, h1)
	ep2, cl2 := endpoint(2, h2)
	return [][]byte{d1, d2}, &policyv1.ConfigEntry{
		PutEndpoints: []*policyv1.EndpointRecord{ep1, ep2}, PutClaims: []*policyv1.ClaimRecord{cl1, cl2}, PairTable: storetest.Table(3, 0),
	}
}

func upNode(t *testing.T, idx int, o upOpts) *fnode {
	t.Helper()
	n := newNodeAt(t, idx)
	n.portBase = 5420 + idx*12
	if o.probes {
		failingProbes(n)
	}
	port := o.unboundPort
	if port == 0 {
		port = 5400 + idx
	}
	ip := ipV1
	fu := newFakeUnbound(t, "127.0.0.1", port, ip)
	blobs, ent := twoTenantEntry(t)
	n.addEntry(blobs, ent)
	if o.freeze {
		n.clock.Slow()
	}
	if o.clockAhead != 0 {
		n.clock.Advance(o.clockAhead)
	}
	n.startAgent()
	s, err := n.hub.NextSession(15 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f := &fnode{node: n, t: t, fu: fu, s: s, c: &clients{n: n}}
	if !o.noServerTime {
		_ = s.Send(serverTime())
	}
	_ = s.Send(nodeConfigMsg(nodeConfig(1, storetest.RandomSecret(t, 32), commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE)))
	_ = s.Send(headNotice(1))
	if _, err := s.Wait(90*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 1 && m.GetApplyResult().Ok }); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "the NodeConfig", func() bool { return lastNodeVersion(s) == 1 })
	_ = s.Send(n.certBundleMsg())
	eventually(t, 30*time.Second, "the zone key", func() bool { return n.keyFiles() >= 1 })
	n.startDNSWith(fu.addr, o.adjust)
	f.waitServing()
	return f
}

// waitServing waits until the identified Plain DNS path answers: dns holds the image.
func (f *fnode) waitServing() {
	f.t.Helper()
	eventually(f.t, 90*time.Second, "Endpoint 1 answered over Plain DNS", func() bool {
		r, err := f.c.tcp("127.0.0.1", q(allowedName, dns.TypeA))
		return err == nil && hasA(r, ipV1)
	})
}

// push sends the PairTable push the hub would sign, with the nodes named withdrawn.
func (f *fnode) push(version uint64, withdrawn ...int) {
	f.t.Helper()
	pt := storetest.Table(3, version, withdrawn...)
	pt.ExpiresAt = time.Now().Unix() + 1800
	if err := f.s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: f.keys.Sign(f.t, pt)}}); err != nil {
		f.t.Fatal(err)
	}
	f.ver = version
}

// fresh is what the hub sends on a stream right after it accepts it, and every 10 s.
func (f *fnode) fresh() { _ = f.s.Send(serverTime()) }

// zoneQ asks the node's Plain UDP port, with no identity: the zone names are
// answered before identity (SC 8a.3).
func (f *fnode) zoneQ(name string, qt uint16) *dns.Msg {
	f.t.Helper()
	r, err := f.c.udp("", q(name, qt))
	if err != nil {
		f.t.Fatalf("%s %s: %v", name, dns.TypeToString[qt], err)
	}
	return r
}

func ridHost(c byte) string { return rid(c) + "." + zoneName + "." }

// addrOf is the address of the single A record of a reply, "" with none.
func addrOf(r *dns.Msg) string {
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// wantAddr waits for the node to answer the Endpoint hostname with ip, the one
// address of the pair (SC 8a.2, invariant 2), AA with TTL 30.
func (f *fnode) wantAddr(why, ip string) {
	f.t.Helper()
	var last *dns.Msg
	eventually(f.t, 30*time.Second, why+": the hostname answers "+ip, func() bool {
		last = f.zoneQ(ridHost(1), dns.TypeA)
		return addrOf(last) == ip
	})
	if len(last.Answer) != 1 || last.Rcode != dns.RcodeSuccess || !last.Authoritative || last.Answer[0].Header().Ttl != 30 {
		f.t.Fatalf("%s: %v", why, last)
	}
	if !echoes(last, ridHost(1), dns.TypeA) {
		f.t.Fatalf("%s: the question is not echoed: %v", why, last.Question)
	}
}

func echoes(r *dns.Msg, name string, qt uint16) bool {
	return len(r.Question) == 1 && r.Question[0].Name == name && r.Question[0].Qtype == qt
}

// assertNoData is NODATA with the zone SOA, TTL 30, AA.
func (f *fnode) assertNoData(name string, qt uint16) {
	f.t.Helper()
	r := f.zoneQ(name, qt)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || !r.Authoritative || len(r.Ns) != 1 {
		f.t.Fatalf("%s %s: want NODATA with the SOA, got %v", name, dns.TypeToString[qt], r)
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Ttl != 30 || soa.Minttl != 30 || soa.Ns != "ns1."+zoneName+"." || soa.Mbox != "hostmaster."+zoneName+"." {
		f.t.Fatalf("%s %s: the SOA is %v", name, dns.TypeToString[qt], r.Ns[0])
	}
}

// steps moves the node's clock by total in steps no longer than 9 s, each with
// time for a probe round, so the 90 s run of PeerDown is not seen as a stall of the
// prober (a gap of 15 s breaks it). onStep runs after each step.
func (f *fnode) steps(total time.Duration, onStep func()) {
	for done := time.Duration(0); done < total; done += 9 * time.Second {
		f.clock.Advance(9 * time.Second)
		if onStep != nil {
			onStep()
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ---- 7.8, SC 8a.2, 8a.3, 8a.5: the answers follow the hub's table

// A node with no table in use answers REFUSED for Endpoint names, the apex NS and
// ns1 to ns4 and answers the rest as usual (SC 8a.5, T-541); once a push is
// accepted it answers by SC 8a.3, and each push moves the one address.
func TestW8TheZoneFollowsThePushes(t *testing.T) {
	f := upNode(t, 0, upOpts{freeze: true})

	// No table in use: the clock is frozen, so the 30 s have not passed and no push came.
	for _, c := range []struct {
		name string
		qt   uint16
	}{
		{ridHost(1), dns.TypeA}, {ridHost(1), dns.TypeAAAA}, {ridHost(9), dns.TypeA}, // known and unknown resolver id
		{rid(1) + "-laptop." + zoneName + ".", dns.TypeA}, // <rid>-<client>
		{zoneName + ".", dns.TypeNS},
		{"ns1." + zoneName + ".", dns.TypeA}, {"ns2." + zoneName + ".", dns.TypeA}, {"ns3." + zoneName + ".", dns.TypeAAAA}, {"ns4." + zoneName + ".", dns.TypeA},
	} {
		r := f.zoneQ(c.name, c.qt)
		if r.Rcode != dns.RcodeRefused || len(r.Answer) != 0 {
			t.Fatalf("no table in use, %s %s: %v", c.name, dns.TypeToString[c.qt], r)
		}
	}
	// What a table is not needed for: the apex SOA the probes ask, the reserved names,
	// a malformed name, and the Endpoints' own queries.
	soa := f.zoneQ(zoneName+".", dns.TypeSOA)
	if soa.Rcode != dns.RcodeSuccess || !soa.Authoritative || len(soa.Answer) != 1 {
		t.Fatalf("the apex SOA: %v", soa)
	}
	f.assertNoData("verify."+zoneName+".", dns.TypeA)
	if r := f.zoneQ("not-a-resolver!."+zoneName+".", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatalf("a malformed name: %v", r)
	}
	if r, err := f.c.tcp("127.0.0.1", q(allowedName, dns.TypeA)); err != nil || !hasA(r, ipV1) {
		t.Fatalf("an Endpoint is served with no table in use: %v %v", r, err)
	}

	// The first push: the table is in use, and the primary is answered.
	f.push(50)
	f.wantAddr("no flags", primaryIP)
	f.assertNoData(ridHost(1), dns.TypeAAAA)
	f.assertNoData(ridHost(1), dns.TypeTXT)
	if got := addrOf(f.zoneQ(ridHost(9), dns.TypeA)); got != primaryIP { // unknown rid: the global pair, so the zone is no oracle
		t.Fatalf("an unknown resolver id gets %q", got)
	}
	if got := addrOf(f.zoneQ(rid(1)+"-laptop."+zoneName+".", dns.TypeA)); got != primaryIP {
		t.Fatalf("<rid>-<client> gets %q", got)
	}
	ns := f.zoneQ(zoneName+".", dns.TypeNS)
	if len(ns.Answer) != 3 || !ns.Authoritative {
		t.Fatalf("the apex NS: %v", ns)
	}
	for i, rr := range ns.Answer {
		x := rr.(*dns.NS)
		if x.Hdr.Ttl != 3600 || x.Ns != "ns"+string(rune('1'+i))+"."+zoneName+"." {
			t.Fatalf("NS %d: %v", i, x)
		}
	}
	for i, want := range []string{primaryIP, fallbackIP, "1.1.1.1"} {
		r := f.zoneQ("ns"+string(rune('1'+i))+"."+zoneName+".", dns.TypeA)
		if addrOf(r) != want || r.Answer[0].Header().Ttl != 3600 {
			t.Fatalf("ns%d: %v", i+1, r)
		}
	}
	f.assertNoData("ns4."+zoneName+".", dns.TypeA) // a slot no node holds: NODATA, never NXDOMAIN
	f.assertNoData("ns1."+zoneName+".", dns.TypeAAAA)

	// The hub withdraws the primary (this node): the answer moves to the fallback. The
	// withdrawn node still serves every Endpoint (invariant 1).
	f.push(51, 0)
	f.wantAddr("primary withdrawn", fallbackIP)
	if r, err := f.c.tcp("127.0.0.1", q(allowedName, dns.TypeA)); err != nil || !hasA(r, ipV1) {
		t.Fatalf("a withdrawn node stopped serving its Endpoints: %v %v", r, err)
	}
	// Both withdrawn, as on a node behind a rollout: the primary.
	f.push(52, 0, 1)
	f.wantAddr("both withdrawn", primaryIP)
	// The fallback withdrawn: the primary. Cleared: the primary.
	f.push(53, 1)
	f.wantAddr("fallback withdrawn", primaryIP)
	f.push(54)
	f.wantAddr("cleared", primaryIP)
	// The NS set does not follow failover.
	if ns2 := f.zoneQ(zoneName+".", dns.TypeNS); len(ns2.Answer) != 3 {
		t.Fatalf("failover changed the NS set: %v", ns2)
	}
	// A lower version is refused and changes nothing.
	f.push(10, 0)
	time.Sleep(500 * time.Millisecond)
	f.wantAddr("a lower version", primaryIP)
}

// ---- a restarted node

// A restarted node answers REFUSED for hostnames until the hub's push (or 30 s),
// keeps every withdrawal it held, and does not pull clients back to a primary the
// hub had withdrawn (SC 8a.5 Table in use, 8a.4 At start).
func TestW8ARestartedNodeKeepsItsWithdrawalAndRefusesUntilAPush(t *testing.T) {
	f := upNode(t, 0, upOpts{})
	f.push(50)
	f.wantAddr("before", primaryIP)
	f.push(51, 0)
	f.wantAddr("withdrawn", fallbackIP)

	// Restart the whole node: agent and dns.
	f.dnsCancel()
	<-f.dnsDone
	f.stopAgent()
	f.clock.Slow()
	f.startAgent()
	s, err := f.hub.NextSession(15 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	f.startDNSWith(f.fu.addr, nil)
	f.waitServing()
	f.c = &clients{n: f.node}
	for _, c := range []struct {
		name string
		qt   uint16
	}{{ridHost(1), dns.TypeA}, {zoneName + ".", dns.TypeNS}, {"ns1." + zoneName + ".", dns.TypeA}} {
		if r := f.zoneQ(c.name, c.qt); r.Rcode != dns.RcodeRefused {
			t.Fatalf("a restarted node with no table in use answered %s %s: %v", c.name, dns.TypeToString[c.qt], r)
		}
	}
	if soa := f.zoneQ(zoneName+".", dns.TypeSOA); soa.Rcode != dns.RcodeSuccess || len(soa.Answer) != 1 {
		t.Fatalf("the apex SOA: %v", soa)
	}
	// 30 s with no push: the persisted flags are used, with PanelStale: the node was
	// withdrawn by the hub, so its answer is still the fallback, not the primary.
	f.clock.Thaw()
	f.clock.Advance(31 * time.Second)
	f.wantAddr("30 s with no push", fallbackIP)
	// The hub's push comes (a redelivery of nothing: a higher version that clears the
	// withdrawal): the primary is answered again.
	f.fresh()
	f.push(52)
	f.wantAddr("the hub's push", primaryIP)
}

// With a push in first, a restarted node leaves "no table in use" at once.
func TestW8ARestartedNodeIsCurrentWithinOnePush(t *testing.T) {
	f := upNode(t, 0, upOpts{})
	f.push(50, 0)
	f.wantAddr("withdrawn", fallbackIP)
	f.dnsCancel()
	<-f.dnsDone
	f.stopAgent()
	f.clock.Slow()
	f.startAgent()
	s, err := f.hub.NextSession(15 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	f.startDNSWith(f.fu.addr, nil)
	f.waitServing()
	f.c = &clients{n: f.node}
	if r := f.zoneQ(ridHost(1), dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatalf("before the push: %v", r)
	}
	// What the hub sends first on a new stream: ServerTime, then the latest push.
	f.fresh()
	f.push(50, 0) // a redelivery of the version in use
	f.wantAddr("the redelivered push", fallbackIP)
}

// ---- local mode and a stalled Control stream

// The fallback with the panel gone: while the stream is stale and its own probes
// say the primary is down, it answers its own address (SC 8a.5). The same node
// with a fresh panel answers by the hub's flags only, and a local view never undoes
// a withdrawal that the hub made.
func TestW8LocalModeFromTheAgentToTheAnswers(t *testing.T) {
	f := upNode(t, 1, upOpts{probes: true})
	f.fresh()
	f.push(50)
	f.wantAddr("fresh panel", primaryIP)

	// Its probes of the primary fail for 100 s of its clock, with the panel fresh the
	// whole time: PeerDown is set, and the answer does not change.
	f.steps(100*time.Second, f.fresh)
	f.wantAddr("the primary is down for this node but the panel is fresh", primaryIP)

	// A stalled Control stream: the stream is open and no ServerTime comes. After 30 s
	// of its clock the node is in local mode and answers the fallback, itself.
	f.steps(36*time.Second, nil)
	f.wantAddr("a stalled stream", fallbackIP)
	// Every answer in local mode is one address of the pair, never empty.
	f.assertNoData(ridHost(1), dns.TypeAAAA)

	// The panel returns: ServerTime and the push, and the node follows the hub again.
	f.fresh()
	f.push(51)
	f.wantAddr("the panel is back", primaryIP)

	// The hub withdraws this node (the fallback), then the stream stalls again: the
	// local view marks the primary down, but never undoes the hub's withdrawal, so the
	// answer is the primary.
	f.push(52, 1)
	f.wantAddr("withdrawn by the hub, fresh", primaryIP)
	f.steps(36*time.Second, nil)
	f.wantAddr("withdrawn by the hub, local mode", primaryIP)
}

// A node never takes itself out: the primary with every peer down in its own view
// and a stale panel still answers its own address, and keeps the withdrawal the hub
// made (T-541).
func TestW8ANodeNeverTakesItselfOut(t *testing.T) {
	f := upNode(t, 0, upOpts{probes: true})
	f.fresh()
	f.push(50)
	f.wantAddr("fresh", primaryIP)
	f.steps(100*time.Second, f.fresh) // every peer is PeerDown for this node
	f.steps(36*time.Second, nil)      // and the panel is stale
	f.wantAddr("every peer down, stale panel", primaryIP)
	// The hub's withdrawal of this node stays in force in local mode: it is the fallback
	// that is answered, though this node's view marks the fallback down too.
	f.fresh()
	f.push(51, 0)
	f.wantAddr("withdrawn by the hub", fallbackIP)
	f.steps(36*time.Second, nil)
	f.wantAddr("withdrawn by the hub, local mode", fallbackIP)
}

// ---- a node whose clock is ahead

// A node whose clock runs 30 minutes ahead keeps accepting pushes and following
// withdrawals once a ServerTime has given it the hub's time; with none yet it judges
// by its own clock and refuses the push as expired (SC 8a.4 Clock).
func TestW8ANodeWhoseClockIsAhead(t *testing.T) {
	f := upNode(t, 0, upOpts{clockAhead: 31 * time.Minute, noServerTime: true})
	// No ServerTime since start: the push expires in 30 minutes of the hub's clock, and
	// the node's own clock is past that.
	f.push(50)
	time.Sleep(time.Second)
	if r := f.zoneQ(ridHost(1), dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatalf("a push the node judged by its own clock was taken: %v", r)
	}
	f.fresh()
	f.push(51)
	f.wantAddr("after a ServerTime", primaryIP)
	f.push(52, 0)
	f.wantAddr("a withdrawal followed", fallbackIP)
	eventually(t, 10*time.Second, "the skew alert", func() bool { return f.alerts.Count(alert.Skew) > 0 })
	// The clock moves a further 30 minutes with a stream open: the next ServerTime puts
	// it right and pushes go on being taken.
	f.clock.Advance(30 * time.Minute)
	f.fresh()
	f.push(53)
	f.wantAddr("30 minutes further", primaryIP)
}

// ---- split brain

// Both nodes of the pair are alive, the panel is unreachable from both, and the link
// between them is cut: each answers an address of the pair (the primary answers
// itself, the fallback answers itself), never empty, NXDOMAIN or REFUSED, AAAA is
// NODATA, and each tenant is served by its own profile on both nodes. Plain DNS gives
// DNS1 the primary and DNS2 the fallback, both serving (T-016). When the panel
// returns, both follow the hub's table within one push.
func TestW8SplitBrainWithTwoNodes(t *testing.T) {
	a := upNode(t, 0, upOpts{probes: true})
	b := upNode(t, 1, upOpts{probes: true})
	for _, f := range []*fnode{a, b} {
		f.fresh()
		f.push(50)
		f.wantAddr("both nodes, panel fresh", primaryIP)
	}

	// The panel is gone from both and the nodes cannot see each other.
	done := make(chan struct{}, 2)
	for _, f := range []*fnode{a, b} {
		f := f
		go func() { f.steps(136*time.Second, nil); done <- struct{}{} }()
	}
	<-done
	<-done
	a.wantAddr("split brain, the primary", primaryIP)
	b.wantAddr("split brain, the fallback", fallbackIP)
	pair := map[string]bool{primaryIP: true, fallbackIP: true}
	for _, f := range []*fnode{a, b} {
		r := f.zoneQ(ridHost(1), dns.TypeA)
		if !pair[addrOf(r)] || r.Rcode != dns.RcodeSuccess {
			t.Fatalf("an answer outside the pair: %v", r)
		}
		f.assertNoData(ridHost(1), dns.TypeAAAA)
		// The NS set is the same on both: failover does not change it.
		if ns := f.zoneQ(zoneName+".", dns.TypeNS); len(ns.Answer) != 3 {
			t.Fatalf("the NS set differs: %v", ns)
		}
	}

	// Each tenant is served from its own profile on both nodes: DNS1 and DNS2 both
	// serve every Endpoint. Tenant 1 blocks one name and lets the other pass, tenant 2
	// the reverse; the block never reaches the resolver.
	for name, f := range map[string]*fnode{"DNS1": a, "DNS2": b} {
		for _, c := range []struct {
			ep      byte
			src     string
			name    string
			blocked bool
		}{
			{1, "127.0.0.1", blockedByOne, true}, {1, "127.0.0.1", blockedByTwo, false},
			{2, "127.0.0.2", blockedByTwo, true}, {2, "127.0.0.2", blockedByOne, false},
		} {
			before := f.fu.asked(c.name)
			r, err := f.c.tcp(c.src, q(c.name, dns.TypeA))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got := hasA(r, ipV1)
			if got == c.blocked {
				t.Fatalf("%s: tenant %d asked %s: blocked=%v, answer %v", name, c.ep, c.name, c.blocked, r.Answer)
			}
			if c.blocked && f.fu.asked(c.name) != before {
				t.Fatalf("%s: a blocked name reached the resolver", name)
			}
		}
	}

	// The panel returns on both: one push each and both follow the hub's table.
	for _, f := range []*fnode{a, b} {
		f.fresh()
		f.push(51)
	}
	a.wantAddr("converged", primaryIP)
	b.wantAddr("converged", primaryIP)
}

// The panel is stale but every peer is reachable: neither node leaves the hub's
// answer (nothing fails, so nothing moves).
func TestW8AStalePanelWithHealthyPeersMovesNothing(t *testing.T) {
	a := upNode(t, 0, upOpts{})
	b := upNode(t, 1, upOpts{})
	for _, f := range []*fnode{a, b} {
		f.fresh()
		f.push(50)
		f.wantAddr("fresh", primaryIP)
		f.clock.Advance(40 * time.Second) // stalled: no ServerTime for 40 s
	}
	time.Sleep(time.Second)
	a.wantAddr("stale, peers fine", primaryIP)
	b.wantAddr("stale, peers fine", primaryIP)
}
