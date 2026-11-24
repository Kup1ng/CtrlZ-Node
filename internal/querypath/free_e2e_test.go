package querypath_test

// End to end, W9: free DNS (SC 5.2a) through the real agent, the real dns role and
// real clients. The agent's facts (the first ServerTime, caught_up_once, the free_dns
// value in force, the off floor) arrive over the real socket, and the stand-ins are
// the hub (shared proto) and two Unbound processes: the identified one and the free
// one, on their own loopback ports, so the test can say which of them was asked.
//
// Linux only, like e2e_test.go. Host ports 5650 to 5699.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/querypath"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const ipFree = "93.184.216.50" // what the free Unbound says

// startFreeDNS is startDNS with the free Unbound and the lane's ports.
func (n *node) startFreeDNS(local, free string) {
	n.t.Helper()
	n.ports = allocFreePorts(n.t)
	ctx, cancel := context.WithCancel(context.Background())
	n.dnsCancel, n.dnsDone = cancel, make(chan struct{})
	ready := make(chan struct{})
	go func() {
		defer close(n.dnsDone)
		err := dnsrole.Run(ctx, dnsrole.Config{
			Root: n.cfg.Root, AgentConf: n.cfg.ConfPath, SockPath: n.cfg.SockPath, Ports: n.ports,
			Build: querypath.Factory(querypath.Options{
				LocalUnbound: netip.MustParseAddrPort(local), IntervalUnit: 200 * time.Millisecond,
				Free:    querypath.FreeOptions{Unbound: netip.MustParseAddrPort(free)},
				OnBuilt: func(j *querypath.Join) { n.join = j },
			}),
			OnReady: func(*listen.Server) { close(ready) },
		})
		if err != nil {
			n.t.Errorf("dnsrole.Run: %v", err)
		}
	}()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		n.t.Fatal("the dns role did not come up")
	}
	n.t.Cleanup(func() { cancel(); <-n.dnsDone })
}

func allocFreePorts(t testing.TB) listen.Ports {
	t.Helper()
	return listen.Ports{DNS: 5660, TLS: 5661, HTTPS: 5662}
}

func freeOffMsg(v uint64) *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_FreeDnsOff{FreeDnsOff: &hubv1.FreeDnsOff{Version: v}}}
}

func TestFreeDNSThroughTheRealNode(t *testing.T) {
	n := newNode(t)
	idU := newFakeUnbound(t, "127.0.0.1", 5651, ipV1)
	freeU := newFakeUnbound(t, "127.0.0.1", 5652, ipFree)

	d1, h1 := profile(t, blockedName)
	ep1, cl1 := endpoint(1, h1)
	n.addEntry([][]byte{d1}, &policyv1.ConfigEntry{
		PutEndpoints: []*policyv1.EndpointRecord{ep1}, PutClaims: []*policyv1.ClaimRecord{cl1}, PairTable: storetest.Table(3, 0),
		FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 1000, Version: 5},
	})

	n.startAgent()
	s, err := n.hub.NextSession(15 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Send(serverTime())
	_ = s.Send(nodeConfigMsg(nodeConfig(1, storetest.RandomSecret(t, 32), commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE)))
	_ = s.Send(headNotice(1))
	if _, err := s.Wait(60*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 1 && m.GetApplyResult().Ok }); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "the NodeConfig", func() bool { return lastNodeVersion(s) == 1 })
	_ = s.Send(n.certBundleMsg())
	eventually(t, 30*time.Second, "the zone key", func() bool { return n.keyFiles() >= 1 })

	n.startFreeDNS(idU.addr, freeU.addr)
	c := &clients{n: n}
	const stranger = "127.0.0.9" // no claim, not a node

	ask := func(f func() (*dns.Msg, error)) *dns.Msg {
		r, err := f()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	tcp := func(name string) *dns.Msg {
		return ask(func() (*dns.Msg, error) { return c.tcp(stranger, q(name, dns.TypeA)) })
	}

	// 1. A stranger on Plain DNS is answered once the agent's facts say so, and by the
	// free Unbound alone.
	eventually(t, 90*time.Second, "a free answer over TCP", func() bool {
		r, err := c.tcp(stranger, q("free-one.example.net", dns.TypeA))
		return err == nil && hasA(r, ipFree)
	})
	if idU.asked("free-one.example.net") != 0 {
		t.Fatal("a free query reached the identified Unbound")
	}
	if freeU.asked("free-one.example.net") == 0 {
		t.Fatal("the free Unbound was not asked")
	}
	// ...and an identified query never reaches the free one.
	if r, err := c.tcp("127.0.0.1", q(allowedName, dns.TypeA)); err != nil || !hasA(r, ipV1) {
		t.Fatalf("identified over Plain DNS: %v %v", r, err)
	}
	if freeU.asked(allowedName) != 0 {
		t.Fatal("an identified query reached the free Unbound")
	}

	// 2. UDP: a source with no cookie gets an answer inside its share, and a source
	// with a valid server cookie is answered too.
	if r, err := c.udp(stranger, q("free-two.example.net", dns.TypeA)); err != nil || (!hasA(r, ipFree) && !r.Truncated) {
		t.Fatalf("udp: %v %v", r, err)
	}
	if r, err := c.udpCookie(stranger, q("free-three.example.net", dns.TypeA)); err != nil || !hasA(r, ipFree) {
		t.Fatalf("udp with a cookie: %v %v", r, err)
	}

	// 3. RD=0 is REFUSED and asks nobody.
	before := freeU.count.Load()
	m := q("free-rd0.example.net", dns.TypeA)
	m.RecursionDesired = false
	if r := ask(func() (*dns.Msg, error) { return c.tcp(stranger, m) }); r.Rcode != dns.RcodeRefused || freeU.count.Load() != before {
		t.Fatalf("rd0: %d, free Unbound asked %d times", r.Rcode, freeU.count.Load()-before)
	}

	// 4. The hub's FreeDnsOff turns the path off within seconds, whatever the log
	// says, and a later free_dns value of a version at or above the floor turns it on.
	_ = s.Send(freeOffMsg(6))
	eventually(t, 10*time.Second, "REFUSED after FreeDnsOff", func() bool { return tcp("free-four.example.net").Rcode == dns.RcodeRefused })
	if r := tcp("free-one.example.net"); r.Rcode != dns.RcodeRefused {
		t.Fatalf("a cached free answer is served while the path is off: %d", r.Rcode)
	}
	n.addEntry(nil, &policyv1.ConfigEntry{FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 1000, Version: 7}})
	_ = s.Send(headNotice(2))
	eventually(t, 60*time.Second, "free DNS back on at version 7", func() bool {
		r, err := c.tcp(stranger, q("free-five.example.net", dns.TypeA))
		return err == nil && hasA(r, ipFree)
	})

	// 5. Identified service is not touched by any of it: Endpoint 1 resolves the same
	// during and after the free path's off period, and was never counted by it.
	if r, err := c.tcp("127.0.0.1", q(allowedName, dns.TypeA)); err != nil || !hasA(r, ipV1) {
		t.Fatalf("identified: %v %v", r, err)
	}

	// 6. A node whose agent is gone has no facts to read: the free path is off. The
	// Unbound stand-ins are never asked while it is.
	n.stopAgent()
	eventually(t, 20*time.Second, "REFUSED with the agent down", func() bool { return tcp("free-six.example.net").Rcode == dns.RcodeRefused })
	if freeU.asked("free-six.example.net") != 0 {
		t.Fatal("the free Unbound was asked with the agent down")
	}
}
