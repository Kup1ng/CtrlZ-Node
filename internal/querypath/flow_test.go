package querypath_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const (
	allowedName = "allowed.example.com"
	blockedName = "blocked.example.com"
	ipV1        = "93.184.216.34" // what the first stand-in Unbound says
	ipV2        = "93.184.216.35" // what the second says
	panelName   = "panel.example.net"
	panel2Name  = "panel2.example.net"
)

func lastNodeVersion(s *fakehub.Session) uint64 {
	msgs := s.Messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if hb := msgs[i].GetHeartbeat(); hb != nil {
			return hb.NodeConfigVersion
		}
	}
	return 0
}

func revocation(seq uint64, exp int64, ids ...byte) *hubv1.HubMessage {
	rev := &policyv1.Revocation{RevSeq: seq, Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, ExpiresAt: exp}
	for _, b := range ids {
		rev.Ids = append(rev.Ids, []byte(strings.Repeat(string([]byte{b}), 16)))
	}
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: rev}}
}

// TestMergeBTheWholeNodeAnswersThroughTheRealPath is the end-to-end test of merge B.
func TestMergeBTheWholeNodeAnswersThroughTheRealPath(t *testing.T) {
	n := newNode(t)
	fu := newFakeUnbound(t, "127.0.0.1", 5310, ipV1)

	// The hub's first entry: Endpoint 1 (blocks one name) with its Plain DNS claim,
	// and a table of three nodes.
	// The panel hostnames are blocked by the Endpoint on purpose: a system name must still
	// get its true answer (T-040), and only a hostname the NodeConfig names is one.
	d1, h1 := profile(t, blockedName, panelName, panel2Name)
	ep1, cl1 := endpoint(1, h1)
	n.addEntry([][]byte{d1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{ep1}, PutClaims: []*policyv1.ClaimRecord{cl1}, PairTable: storetest.Table(3, 0)})

	n.startAgent()
	s, err := n.hub.NextSession(15 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	proofKey := storetest.RandomSecret(t, 32)
	_ = s.Send(serverTime())
	_ = s.Send(nodeConfigMsg(nodeConfig(1, proofKey, commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE)))
	_ = s.Send(headNotice(1))
	if _, err := s.Wait(60*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 1 && m.GetApplyResult().Ok }); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "the NodeConfig", func() bool { return lastNodeVersion(s) == 1 })
	_ = s.Send(n.certBundleMsg())
	eventually(t, 30*time.Second, "the zone key", func() bool { return n.keyFiles() >= 1 })

	n.startDNS(fu.addr)
	c := &clients{n: n}
	byName := map[string]asker{}
	for _, a := range askers() {
		byName[a.name] = a
	}
	resolve := func(a asker, ep byte, name string) (*dns.Msg, error) { return a.ask(c, ep, q(name, dns.TypeA)) }

	// dns serves only once the agent has handed it the image: the first identified
	// Plain query that gets an answer ends the wait.
	eventually(t, 90*time.Second, "Endpoint 1 answered over Plain DNS", func() bool {
		r, err := resolve(byName["plain-tcp"], 1, allowedName)
		return err == nil && hasA(r, ipV1)
	})

	// 1. Every transport answers an identified query through the real path: the
	// allowed name comes from the Unbound stand-in, the blocked one never reaches it.
	for _, a := range askers() {
		t.Run("identified/"+a.name, func(t *testing.T) {
			r, err := resolve(a, 1, allowedName)
			if err != nil {
				t.Fatalf("allowed: %v", err)
			}
			if r.Rcode != dns.RcodeSuccess || !hasA(r, ipV1) {
				t.Fatalf("allowed name: rcode %d, %v", r.Rcode, r.Answer)
			}
			before := fu.asked(blockedName)
			r, err = resolve(a, 1, blockedName)
			if err != nil {
				t.Fatalf("blocked: %v", err)
			}
			if hasA(r, ipV1) {
				t.Fatalf("the block rule did not act: %v", r.Answer)
			}
			if fu.asked(blockedName) != before {
				t.Fatal("a blocked name reached the resolver")
			}
		})
	}

	// 2. A Plain DNS source nobody claims is REFUSED (free DNS is a seam, off); an
	// unknown resolver id is refused at the handshake.
	t.Run("unidentified", func(t *testing.T) {
		r, err := c.tcp("127.0.0.9", q(allowedName, dns.TypeA))
		if err != nil || r.Rcode != dns.RcodeRefused {
			t.Fatalf("tcp: %v %v", r, err)
		}
		r, err = c.udp("127.0.0.9", q(allowedName, dns.TypeA))
		if err != nil || r.Rcode != dns.RcodeRefused {
			t.Fatalf("udp: %v %v", r, err)
		}
		if _, err := c.dot(rid(9)+"."+zoneName, q(allowedName, dns.TypeA)); err == nil {
			t.Fatal("a DoT handshake for an unknown resolver id completed")
		}
	})

	// 3. Heartbeat numbers: the local Unbound's health, qps and the cache hit rate
	// reach the hub through dns -> socket -> agent.
	t.Run("heartbeat stats", func(t *testing.T) {
		for i := 0; i < 150; i++ {
			if _, err := resolve(byName["plain-tcp"], 1, allowedName); err != nil {
				t.Fatal(err)
			}
		}
		local := wire.LocalUnboundID()
		eventually(t, 40*time.Second, "stats in the Heartbeat", func() bool {
			hb := lastHeartbeat(s)
			ok := false
			for _, u := range hb.Upstreams {
				if string(u.Id) == string(local[:]) && u.Healthy && u.LatencyMs >= 1 {
					ok = true
				}
			}
			return ok && hb.Qps > 0 && hb.CacheHitPermille > 500
		})
	})

	fu = wiringChecks(t, n, s, c, fu, proofKey, byName, resolve)

	// 4. A revocation takes effect at once and ends at its expiry (hub time).
	t.Run("revocation", func(t *testing.T) {
		_ = s.Send(revocation(5, time.Now().Add(6*time.Second).Unix(), 1))
		eventually(t, 20*time.Second, "DoT refused", func() bool {
			r, err := resolve(byName["dot"], 1, allowedName)
			return err == nil && r.Rcode == dns.RcodeRefused
		})
		if st, _, err := c.doh(listen.DoH, true, "x."+zoneName, "/"+tok(1), rid(1)+"."+zoneName, q(allowedName, dns.TypeA)); err != nil || st != 403 {
			t.Fatalf("DoH under a revocation: status %d, %v", st, err)
		}
		eventually(t, 40*time.Second, "the revocation to end", func() bool {
			r, err := resolve(byName["dot"], 1, allowedName)
			return err == nil && r.Rcode == dns.RcodeSuccess && hasA(r, ipV1)
		})
	})

	// 5. A NodeConfig that changes the resolve path: upstream mode with one upstream
	// that is this node's own address (left out and reported down, never asked) and one
	// healthy. The cache is purged, so the same name now comes from the second.
	fu2 := newFakeUnbound(t, "127.0.0.5", 5311, ipV2)
	t.Run("resolve change and upstream loop", func(t *testing.T) {
		loopID, okID := strings.Repeat("\x11", 16), strings.Repeat("\x22", 16)
		cfg := nodeConfig(3, proofKey, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
			&hubv1.Upstream{Id: []byte(loopID), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "8.8.8.8:53", TimeoutMs: 3000, HealthIntervalS: 1},
			&hubv1.Upstream{Id: []byte(okID), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: fu2.addr, TimeoutMs: 3000, HealthIntervalS: 1})
		_ = s.Send(nodeConfigMsg(cfg))
		eventually(t, 30*time.Second, "the new NodeConfig", func() bool { return lastNodeVersion(s) == 3 })
		var last string
		defer func() {
			if t.Failed() {
				t.Logf("last answer: %s", last)
			}
		}()
		eventually(t, 30*time.Second, "the answer from the second resolver", func() bool {
			start := time.Now()
			r, err := resolve(byName["dot"], 1, allowedName)
			last = fmt.Sprintf("%v %v after %s", r, err, time.Since(start))
			// The looping upstream is first in the config: a query sent to it would
			// wait for its 3 s timeout (the container has no network).
			return err == nil && hasA(r, ipV2) && time.Since(start) < 2*time.Second
		})
		if n.alerts.Count(alert.UpstreamLoop) == 0 {
			t.Error("the agent did not alert on the looping upstream")
		}
		eventually(t, 40*time.Second, "upstream health in the Heartbeat", func() bool {
			var loopDown, okUp bool
			for _, u := range lastHeartbeat(s).Upstreams {
				switch string(u.Id) {
				case loopID:
					loopDown = !u.Healthy
				case okID:
					okUp = u.Healthy
				}
			}
			return loopDown && okUp
		})
	})

	// 5b. An upstream-only config whose every upstream is a node's own address leaves
	// the node no path: a miss is SERVFAIL, and the next config that has a usable
	// upstream brings the path back.
	t.Run("only looping upstreams", func(t *testing.T) {
		loopID, okID := strings.Repeat("\x11", 16), strings.Repeat("\x22", 16)
		up := func(id, addr string) *hubv1.Upstream {
			return &hubv1.Upstream{Id: []byte(id), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr, TimeoutMs: 3000, HealthIntervalS: 1}
		}
		_ = s.Send(nodeConfigMsg(nodeConfig(4, proofKey, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, up(loopID, "8.8.8.8:53"))))
		eventually(t, 30*time.Second, "the looping-only NodeConfig", func() bool { return lastNodeVersion(s) == 4 })
		eventually(t, 30*time.Second, "SERVFAIL with no path", func() bool {
			r, err := resolve(byName["dot"], 1, "nopath.example.com")
			return err == nil && r.Rcode == dns.RcodeServerFailure
		})
		eventually(t, 40*time.Second, "the upstream reported down", func() bool {
			hb := lastHeartbeat(s)
			for _, u := range hb.Upstreams {
				if string(u.Id) == loopID && !u.Healthy {
					return true
				}
			}
			return false
		})
		_ = s.Send(nodeConfigMsg(nodeConfig(5, proofKey, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, up(loopID, "8.8.8.8:53"), up(okID, fu2.addr))))
		eventually(t, 30*time.Second, "the path back", func() bool {
			r, err := resolve(byName["dot"], 1, "nopath.example.com")
			return err == nil && hasA(r, ipV2)
		})
	})

	// 6. An image switch: Endpoint 2 does not exist until the hub's second entry is
	// applied, and then answers on every transport.
	t.Run("image switch", func(t *testing.T) {
		if _, err := resolve(byName["dot"], 2, allowedName); err == nil {
			t.Fatal("Endpoint 2 answered before its entry")
		}
		d2, h2 := profile(t, "other.example.com")
		ep2, cl2 := endpoint(2, h2)
		n.addEntry([][]byte{d2}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{ep2}, PutClaims: []*policyv1.ClaimRecord{cl2}})
		_ = s.Send(headNotice(2))
		if _, err := s.Wait(60*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 2 && m.GetApplyResult().Ok }); err != nil {
			t.Fatal(err)
		}
		for _, a := range askers() {
			a := a
			eventually(t, 30*time.Second, "Endpoint 2 over "+a.name, func() bool {
				r, err := resolve(a, 2, allowedName)
				return err == nil && hasA(r, ipV2)
			})
		}
		if r, err := resolve(byName["doq"], 1, allowedName); err != nil || !hasA(r, ipV2) {
			t.Fatalf("Endpoint 1 after the switch: %v %v", r, err)
		}
		// Two tenants through the real path, on every transport: each Endpoint's block
		// list acts on its own queries only, and the shared cache holds true answers.
		for _, a := range askers() {
			if r, err := resolve(a, 1, blockedName); err != nil || hasA(r, ipV2) {
				t.Fatalf("%s: tenant 1 must block its own name: %v %v", a.name, r, err)
			}
			if r, err := resolve(a, 2, blockedName); err != nil || !hasA(r, ipV2) {
				t.Fatalf("%s: tenant 2 must not inherit tenant 1's block: %v %v", a.name, r, err)
			}
			if r, err := resolve(a, 2, "other.example.com"); err != nil || hasA(r, ipV2) {
				t.Fatalf("%s: tenant 2 must block its own name: %v %v", a.name, r, err)
			}
			if r, err := resolve(a, 1, "other.example.com"); err != nil || !hasA(r, ipV2) {
				t.Fatalf("%s: tenant 1 must not inherit tenant 2's block: %v %v", a.name, r, err)
			}
		}
	})

	// 6a. Loops are judged against every node of the image's table, not only the
	// node's own bind and advertised address (p4n-MB-r3-1). 1.1.1.1 is node 2's
	// dns_ip in the table and is neither address of this node; 9.9.9.9 is in no
	// table until a later image adds node 3.
	t.Run("upstream equal to a peer node's dns_ip", func(t *testing.T) {
		peerID, okID := strings.Repeat("\x33", 16), strings.Repeat("\x22", 16)
		up := func(id, addr string) *hubv1.Upstream {
			return &hubv1.Upstream{Id: []byte(id), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr, TimeoutMs: 3000, HealthIntervalS: 1}
		}
		heartbeatDown := func(id string) bool {
			for _, u := range lastHeartbeat(s).Upstreams {
				if string(u.Id) == id {
					return !u.Healthy
				}
			}
			return false
		}
		// From the table that is already in the image.
		_ = s.Send(nodeConfigMsg(nodeConfig(6, proofKey, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, up(peerID, "1.1.1.1:53"), up(okID, fu2.addr))))
		eventually(t, 30*time.Second, "the NodeConfig with a peer's address", func() bool { return lastNodeVersion(s) == 6 })
		eventually(t, 30*time.Second, "the peer upstream left out", func() bool { return n.join.Looping() == 1 })
		eventually(t, 40*time.Second, "the peer upstream reported down", func() bool { return heartbeatDown(peerID) })
		eventually(t, 30*time.Second, "the answer from the healthy upstream", func() bool {
			start := time.Now()
			r, err := resolve(byName["dot"], 1, "peer1.example.com")
			return err == nil && hasA(r, ipV2) && time.Since(start) < 2*time.Second
		})

		// An image that adds the peer later: the upstream is a member of the Router
		// until the image arrives, and leaves it when the image does.
		newID := strings.Repeat("\x44", 16)
		_ = s.Send(nodeConfigMsg(nodeConfig(7, proofKey, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, up(newID, "9.9.9.9:53"), up(okID, fu2.addr))))
		eventually(t, 30*time.Second, "the NodeConfig before the image", func() bool { return lastNodeVersion(s) == 7 })
		eventually(t, 30*time.Second, "no upstream left out before the image", func() bool { return n.join.Looping() == 0 })
		before := n.join.Switched()
		seq := n.addEntry(nil, &policyv1.ConfigEntry{PairTable: storetest.Table(4, 1)})
		_ = s.Send(headNotice(seq))
		if _, err := s.Wait(60*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == seq && m.GetApplyResult().Ok }); err != nil {
			t.Fatal(err)
		}
		eventually(t, 30*time.Second, "the new peer's upstream left out by the image", func() bool { return n.join.Looping() == 1 })
		if n.join.Switched() == before {
			t.Fatal("the image changed the loop set and the Router was not rebuilt")
		}
		eventually(t, 40*time.Second, "the new peer's upstream reported down", func() bool { return heartbeatDown(newID) })
		eventually(t, 30*time.Second, "the answer from the healthy upstream after the image", func() bool {
			start := time.Now()
			r, err := resolve(byName["dot"], 1, "peer2.example.com")
			return err == nil && hasA(r, ipV2) && time.Since(start) < 2*time.Second
		})
	})

	// 6a2. Upstream health and failover through the wired role (7.7): the first
	// upstream of the config is killed, comes back, and is blackholed; queries are
	// answered throughout, and the Heartbeat carries the Router's health and latency.
	t.Run("upstream failover", func(t *testing.T) {
		failoverChecks(t, s, proofKey, fu2, func(name string) (*dns.Msg, error) {
			return resolve(byName["dot"], 1, name)
		}, 8)
	})

	// 6b. The query path judges revocations in hub time (p4n-MB-r2-1, -6). The hub's
	// clock is moved against the node's, in both directions, and a revocation whose
	// expiry lies in hub time must refuse while hub time is before it and end after it.
	// A Handler on the node clock would end it at once (hub behind) or never (hub ahead).
	// It runs late and the hub's clock is not put back after the second case: a
	// revocation that was held while the hub was ahead would act again if it were.
	for i, skew := range []int64{-120, 120} {
		skew := skew
		t.Run(fmt.Sprintf("hub clock %+d s", skew), func(t *testing.T) {
			if skew < 0 {
				defer func() {
					_ = s.Send(serverTime()) // the hub's clock is the node's again; the revocation has ended
					time.Sleep(1500 * time.Millisecond)
				}()
			}
			_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: time.Now().Unix() + skew}}})
			time.Sleep(1500 * time.Millisecond) // the agent has told dns the offset
			hubNow := time.Now().Unix() + skew
			_ = s.Send(revocation(uint64(6+i), hubNow+6, 1))
			refused := time.Now()
			eventually(t, 20*time.Second, "DoT refused under a hub-time revocation", func() bool {
				r, err := resolve(byName["dot"], 1, allowedName)
				return err == nil && r.Rcode == dns.RcodeRefused
			})
			eventually(t, 40*time.Second, "the revocation to end in hub time", func() bool {
				r, err := resolve(byName["dot"], 1, allowedName)
				return err == nil && r.Rcode == dns.RcodeSuccess && hasA(r, ipV2)
			})
			if time.Since(refused) < 2*time.Second {
				t.Fatalf("the revocation ended after %s, long before its hub-time expiry", time.Since(refused))
			}
		})
	}

	// 7. The agent goes away: dns keeps its last image and keeps answering, through
	// the real resolver (a name nobody has asked yet).
	t.Run("agent socket down", func(t *testing.T) {
		n.stopAgent()
		time.Sleep(500 * time.Millisecond)
		before := fu2.asked("fresh1.example.com") + fu2.asked("fresh2.example.com")
		for i, name := range []string{"fresh1.example.com", "fresh2.example.com"} {
			a := askers()[2+i] // dot, doq
			r, err := resolve(a, 1, name)
			if err != nil || !hasA(r, ipV2) {
				t.Fatalf("%s with the agent down: %v %v", a.name, r, err)
			}
		}
		if fu2.asked("fresh1.example.com")+fu2.asked("fresh2.example.com") == before {
			t.Fatal("the answers did not come through the resolver")
		}
		if r, err := resolve(byName["plain-tcp"], 2, blockedName); err != nil || r == nil {
			t.Fatalf("Endpoint 2 over Plain with the agent down: %v", err)
		}
	})
}
