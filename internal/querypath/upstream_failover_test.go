package querypath_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
)

// blackhole is a UDP socket that reads every datagram and answers none: a path
// that is dark in the way a firewall DROP makes it, which a refused port is not
// (that one fails at once). A query to it can only time out.
type blackhole struct {
	pc   net.PacketConn
	read chan struct{}
}

func newBlackhole(t *testing.T, addr string) *blackhole {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{pc: pc, read: make(chan struct{}, 1024)}
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			select {
			case b.read <- struct{}{}:
			default:
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return b
}

func (b *blackhole) close() { _ = b.pc.Close() }

// failoverChecks drives the upstream health and failover model of 7.7 through the
// whole wired node: a real agent and hub stand-in, the dns role with its query path
// and Router, a client over DoT, and two UDP upstreams that this test kills and then
// blackholes. The first upstream of the config is the one that breaks, so every
// query that gets an answer has failed over inside the Router, and what the hub
// sees (Heartbeat upstream health with its check latency) comes from the same
// Router. It leaves the node with config version cfgVersion+1 (one upstream, fu2),
// the state the tests after it expect.
func failoverChecks(t *testing.T, s *fakehub.Session, proofKey []byte, fu2 *fakeUnbound,
	askDoT func(name string) (*dns.Msg, error), cfgVersion uint64) {

	const addrA = "127.0.0.6:5312"
	idA, idB := strings.Repeat("\x55", 16), strings.Repeat("\x22", 16)
	up := func(id, addr string) *hubv1.Upstream {
		return &hubv1.Upstream{Id: []byte(id), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr, TimeoutMs: 1000, HealthIntervalS: 1}
	}
	host, port := splitHostPort(t, addrA)
	a := newFakeUnbound(t, host, port, ipV1)

	_ = s.Send(nodeConfigMsg(nodeConfig(cfgVersion, proofKey, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, up(idA, addrA), up(idB, fu2.addr))))
	eventually(t, 30*time.Second, "the failover NodeConfig", func() bool { return lastNodeVersion(s) == cfgVersion })

	n := 0
	fresh := func() string { n++; return fmt.Sprintf("fo%d.example.com", n) }
	// ask returns what the client got for a name nobody has asked before, and how
	// long it took.
	ask := func() (*dns.Msg, time.Duration, error) {
		start := time.Now()
		r, err := askDoT(fresh())
		return r, time.Since(start), err
	}
	healthOf := func(id string) (known, healthy bool, ms uint32) {
		for _, u := range lastHeartbeat(s).Upstreams {
			if string(u.Id) == id {
				return true, u.Healthy, u.LatencyMs
			}
		}
		return false, false, 0
	}

	// 1. Both up: the first upstream of the config answers, and the hub is told
	// how long its latest passed check took.
	t.Run("first upstream answers", func(t *testing.T) {
		eventually(t, 30*time.Second, "the answer from the first upstream", func() bool {
			r, _, err := ask()
			return err == nil && hasA(r, ipV1)
		})
		eventually(t, 40*time.Second, "both upstreams healthy with a latency in the Heartbeat", func() bool {
			_, hA, msA := healthOf(idA)
			_, hB, msB := healthOf(idB)
			return hA && hB && msA >= 1 && msB >= 1
		})
	})

	// 2. The first upstream is killed: its port refuses, every attempt fails at
	// once. Queries keep being answered, by the second upstream, and the hub is
	// told the first is down.
	t.Run("first upstream killed", func(t *testing.T) {
		_ = a.srv.Shutdown()
		for i := 0; i < 12; i++ {
			r, took, err := ask()
			if err != nil || r.Rcode != dns.RcodeSuccess || !hasA(r, ipV2) {
				t.Fatalf("query %d with the first upstream killed: %v %v", i, r, err)
			}
			if took > 2500*time.Millisecond {
				t.Fatalf("query %d took %s: a refused upstream must fail over at once", i, took)
			}
		}
		eventually(t, 40*time.Second, "the killed upstream down in the Heartbeat", func() bool {
			known, h, _ := healthOf(idA)
			_, hB, _ := healthOf(idB)
			return known && !h && hB
		})
	})

	// 3. It comes back and takes the first place again: three passed checks bring it
	// up (SC 8a.4), and the order puts it ahead of the second.
	var a2 *fakeUnbound // the restored first upstream, which step 4 blackholes
	t.Run("first upstream back", func(t *testing.T) {
		a2 = newFakeUnbound(t, host, port, ipV1)
		eventually(t, 40*time.Second, "the upstream healthy again in the Heartbeat", func() bool {
			_, h, ms := healthOf(idA)
			return h && ms >= 1
		})
		eventually(t, 30*time.Second, "answers from the first upstream again", func() bool {
			r, _, err := ask()
			return err == nil && hasA(r, ipV1)
		})
	})

	// 4. The first upstream is blackholed while the order still prefers it: it
	// reads every packet and says nothing. No query may fail (the second upstream is
	// behind it), the first queries pay the timeout, and then the Router passes
	// the dark member over: three errors, then two failed checks.
	t.Run("first upstream blackholed", func(t *testing.T) {
		_ = a2.srv.Shutdown()
		bh := newBlackhole(t, addrA)
		defer bh.close()
		start := time.Now()
		var slowest time.Duration
		for i := 0; i < 4; i++ {
			r, took, err := ask()
			if err != nil || r.Rcode != dns.RcodeSuccess || !hasA(r, ipV2) {
				t.Fatalf("query %d with the first upstream blackholed: %v %v", i, r, err)
			}
			slowest = max(slowest, took)
		}
		if len(bh.read) == 0 {
			t.Fatal("the blackhole saw no query: the first upstream was not tried first")
		}
		// Once the checks have confirmed it dark, an answer no longer waits for it.
		eventually(t, 30*time.Second, "the dark upstream passed over", func() bool {
			r, took, err := ask()
			return err == nil && hasA(r, ipV2) && took < 400*time.Millisecond
		})
		t.Logf("slowest of the first queries %s; passed over after %s", slowest, time.Since(start))
		eventually(t, 40*time.Second, "the blackholed upstream down in the Heartbeat", func() bool {
			known, h, _ := healthOf(idA)
			return known && !h
		})
	})

	// 5. The path is restored: the member comes back by passed checks, and is the
	// first again.
	t.Run("first upstream restored", func(t *testing.T) {
		newFakeUnbound(t, host, port, ipV1)
		eventually(t, 40*time.Second, "the upstream healthy again in the Heartbeat", func() bool {
			_, h, _ := healthOf(idA)
			return h
		})
		eventually(t, 30*time.Second, "answers from the first upstream again", func() bool {
			r, _, err := ask()
			return err == nil && hasA(r, ipV1)
		})
	})

	// The node goes on with the single upstream the later tests expect.
	_ = s.Send(nodeConfigMsg(nodeConfig(cfgVersion+1, proofKey, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, up(idB, fu2.addr))))
	eventually(t, 30*time.Second, "the NodeConfig after the failover checks", func() bool { return lastNodeVersion(s) == cfgVersion+1 })
}
