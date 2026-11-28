package querypath_test

// The joins of merge B that the main end-to-end flow does not reach: the verify names
// and GET /v, the proof_key the hub delivered, the zone names and the DNS-01 TXT of
// the zone state, what the reporter hands to the hub, a NodeConfig that changes
// nothing the resolver uses, and the Isolated flag. Each assertion fails when its
// join is cut (p4n-MB-r1-3, -6 and -1). Host ports 5300 to 5349, as the flow.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// addedZone is a zone a later NodeConfig adds to zoneName.
const addedZone = "dns2.example.net"

func verifyLabel(c byte) string { return strings.Repeat(string(rune('q'+c)), 26) }

// getVerify is GET /v of a label, as the verify page makes it; only `seen` is read.
func (c *clients) getVerify(label string) (seen bool, err error) {
	host := label + ".verify." + zoneName
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: c.n.pool, ServerName: host, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	req, err := http.NewRequest("GET", "https://"+c.addr(listen.DoH)+"/v", nil)
	if err != nil {
		return false, err
	}
	req.Host = host
	resp, err := cl.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("GET /v: status %d", resp.StatusCode)
	}
	var b struct {
		Seen bool `json:"seen"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return false, err
	}
	return b.Seen, nil
}

func hasTXT(r *dns.Msg, v string) bool {
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == v {
			return true
		}
	}
	return false
}

func (n *node) proofObserved(s *fakehub.Session, label string) *hubv1.ProofObservation {
	for _, m := range s.Messages() {
		if p := m.GetProofObservation(); p != nil && p.Label == label {
			return p
		}
	}
	return nil
}

// wiringChecks runs the subtests and returns the identified Unbound's stand-in in
// use afterwards (it is stopped and started again by the Isolated subtest).
func wiringChecks(t *testing.T, n *node, s *fakehub.Session, c *clients, fu *fakeUnbound, proofKey []byte,
	byName map[string]asker, resolve func(asker, byte, string) (*dns.Msg, error)) *fakeUnbound {

	// The verify names (step 4a) and the proof_key of the NodeConfig the hub delivered.
	t.Run("verify names", func(t *testing.T) {
		l1, l2 := verifyLabel(0), verifyLabel(1)
		src := "127.0.0.9"
		r, err := c.udpCookie(src, q(l1+".verify."+zoneName, dns.TypeTXT))
		if err != nil {
			t.Fatal(err)
		}
		want := identity.ProofCode(proofKey, l1, netip.MustParseAddr(src))
		if !hasTXT(r, want) {
			t.Fatalf("the proof code is not the one of the hub's proof_key: %v", r.Answer)
		}
		// An identified DoT query leaves a label that GET /v reports as seen, and the
		// hub receives the observation with the resolver identity's hash.
		r, err = c.dot(rid(1)+"."+zoneName, q(l2+".verify."+zoneName, dns.TypeA))
		if err != nil || !hasA(r, "8.8.8.8") {
			t.Fatalf("verify name over DoT: %v %v", r, err)
		}
		seen, err := c.getVerify(l2)
		if err != nil || !seen {
			t.Fatalf("GET /v of a label that was asked: seen %v, %v", seen, err)
		}
		if seen, err := c.getVerify(verifyLabel(2)); err != nil || seen {
			t.Fatalf("GET /v of a label nobody asked: seen %v, %v", seen, err)
		}
		eventually(t, 20*time.Second, "the proof observations at the hub", func() bool {
			p1, p2 := n.proofObserved(s, l1), n.proofObserved(s, l2)
			if p1 == nil || p2 == nil {
				return false
			}
			rh := identity.RIDHash(rid(1))
			return len(p1.RidHash) == 0 && bytes.Equal(p2.RidHash, rh[:])
		})
	})

	// The zone state: the table the agent holds answers resolver hostnames and the
	// apex NS, and a hub-time DNS-01 challenge is served as a TXT until it ends.
	t.Run("zone names and acme", func(t *testing.T) {
		eventually(t, 60*time.Second, "the resolver hostname from the table in use", func() bool {
			r, err := c.tcp("127.0.0.9", q(rid(1)+"."+zoneName, dns.TypeA))
			return err == nil && hasA(r, "8.8.8.8")
		})
		r, err := c.tcp("127.0.0.9", q(zoneName, dns.TypeNS))
		if err != nil || len(r.Answer) != 3 {
			t.Fatalf("apex NS: %v %v", r, err)
		}
		fq := "_acme-challenge." + zoneName
		if r, err := c.tcp("127.0.0.9", q(fq, dns.TypeTXT)); err != nil || len(r.Answer) != 0 {
			t.Fatalf("a TXT before any challenge: %v %v", r, err)
		}
		// The hub's fqdn is validated for length only: a trailing dot and capitals
		// must still match the name the Handler asks with.
		_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_AcmeChallenge{AcmeChallenge: &hubv1.AcmeChallenge{
			TokenId: bytes.Repeat([]byte{7}, 16), Fqdn: "_ACME-challenge." + zoneName + ".", Value: "challenge-value-1", ExpiresAt: time.Now().Add(8 * time.Second).Unix()}}})
		eventually(t, 20*time.Second, "the DNS-01 TXT", func() bool {
			r, err := c.tcp("127.0.0.9", q(fq, dns.TypeTXT))
			return err == nil && hasTXT(r, "challenge-value-1")
		})
		eventually(t, 30*time.Second, "the challenge to end at its hub-time expiry", func() bool {
			r, err := c.tcp("127.0.0.9", q(fq, dns.TypeTXT))
			return err == nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0
		})
	})

	// What the reporter hands the agent reaches the hub.
	t.Run("activity at the hub", func(t *testing.T) {
		want := bytes.Repeat([]byte{1}, 16)
		eventually(t, 30*time.Second, "an activity entry of Endpoint 1", func() bool {
			for _, b := range n.hub.Activity() {
				for _, e := range b.Entries {
					if bytes.Equal(e.EndpointId, want) {
						return true
					}
				}
			}
			return false
		})
	})

	// The node's own addresses and the panel hostnames the NodeConfig names reach the
	// Handler (p4n-MB-r2-2): a panel hostname is a system name and gets its true answer
	// through the identified resolver whatever the Endpoint's rules say (T-040), and a
	// Block answer carries the node's proxy address.
	t.Run("panel hostnames and the node's own addresses", func(t *testing.T) {
		if r, err := resolve(byName["dot"], 1, panelName); err != nil || !hasA(r, ipV1) {
			t.Fatalf("the panel hostname must get its true answer despite the Endpoint's rule: %v %v", r, err)
		}
		r, err := resolve(byName["dot"], 1, blockedName)
		if err != nil || !hasA(r, proxyIPText) || hasA(r, ipV1) {
			t.Fatalf("a Block answer must carry the node's proxy address %s: %v %v", proxyIPText, r, err)
		}
		if r, err := resolve(byName["dot"], 1, panel2Name); err != nil || !hasA(r, proxyIPText) {
			t.Fatalf("a name that is not yet a panel hostname is under the Endpoint's rule: %v %v", r, err)
		}
	})

	// A NodeConfig whose resolve part is the same keeps the Router and the warm cache
	// (the agent resends the NodeConfig on every dns reconnect).
	t.Run("a NodeConfig that changes nothing the resolver uses", func(t *testing.T) {
		const warm = "warm.example.com"
		if r, err := resolve(byName["dot"], 1, warm); err != nil || !hasA(r, ipV1) {
			t.Fatalf("warm-up: %v %v", r, err)
		}
		builtBefore, askedBefore := n.join.Switched(), fu.asked(warm)
		cfg := nodeConfig(2, proofKey, commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE)
		cfg.PanelHostnames = []string{panel2Name}
		cfg.Zones = append(cfg.Zones, addedZone)
		_ = s.Send(nodeConfigMsg(cfg))
		eventually(t, 30*time.Second, "the new NodeConfig", func() bool { return lastNodeVersion(s) == 2 })
		time.Sleep(1500 * time.Millisecond) // dns holds it before the agent reports it, and its tick has run
		if got := n.join.Switched(); got != builtBefore {
			t.Fatalf("the Router was rebuilt %d time(s) for a config that changes nothing it uses", got-builtBefore)
		}
		if r, err := resolve(byName["dot"], 1, warm); err != nil || !hasA(r, ipV1) {
			t.Fatalf("after the config: %v %v", r, err)
		}
		if fu.asked(warm) != askedBefore {
			t.Fatal("the warm answer was dropped from the cache by a config that changes nothing it uses")
		}
		// The hostnames and the zones of the new config reach the Handler (p4n-MB-r2-2, -5):
		// panel2 is now a system name and panel no longer is, and the added zone answers
		// its resolver hostnames.
		eventually(t, 30*time.Second, "the new panel hostname as a system name", func() bool {
			r, err := resolve(byName["dot"], 1, panel2Name)
			return err == nil && hasA(r, ipV1)
		})
		if r, err := resolve(byName["dot"], 1, panelName); err != nil || hasA(r, ipV1) || !hasA(r, proxyIPText) {
			t.Fatalf("a retired panel hostname must be under the Endpoint's rule again: %v %v", r, err)
		}
		eventually(t, 30*time.Second, "the added zone's resolver hostname", func() bool {
			r, err := c.tcp("127.0.0.9", q(rid(1)+"."+addedZone, dns.TypeA))
			return err == nil && hasA(r, "8.8.8.8")
		})
	})

	// Isolated: no healthy resolve path. It reaches the Heartbeat and the Settings
	// (isolated_synth names answer with the node's own address); the path coming back
	// ends it.
	t.Run("isolated", func(t *testing.T) {
		const synth = "x-dnsotls-ds.metric.gstatic.com"
		if r, err := resolve(byName["dot"], 1, synth); err != nil || !hasA(r, ipV1) {
			t.Fatalf("not isolated, the true answer: %v %v", r, err)
		}
		if lastHeartbeat(s).Isolated {
			t.Fatal("the node reported Isolated with a healthy path")
		}
		addr := fu.addr
		fu.stop()
		eventually(t, 120*time.Second, "Isolated in the Heartbeat", func() bool { return lastHeartbeat(s).Isolated })
		eventually(t, 30*time.Second, "the isolated_synth answer", func() bool {
			r, err := resolve(byName["dot"], 1, synth)
			return err == nil && hasA(r, "8.8.8.8") && !hasA(r, ipV1)
		})
		host, port := splitHostPort(t, addr)
		fu = newFakeUnbound(t, host, port, ipV1)
		eventually(t, 120*time.Second, "Isolated to end", func() bool { return !lastHeartbeat(s).Isolated })
		eventually(t, 30*time.Second, "the true answer again", func() bool {
			r, err := resolve(byName["dot"], 1, synth)
			return err == nil && hasA(r, ipV1)
		})
	})
	return fu
}
