package agent_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// ---- p4n-W5b-r3-1: the bound on ACME challenges never takes the one just given

// 64 challenges are held, and a 65th arrives that expires before all of them. It is
// the one the strict "expires first" rule would evict, and it is the one that was just
// acked: it must stay, and the one that goes is the oldest of the rest. The snapshot a
// new dns gets holds exactly the challenges the agent holds.
func TestAcmeBoundNeverEvictsTheChallengeJustTaken(t *testing.T) {
	l := newLab(t)
	l.start()
	s := l.session()
	_ = s.Send(serverTime())
	now := time.Now().Unix()
	send := func(i byte, exp int64) {
		_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_AcmeChallenge{AcmeChallenge: &hubv1.AcmeChallenge{
			TokenId: []byte{i, 1}, Fqdn: "_acme-challenge.dns.example.net", Value: "v", ExpiresAt: exp}}})
	}
	for i := 0; i < 64; i++ {
		send(byte(i), now+3600+int64(i))
	}
	send(64, now+60) // expires before every other
	eventually(t, "the last ack", func() bool {
		for _, m := range s.Messages() {
			if a := m.GetAcmeAck(); a != nil && len(a.TokenId) == 2 && a.TokenId[0] == 64 {
				return true
			}
		}
		return false
	})
	l.attachDNS()
	l.waitDNS("the snapshot", func() bool { return l.lastDNS(sock.TypeFacts) != nil })
	have := map[byte]bool{}
	l.dnsMu.Lock()
	for _, m := range l.dnsMsgs {
		if m.Type == sock.TypeAcme && m.Acme.ExpiresAt > now {
			have[m.Acme.TokenID[0]] = true
		}
	}
	l.dnsMu.Unlock()
	if len(have) != 64 || !have[64] || have[0] {
		t.Errorf("snapshot holds %d challenges, has the new one %v, still has the oldest %v", len(have), have[64], have[0])
	}
}

// ---- p4n-W5b-r3-2: a revocation ends when dns has the image, not when the entry commits

// Entry 1 commits and entry 2 of the same batch stalls on a blob. applied_seq is 1,
// but dns still serves the image from before entry 1, so the revocation of entry 1
// must outlast the 5 s sweep, and a revocation for entry 1 that arrives now is kept.
// Once the batch is done and the image is published, both end.
func TestRevocationOutlastsAnEntryUntilTheImageIsPublished(t *testing.T) {
	l := newLab(t)
	// The stall must last as long as the test says: at the lab's 5 s idle cancel the batch ends
	// with entry 1 alone, its image reaches dns and is confirmed, and the revocation then
	// rightly ends (a loaded machine reached that point before the 6 s check).
	l.cfg.TransferIdle = time.Minute
	hold := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-hold:
		default:
			close(hold)
		}
	})
	b1, b2 := storetest.Blob(t, "first.example.com"), storetest.Blob(t, "second.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	l.addEntry([][]byte{b2}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(2, b2)}})
	stalled := storetest.Hash(b2)
	l.hub.Script(func(h *fakehub.Hub) {
		h.BlobHook = func(ctx context.Context, hash [32]byte) error {
			if hash != stalled {
				return nil
			}
			select {
			case <-hold:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	items := func() int {
		m := l.lastDNS(sock.TypeRevocations)
		if m == nil {
			return -1
		}
		return len(m.Revocations.Items)
	}
	_ = s.Send(revMsg(1, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, 0, 5))
	l.waitDNS("the revocation at dns", func() bool { return items() == 1 })
	_ = s.Send(headNotice(2))
	eventually(t, "entry 1 committed, entry 2 stalled", func() bool { return lastHB(s).AppliedSeq == 1 })
	time.Sleep(6 * time.Second) // past a sweep
	if items() != 1 {
		t.Fatalf("the revocation ended with the image of entry 1 not yet at dns (items %d)", items())
	}
	_ = s.Send(revMsg(1, policyv1.RevocationKind_REVOCATION_KIND_CLAIM, time.Now().Unix()+600, 6))
	l.waitDNS("a revocation of the committed entry still kept", func() bool { return items() == 2 })
	close(hold)
	eventually(t, "entry 2 applied", func() bool { return lastHB(s).AppliedSeq == 2 })
	l.waitDNS("both ended with the published image", func() bool { return items() == 0 })
}

// ---- p4n-W5b-r3-4: the real proof_key after a restart

// After a restart the NodeConfig on disk holds a stand-in key. The hub resends a
// build of the same version to a new stream, and that message is the only one with
// the real key: it must be taken (once), not dropped as a replay.
func TestProofKeyComesBackWhenTheHubResendsTheSameVersionAfterARestart(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	key := storetest.RandomSecret(t, 32)
	_ = s.Send(nodeConfigMsg(5, key))
	eventually(t, "config 5", func() bool { return lastHB(s).NodeConfigVersion == 5 })

	l.restart()
	l.attachDNS()
	s2 := l.session()
	_ = s2.Send(serverTime())
	eventually(t, "version kept", func() bool { return lastHB(s2).NodeConfigVersion == 5 })
	dnsConf := func() *hubv1.NodeConfig {
		m := l.lastDNS(sock.TypeConfig)
		if m == nil {
			return nil
		}
		var nc hubv1.NodeConfig
		_ = proto.Unmarshal(m.Config.NodeConfig, &nc)
		return &nc
	}
	if nc := dnsConf(); nc != nil && bytesEq(nc.ProofKey, key) {
		t.Fatal("the real key was already there")
	}
	_ = s2.Send(nodeConfigMsg(5, key)) // the hub's cached build, same version
	l.waitDNS("the real proof_key at dns", func() bool { nc := dnsConf(); return nc != nil && bytesEq(nc.ProofKey, key) })
	if storetest.Contains(t, l.dir, key) {
		t.Fatal("the real proof_key reached a file")
	}
	// Taken once: a second message of that version, with another key, is a replay.
	_ = s2.Send(nodeConfigMsg(5, storetest.RandomSecret(t, 32)))
	time.Sleep(300 * time.Millisecond)
	if nc := dnsConf(); nc == nil || !bytesEq(nc.ProofKey, key) {
		t.Error("a replay of the same version changed the key")
	}

	// A different content under the stored version is not taken, after another restart.
	c := testNodeConfig(5, storetest.RandomSecret(t, 32))
	c.Zones = []string{"other.example.net"}
	l.restart()
	l.attachDNS()
	s3 := l.session()
	_ = s3.Send(serverTime())
	_ = s3.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: c}})
	time.Sleep(300 * time.Millisecond)
	if nc := dnsConf(); nc != nil && len(nc.Zones) == 1 && nc.Zones[0] == "other.example.net" {
		t.Error("another content under the stored version was taken")
	}
}

// ---- p4n-W5b-r3-6: a restart of dns that is owed survives an agent restart

func TestOwedDNSRestartSurvivesAnAgentRestart(t *testing.T) {
	l := systemLab(t)
	l.cfg.HostEvery = 30 * time.Millisecond
	var failing atomic.Bool
	failing.Store(true)
	var ok atomic.Int32
	base := l.runner.Reply
	l.runner.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "systemctl" && len(c.Args) == 2 && c.Args[0] == "restart" && c.Args[1] == "ctrlz-dns.service" {
			if failing.Load() {
				return nil, errors.New("polkit rule not loaded")
			}
			ok.Add(1)
		}
		return base(c)
	}
	l.start()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(nodeConfigMsg(1, make([]byte, 16)))
	eventually(t, "the failed restart alerts", func() bool { return l.alerts.Count(alert.DNSRestartFailed) >= 1 })
	if ok.Load() != 0 {
		t.Fatal("a restart succeeded while it was meant to fail")
	}
	l.restart() // the agent goes away with the restart still owed
	failing.Store(false)
	eventually(t, "dns restarted after the agent restart", func() bool { return ok.Load() >= 1 })
	n := ok.Load()
	time.Sleep(300 * time.Millisecond)
	if ok.Load() != n || !strings.Contains(lines(l), "systemctl restart ctrlz-dns.service") {
		t.Errorf("restarts after the fix: %d then %d, want it made once and no more", n, ok.Load())
	}
	// and after a clean restart the marker is gone: a further agent restart owes nothing
	l.restart()
	time.Sleep(300 * time.Millisecond)
	if ok.Load() != n {
		t.Errorf("dns was restarted again with nothing owed: %d", ok.Load())
	}
}
