package agent_test

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// ---- p4n-W5b-r5-1 and r5-4: the hub stops renewing a revocation once the node's
// Heartbeat says the entry is applied, so the agent must not let it lapse while dns
// still serves the image from before the entry

func TestRevocationOfACommittedEntryOutlivesItsExpiryWhileTheImageIsMissing(t *testing.T) {
	l := newLab(t)
	var fail atomic.Bool
	l.cfg.FSHook = func(path string, s fsx.Step) error {
		if fail.Load() && s == fsx.StepCreate && filepath.Base(path) == image.CurrentLink {
			return fsx.ErrInjected
		}
		return nil
	}
	b1, b2 := storetest.Blob(t, "one.example.com"), storetest.Blob(t, "two.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1 applied", func() bool { return lastHB(s).AppliedSeq == 1 })
	l.waitDNS("the image of entry 1 at dns", func() bool { return l.lastDNS(sock.TypeImage) != nil })

	fail.Store(true)
	l.addEntry([][]byte{b2}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(2, b2)}})
	_ = s.Send(headNotice(2))
	eventually(t, "entry 2 committed", func() bool { return lastHB(s).AppliedSeq == 2 })
	eventually(t, "the failed publish alerts", func() bool { return l.alerts.Count(alert.ImagePublishFailed) >= 1 })
	// The hub's revocation for entry 2, ending 3 s from now: it is past by the time the
	// sweep runs again, and the hub no longer renews it (applied_seq is already 2).
	end := time.Now().Unix() + 3
	_ = s.Send(revMsg(2, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, end, 5))
	l.waitDNS("the revocation at dns", func() bool { return revItems(l) == 1 })
	time.Sleep(7 * time.Second) // past two sweeps and past the expiry
	m := l.lastDNS(sock.TypeRevocations)
	if m == nil || len(m.Revocations.Items) != 1 {
		t.Fatalf("the revocation ended with the image of entry 2 never at dns: %+v", m)
	}
	if exp := m.Revocations.Items[0].ExpiresAt; exp <= time.Now().Unix()+60 {
		t.Fatalf("the revocation ends at %d, within a minute: it must be extended while the image is missing", exp)
	}
}

// ---- p4n-W5b-r5-6: a restart of the agent must not lift what dns enforces

func TestRevocationsSurviveAnAgentRestart(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(revMsg(9, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, 0, 5))
	l.waitDNS("the revocation at dns", func() bool { return revItems(l) == 1 })
	l.restart() // the hub sends nothing to the new run
	l.attachDNS()
	l.waitDNS("the revocation in the first snapshot of the new run", func() bool { return revItems(l) == 1 })
	l.dnsMu.Lock()
	defer l.dnsMu.Unlock()
	for _, m := range l.dnsMsgs {
		if m.Type == sock.TypeRevocations && len(m.Revocations.Items) == 0 {
			t.Fatal("dns was handed an empty revocation list after the agent restarted")
		}
	}
}

// ---- p4n-W5b-r5-7: an expires_at far in the future does not pin a revocation

func TestRevocationExpiryIsClampedToTheHubsLifetime(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(revMsg(3, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, time.Now().Unix()+10*365*86400, 5))
	l.waitDNS("the revocation at dns", func() bool { return revItems(l) == 1 })
	exp := l.lastDNS(sock.TypeRevocations).Revocations.Items[0].ExpiresAt
	if max := time.Now().Unix() + int64((20*time.Minute)/time.Second) + 5; exp > max {
		t.Fatalf("expires_at %d is beyond the hub's lifetime plus the margin (%d)", exp, max)
	}
}
