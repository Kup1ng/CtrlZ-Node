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

func revItems(l *lab) int {
	m := l.lastDNS(sock.TypeRevocations)
	if m == nil {
		return -1
	}
	return len(m.Revocations.Items)
}

// ---- p4n-W5b-r4-1 and r4-3: a revocation ends when dns confirms the image, not
// when the state is committed or an image was handed over

// Entry 2 commits but its image swap fails, so dns still serves the image of
// entry 1, where the Endpoint is enabled. The revocation of entry 2 must stay, and
// the failure must be alerted. When a later entry makes the swap work, it ends.
func TestRevocationIsKeptWhileTheImageSwapFails(t *testing.T) {
	l := newLab(t)
	var fail atomic.Bool
	l.cfg.FSHook = func(path string, s fsx.Step) error {
		if fail.Load() && s == fsx.StepCreate && filepath.Base(path) == image.CurrentLink {
			return fsx.ErrInjected
		}
		return nil
	}
	b1, b2, b3 := storetest.Blob(t, "one.example.com"), storetest.Blob(t, "two.example.com"), storetest.Blob(t, "three.example.com")
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
	_ = s.Send(revMsg(2, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, 0, 5))
	l.waitDNS("the revocation at dns", func() bool { return revItems(l) == 1 })
	_ = s.Send(headNotice(2))
	eventually(t, "entry 2 committed", func() bool { return lastHB(s).AppliedSeq == 2 })
	eventually(t, "the failed publish alerts", func() bool { return l.alerts.Count(alert.ImagePublishFailed) >= 1 })
	time.Sleep(6 * time.Second) // past a sweep
	if n := revItems(l); n != 1 {
		t.Fatalf("the revocation ended (items %d) with the image of entry 2 never at dns", n)
	}

	fail.Store(false)
	l.addEntry([][]byte{b3}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(3, b3)}})
	_ = s.Send(headNotice(3))
	eventuallyWithin(t, 60*time.Second, "entry 3 applied", func() bool { return lastHB(s).AppliedSeq == 3 })
	l.waitDNS("the revocation ended with the image dns confirmed", func() bool { return revItems(l) == 0 })
}

// dns cannot open the image the agent published: it sends no ack, and the
// revocation stays. A dns that does open it acks, and the revocation ends.
func TestRevocationIsKeptUntilDNSConfirmsTheImage(t *testing.T) {
	l := newLab(t)
	l.dnsNoAck.Store(true)
	b1 := storetest.Blob(t, "one.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(revMsg(1, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, 0, 5))
	l.waitDNS("the revocation at dns", func() bool { return revItems(l) == 1 })
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1 applied", func() bool { return lastHB(s).AppliedSeq == 1 })
	l.waitDNS("the image at dns", func() bool { return l.lastDNS(sock.TypeImage) != nil })
	time.Sleep(6 * time.Second)
	if n := revItems(l); n != 1 {
		t.Fatalf("the revocation ended (items %d) although dns never confirmed an image", n)
	}
	l.dnsNoAck.Store(false)
	l.attachDNS() // a dns that comes back gets the snapshot and opens the image
	l.waitDNS("the revocation ended after the ack", func() bool { return revItems(l) == 0 })
}
