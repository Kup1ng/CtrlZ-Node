package agent_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// SC 8a.11 L11, the case of a blob: an entry whose FetchBlob never answers holds
// the Apply, and still a push is applied within 2 s, further HeadNotices are not
// lost, and once the stall ends applied_seq reaches the last HeadNotice sent.
func TestStalledBlobFetchHoldsBackNeitherPushNorLaterNotices(t *testing.T) {
	l := newLab(t)
	hold := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-hold:
		default:
			close(hold)
		}
	})
	b0 := storetest.Blob(t, "first.example.com")
	l.addEntry([][]byte{b0}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b0)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })

	// entry 2 names a blob the hub will not deliver until released
	b2 := storetest.Blob(t, "second.example.com")
	l.hub.Script(func(h *fakehub.Hub) {
		h.BlobHook = func(ctx context.Context, _ [32]byte) error {
			select {
			case <-hold:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	l.addEntry([][]byte{b2}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(2, b2)}})
	l.addEntry(nil, &policyv1.ConfigEntry{})
	l.addEntry(nil, &policyv1.ConfigEntry{})
	_ = s.Send(headNotice(2))
	time.Sleep(300 * time.Millisecond) // the Apply is inside its fetch now
	_ = s.Send(headNotice(3))
	_ = s.Send(headNotice(4))

	pt := storetest.Table(3, 300, 1)
	pt.ExpiresAt = time.Now().Unix() + 1800
	sent := time.Now()
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: l.keys.Sign(t, pt)}})
	l.waitDNS("the push at dns", func() bool { m := l.lastDNS(sock.TypeTable); return m != nil && m.Table.Version == 300 })
	if d := time.Since(sent); d > 2*time.Second {
		t.Errorf("the push took %v while an Apply waited on a blob", d)
	}
	for i := 0; i < 3; i++ { // the Heartbeats keep coming
		before := countHB(s)
		time.Sleep(250 * time.Millisecond)
		if countHB(s) <= before {
			t.Fatal("no Heartbeat while an Apply waits on a blob")
		}
	}
	if lastHB(s).AppliedSeq != 1 {
		t.Errorf("applied_seq %d moved during the stall", lastHB(s).AppliedSeq)
	}
	close(hold)
	eventually(t, "every announced entry applied", func() bool { return lastHB(s).AppliedSeq == 4 })
}

// An entry the node refuses is reported, held back, and does not stop the node.
func TestRefusedEntryIsReportedAndKeptOut(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	// entry 2 chains from the wrong hash
	wrong := storetest.Chain{Seq: 1, Head: [32]byte{9}}
	stored := wrong.Marshal(t, &policyv1.ConfigEntry{})
	l.hub.Script(func(h *fakehub.Hub) {
		h.Entries = append(h.Entries, &hubv1.StoredEntry{Seq: 2, EntryBytes: stored})
		// The head is the true hash of the bytes the hub serves, so the chain check of
		// the agent passes and it is Apply that refuses the entry (its prev_hash is wrong).
		h.Head = signHead(t, l.keys, 2, wire.EntryHash(l.chain.Head, stored))
	})
	l.start()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(2))
	if _, err := s.Wait(10*time.Second, func(m *hubv1.NodeMessage) bool {
		q := m.GetQuarantineReport()
		return q != nil && q.Scope == hubv1.Scope_SCOPE_ENTRY && q.Seq == 2
	}); err != nil {
		t.Fatalf("no QuarantineReport for the refused entry: %v", err)
	}
	m, err := s.Wait(5*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 2 })
	if err != nil || m.GetApplyResult().Ok {
		t.Errorf("the refused entry was reported as applied: %v %v", m, err)
	}
	for _, msg := range s.Messages() {
		if q := msg.GetQuarantineReport(); q != nil {
			if err := wire.ValidateQuarantineReport(q); err != nil {
				t.Errorf("the hub's door refuses the report: %v", err)
			}
		}
	}
	eventually(t, "applied_seq 1 in the Heartbeat", func() bool { return lastHB(s).AppliedSeq == 1 })
	if l.alerts.Count(alert.QuarantineTwoNodes) == 0 {
		t.Error("no alert")
	}
}

func shortCert(l *lab) {
	l.id, l.idp = newIdentity(l.t, true)
	l.cfg.Identity = l.id
}

func TestCertificateRenewal(t *testing.T) {
	l := newLab(t, shortCert)
	var csrKeyOK bool
	l.hub.Renew = func(r *hubv1.RenewCertRequest) (*hubv1.RenewCertResponse, error) {
		csr, err := x509.ParseCertificateRequest(r.CsrDer)
		if err != nil || csr.CheckSignature() != nil {
			return nil, err
		}
		csrKeyOK = csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(&l.idp.node.PublicKey)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: l.id.Leaf().Subject.CommonName},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, l.idp.ca, csr.PublicKey, l.idp.caKey)
		return &hubv1.RenewCertResponse{CertDer: der}, err
	}
	l.start()
	ok, err := l.ag.RenewIfDue(context.Background())
	if err != nil || !ok || !csrKeyOK {
		t.Fatalf("renewed=%v keyOK=%v err=%v", ok, csrKeyOK, err)
	}
	if !l.id.Leaf().NotAfter.After(time.Now().Add(24 * time.Hour)) {
		t.Error("the new certificate is not in use")
	}
	if b, err := os.ReadFile(filepath.Join(l.cfg.Root, "keys", "node.crt")); err != nil || len(b) == 0 {
		t.Errorf("the renewed certificate is not on disk: %v", err)
	}
	// not due any more
	if ok, err := l.ag.RenewIfDue(context.Background()); ok || err != nil {
		t.Errorf("renewed again: %v %v", ok, err)
	}
}

func TestRenewalRefusesAnotherKeysCertificate(t *testing.T) {
	l := newLab(t, shortCert)
	l.hub.Renew = func(r *hubv1.RenewCertRequest) (*hubv1.RenewCertResponse, error) {
		other := newIdentityKey(t)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(78), Subject: pkix.Name{CommonName: l.id.Leaf().Subject.CommonName},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, l.idp.ca, &other.PublicKey, l.idp.caKey)
		return &hubv1.RenewCertResponse{CertDer: der}, err
	}
	l.start()
	before := l.id.Leaf().NotAfter
	if ok, err := l.ag.RenewIfDue(context.Background()); ok || err == nil {
		t.Fatalf("a certificate for another key was taken: %v %v", ok, err)
	}
	if !l.id.Leaf().NotAfter.Equal(before) {
		t.Error("the certificate in use changed")
	}
}
