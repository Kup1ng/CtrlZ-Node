package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/zonekeys"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// ---- helpers

func zoneNames(zone string) []string { return []string{zone, "*." + zone, "*.verify." + zone} }

// certBundleMsg is the hub's CertBundle for a zone, sealed to the lab node's key.
func (l *lab) certBundleMsg(zone string) *hubv1.HubMessage {
	l.t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "zone ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cder, err := x509.CreateCertificate(rand.Reader, ctmpl, ctmpl, &caKey.PublicKey, caKey)
	if err != nil {
		l.t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(cder)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notAfter := time.Now().Add(2 * time.Hour)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: zone}, DNSNames: zoneNames(zone),
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &lk.PublicKey, caKey)
	if err != nil {
		l.t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(lk)
	wrapped, err := zonekeys.Seal(&l.idp.node.PublicKey, kder)
	if err != nil {
		l.t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder})...)
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_CertBundle{CertBundle: &hubv1.CertBundle{
		Kind: signv1.Kind_KIND_CERTS, WrappedKey: wrapped, ChainPem: chain, NotAfter: notAfter.Unix()}}}
}

func nodeConfigZones(version uint64, zones ...string) *hubv1.HubMessage {
	c := testNodeConfig(version, make([]byte, 16))
	c.Zones = zones
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: c}}
}

func (l *lab) zoneKeyMsgs() []*sock.Msg {
	l.dnsMu.Lock()
	defer l.dnsMu.Unlock()
	var out []*sock.Msg
	for _, m := range l.dnsMsgs {
		if m.Type == sock.TypeZoneKey {
			out = append(out, m)
		}
	}
	return out
}

func (l *lab) keyFiles() int {
	ents, _ := os.ReadDir(filepath.Join(l.cfg.Root, "keys"))
	n := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "zone-") {
			n++
		}
	}
	return n
}

func hasSANs(m *sock.Msg, zone string) bool {
	return len(m.ZoneKey.SANs) == 3 && strings.Contains(strings.Join(m.ZoneKey.SANs, ","), "*.verify."+zone)
}

func revMsg(seq uint64, kind policyv1.RevocationKind, exp int64, ids ...byte) *hubv1.HubMessage {
	var list [][]byte
	for _, b := range ids {
		list = append(list, bytes.Repeat([]byte{b}, 16))
	}
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: &policyv1.Revocation{RevSeq: seq, Kind: kind, Ids: list, ExpiresAt: exp}}}
}

// ---- p4n-W5b-r1-1, -14, -20: a CertBundle that overtakes its NodeConfig

// The bundle for a zone arrives before any NodeConfig names it. It is not served
// and not stored while no zone is known, and it is taken, not lost, when the
// NodeConfig that names the zone arrives.
func TestCertBundleBeforeAnyNodeConfigIsHeldAndTakenLater(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(l.certBundleMsg("dns.example.net"))
	time.Sleep(400 * time.Millisecond)
	if n := len(l.zoneKeyMsgs()); n != 0 || l.keyFiles() != 0 {
		t.Fatalf("a bundle was served (%d) or stored (%d) while no zone was known", n, l.keyFiles())
	}
	_ = s.Send(nodeConfigZones(1, "dns.example.net"))
	l.waitDNS("the zone key at dns", func() bool { ms := l.zoneKeyMsgs(); return len(ms) == 1 && hasSANs(ms[0], "dns.example.net") })
	if l.keyFiles() != 1 {
		t.Errorf("key files = %d", l.keyFiles())
	}
	if l.alerts.Count(alert.CertBundleRefused) != 0 {
		t.Error("a bundle that only overtook its NodeConfig raised an alert")
	}
}

// A domain change: the NodeConfig that adds a zone and its CertBundle go out
// back to back and are handled on two workers; the bundle checked against the old
// zones must still end up served.
func TestCertBundleForANewZoneThatOvertakesItsNodeConfig(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(nodeConfigZones(1, "dns.example.net"))
	eventually(t, "the first config", func() bool { return lastHB(s).NodeConfigVersion == 1 })
	_ = s.Send(l.certBundleMsg("dns.new.example"))
	time.Sleep(300 * time.Millisecond)
	if len(l.zoneKeyMsgs()) != 0 {
		t.Fatal("a bundle for a zone that is not live was served")
	}
	_ = s.Send(nodeConfigZones(2, "dns.example.net", "dns.new.example"))
	l.waitDNS("the new zone's key", func() bool { ms := l.zoneKeyMsgs(); return len(ms) == 1 && hasSANs(ms[0], "dns.new.example") })
}

// Many rounds of the race itself, both orders, so the lock between the two
// workers is what is tested and not the luck of one ordering.
func TestCertBundleAndNodeConfigBackToBack(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	zones := []string{"dns.example.net"}
	_ = s.Send(nodeConfigZones(1, zones...))
	for i := 0; i < 8; i++ {
		z := "dns.z" + string(rune('a'+i)) + ".example"
		zones = []string{zones[len(zones)-1], z} // a domain change has two live zones at most
		bundle, cfg := l.certBundleMsg(z), nodeConfigZones(uint64(i+2), zones...)
		if i%2 == 0 {
			_ = s.Send(cfg)
			_ = s.Send(bundle)
		} else {
			_ = s.Send(bundle)
			_ = s.Send(cfg)
		}
		l.waitDNS("the key of "+z, func() bool {
			for _, m := range l.zoneKeyMsgs() {
				if hasSANs(m, z) {
					return true
				}
			}
			return false
		})
	}
}

// A bundle whose names no zone ever claims is never served or stored, and the owner
// hears of it after the grace.
func TestCertBundleOfNoLiveZoneIsNeverServedAndAlertsAfterTheGrace(t *testing.T) {
	l := newLab(t, func(l *lab) { l.cfg.HeldBundleGrace = time.Second })
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(nodeConfigZones(1, "dns.example.net"))
	eventually(t, "the config", func() bool { return lastHB(s).NodeConfigVersion == 1 })
	_ = s.Send(l.certBundleMsg("dns.other.org"))
	l.skew.Store(60) // the grace is judged on the node clock; the sweep runs every 5 s
	eventually(t, "the alert", func() bool { return l.alerts.Count(alert.CertBundleRefused) > 0 })
	if len(l.zoneKeyMsgs()) != 0 || l.keyFiles() != 0 {
		t.Error("a bundle of no live zone was served or stored")
	}
}

// ---- p4n-W5b-r1-15: a retired zone's key goes

func TestRetiredZoneKeyIsDroppedEverywhere(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(nodeConfigZones(1, "dns.example.net", "dns.old.example"))
	_ = s.Send(l.certBundleMsg("dns.example.net"))
	_ = s.Send(l.certBundleMsg("dns.old.example"))
	l.waitDNS("both keys", func() bool { return len(l.zoneKeyMsgs()) == 2 })
	if l.keyFiles() != 2 {
		t.Fatalf("key files = %d", l.keyFiles())
	}
	_ = s.Send(nodeConfigZones(2, "dns.example.net"))
	eventually(t, "the old key file is gone", func() bool { return l.keyFiles() == 1 })
	// a dns that connects now is given the live zone's key only
	l.attachDNS()
	l.waitDNS("the snapshot", func() bool { return l.lastDNS(sock.TypeConfig) != nil })
	time.Sleep(200 * time.Millisecond)
	ms := l.zoneKeyMsgs()
	if len(ms) != 1 || !hasSANs(ms[0], "dns.example.net") {
		t.Fatalf("a new dns got %d zone keys", len(ms))
	}
	// and after a restart of the agent nothing comes back from disk
	l.restart()
	l.attachDNS()
	l.waitDNS("the snapshot after restart", func() bool { return l.lastDNS(sock.TypeConfig) != nil })
	time.Sleep(200 * time.Millisecond)
	if ms := l.zoneKeyMsgs(); len(ms) != 1 || !hasSANs(ms[0], "dns.example.net") {
		t.Fatalf("after a restart: %d zone keys", len(ms))
	}
}

// ---- p4n-W5b-r1-2: the signed head and the entries

func hashOf(l *lab) [32]byte { return l.chain.Head }

// A hub that puts into its log an entry the policy key never signed is not
// believed: the chain from the node's state through the entries must reach the
// signed head's hash, and nothing is applied when it does not.
func TestEntriesThatDoNotReachTheSignedHeadAreNotApplied(t *testing.T) {
	l := newLab(t)
	b := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b)}, PairTable: storetest.Table(3, 0)})
	l.addEntry(nil, &policyv1.ConfigEntry{})
	c2 := l.chain
	l.addEntry(nil, &policyv1.ConfigEntry{}) // the genuine entry 3, which the head signs
	// the hub serves another entry 3 that chains from entry 2 as well
	forged := c2.Marshal(t, &policyv1.ConfigEntry{FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 1000, Version: 9}})
	var genuine3 *hubv1.StoredEntry
	l.hub.Script(func(h *fakehub.Hub) {
		genuine3, h.Entries[2] = h.Entries[2], &hubv1.StoredEntry{Seq: 3, EntryBytes: forged}
	})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(3))
	eventually(t, "the mismatch is raised", func() bool { return l.alerts.Count(alert.ChainMismatch) > 0 })
	time.Sleep(300 * time.Millisecond)
	if got := lastHB(s).AppliedSeq; got != 0 {
		t.Fatalf("applied_seq %d: entries the signed head does not cover were applied", got)
	}
	// the hub serves what the head signs again: the node goes on by itself
	l.hub.Script(func(h *fakehub.Hub) { h.Entries[2] = genuine3 })
	eventuallyWithin(t, 60*time.Second, "the genuine log applied", func() bool { return lastHB(s).AppliedSeq == 3 })
}

// What the signed head does not reach yet is not applied: a HeadNotice (unsigned)
// that names more only makes the node ask for a fresh head.
func TestOnlyWhatTheSignedHeadCoversIsApplied(t *testing.T) {
	l := newLab(t)
	b := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b)}, PairTable: storetest.Table(3, 0)})
	h1, s1 := hashOf(l), l.chain.Seq
	l.addEntry(nil, &policyv1.ConfigEntry{})
	l.addEntry(nil, &policyv1.ConfigEntry{})
	// the hub's signed head lags the log (the release point of L12)
	l.hub.Script(func(h *fakehub.Hub) { h.Head = signHead(t, l.keys, s1, h1) })
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(3))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })
	time.Sleep(400 * time.Millisecond)
	if got := lastHB(s).AppliedSeq; got != 1 {
		t.Fatalf("applied_seq %d, above the signed head", got)
	}
	l.setHead() // the head now covers 3
	_ = s.Send(headNotice(3))
	eventually(t, "entries 2 and 3", func() bool { return lastHB(s).AppliedSeq == 3 })
}

// More entries than one fetch, the plan spans batches; and bytes the hub serves
// differently the second time (after the plan passed) are caught by the batch check.
func TestChainIsCheckedAcrossBatches(t *testing.T) {
	l := newLab(t, func(l *lab) { l.cfg.FetchBatch = 3 })
	for i := 0; i < 7; i++ {
		if i == 0 {
			b := storetest.Blob(t, "a.example.com")
			l.addEntry([][]byte{b}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b)}, PairTable: storetest.Table(3, 0)})
			continue
		}
		l.addEntry(nil, &policyv1.ConfigEntry{})
	}
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(7))
	eventuallyWithin(t, 60*time.Second, "all seven across three batches", func() bool { return lastHB(s).AppliedSeq == 7 })
	if l.alerts.Count(alert.ChainMismatch) != 0 {
		t.Error("a genuine chain raised a mismatch")
	}
}

func TestBytesServedDifferentlyAfterThePlanAreNotApplied(t *testing.T) {
	l := newLab(t, func(l *lab) { l.cfg.FetchBatch = 3 })
	var c6 storetest.Chain
	for i := 0; i < 7; i++ {
		if i == 0 {
			b := storetest.Blob(t, "a.example.com")
			l.addEntry([][]byte{b}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b)}, PairTable: storetest.Table(3, 0)})
			continue
		}
		if i == 6 {
			c6 = l.chain
		}
		l.addEntry(nil, &policyv1.ConfigEntry{})
	}
	forged := c6.Marshal(t, &policyv1.ConfigEntry{FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 1000, Version: 9}})
	var calls atomic.Int32
	// The plan reads 0..3, 3..6 and 6..7 (calls 1 to 3) and the first batch is applied
	// from call 1's bytes; the next fetch (call 4) is the application of 4..6. The
	// forged 7th entry is put in before call 5, the application of entry 7.
	l.hub.Script(func(h *fakehub.Hub) {
		h.EntriesHook = func(_ context.Context, _ *hubv1.FetchEntriesRequest) error {
			if calls.Add(1) == 4 {
				l.hub.Script(func(h *fakehub.Hub) { h.Entries[6] = &hubv1.StoredEntry{Seq: 7, EntryBytes: forged} })
			}
			return nil
		}
	})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(7))
	eventuallyWithin(t, 60*time.Second, "the mismatch", func() bool { return l.alerts.Count(alert.ChainMismatch) > 0 })
	time.Sleep(300 * time.Millisecond)
	if got := lastHB(s).AppliedSeq; got != 6 {
		t.Fatalf("applied_seq %d, want 6: the forged seventh entry must not be applied", got)
	}
}

// ---- p4n-W5b-r1-3, -13, -9, -17: revocations

// One entry yields several revocations with one rev_seq, of different kinds (5.5):
// the node keeps all of them and hands all to dns, and acks each.
func TestRevocationsOfOneSeqAndDifferentKindsAreAllKept(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	exp := time.Now().Unix() + 600
	_ = s.Send(revMsg(40, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, exp, 1))
	_ = s.Send(revMsg(40, policyv1.RevocationKind_REVOCATION_KIND_CLAIM, exp, 2))
	_ = s.Send(revMsg(40, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, exp, 3)) // same key: merged
	l.waitDNS("all the revocations at dns", func() bool {
		m := l.lastDNS(sock.TypeRevocations)
		if m == nil || len(m.Revocations.Items) != 2 {
			return false
		}
		var ep, claim int
		for _, it := range m.Revocations.Items {
			switch policyv1.RevocationKind(it.Kind) {
			case policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT:
				ep = len(it.IDs)
			case policyv1.RevocationKind_REVOCATION_KIND_CLAIM:
				claim = len(it.IDs)
			}
		}
		return ep == 2 && claim == 1
	})
	// The ack is queued after the list goes to dns, so on a loaded machine it can trail it.
	acks := func() (n int) {
		for _, m := range s.Messages() {
			if m.GetRevocationAck().GetRevSeq() == 40 {
				n++
			}
		}
		return n
	}
	eventually(t, "one ack per message", func() bool { return acks() >= 3 })
	if n := acks(); n != 3 {
		t.Errorf("acks = %d, want one per message", n)
	}
}

// A revocation acts until the node has applied an entry at or above its rev_seq.
func TestRevocationEndsWhenItsEntryIsApplied(t *testing.T) {
	l := newLab(t)
	b := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(revMsg(1, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, 0, 5)) // no expiry given
	l.waitDNS("the revocation", func() bool {
		m := l.lastDNS(sock.TypeRevocations)
		return m != nil && len(m.Revocations.Items) == 1 && m.Revocations.Items[0].ExpiresAt > time.Now().Unix()
	})
	// entry 1 is applied: the revocation of entry 1 is over, whatever its expiry
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1 applied", func() bool { return lastHB(s).AppliedSeq == 1 })
	l.waitDNS("the revocation ended", func() bool {
		m := l.lastDNS(sock.TypeRevocations)
		return m != nil && len(m.Revocations.Items) == 0
	})
	// a resend of it after that is acked and not kept
	_ = s.Send(revMsg(1, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, time.Now().Unix()+600, 5))
	time.Sleep(300 * time.Millisecond)
	if m := l.lastDNS(sock.TypeRevocations); m == nil || len(m.Revocations.Items) != 0 {
		t.Error("a revocation of an applied entry was kept")
	}
}

// The ids held are bounded, so the list never becomes a frame the socket cannot
// carry; the oldest goes first and the owner is told.
func TestRevocationIDsAreBounded(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	exp := time.Now().Unix() + 600
	big := &policyv1.Revocation{RevSeq: 50, Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, ExpiresAt: exp}
	for i := 0; i < wire.MaxRecordsPerEntry; i++ {
		id := make([]byte, 16)
		id[0], id[1], id[2] = byte(i), byte(i>>8), byte(i>>16)
		big.Ids = append(big.Ids, id)
	}
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: big}})
	_ = s.Send(revMsg(60, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, exp, 9))
	l.waitDNS("only the newer one", func() bool {
		m := l.lastDNS(sock.TypeRevocations)
		return m != nil && len(m.Revocations.Items) == 1 && m.Revocations.Items[0].Seq == 60
	})
	if l.alerts.Count(alert.RevocationOverflow) == 0 {
		t.Error("no alert for the dropped revocation")
	}
}

// ACME challenges are bounded and always end.
func TestAcmeChallengesAreBoundedAndGetAnExpiry(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	for i := 0; i < 70; i++ {
		_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_AcmeChallenge{AcmeChallenge: &hubv1.AcmeChallenge{
			TokenId: []byte{byte(i), 1}, Fqdn: "_acme-challenge.dns.example.net", Value: "v", ExpiresAt: 0}}})
	}
	eventually(t, "the last ack", func() bool {
		for _, m := range s.Messages() {
			if a := m.GetAcmeAck(); a != nil && len(a.TokenId) == 2 && a.TokenId[0] == 69 {
				return true
			}
		}
		return false
	})
	l.attachDNS() // a new dns sees the snapshot
	l.waitDNS("the snapshot", func() bool { return l.lastDNS(sock.TypeFacts) != nil })
	n := 0
	l.dnsMu.Lock()
	for _, m := range l.dnsMsgs {
		if m.Type == sock.TypeAcme {
			n++
			if m.Acme.ExpiresAt == 0 {
				t.Error("a challenge with no expiry was kept as it came")
			}
		}
	}
	l.dnsMu.Unlock()
	if n == 0 || n > 64 {
		t.Errorf("challenges in the snapshot = %d, want between 1 and 64", n)
	}
}

// ---- p4n-W5b-r1-7, -18: what dns says about its upstreams

func TestMalformedUpstreamListFromDNSDoesNotGetTheHeartbeatRefused(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	local := wire.LocalUnboundID()
	other := make([]byte, 16)
	other[0] = 3
	l.dnsCl.Send(&sock.Msg{Type: sock.TypeStats, Stats: &sock.Stats{QPS: 77, Upstreams: []sock.Health{
		{ID: local[:], Healthy: true, LatencyMS: 1}, {ID: local[:], Healthy: false}, {ID: other, Healthy: true}, {ID: other, Healthy: false}}}})
	eventually(t, "stats in the Heartbeat", func() bool { return lastHB(s).Qps == 77 })
	hb := lastHB(s)
	if err := wire.ValidateHeartbeat(hb); err != nil {
		t.Fatalf("the hub would refuse this Heartbeat: %v", err)
	}
	if len(hb.Upstreams) != 2 {
		t.Errorf("upstreams = %d, want the two distinct ids", len(hb.Upstreams))
	}
}

// ---- p4n-W5b-r1-4: dns follows the NodeConfig

func TestDNSIsRestartedOntoANewNodeConfig(t *testing.T) {
	l := systemLab(t)
	l.start()
	s := l.session()
	_ = s.Send(serverTime())
	restarts := func() int { return strings.Count(lines(l), "systemctl restart ctrlz-dns.service") }
	_ = s.Send(nodeConfigMsg(1, make([]byte, 16)))
	eventually(t, "dns restarted onto the first NodeConfig", func() bool { return restarts() == 1 })
	// the same bind address: nothing to move
	_ = s.Send(nodeConfigMsg(2, make([]byte, 16)))
	eventually(t, "config 2", func() bool { return lastHB(s).NodeConfigVersion == 2 })
	time.Sleep(300 * time.Millisecond)
	if restarts() != 1 {
		t.Fatalf("restarts = %d for a config that changes nothing dns binds", restarts())
	}
	// a new bind address
	c := testNodeConfig(3, make([]byte, 16))
	c.DnsBindIp = []byte{10, 0, 0, 6}
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: c}})
	eventually(t, "dns restarted onto the new bind address", func() bool { return restarts() == 2 })
}

// A node that restarts with its NodeConfig on disk already runs dns on it.
func TestNoRestartWhenDNSStartedFromTheSameNodeConfig(t *testing.T) {
	l := systemLab(t)
	l.start()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(nodeConfigMsg(1, make([]byte, 16)))
	eventually(t, "restart onto config 1", func() bool { return strings.Contains(lines(l), "systemctl restart ctrlz-dns.service") })
	n := strings.Count(lines(l), "systemctl restart ctrlz-dns.service")
	l.restart()
	s2 := l.session()
	_ = s2.Send(serverTime())
	_ = s2.Send(nodeConfigMsg(1, make([]byte, 16))) // a resend of the same version
	time.Sleep(500 * time.Millisecond)
	if got := strings.Count(lines(l), "systemctl restart ctrlz-dns.service"); got != n {
		t.Errorf("restarts %d -> %d after an agent restart with the same config", n, got)
	}
}

// ---- p4n-W5b-r1-10: a table that was not applied is tried again

func TestFailedNftIsRetriedOnTheHostTick(t *testing.T) {
	l := systemLab(t)
	l.cfg.HostEvery = 100 * time.Millisecond
	var fails atomic.Int32
	base := l.runner.Reply
	l.runner.Reply = func(c fake.Call) ([]byte, error) {
		if c.Name == "nft" && len(c.Args) == 3 && c.Args[0] == "-c" && fails.Add(1) <= 2 {
			return nil, os.ErrInvalid
		}
		return base(c)
	}
	l.start()
	eventually(t, "the table applied after the failures", func() bool {
		return strings.Contains(lines(l), "nft -f -")
	})
	if l.alerts.Count(alert.NftFailed) < 2 {
		t.Errorf("failures alerted %d times", l.alerts.Count(alert.NftFailed))
	}
}

// ---- p4n-W5b-r1-16: a renewal answer that is not a certificate this agent can use

func TestRenewalWithAnUnknownKeyAlgorithmIsRefusedNotAPanic(t *testing.T) {
	l := newLab(t, shortCert)
	l.hub.Renew = func(r *hubv1.RenewCertRequest) (*hubv1.RenewCertResponse, error) {
		csr, err := x509.ParseCertificateRequest(r.CsrDer)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: l.id.Leaf().Subject.CommonName},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, l.idp.ca, csr.PublicKey, l.idp.caKey)
		if err != nil {
			return nil, err
		}
		// id-ecPublicKey (1.2.840.10045.2.1) becomes an OID no x509 package knows: the
		// parser then returns PublicKey nil with no error.
		oid := []byte{0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}
		i := bytes.Index(der, oid)
		if i < 0 {
			t.Fatal("no id-ecPublicKey in the certificate")
		}
		der[i+8] = 0x7F
		if c, err := x509.ParseCertificate(der); err != nil || c.PublicKey != nil {
			t.Fatalf("the test certificate does not parse as intended: %v", err)
		}
		return &hubv1.RenewCertResponse{CertDer: der}, nil
	}
	l.start()
	before := l.id.Leaf().NotAfter
	if ok, err := l.ag.RenewIfDue(context.Background()); ok || err == nil {
		t.Fatalf("renewed=%v err=%v", ok, err)
	}
	if !l.id.Leaf().NotAfter.Equal(before) {
		t.Error("the certificate in use changed")
	}
}

// A certificate that does not chain to the node CA is refused too.
func TestRenewalFromAnotherCAIsRefused(t *testing.T) {
	l := newLab(t, shortCert)
	l.hub.Renew = func(r *hubv1.RenewCertRequest) (*hubv1.RenewCertResponse, error) {
		csr, err := x509.ParseCertificateRequest(r.CsrDer)
		if err != nil {
			return nil, err
		}
		otherKey := newIdentityKey(t)
		otherCA := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "evil"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(98), Subject: pkix.Name{CommonName: l.id.Leaf().Subject.CommonName},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, otherCA, csr.PublicKey, otherKey)
		return &hubv1.RenewCertResponse{CertDer: der}, err
	}
	l.start()
	if ok, err := l.ag.RenewIfDue(context.Background()); ok || err == nil {
		t.Fatalf("a certificate of another CA was taken: %v %v", ok, err)
	}
}
