package agent_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func TestHeartbeatFirstConfigAndProofKey(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	if _, err := s.Wait(5*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetHeartbeat() != nil }); err != nil {
		t.Fatal(err)
	}
	first := s.Messages()
	if len(first) == 0 || first[0].GetHeartbeat() == nil {
		t.Fatal("the first NodeMessage of the stream is not a Heartbeat")
	}
	hb := first[0].GetHeartbeat()
	if hb.NodeVersion != "vtest" || hb.BlobMajorMax != 1 || hb.AppliedSeq != 0 {
		t.Errorf("heartbeat: %+v", hb)
	}
	if err := wire.ValidateHeartbeat(hb); err != nil {
		t.Errorf("the hub's door refuses the Heartbeat: %v", err)
	}
	_ = s.Send(serverTime())

	proofKey := storetest.RandomSecret(t, 32)
	_ = s.Send(nodeConfigMsg(5, proofKey))
	l.waitDNS("the NodeConfig at dns", func() bool {
		m := l.lastDNS(sock.TypeConfig)
		if m == nil {
			return false
		}
		var nc hubv1.NodeConfig
		return proto.Unmarshal(m.Config.NodeConfig, &nc) == nil && nc.Version == 5 && bytesEq(nc.ProofKey, proofKey)
	})
	eventually(t, "Heartbeat reports the version", func() bool { return lastHB(s).NodeConfigVersion == 5 })
	// the real proof_key is in the memory of the two processes and on no disk
	if storetest.Contains(t, l.dir, proofKey) {
		t.Fatal("the real proof_key reached a file")
	}
	// a replay of an older NodeConfig changes nothing
	_ = s.Send(nodeConfigMsg(3, storetest.RandomSecret(t, 32)))
	time.Sleep(300 * time.Millisecond)
	if lastHB(s).NodeConfigVersion != 5 {
		t.Error("an older NodeConfig was applied")
	}
	// after a restart the persisted config is the one in force, with no key
	l.restart()
	l.attachDNS()
	s2 := l.session()
	eventually(t, "restart keeps the version", func() bool { return lastHB(s2).NodeConfigVersion == 5 })
	if m := l.lastDNS(sock.TypeConfig); m != nil {
		var nc hubv1.NodeConfig
		_ = proto.Unmarshal(m.Config.NodeConfig, &nc)
		if bytesEq(nc.ProofKey, proofKey) {
			t.Error("the proof_key survived a restart, it must come from the hub again")
		}
	}
}

func TestLogApplyImageAndFreeFacts(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	ep := storetest.Endpoint(1, b1)
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{ep}, PairTable: storetest.Table(3, 0),
		FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 40, Version: 2}})
	l.start()
	l.attachDNS()
	s := l.session()

	// Before any ServerTime the free path is off, whatever else holds.
	l.waitDNS("facts", func() bool { return l.lastDNS(sock.TypeFacts) != nil })
	if f := l.lastDNS(sock.TypeFacts).Facts; f.FreeOK() || f.ServerTimeSeen {
		t.Fatalf("facts before a ServerTime: %+v", f)
	}
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	if _, err := s.Wait(10*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 1 && m.GetApplyResult().Ok }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "applied_seq in the Heartbeat", func() bool { return lastHB(s).AppliedSeq == 1 })
	l.waitDNS("image at dns", func() bool { return l.lastDNS(sock.TypeImage) != nil })
	name := l.lastDNS(sock.TypeImage).Image.Name
	if name == "" || l.ag == nil {
		t.Fatal("no image name")
	}
	l.waitDNS("free path facts", func() bool {
		f := l.lastDNS(sock.TypeFacts).Facts
		return f.FreeOK() && f.FreeVersion == 2 && f.AppliedSeq == 1 // p4n-MD-r1-4: dns judges the image against this
	})
	tbl := l.lastDNS(sock.TypeTable)
	if tbl == nil || len(tbl.Table.Member) == 0 {
		t.Fatalf("no membership at dns: %+v", tbl)
	}
	// FreeDnsOff raises the floor and turns the path off at once; a free_dns value
	// of that version or later turns it on again.
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_FreeDnsOff{FreeDnsOff: &hubv1.FreeDnsOff{Version: 5}}})
	l.waitDNS("the floor", func() bool { f := l.lastDNS(sock.TypeFacts).Facts; return f.OffFloor == 5 && !f.FreeOK() })
	l.addEntry(nil, &policyv1.ConfigEntry{FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 40, Version: 5}})
	_ = s.Send(headNotice(2))
	l.waitDNS("free path back on", func() bool { f := l.lastDNS(sock.TypeFacts).Facts; return f.FreeOK() && f.FreeVersion == 5 })

	// A restart of the agent clears every fact of the run: free DNS is off until
	// the new run has heard a ServerTime again (SC 5.2a (c)).
	l.restart()
	l.attachDNS()
	s2 := l.session()
	l.waitDNS("facts after restart", func() bool { return l.lastDNS(sock.TypeFacts) != nil })
	if f := l.lastDNS(sock.TypeFacts).Facts; f.FreeOK() || f.ServerTimeSeen || f.OffFloor != 0 {
		t.Fatalf("facts survived a restart: %+v", f)
	}
	_ = s2.Send(serverTime())
	l.waitDNS("facts after a ServerTime", func() bool {
		f := l.lastDNS(sock.TypeFacts).Facts
		return f.ServerTimeSeen && f.CaughtUpOnce && f.FreeOK()
	})
	// the image is the one the state names, read by dns from disk
	if n := l.lastDNS(sock.TypeImage).Image.Name; n == "" {
		t.Error("no image after restart")
	}
}

// SC 8a.11 L11: with the log work stalled (a FetchEntries the hub never
// answers), a push is applied at once and a Revocation is acknowledged, and
// applied_seq does not move.
func TestStalledLogWorkHoldsBackNeitherPushNorRevocation(t *testing.T) {
	l := newLab(t)
	hold := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-hold:
		default:
			close(hold)
		}
	})
	l.hub.EntriesHook = func(ctx context.Context, req *hubv1.FetchEntriesRequest) error {
		if req.AfterSeq >= 1 {
			select {
			case <-hold:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	b1 := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })

	l.addEntry(nil, &policyv1.ConfigEntry{PairTable: storetest.Table(3, 0)})
	_ = s.Send(headNotice(2)) // the log work now stalls on FetchEntries
	time.Sleep(200 * time.Millisecond)

	// a push of a higher version that withdraws node 0
	pt := storetest.Table(3, 100, 0)
	pt.ExpiresAt = time.Now().Unix() + 1800
	sent := time.Now()
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: l.keys.Sign(t, pt)}})
	l.waitDNS("the push at dns", func() bool {
		m := l.lastDNS(sock.TypeTable)
		if m == nil || m.Table.Version != 100 {
			return false
		}
		for _, f := range m.Table.Flags {
			if bytesEq(f.Node, storetest.NodeID(0)) && f.Withdrawn {
				return true
			}
		}
		return false
	})
	if d := time.Since(sent); d > 2*time.Second {
		t.Errorf("the push took %v to apply while the log work was stalled", d)
	}
	eventually(t, "the version in the next PeerView", func() bool {
		pv, err := wire.ValidatePeerView(lastHB(s).PeerView)
		return err == nil && pv.PairTableVersion == 100
	})

	// a Revocation is taken, handed to dns and acknowledged
	rev := &policyv1.Revocation{RevSeq: 9, Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, Ids: [][]byte{make([]byte, 16)},
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 600}
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: rev}})
	if _, err := s.Wait(2*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetRevocationAck().GetRevSeq() == 9 }); err != nil {
		t.Fatal("the Revocation was not acknowledged while the log work was stalled")
	}
	l.waitDNS("the revocation at dns", func() bool {
		m := l.lastDNS(sock.TypeRevocations)
		return m != nil && len(m.Revocations.Items) == 1 && m.Revocations.Items[0].Seq == 9
	})
	if lastHB(s).AppliedSeq != 1 {
		t.Error("applied_seq moved while the log work was stalled")
	}

	// the stall ends: entry 2 applies, and its membership does not undo the push
	close(hold)
	eventually(t, "entry 2", func() bool { return lastHB(s).AppliedSeq == 2 })
	l.waitDNS("table after entry 2", func() bool {
		m := l.lastDNS(sock.TypeTable)
		if m == nil || m.Table.Version != 100 {
			return false
		}
		for _, f := range m.Table.Flags {
			if bytesEq(f.Node, storetest.NodeID(0)) && f.Withdrawn {
				return true
			}
		}
		return false
	})
}

// A hostile push is refused and the node keeps its table.
func TestRefusedPushKeepsTheTableAndAlerts(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })
	pt := storetest.Table(3, 50)
	pt.ExpiresAt = time.Now().Unix() + 1800
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: l.keys.Sign(t, pt)}})
	eventually(t, "push accepted", func() bool {
		pv, err := wire.ValidatePeerView(lastHB(s).PeerView)
		return err == nil && pv.PairTableVersion == 50
	})
	// lower version: refused, reported, version stays
	low := storetest.Table(3, 10)
	low.ExpiresAt = time.Now().Unix() + 1800
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: l.keys.Sign(t, low)}})
	// signed by someone else
	other := storetest.NewKeys(t)
	bad := storetest.Table(3, 200)
	bad.ExpiresAt = time.Now().Unix() + 1800
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: other.Sign(t, bad)}})
	eventually(t, "two refusals", func() bool {
		pv, err := wire.ValidatePeerView(lastHB(s).PeerView)
		return err == nil && pv.Refusals == 2 && pv.PairTableVersion == 50
	})
	pv, _ := wire.ValidatePeerView(lastHB(s).PeerView)
	if pv.LastRefusal != hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE {
		t.Errorf("last refusal %v", pv.LastRefusal)
	}
	if l.alerts.Count(alert.PushRefused) < 2 {
		t.Errorf("alerts: %v", l.alerts.Codes())
	}
	if m := l.lastDNS(sock.TypeTable); m == nil || m.Table.Version != 50 {
		t.Errorf("dns table: %+v", m)
	}
}

// SC 8a.11 L6 and L10: no transfer or upload RPC goes on the connection that
// carries Control, and transfers and uploads do not share one.
func TestEachRoleHasAConnectionOfItsOwn(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	ep := storetest.Endpoint(1, b1)
	ep.ClientCap = 2
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{ep}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })
	// counters and activity from dns, then time moves so both go out
	l.dnsCl.Send(&sock.Msg{Type: sock.TypeFreeCounts, FreeCounts: &sock.FreeCounts{Items: []sock.FreeCount{{Proto: int32(commonv1.Protocol_PROTOCOL_UDP), Outcome: int32(telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED), Count: 3}}}})
	l.dnsCl.Send(&sock.Msg{Type: sock.TypeActivity, Activity: &sock.Activity{Items: []sock.ActivityItem{{Endpoint: storetest.Endpoint(1, b1).EndpointId, Label: "default", Proto: int32(commonv1.Protocol_PROTOCOL_DOH), At: time.Now().Unix()}}}})
	time.Sleep(100 * time.Millisecond)
	l.skew.Store(400)
	eventually(t, "a counters batch", func() bool { return len(l.hub.Counters()) > 0 })
	eventually(t, "an activity batch", func() bool { return len(l.hub.Activity()) > 0 })

	set := func(m string) map[uint64]bool { return l.hub.ConnsOf("/ctrlz.hub.v1.NodeHub/" + m) }
	control := set("Control")
	transfer := map[uint64]bool{}
	for _, m := range []string{"FetchEntries", "GetHead", "FetchBlob", "GetSnapshot"} {
		for c := range set(m) {
			transfer[c] = true
		}
	}
	upload := map[uint64]bool{}
	for _, m := range []string{"UploadCounters", "ReportActivity"} {
		for c := range set(m) {
			upload[c] = true
		}
	}
	if len(control) != 1 || len(transfer) == 0 || len(upload) != 1 {
		t.Fatalf("connections: control %v transfer %v upload %v", control, transfer, upload)
	}
	for c := range transfer {
		if control[c] || upload[c] {
			t.Errorf("a transfer RPC went on connection %d, which carries another role", c)
		}
	}
	for c := range upload {
		if control[c] {
			t.Error("an upload RPC went on the Control connection")
		}
	}
	// what was uploaded is what dns counted, with no name and no address
	b := l.hub.Counters()[0]
	if len(b.Free) != 1 || b.Free[0].Count != 3 || b.BucketStart%300 != 0 {
		t.Errorf("counters batch: %v", b)
	}
	if err := wire.ValidateTelemetryMessage(b, l.now().Unix()); err != nil {
		t.Errorf("the hub's door refuses the counters: %v", err)
	}
	a := l.hub.Activity()[0]
	if len(a.Entries) != 1 || a.Entries[0].ClientLabel != "default" {
		t.Errorf("activity batch: %v", a)
	}
	if err := wire.ValidateTelemetryMessage(a, l.now().Unix()); err != nil {
		t.Errorf("the hub's door refuses the activity: %v", err)
	}
}

// What dns may ask the agent to relay is the three kinds an outside party can
// cause, and the agent checks them again.
func TestOutboundRelayIsLimitedAndValidated(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	send := func(m *hubv1.NodeMessage) {
		b, _ := proto.Marshal(m)
		l.dnsCl.Send(&sock.Msg{Type: sock.TypeOutbound, Outbound: &sock.Outbound{NodeMessage: b}})
	}
	label := "abcdefghijklmnopqrstuvwxyz"[:0] + "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	good := &hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{
		Label: label, SourceIp: []byte{1, 2, 3, 4}, Protocol: commonv1.Protocol_PROTOCOL_UDP, ObservedAt: time.Now().Unix()}}}
	send(good)
	if _, err := s.Wait(3*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetProofObservation().GetLabel() == label }); err != nil {
		t.Fatal("a valid observation was not relayed")
	}
	// a repeat inside 60 s, an old observation, a bad label and the agent's own kinds are not
	send(good)
	send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{
		Label: "bbbbbbbbbbbbbbbbbbbbbbbbbb", SourceIp: []byte{1, 2, 3, 4}, Protocol: commonv1.Protocol_PROTOCOL_UDP, ObservedAt: time.Now().Unix() - 7200}}})
	send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{
		Label: "NOT A LABEL", SourceIp: []byte{1, 2, 3, 4}, Protocol: commonv1.Protocol_PROTOCOL_UDP, ObservedAt: time.Now().Unix()}}})
	send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ApplyResult{ApplyResult: &hubv1.ApplyResult{Seq: 99, Ok: true}}})
	send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: &hubv1.Heartbeat{AppliedSeq: 999, BlobMajorMax: 1}}})
	send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_RevocationAck{RevocationAck: &hubv1.RevocationAck{RevSeq: 1}}})
	l.dnsCl.Send(&sock.Msg{Type: sock.TypeOutbound, Outbound: &sock.Outbound{NodeMessage: []byte("not a proto \xff\xff")}})
	time.Sleep(500 * time.Millisecond)
	n := 0
	for _, m := range s.Messages() {
		switch {
		case m.GetProofObservation() != nil:
			n++
		case m.GetApplyResult().GetSeq() == 99, m.GetRevocationAck() != nil, m.GetHeartbeat().GetAppliedSeq() == 999:
			t.Errorf("dns made the agent send %T", m.Body)
		}
	}
	if n != 1 {
		t.Errorf("observations relayed: %d, want 1", n)
	}
}

func TestStatsFromDNSReachTheHeartbeat(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	id := make([]byte, 16)
	id[0] = 7
	l.dnsCl.Send(&sock.Msg{Type: sock.TypeStats, Stats: &sock.Stats{QPS: 1234, CacheHitPermille: 900, Isolated: true,
		Upstreams: []sock.Health{{ID: id, Healthy: true, LatencyMS: 12}, {ID: []byte{1}, Healthy: true}}}})
	eventually(t, "stats in the Heartbeat", func() bool {
		hb := lastHB(s)
		return hb.Qps == 1234 && hb.CacheHitPermille == 900 && hb.Isolated && len(hb.Upstreams) == 1 && hb.Upstreams[0].LatencyMs == 12
	})
	if err := wire.ValidateHeartbeat(lastHB(s)); err != nil {
		t.Error(err)
	}
}

func TestAcmeChallengeIsHandedToDNSAndAcked(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_AcmeChallenge{AcmeChallenge: &hubv1.AcmeChallenge{
		TokenId: []byte("tok1"), Fqdn: "_acme-challenge.dns.example.net", Value: "xyz", ExpiresAt: time.Now().Unix() + 600}}})
	if _, err := s.Wait(3*time.Second, func(m *hubv1.NodeMessage) bool { return string(m.GetAcmeAck().GetTokenId()) == "tok1" }); err != nil {
		t.Fatal("no AcmeAck")
	}
	l.waitDNS("acme at dns", func() bool { m := l.lastDNS(sock.TypeAcme); return m != nil && m.Acme.Value == "xyz" })
	// a challenge that already expired is neither handed over nor acked
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_AcmeChallenge{AcmeChallenge: &hubv1.AcmeChallenge{
		TokenId: []byte("tok2"), Fqdn: "_acme-challenge.dns.example.net", Value: "old", ExpiresAt: time.Now().Unix() - 10}}})
	time.Sleep(300 * time.Millisecond)
	for _, m := range s.Messages() {
		if string(m.GetAcmeAck().GetTokenId()) == "tok2" {
			t.Error("an expired challenge was acked")
		}
	}
}

// Three of the four ways PanelStale holds, seen at dns through the table message.
func TestPanelStaleReachesDNS(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	// no push accepted since the start: stale from the start
	l.waitDNS("a table message", func() bool { return l.lastDNS(sock.TypeTable) != nil })
	if !l.lastDNS(sock.TypeTable).Table.PanelStale {
		t.Fatal("a node that has accepted no push is not PanelStale")
	}
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })
	pt := storetest.Table(3, 50)
	pt.ExpiresAt = time.Now().Unix() + 1800
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: l.keys.Sign(t, pt)}})
	l.waitDNS("not stale", func() bool {
		m := l.lastDNS(sock.TypeTable)
		return m.Table.Version == 50 && !m.Table.PanelStale && m.Table.InUse
	})
	// the clock of the node moves 40 s on with no ServerTime: the hub's time stopped
	l.skew.Store(40)
	l.waitDNS("stale again", func() bool { return l.lastDNS(sock.TypeTable).Table.PanelStale })
	// a ServerTime and a redelivery clear it
	l.skew.Store(0)
	_ = s.Send(serverTime())
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: l.keys.Sign(t, pt)}})
	l.waitDNS("clear", func() bool { return !l.lastDNS(sock.TypeTable).Table.PanelStale })
}

// SC 8a.6 on the agent side: it runs the drain rule over every table it applies and
// tells dns (drain_since in the table message): set when the node stops being the
// advertised node, cleared when a push makes it the advertised node again, and never
// set for a node that was not advertised when it started.
func TestDrainSinceReachesDNS(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(3, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })
	ds := func() int64 { return l.lastDNS(sock.TypeTable).Table.DrainSince }
	l.waitDNS("a table in use", func() bool { m := l.lastDNS(sock.TypeTable); return m != nil && m.Table.Member != nil })
	if ds() != 0 {
		t.Fatalf("a node that has always been the advertised node drains: %d", ds())
	}
	push := func(version uint64, withdrawn ...int) {
		pt := storetest.Table(3, version, withdrawn...)
		pt.ExpiresAt = time.Now().Unix() + 1800
		_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: l.keys.Sign(t, pt)}})
	}
	push(50)
	l.waitDNS("push 50 in use", func() bool { return l.lastDNS(sock.TypeTable).Table.Version == 50 })
	if ds() != 0 {
		t.Fatal("a push that changes nothing for this node started a drain")
	}
	// The hub withdraws node 0, the advertised primary of the global pair: the answer
	// moves to node 1 and this node drains.
	push(51, 0)
	l.waitDNS("drain since", func() bool { return ds() != 0 })
	since := ds()
	if d := time.Now().Unix() - since; d < -2 || d > 10 {
		t.Fatalf("drain_since %d is not the time of the apply", since)
	}
	// A later table that still does not advertise it keeps the time of the first.
	push(52, 0, 2)
	l.waitDNS("push 52 in use", func() bool { return l.lastDNS(sock.TypeTable).Table.Version == 52 })
	if ds() != since {
		t.Fatalf("drain_since moved from %d to %d while the node stayed not advertised", since, ds())
	}
	// The hub clears the withdrawal: advertised again, the drain ends.
	push(53)
	l.waitDNS("drain cancelled", func() bool { m := l.lastDNS(sock.TypeTable); return m.Table.Version == 53 && ds() == 0 })
}

var _ sync.Mutex

// SC 8a.10 "Drain test": a log entry that moves the global pair from (A, B) to an
// existing pair (C, D) starts the drain of A although the pair (A, B) still exists.
// The drain input changes through the membership of an applied entry, not through a
// push, and the node's table in use must follow it (p4n-W8-r1-4).
func TestDrainSinceStartsWhenALogEntrySwitchesTheGlobalPair(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, b1)}, PairTable: storetest.Table(4, 0)})
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })
	ds := func() int64 { return l.lastDNS(sock.TypeTable).Table.DrainSince }
	l.waitDNS("a table in use", func() bool { m := l.lastDNS(sock.TypeTable); return m != nil && m.Table.Member != nil })
	if ds() != 0 {
		t.Fatalf("a node that has always been the advertised node drains: %d", ds())
	}
	// Entry 2: the pair table keeps (A, B) = nodes 0 and 1, adds (C, D) = nodes 2 and 3
	// and makes it the global pair.
	pt := storetest.Table(4, 1)
	second := bytes.Repeat([]byte{0xb1}, 16)
	pt.Pairs = append(pt.Pairs, &policyv1.Pair{PairId: second, Primary: storetest.NodeID(2), Fallback: storetest.NodeID(3)})
	pt.GlobalPairId = second
	l.addEntry(nil, &policyv1.ConfigEntry{PairTable: pt})
	_ = s.Send(headNotice(2))
	eventually(t, "entry 2", func() bool { return lastHB(s).AppliedSeq == 2 })
	l.waitDNS("drain since after the switch", func() bool { return ds() != 0 })
	if d := time.Now().Unix() - ds(); d < -2 || d > 10 {
		t.Fatalf("drain_since %d is not the time of the apply", ds())
	}
}
