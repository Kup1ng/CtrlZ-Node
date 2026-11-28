package control

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
)

type rig struct {
	t      *testing.T
	hub    *fakehub.Hub
	c      *Client
	cancel context.CancelFunc
	done   chan struct{}

	serverTimes atomic.Int64
	heads       atomic.Int64
	offs        atomic.Int64
	pushes      atomic.Int64
	applied     atomic.Uint64
}

func hb(applied uint64) *hubv1.Heartbeat {
	return &hubv1.Heartbeat{NodeTime: time.Now().Unix(), AppliedSeq: applied, NodeVersion: "test", BlobMajorMax: 1}
}

func newRig(t *testing.T, tweak func(*Config, *rig)) *rig {
	t.Helper()
	r := &rig{t: t, hub: fakehub.New(), done: make(chan struct{})}
	r.hub.Start()
	t.Cleanup(r.hub.Stop)
	cc, err := r.hub.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	cfg := Config{
		Hub:               hubv1.NewNodeHubClient(cc),
		Heartbeat:         func() *hubv1.Heartbeat { return hb(r.applied.Load()) },
		HeartbeatEvery:    40 * time.Millisecond,
		ServerTimeTimeout: 2 * time.Second,
		SendTimeout:       2 * time.Second,
		BackoffMin:        20 * time.Millisecond,
		BackoffMax:        200 * time.Millisecond,
		CB: Callbacks{
			ServerTime: func(int64) { r.serverTimes.Add(1) },
			HeadNotice: func(seq uint64, _ bool) { r.heads.Add(1) },
			FreeDNSOff: func(uint64) { r.offs.Add(1) },
			Push:       func(context.Context, *signv1.Envelope) { r.pushes.Add(1) },
		},
	}
	if tweak != nil {
		tweak(&cfg, r)
	}
	r.c = New(cfg)
	return r
}

func (r *rig) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { defer close(r.done); r.c.Run(ctx) }()
	r.t.Cleanup(func() { cancel(); <-r.done })
}

func isHB(m *hubv1.NodeMessage) bool { return m.GetHeartbeat() != nil }

func serverTime() *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: time.Now().Unix()}}}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 600; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestHeartbeatIsFirstAndPeriodic(t *testing.T) {
	r := newRig(t, nil)
	// Queued before any stream exists: they must not overtake the Heartbeat.
	for i := 0; i < 5; i++ {
		r.c.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ApplyResult{ApplyResult: &hubv1.ApplyResult{Seq: uint64(i + 1), Ok: true}}})
	}
	r.c.Outside(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{Label: "a"}}})
	r.start()
	s, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Wait(3*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 5 }); err != nil {
		t.Fatal(err)
	}
	msgs := s.Messages()
	if !isHB(msgs[0]) {
		t.Fatalf("the first message is %T, not a Heartbeat", msgs[0].Body)
	}
	if err := sendST(s); err != nil {
		t.Fatal(err)
	}
	eventually(t, "heartbeats", func() bool {
		n := 0
		for _, m := range s.Messages() {
			if isHB(m) {
				n++
			}
		}
		return n >= 4
	})
	r.applied.Store(77)
	if _, err := s.Wait(2*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetHeartbeat().GetAppliedSeq() == 77 }); err != nil {
		t.Fatal("a later Heartbeat does not carry the new applied_seq")
	}
}

func sendST(s *fakehub.Session) error { return s.Send(serverTime()) }

// SC 8a.11 L10: a due Heartbeat waits for at most the one message being
// written, whatever is queued behind it and however fast the queues are fed.
func TestDueHeartbeatGoesBeforeQueuedMessages(t *testing.T) {
	var mu sync.Mutex
	type ev struct {
		hb bool
		at time.Time
	}
	var trace []ev
	r := newRig(t, func(c *Config, r *rig) {
		c.HeartbeatEvery = 50 * time.Millisecond
		c.Trace = func(m *hubv1.NodeMessage) {
			mu.Lock()
			trace = append(trace, ev{hb: isHB(m), at: time.Now()})
			mu.Unlock()
			// Each send takes 3 ms, so the 1024 reports that queue up are 3 s of
			// writing: an agent that wrote every message in one FIFO would hold a due
			// Heartbeat behind all of them.
			time.Sleep(3 * time.Millisecond)
		}
	})
	r.start()
	s, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = sendST(s)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // a burst of ApplyResults, faster than they can be sent
		defer wg.Done()
		for i := uint64(1); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			r.c.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ApplyResult{ApplyResult: &hubv1.ApplyResult{Seq: i, Ok: true}}})
			if i%64 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	go func() { // and the outside kind, each different so none is a repeat
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			r.c.Outside(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{Label: fmt.Sprintf("l%d", i), SourceIp: []byte{1, 2, 3, 4}}}})
			time.Sleep(time.Millisecond)
		}
	}()
	time.Sleep(2500 * time.Millisecond)
	close(stop)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	var lastHB time.Time
	var hbs, others int
	var worst time.Duration
	for _, e := range trace {
		if e.hb {
			if !lastHB.IsZero() {
				if g := e.at.Sub(lastHB); g > worst {
					worst = g
				}
			}
			lastHB = e.at
			hbs++
		} else {
			others++
		}
	}
	if !trace[0].hb {
		t.Fatal("first message is not a Heartbeat")
	}
	if others < 150 || hbs < 10 {
		t.Fatalf("the flood did not run: %d heartbeats, %d others", hbs, others)
	}
	// 50 ms interval; one message being written and scheduling noise may add to it,
	// but never a run of queued messages.
	if worst > 250*time.Millisecond {
		t.Errorf("worst gap between Heartbeats %v under a flood", worst)
	}
}

func TestOutsideQueueIsBoundedDedupedAndPaced(t *testing.T) {
	// The pace is measured where the sender hands each message to the stream (Trace), not
	// where the hub's goroutine happens to read it: under load the reads bunch up, and a
	// receive-side gap of 20 ms does not mean the sender sent faster than 20 a second.
	var tmu sync.Mutex
	var sent []time.Time
	r := newRig(t, func(c *Config, _ *rig) {
		c.Trace = func(m *hubv1.NodeMessage) {
			if m.GetLearnedIp() != nil {
				tmu.Lock()
				sent = append(sent, time.Now())
				tmu.Unlock()
			}
		}
	})
	mk := func(i int) *hubv1.NodeMessage {
		return &hubv1.NodeMessage{Body: &hubv1.NodeMessage_LearnedIp{LearnedIp: &hubv1.LearnedIP{
			EndpointId: []byte{byte(i), byte(i >> 8), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, SourceIp: []byte{9, 9, 9, 9}, Protocol: commonv1.Protocol_PROTOCOL_DOH}}}
	}
	accepted := 0
	for i := 0; i < 1000; i++ {
		if r.c.Outside(mk(i)) {
			accepted++
		}
	}
	if accepted != OutsideQueueMax {
		t.Fatalf("accepted %d, the queue holds %d", accepted, OutsideQueueMax)
	}
	st := r.c.Stats()
	if st.OutsideDropped != 1000-OutsideQueueMax {
		t.Errorf("dropped %d", st.OutsideDropped)
	}
	// a repeat inside the window is dropped without touching the queue
	if r.c.Outside(mk(0)) {
		t.Error("a repeat inside 60 s was accepted")
	}
	if r.c.Stats().OutsideRepeats != 1 {
		t.Error("repeat not counted")
	}
	if r.c.Outside(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: hb(1)}}) {
		t.Error("a Heartbeat went through the outside door")
	}
	// paced: at most 20 a second once a stream is open
	r.start()
	s, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = sendST(s)
	eventually(t, "ten outside messages", func() bool {
		n := 0
		for _, m := range s.Messages() {
			if m.GetLearnedIp() != nil {
				n++
			}
		}
		return n >= 10
	})
	tmu.Lock()
	ts := append([]time.Time(nil), sent...)
	tmu.Unlock()
	if len(ts) < 10 {
		t.Fatalf("only %d sends traced", len(ts))
	}
	for i := 1; i < 10; i++ {
		if g := ts[i].Sub(ts[i-1]); g < 30*time.Millisecond {
			t.Errorf("messages %d and %d are %v apart: the pace is 20 a second", i-1, i, g)
		}
	}
}

// L11: the receive loop only reads. Every kind of work stalls here, and
// ServerTime, HeadNotice, FreeDnsOff and the Heartbeats go on regardless.
func TestReceiveLoopNeverWaits(t *testing.T) {
	block := make(chan struct{})
	var cfgs, revs, certs, acmes atomic.Int64
	r := newRig(t, func(c *Config, r *rig) {
		c.CB.Push = func(ctx context.Context, e *signv1.Envelope) { r.pushes.Add(1); <-block }
		c.CB.NodeConfig = func(ctx context.Context, n *hubv1.NodeConfig) { cfgs.Add(1); <-block }
		c.CB.Revocation = func(ctx context.Context, n *policyv1.Revocation) { revs.Add(1); <-block }
		c.CB.CertBundle = func(ctx context.Context, n *hubv1.CertBundle) { certs.Add(1); <-block }
		c.CB.Acme = func(ctx context.Context, n *hubv1.AcmeChallenge) { acmes.Add(1); <-block }
	})
	r.start()
	// registered after start, so it runs before the rig's cleanup waits for the workers
	t.Cleanup(func() { close(block) })
	s, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	send := func(m *hubv1.HubMessage) {
		if err := s.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 300; i++ {
		send(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: &signv1.Envelope{PayloadType: "x"}}})
		send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: &hubv1.NodeConfig{Version: uint64(i + 1)}}})
		send(&hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: &policyv1.Revocation{RevSeq: uint64(i + 1), Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, Ids: [][]byte{make([]byte, 16)}, IssuedAt: 1, ExpiresAt: 4_000_000_000}}})
		send(&hubv1.HubMessage{Body: &hubv1.HubMessage_CertBundle{CertBundle: &hubv1.CertBundle{}}})
		send(&hubv1.HubMessage{Body: &hubv1.HubMessage_AcmeChallenge{AcmeChallenge: &hubv1.AcmeChallenge{TokenId: []byte{1}}}})
		send(&hubv1.HubMessage{Body: &hubv1.HubMessage_HeadNotice{HeadNotice: &hubv1.HeadNotice{Seq: uint64(i + 1)}}})
		send(serverTime())
	}
	send(&hubv1.HubMessage{Body: &hubv1.HubMessage_FreeDnsOff{FreeDnsOff: &hubv1.FreeDnsOff{Version: 5}}})
	eventually(t, "ServerTime, HeadNotice and FreeDnsOff all taken while every worker is stuck", func() bool {
		return r.serverTimes.Load() == 300 && r.heads.Load() == 300 && r.offs.Load() == 1
	})
	if cfgs.Load() != 1 || r.pushes.Load() != 1 || revs.Load() != 1 || certs.Load() != 1 || acmes.Load() != 1 {
		t.Errorf("each worker should be stuck on its first item: cfg=%d push=%d rev=%d cert=%d acme=%d", cfgs.Load(), r.pushes.Load(), revs.Load(), certs.Load(), acmes.Load())
	}
	// Heartbeats are still coming.
	before := 0
	for _, m := range s.Messages() {
		if isHB(m) {
			before++
		}
	}
	time.Sleep(300 * time.Millisecond)
	after := 0
	for _, m := range s.Messages() {
		if isHB(m) {
			after++
		}
	}
	if after-before < 4 {
		t.Errorf("only %d Heartbeats in 300 ms while the workers are stuck", after-before)
	}
	st := r.c.Stats()
	if st.PushesDropped == 0 || st.ConfigsDropped == 0 || st.RevocationsLost == 0 {
		t.Errorf("the queues are not bounded: %+v", st)
	}
	if r.c.Stats().Streams != 1 {
		t.Errorf("the stream was cut %d times", r.c.Stats().Streams)
	}
}

func TestSilentHubEndsTheStreamAndReconnects(t *testing.T) {
	r := newRig(t, func(c *Config, r *rig) { c.ServerTimeTimeout = 300 * time.Millisecond })
	r.start()
	for i := 0; i < 3; i++ {
		s, err := r.hub.NextSession(5 * time.Second)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		// no ServerTime: the node gives up on this stream
		select {
		case <-s.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("session %d was kept open for a hub that says nothing", i)
		}
		if first := s.Messages()[0]; !isHB(first) {
			t.Error("the first message of a reconnected stream is not a Heartbeat")
		}
	}
	if r.c.Up() {
		// may be briefly true between sessions, but not forever
		eventually(t, "down", func() bool { return !r.c.Up() || r.c.Stats().Streams > 3 })
	}
}

func TestReconnectsAfterTheHubEndsTheStream(t *testing.T) {
	var states []bool
	var mu sync.Mutex
	r := newRig(t, func(c *Config, r *rig) {
		c.CB.StreamState = func(up bool) { mu.Lock(); states = append(states, up); mu.Unlock() }
	})
	r.start()
	s1, _ := r.hub.NextSession(5 * time.Second)
	_ = sendST(s1)
	eventually(t, "up", r.c.Up)
	s1.End()
	s2, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal("no reconnect")
	}
	if _, err := s2.Wait(2*time.Second, isHB); err != nil {
		t.Fatal("no Heartbeat on the second stream")
	}
	if !isHB(s2.Messages()[0]) {
		t.Error("the first message of the second stream is not a Heartbeat")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(states) < 3 || !states[0] || states[1] || !states[2] {
		t.Errorf("stream states %v", states)
	}
}

// A hub that sends hostile or oversized messages costs the node the stream and
// nothing else.
func TestHostileHub(t *testing.T) {
	var cfgs atomic.Int64
	r := newRig(t, func(c *Config, r *rig) {
		c.CB.NodeConfig = func(context.Context, *hubv1.NodeConfig) { cfgs.Add(1) }
		c.CB.Revocation = func(context.Context, *policyv1.Revocation) { cfgs.Add(100) }
		c.CB.ServerTime = func(int64) { r.serverTimes.Add(1); panic("callback bug") }
	})
	r.start()
	s, _ := r.hub.NextSession(5 * time.Second)
	for _, m := range []*hubv1.HubMessage{
		{}, // no body
		{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: -1}}},
		{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: 1}}},
		{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: 1 << 60}}},
		{Body: &hubv1.HubMessage_HeadNotice{HeadNotice: &hubv1.HeadNotice{Seq: 0}}},
		{Body: &hubv1.HubMessage_FreeDnsOff{FreeDnsOff: &hubv1.FreeDnsOff{Version: 0}}},
		{Body: &hubv1.HubMessage_Revocation{Revocation: &policyv1.Revocation{RevSeq: 0}}},
		{Body: &hubv1.HubMessage_Revocation{Revocation: &policyv1.Revocation{RevSeq: 1, Kind: 99, Ids: [][]byte{{1}}}}},
	} {
		if err := s.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	// a ServerTime whose callback panics: the loop lives and the next message is read
	_ = sendST(s)
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_HeadNotice{HeadNotice: &hubv1.HeadNotice{Seq: 3}}})
	eventually(t, "the HeadNotice after the panic", func() bool { return r.heads.Load() == 1 })
	st := r.c.Stats()
	if r.offs.Load() != 0 || cfgs.Load() != 0 {
		t.Errorf("a hostile message reached a callback: offs=%d cfgs=%d", r.offs.Load(), cfgs.Load())
	}
	if st.Ignored < 7 {
		t.Errorf("ignored = %d", st.Ignored)
	}
	if st.Streams != 1 {
		t.Errorf("the stream was cut by a message the node can ignore (%d streams)", st.Streams)
	}
	// An oversized message (over the gRPC limit) ends the stream. The node opens
	// another and goes on.
	big := &hubv1.NodeConfig{ProofKey: make([]byte, 5<<20)}
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: big}})
	s2, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal("no new stream after an oversized message")
	}
	_ = sendST(s2)
	eventually(t, "the node serves on", func() bool { return r.serverTimes.Load() >= 2 })
	if cfgs.Load() != 0 {
		t.Error("the oversized NodeConfig was delivered")
	}
}

// p4n-W5b-r6-2: a report whose Send fails is not lost with the stream; the next stream
// carries it. An outside message in the same position is best effort and is dropped.
func TestReportWhoseSendFailedGoesOutOnTheNextStream(t *testing.T) {
	var held atomic.Int32
	r := newRig(t, func(cfg *Config, _ *rig) {
		cfg.SendTimeout = 100 * time.Millisecond
		cfg.Trace = func(m *hubv1.NodeMessage) {
			// The first write of the report outlasts SendTimeout, so the stream is
			// cancelled before Send runs and Send fails.
			if m.GetApplyResult().GetSeq() == 42 && held.Add(1) == 1 {
				time.Sleep(400 * time.Millisecond)
			}
		}
	})
	r.start()
	s, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := sendST(s); err != nil {
		t.Fatal(err)
	}
	r.c.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ApplyResult{ApplyResult: &hubv1.ApplyResult{Seq: 42, Ok: true}}})
	s2, err := r.hub.NextSession(5 * time.Second)
	if err != nil {
		t.Fatal("the stream was not reopened after the failed Send")
	}
	if err := sendST(s2); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Wait(3*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetApplyResult().GetSeq() == 42 }); err != nil {
		t.Fatalf("the report popped when the stream broke was lost: %v", err)
	}
	if got := r.c.snd.reports.len(); got != 0 {
		t.Errorf("%d reports left queued", got)
	}
}

func TestUnsentKeepsReportsAndDropsOutsideMessages(t *testing.T) {
	s := newSender(time.Now)
	s.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_RevocationAck{RevocationAck: &hubv1.RevocationAck{RevSeq: 1}}})
	s.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_RevocationAck{RevocationAck: &hubv1.RevocationAck{RevSeq: 2}}})
	m, _ := s.next()
	s.unsent(m)
	if got, _ := s.next(); got != m {
		t.Fatalf("the report taken back is not the next one: %v", got)
	}
	s.Outside(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{Label: "a"}}})
	m, _ = s.next() // the second ack
	m, _ = s.next() // the outside message
	s.unsent(m)
	if s.reports.len() != 0 {
		t.Error("an outside message went back to the reports queue")
	}
}

// A BlockKeyRequest is a message a visitor of a block page can cause, so it goes
// through the outside queue and the same Endpoint is not asked for twice in 60 s.
func TestOutsideTakesABlockKeyRequestOncePerEndpoint(t *testing.T) {
	now := time.Now()
	s := newSender(func() time.Time { return now })
	mk := func(b byte) *hubv1.NodeMessage {
		return &hubv1.NodeMessage{Body: &hubv1.NodeMessage_BlockKeyRequest{BlockKeyRequest: &hubv1.BlockKeyRequest{EndpointId: bytes.Repeat([]byte{b}, 16)}}}
	}
	if !s.Outside(mk(1)) {
		t.Fatal("the first request was refused")
	}
	if s.Outside(mk(1)) {
		t.Fatal("the same Endpoint was queued again inside the window")
	}
	if !s.Outside(mk(2)) {
		t.Fatal("another Endpoint was refused")
	}
	now = now.Add(OutsideDedupe + time.Second)
	if !s.Outside(mk(1)) {
		t.Fatal("the Endpoint stays refused after the window")
	}
}
