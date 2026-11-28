package dnsrole

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Sink is what the query path reports to the agent: free-path counts, activity
// and the messages an outside party can cause. Everything is best effort. A
// report that cannot be sent now (the socket is down, a buffer is full) is
// dropped and counted, never held without bound and never blocking a query.
// None of it holds a query name or, for the free counts, an address.
type Sink struct {
	send func(*sock.Msg) bool

	mu       sync.Mutex
	free     map[freeKey]uint64
	activity []sock.ActivityItem
	stats    func() sock.Stats
	dropped  uint64
}

type freeKey struct {
	proto   commonv1.Protocol
	outcome telemetryv1.FreeOutcome
	rcode   uint32
}

// maxActivityBuffered bounds activity between two flushes.
const maxActivityBuffered = 100_000

func newSink(send func(*sock.Msg) bool) *Sink {
	return &Sink{send: send, free: map[freeKey]uint64{}}
}

// FreeCount counts one Plain DNS query decided by identity case 3 (SC 5.2a,
// Counters): protocol udp or tcp, the outcome and the rcode.
func (s *Sink) FreeCount(p commonv1.Protocol, o telemetryv1.FreeOutcome, rcode uint32) {
	s.mu.Lock()
	s.free[freeKey{p, o, rcode}]++
	s.mu.Unlock()
}

// Activity reports a query that passed step 4b (SC 7.6, Activity). Claim and
// sourceIPHash are 16 bytes or empty, never both set.
func (s *Sink) Activity(endpoint [16]byte, label string, claim, sourceIPHash []byte, p commonv1.Protocol, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.activity) >= maxActivityBuffered {
		s.dropped++
		return
	}
	s.activity = append(s.activity, sock.ActivityItem{Endpoint: endpoint[:], Label: label, Claim: claim, SourceIPHash: sourceIPHash, Proto: int32(p), At: at.Unix()})
}

// Proof reports a ProofObservation, LearnedIP or BlockUnblockRequest for the
// agent to relay. The agent validates it again and drops what it must.
func (s *Sink) Outbound(m *hubv1.NodeMessage) {
	b, err := proto.Marshal(m)
	if err != nil {
		return
	}
	if !s.send(&sock.Msg{Type: sock.TypeOutbound, Outbound: &sock.Outbound{NodeMessage: b}}) {
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// Send queues a message for the agent: the P4b answers (grant_res, grant_out,
// proxy_state). It never blocks and says whether the message was queued.
func (s *Sink) Send(m *sock.Msg) bool { return s.send(m) }

// SetStats gives the Sink the function that reads the Heartbeat numbers only dns
// knows (queries a second, cache hits, isolation, resolve health). It is called
// every 5 s.
func (s *Sink) SetStats(f func() sock.Stats) {
	s.mu.Lock()
	s.stats = f
	s.mu.Unlock()
}

// Dropped is how many reports were dropped.
func (s *Sink) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// run flushes every second and sends the stats every 5 s.
func (s *Sink) run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.flush()
		if n++; n%5 == 0 {
			s.mu.Lock()
			f := s.stats
			s.mu.Unlock()
			if f != nil {
				st := f()
				s.send(&sock.Msg{Type: sock.TypeStats, Stats: &st})
			}
		}
	}
}

func (s *Sink) flush() {
	s.mu.Lock()
	free, act := s.free, s.activity
	s.free, s.activity = map[freeKey]uint64{}, nil
	s.mu.Unlock()
	var items []sock.FreeCount
	for k, v := range free {
		items = append(items, sock.FreeCount{Proto: int32(k.proto), Outcome: int32(k.outcome), Rcode: k.rcode, Count: v})
		if len(items) == sock.MaxItems {
			s.sendFree(items)
			items = nil
		}
	}
	if len(items) > 0 {
		s.sendFree(items)
	}
	for len(act) > 0 {
		n := min(len(act), sock.MaxItems)
		if !s.send(&sock.Msg{Type: sock.TypeActivity, Activity: &sock.Activity{Items: act[:n]}}) {
			s.mu.Lock()
			s.dropped += uint64(len(act))
			s.mu.Unlock()
			return
		}
		act = act[n:]
	}
}

func (s *Sink) sendFree(items []sock.FreeCount) {
	if !s.send(&sock.Msg{Type: sock.TypeFreeCounts, FreeCounts: &sock.FreeCounts{Items: items}}) {
		s.mu.Lock()
		s.dropped += uint64(len(items))
		s.mu.Unlock()
	}
}

func addrOf(b []byte) (netip.Addr, bool) {
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func marshalConfig(c *hubv1.NodeConfig) ([]byte, error) { return proto.Marshal(c) }

var _ = policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT
