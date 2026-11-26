package control

import (
	"sync"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// Outbound limits (p4-nodes 5.7, SC 8a.11 L10, D31).
const (
	// OutsideQueueMax is the queue of messages an outside party can cause:
	// ProofObservation, LearnedIP and BlockUnblockRequest.
	OutsideQueueMax = 256
	// OutsideMinGap paces them to at most 20 a second.
	OutsideMinGap = 50 * time.Millisecond
	// OutsideDedupe is the window in which a repeat of the same (label or
	// endpoint, source, protocol) is dropped.
	OutsideDedupe = 60 * time.Second
	// OutsideMaxAge is how long a queued outside message may wait. A proof
	// challenge lives ten minutes and the hub refuses an observation older than an
	// hour, so a message that waited out a long outage is of no use.
	OutsideMaxAge = 5 * time.Minute
	// ReportQueueMax is the queue of the node's own answers to the hub
	// (ApplyResult, QuarantineReport, RevocationAck, AcmeAck).
	ReportQueueMax = 1024
	maxDedupeKeys  = 4096
)

type outsideItem struct {
	m  *hubv1.NodeMessage
	at time.Time
}

// sender is the node's outbound side of one Control stream, kept across
// streams so what is queued survives a reconnect. It holds no Heartbeat: that is
// built when it is due and goes before everything else (L10).
type sender struct {
	now func() time.Time

	reports *queue[*hubv1.NodeMessage]
	outside *queue[outsideItem]
	wake    chan struct{}

	mu       sync.Mutex
	seen     map[string]time.Time
	nextOut  time.Time
	repeats  uint64
	tooOld   uint64
	fullSeen uint64
}

func newSender(now func() time.Time) *sender {
	return &sender{
		now:     now,
		reports: newQueue[*hubv1.NodeMessage](ReportQueueMax, true),
		outside: newQueue[outsideItem](OutsideQueueMax, false),
		wake:    make(chan struct{}, 1),
		seen:    map[string]time.Time{},
	}
}

func (s *sender) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Report queues one of the node's own messages. Past ReportQueueMax the oldest
// is dropped: applied_seq is also in every Heartbeat, so a lost ApplyResult costs
// the hub its timing only.
func (s *sender) Report(m *hubv1.NodeMessage) {
	s.reports.push(m)
	s.poke()
}

// outsideKey names what makes two messages "the same" for the 60 s rule.
func outsideKey(m *hubv1.NodeMessage) string {
	switch b := m.Body.(type) {
	case *hubv1.NodeMessage_ProofObservation:
		p := b.ProofObservation
		return "p|" + p.Label + "|" + string(p.SourceIp) + "|" + p.Protocol.String()
	case *hubv1.NodeMessage_LearnedIp:
		l := b.LearnedIp
		return "l|" + string(l.EndpointId) + "|" + string(l.SourceIp) + "|" + l.Protocol.String()
	case *hubv1.NodeMessage_BlockUnblockRequest:
		r := b.BlockUnblockRequest
		return "b|" + string(r.EndpointId) + "|" + string(r.QnameWire)
	}
	return ""
}

// Outside queues a message an outside party can cause. It reports false when the
// message is not of those kinds, is a repeat inside the window, or finds the queue
// full; the three are counted apart and none is an error.
func (s *sender) Outside(m *hubv1.NodeMessage) bool {
	k := outsideKey(m)
	if k == "" {
		return false
	}
	now := s.now()
	s.mu.Lock()
	if t, ok := s.seen[k]; ok && now.Sub(t) < OutsideDedupe {
		s.repeats++
		s.mu.Unlock()
		return false
	}
	if len(s.seen) >= maxDedupeKeys {
		for kk, t := range s.seen {
			if now.Sub(t) >= OutsideDedupe {
				delete(s.seen, kk)
			}
		}
		if len(s.seen) >= maxDedupeKeys {
			s.fullSeen++
			s.mu.Unlock()
			return false
		}
	}
	s.mu.Unlock()
	if s.outside.push(outsideItem{m: m, at: now}) {
		return false
	}
	// Recorded only once it is in: a message the full queue refused may come again.
	s.mu.Lock()
	s.seen[k] = now
	s.mu.Unlock()
	s.poke()
	return true
}

// next picks what to write now, besides a due Heartbeat: first the node's own
// reports, then one outside message if the pacing allows. wait is how long until
// an outside message could go, 0 when there is nothing queued.
func (s *sender) next() (m *hubv1.NodeMessage, wait time.Duration) {
	if r, ok := s.reports.pop(); ok {
		return r, 0
	}
	now := s.now()
	s.mu.Lock()
	gap := s.nextOut.Sub(now)
	s.mu.Unlock()
	if gap > 0 && s.outside.len() > 0 {
		return nil, gap
	}
	for {
		it, ok := s.outside.pop()
		if !ok {
			return nil, 0
		}
		if now.Sub(it.at) > OutsideMaxAge {
			s.mu.Lock()
			s.tooOld++
			s.mu.Unlock()
			continue
		}
		s.mu.Lock()
		s.nextOut = now.Add(OutsideMinGap)
		s.mu.Unlock()
		return it.m, 0
	}
}

// unsent takes back a message that next returned and whose Send failed. The node's own
// reports go back to the head of their queue, so the next stream carries them: a
// QuarantineReport or a RevocationAck is not repeated by anything else. A message an
// outside party can cause is best effort and is dropped, as when it ages out.
func (s *sender) unsent(m *hubv1.NodeMessage) {
	if outsideKey(m) != "" {
		return
	}
	s.reports.pushFront(m)
}
