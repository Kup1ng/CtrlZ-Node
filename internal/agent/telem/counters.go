// Package telem holds what the agent keeps between dns and the hub for
// telemetry: the free DNS counters (CountersBatch.free, SC 5.2a Counters) and
// the activity heartbeat (ActivityBatch, SC 12, p4-nodes 7.3).
//
// Both are best effort and memory only. A restart loses what is queued, because
// a spool on disk would add writes for no promise (SC 5.2a), and neither holds a
// query name or an address: the free counts are keyed by (protocol, outcome,
// rcode), the activity entries carry an Endpoint id, a client label, a claim id
// or a prefix hash and a bucket.
package telem

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// Limits of SC 5.2a, Counters.
const (
	// QueueMax is the 25 hours and 5 minutes of 5-minute buckets the hub's validator accepts.
	QueueMax = 301
	// MinGap is the least time between two sends: at most one batch every 2 s.
	MinGap = 2 * time.Second
	// ResendAfter is how long an unacknowledged batch waits before it is sent again.
	ResendAfter = 15 * time.Second
	// MaxItems is the most items of one bucket: 2 protocols x 14 outcomes x 24 rcodes.
	MaxItems = wire.MaxFreeCounters
)

// FreeKey is the key of a free counter.
type FreeKey struct {
	Proto   commonv1.Protocol
	Outcome telemetryv1.FreeOutcome
	Rcode   uint32
}

func (k FreeKey) valid() bool {
	if k.Proto != commonv1.Protocol_PROTOCOL_UDP && k.Proto != commonv1.Protocol_PROTOCOL_TCP {
		return false
	}
	if k.Outcome == telemetryv1.FreeOutcome_FREE_OUTCOME_UNSPECIFIED {
		return false
	}
	if _, ok := telemetryv1.FreeOutcome_name[int32(k.Outcome)]; !ok {
		return false
	}
	return k.Rcode <= wire.MaxFreeRCode
}

// FreeCounters aggregates free counts into 5-minute buckets and queues sealed
// batches for the upload stream.
type FreeCounters struct {
	now   func() time.Time
	newID func() uint64
	// ResendAfter replaces the ResendAfter constant when set (tests).
	ResendAfter time.Duration

	mu       sync.Mutex
	bucket   int64 // start of the bucket in progress, 0 before the first count
	cur      map[FreeKey]uint64
	queue    []*telemetryv1.CountersBatch
	dropped  uint64
	invalid  uint64
	lastSend time.Time
	sentID   uint64 // batch_id of the batch sent and not yet acknowledged, 0 when none
	sentAt   time.Time
	haveSent bool
}

// NewFreeCounters returns an aggregator. now nil means time.Now; newID nil means
// a random 64-bit id from the system's CSPRNG (never 0).
func NewFreeCounters(now func() time.Time, newID func() uint64) *FreeCounters {
	if now == nil {
		now = time.Now
	}
	if newID == nil {
		newID = randomID
	}
	return &FreeCounters{now: now, newID: newID, cur: map[FreeKey]uint64{}}
}

func randomID() uint64 {
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("telem: no system randomness") // the node cannot run without it
		}
		if id := binary.BigEndian.Uint64(b[:]); id != 0 {
			return id
		}
	}
}

func bucketOf(t time.Time) int64 {
	s := t.Unix()
	return s - s%wire.FreeBucketSeconds
}

// Add counts n queries under key. A key outside the vocabulary is counted as
// invalid and nothing else: dns is trusted but not trusted blindly.
func (c *FreeCounters) Add(key FreeKey, n uint64) {
	if n == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !key.valid() {
		c.invalid++
		return
	}
	c.rollLocked()
	if b := bucketOf(c.now()); c.bucket == 0 {
		c.bucket = b
	}
	if _, ok := c.cur[key]; !ok && len(c.cur) >= MaxItems {
		return // unreachable: the key space is the bound
	}
	v := c.cur[key]
	if n > wire.MaxFreeCount-v {
		v = wire.MaxFreeCount
	} else {
		v += n
	}
	c.cur[key] = v
}

// Tick seals a bucket that has ended and drops what is too old. Call it every
// few seconds; Add and Next also call it.
func (c *FreeCounters) Tick() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollLocked()
}

func (c *FreeCounters) rollLocked() {
	now := c.now()
	if c.bucket != 0 && bucketOf(now) > c.bucket && len(c.cur) > 0 {
		b := &telemetryv1.CountersBatch{BatchId: c.newID(), BucketStart: c.bucket}
		for k, v := range c.cur {
			b.Free = append(b.Free, &telemetryv1.FreeCounter{Protocol: k.Proto, Outcome: k.Outcome, Rcode: k.Rcode, Count: v})
		}
		c.queue = append(c.queue, b)
		for len(c.queue) > QueueMax {
			c.dropHead()
		}
		c.cur = map[FreeKey]uint64{}
		c.bucket = 0
	} else if c.bucket != 0 && bucketOf(now) > c.bucket {
		c.bucket = 0 // an empty bucket seals nothing
	}
	for len(c.queue) > 0 && now.Unix()-c.queue[0].BucketStart > wire.MaxFreeAge {
		c.dropHead()
	}
}

func (c *FreeCounters) dropHead() {
	if c.queue[0].BatchId == c.sentID {
		c.sentID, c.haveSent = 0, false
	}
	c.queue = c.queue[1:]
	c.dropped++
}

// Next returns the batch to send now, or nil. It is the oldest queued batch, and
// only when the last send was at least MinGap ago and no batch is waiting for
// its Ack (or the wait passed ResendAfter, which is a resend of the same
// batch_id). The batch stays queued until Ack names it.
func (c *FreeCounters) Next() *telemetryv1.CountersBatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollLocked()
	if len(c.queue) == 0 {
		return nil
	}
	now := c.now()
	if !c.lastSend.IsZero() && now.Sub(c.lastSend) < MinGap {
		return nil
	}
	ra := ResendAfter
	if c.ResendAfter != 0 {
		ra = c.ResendAfter
	}
	if c.haveSent && now.Sub(c.sentAt) < ra {
		return nil
	}
	b := c.queue[0]
	c.lastSend, c.sentAt, c.sentID, c.haveSent = now, now, b.BatchId, true
	return b
}

// Ack removes the batch the hub acknowledged durably. An Ack for a batch that
// is not the one in flight, or a non-durable one, changes nothing.
func (c *FreeCounters) Ack(id uint64, durable bool) {
	if !durable {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, b := range c.queue {
		if b.BatchId == id {
			c.queue = append(c.queue[:i], c.queue[i+1:]...)
			if c.sentID == id {
				c.sentID, c.haveSent = 0, false
			}
			return
		}
	}
}

// Reset forgets that a batch is in flight, after the upload stream broke: the
// next Next resends the same batch without waiting for ResendAfter.
func (c *FreeCounters) Reset() {
	c.mu.Lock()
	c.sentID, c.haveSent = 0, false
	c.mu.Unlock()
}

// Stats are the counts of what was dropped, with no name or address.
type Stats struct {
	Queued, Dropped, Invalid uint64
}

// Stats returns the counts.
func (c *FreeCounters) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Queued: uint64(len(c.queue)), Dropped: c.dropped, Invalid: c.invalid}
}
