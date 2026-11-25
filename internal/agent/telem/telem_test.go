package telem

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) adv(d time.Duration) { c.t = c.t.Add(d) }

// start is 1,000,200 s: a multiple of 300.
func newClock() *clock { return &clock{t: time.Unix(1_000_200, 0)} }

func seqIDs() func() uint64 {
	n := uint64(0)
	return func() uint64 { n++; return n }
}

var (
	udpAns = FreeKey{commonv1.Protocol_PROTOCOL_UDP, telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, 0}
	tcpRef = FreeKey{commonv1.Protocol_PROTOCOL_TCP, telemetryv1.FreeOutcome_FREE_OUTCOME_OVER_BUDGET, 5}
)

func TestBucketsSealOnTheClockAndHoldNoName(t *testing.T) {
	c := newClock()
	f := NewFreeCounters(c.now, seqIDs())
	f.Add(udpAns, 3)
	c.adv(100 * time.Second)
	f.Add(udpAns, 4)
	f.Add(tcpRef, 1)
	if f.Next() != nil {
		t.Fatal("the bucket is still open")
	}
	c.adv(200 * time.Second) // now 300 s after the start: the bucket ended
	b := f.Next()
	if b == nil {
		t.Fatal("the sealed bucket was not offered")
	}
	if b.BucketStart != 1_000_200 || b.BucketStart%300 != 0 {
		t.Errorf("bucket_start = %d", b.BucketStart)
	}
	if len(b.Free) != 2 || len(b.Counters) != 0 {
		t.Fatalf("items: %v", b.Free)
	}
	got := map[FreeKey]uint64{}
	for _, it := range b.Free {
		got[FreeKey{it.Protocol, it.Outcome, it.Rcode}] = it.Count
	}
	if got[udpAns] != 7 || got[tcpRef] != 1 {
		t.Errorf("counts: %v", got)
	}
	if err := wire.ValidateTelemetryMessage(b, c.t.Unix()); err != nil {
		t.Errorf("the hub's door refuses the batch: %v", err)
	}
}

func TestOneBatchAtATimeAndTwoSecondGap(t *testing.T) {
	c := newClock()
	f := NewFreeCounters(c.now, seqIDs())
	for i := 0; i < 3; i++ {
		f.Add(udpAns, 1)
		c.adv(300 * time.Second)
	}
	b1 := f.Next()
	if b1 == nil || b1.BatchId != 1 {
		t.Fatalf("first: %v", b1)
	}
	if f.Next() != nil {
		t.Fatal("a second batch was offered before the Ack")
	}
	c.adv(3 * time.Second)
	if f.Next() != nil {
		t.Fatal("a second batch was offered while the first waits for its Ack")
	}
	f.Ack(1, false)
	if f.Next() != nil {
		t.Fatal("a non-durable Ack released the batch")
	}
	f.Ack(1, true)
	if n := f.Next(); n == nil || n.BatchId == 1 {
		t.Fatal("the next batch is due: acked, and the gap of 2 s has passed")
	}
}

func TestAckThenNextAfterGap(t *testing.T) {
	c := newClock()
	f := NewFreeCounters(c.now, seqIDs())
	for i := 0; i < 3; i++ {
		f.Add(udpAns, 1)
		c.adv(300 * time.Second)
	}
	b1 := f.Next()
	f.Ack(b1.BatchId, true)
	if f.Next() != nil {
		t.Fatal("the next batch went out less than 2 s after the last")
	}
	c.adv(2 * time.Second)
	b2 := f.Next()
	if b2 == nil || b2.BatchId == b1.BatchId || b2.BucketStart <= b1.BucketStart {
		t.Fatalf("second batch: %v", b2)
	}
}

func TestResendsSameBatchIDUntilAcked(t *testing.T) {
	c := newClock()
	f := NewFreeCounters(c.now, seqIDs())
	f.Add(udpAns, 1)
	c.adv(300 * time.Second)
	b := f.Next()
	c.adv(ResendAfter + time.Second)
	again := f.Next()
	if again == nil || again.BatchId != b.BatchId {
		t.Fatal("not resent with its batch_id")
	}
	f.Reset() // the stream broke
	c.adv(MinGap)
	if r := f.Next(); r == nil || r.BatchId != b.BatchId {
		t.Fatal("not resent after a reset")
	}
	f.Ack(b.BatchId, true)
	c.adv(10 * time.Second)
	if f.Next() != nil {
		t.Fatal("acked batch offered again")
	}
}

func TestQueueIsBoundedAndOldBatchesDrop(t *testing.T) {
	c := newClock()
	f := NewFreeCounters(c.now, seqIDs())
	for i := 0; i < QueueMax+20; i++ {
		f.Add(udpAns, 1)
		c.adv(300 * time.Second)
		f.Tick()
	}
	st := f.Stats()
	// 301 buckets span 25 h 5 min; anything older than 25 h is dropped too.
	if st.Queued > QueueMax || st.Dropped < 20 {
		t.Fatalf("stats: %+v", st)
	}
	b := f.Next()
	if age := c.t.Unix() - b.BucketStart; age > wire.MaxFreeAge {
		t.Errorf("offered a batch %d s old", age)
	}
	// a long silence drops everything old, and a count after it starts a fresh bucket
	c.adv(48 * time.Hour)
	f.Tick()
	if f.Stats().Queued != 0 {
		t.Errorf("old batches kept: %+v", f.Stats())
	}
}

func TestEmptyBucketsSealNothingAndBadKeysAreCounted(t *testing.T) {
	c := newClock()
	f := NewFreeCounters(c.now, seqIDs())
	c.adv(900 * time.Second)
	f.Tick()
	if f.Stats().Queued != 0 || f.Next() != nil {
		t.Fatal("an empty bucket produced a batch")
	}
	f.Add(FreeKey{commonv1.Protocol_PROTOCOL_DOT, telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, 0}, 1)
	f.Add(FreeKey{commonv1.Protocol_PROTOCOL_UDP, 0, 0}, 1)
	f.Add(FreeKey{commonv1.Protocol_PROTOCOL_UDP, 99, 0}, 1)
	f.Add(FreeKey{commonv1.Protocol_PROTOCOL_UDP, telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, 24}, 1)
	if f.Stats().Invalid != 4 {
		t.Errorf("invalid = %d", f.Stats().Invalid)
	}
}

func TestEveryKeyFitsOneBucket(t *testing.T) {
	c := newClock()
	f := NewFreeCounters(c.now, seqIDs())
	n := 0
	for _, p := range []commonv1.Protocol{commonv1.Protocol_PROTOCOL_UDP, commonv1.Protocol_PROTOCOL_TCP} {
		for o := range telemetryv1.FreeOutcome_name {
			if o == 0 {
				continue
			}
			for r := uint32(0); r <= wire.MaxFreeRCode; r++ {
				f.Add(FreeKey{p, telemetryv1.FreeOutcome(o), r}, wire.MaxFreeCount)
				f.Add(FreeKey{p, telemetryv1.FreeOutcome(o), r}, 5) // saturates, never wraps
				n++
			}
		}
	}
	if n != MaxItems {
		t.Fatalf("keys = %d, bound = %d", n, MaxItems)
	}
	c.adv(300 * time.Second)
	b := f.Next()
	if len(b.Free) != MaxItems {
		t.Fatalf("items = %d", len(b.Free))
	}
	if err := wire.ValidateTelemetryMessage(b, c.t.Unix()); err != nil {
		t.Errorf("full batch refused: %v", err)
	}
}

// ---- activity

type recs map[[16]byte]EndpointInfo

func (r recs) Lookup(eps [][16]byte) map[[16]byte]EndpointInfo {
	out := map[[16]byte]EndpointInfo{}
	for _, e := range eps {
		if i, ok := r[e]; ok {
			out[e] = i
		}
	}
	return out
}

func ep(n byte) [16]byte { var e [16]byte; e[0] = n; return e }

func hashes(labels ...string) map[[16]byte]struct{} {
	m := map[[16]byte]struct{}{}
	for _, l := range labels {
		m[identity.ClientHash(l)] = struct{}{}
	}
	return m
}

func TestActivityDedupesPerKeyAndBucket(t *testing.T) {
	c := newClock()
	a := NewActivity(recs{ep(1): {Clients: hashes("laptop"), Cap: 3}}, c.now, seqIDs())
	r := Report{EndpointID: ep(1), ClientLabel: "laptop", Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t}
	for i := 0; i < 50; i++ {
		a.Add(r)
	}
	b := a.Flush()
	if b == nil || len(b.Entries) != 1 {
		t.Fatalf("batch: %v", b)
	}
	e := b.Entries[0]
	if e.FirstSeenBucket != 1_000_200 || e.LastSeenBucket != 1_000_200 || e.ClientLabel != "laptop" {
		t.Errorf("entry: %v", e)
	}
	if err := wire.ValidateActivityBatch(b, c.t.Unix()); err != nil {
		t.Errorf("refused by the hub's door: %v", err)
	}
	// the same key in the same bucket again, a minute later: nothing
	c.adv(60 * time.Second)
	r.At = c.t
	a.Add(r)
	if b := a.Flush(); b != nil {
		t.Errorf("repeat in the same bucket was sent: %v", b)
	}
	// the next bucket: sent again
	c.adv(300 * time.Second)
	r.At = c.t
	a.Add(r)
	if b := a.Flush(); b == nil || b.Entries[0].LastSeenBucket != 1_000_500 {
		t.Errorf("next bucket: %v", b)
	}
	// a different key (protocol) in the same bucket is its own entry
	r.Protocol = commonv1.Protocol_PROTOCOL_DOT
	a.Add(r)
	if b := a.Flush(); b == nil || len(b.Entries) != 1 {
		t.Error("other protocol")
	}
}

func TestActivityClaimOrHashNeverBoth(t *testing.T) {
	c := newClock()
	a := NewActivity(recs{ep(1): {Clients: hashes("default"), Cap: 1}}, c.now, seqIDs())
	id := make([]byte, 16)
	id[0] = 9
	a.Add(Report{EndpointID: ep(1), ClientLabel: "default", ClaimID: id, Protocol: commonv1.Protocol_PROTOCOL_UDP, At: c.t})
	a.Add(Report{EndpointID: ep(1), ClientLabel: "default", SourceIPHash: id, Protocol: commonv1.Protocol_PROTOCOL_TCP, At: c.t})
	a.Add(Report{EndpointID: ep(1), ClientLabel: "default", ClaimID: id, SourceIPHash: id, Protocol: commonv1.Protocol_PROTOCOL_TCP, At: c.t})
	a.Add(Report{EndpointID: ep(1), ClientLabel: "default", Protocol: commonv1.Protocol_PROTOCOL_DOT, At: c.t})
	b := a.Flush()
	if len(b.Entries) != 3 {
		t.Fatalf("entries %d", len(b.Entries))
	}
	if _, inv := a.Dropped(); inv != 1 {
		t.Errorf("invalid = %d", inv)
	}
	if err := wire.ValidateActivityBatch(b, c.t.Unix()); err != nil {
		t.Error(err)
	}
}

func TestActivityClientCap(t *testing.T) {
	c := newClock()
	a := NewActivity(recs{ep(1): {Clients: hashes("known"), Cap: 2}, ep(2): {Clients: hashes(), Cap: 1}}, c.now, seqIDs())
	add := func(e byte, label string) {
		a.Add(Report{EndpointID: ep(e), ClientLabel: label, Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	}
	add(1, "known")
	for i := 0; i < 10; i++ {
		add(1, fmt.Sprintf("auto%d", i))
	}
	add(2, "one")
	add(2, "two")
	b := a.Flush()
	perEp := map[byte]int{}
	for _, e := range b.Entries {
		perEp[e.EndpointId[0]]++
	}
	// endpoint 1: the known label plus at most cap=2 unknown; endpoint 2: cap=1
	if perEp[1] != 3 || perEp[2] != 1 {
		t.Fatalf("entries per endpoint: %v", perEp)
	}
	if d, _ := a.Dropped(); d != 9 {
		t.Errorf("dropped = %d, want 8 labels of endpoint 1 and 1 of endpoint 2", d)
	}
	// a label that was admitted stays admitted in a later bucket
	var admitted string
	for _, e := range b.Entries {
		if e.EndpointId[0] == 2 {
			admitted = e.ClientLabel
		}
	}
	c.adv(300 * time.Second)
	add(2, admitted)
	if b := a.Flush(); b == nil || len(b.Entries) != 1 {
		t.Error("an admitted label was dropped later")
	}
}

func TestActivityUnknownEndpointAndLabelGrammar(t *testing.T) {
	c := newClock()
	a := NewActivity(recs{}, c.now, seqIDs())
	a.Add(Report{EndpointID: ep(7), ClientLabel: "x", Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	a.Add(Report{EndpointID: ep(7), ClientLabel: "Bad Label", Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	a.Add(Report{EndpointID: ep(7), ClientLabel: "", Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	a.Add(Report{EndpointID: ep(7), ClientLabel: "x", Protocol: 0, At: c.t})
	if b := a.Flush(); b != nil {
		t.Errorf("batch for an Endpoint with no record: %v", b)
	}
	d, inv := a.Dropped()
	if d != 1 || inv != 3 {
		t.Errorf("dropped %d invalid %d", d, inv)
	}
}

func TestActivityLargeWindowGoesOutOverSeveralFlushes(t *testing.T) {
	c := newClock()
	r := recs{}
	for e := byte(0); e < 20; e++ { // spread: one Endpoint holds at most MaxKeysPerEndpoint keys
		r[ep(e)] = EndpointInfo{Clients: hashes("default"), Cap: 1}
	}
	a := NewActivity(r, c.now, seqIDs())
	n := MaxBatchEntries + 10
	for i := 0; i < n; i++ {
		var h [16]byte
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		a.Add(Report{EndpointID: ep(byte(i % 20)), ClientLabel: "default", SourceIPHash: h[:], Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	}
	// The byte bound (MaxBatchBytes) is reached before the entry cap with entries this
	// small, so what matters is that every batch is within both and nothing is lost.
	got := 0
	for b := a.Flush(); b != nil; b = a.Flush() {
		if len(b.Entries) > MaxBatchEntries {
			t.Fatalf("batch of %d entries", len(b.Entries))
		}
		got += len(b.Entries)
	}
	if got != n {
		t.Errorf("entries flushed %d of %d", got, n)
	}
}

// The admission set is trimmed against the record: a label the record lists has
// its own row and stops counting, so deleting clients makes room for new labels
// without an agent restart, and the set of a deleted Endpoint goes (p4n-W5b-r2-9).
func TestActivityAdmissionSetFollowsTheRecord(t *testing.T) {
	c := newClock()
	r := recs{ep(1): {Clients: hashes("known"), Cap: 2}, ep(2): {Clients: hashes(), Cap: 1}}
	a := NewActivity(r, c.now, seqIDs())
	add := func(e byte, label string) {
		a.Add(Report{EndpointID: ep(e), ClientLabel: label, Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	}
	add(1, "auto0")
	add(1, "auto1")
	add(2, "x")
	if b := a.Flush(); b == nil || len(b.Entries) != 3 {
		t.Fatalf("first flush: %v", b)
	}
	// The hub made auto rows for both; the tenant then deleted auto0. Endpoint 2 is gone.
	r[ep(1)] = EndpointInfo{Clients: hashes("known", "auto1"), Cap: 2}
	delete(r, ep(2))
	c.adv(300 * time.Second)
	add(1, "new0")
	b := a.Flush()
	if b == nil || len(b.Entries) != 1 || b.Entries[0].ClientLabel != "new0" {
		t.Fatalf("a new label was dropped although the record has room: %v", b)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.accepted[ep(2)]; ok {
		t.Error("the set of a deleted Endpoint is still held")
	}
	if _, ok := a.accepted[ep(1)]["auto1"]; ok {
		t.Error("a label the record now lists still counts against the cap")
	}
}

// p4b-n0 (a): the record lists only clients with a profile or an analytics level, so the
// auto rows the hub made from admitted labels never show in it. Idle labels must still
// free their place, or an Endpoint's later labels are dropped until the agent restarts.
func TestActivityIdleAdmittedLabelsFreeTheirPlaces(t *testing.T) {
	c := newClock()
	r := recs{ep(1): {Clients: hashes(), Cap: 2}, ep(2): {Clients: hashes(), Cap: 2}}
	a := NewActivity(r, c.now, seqIDs())
	add := func(e byte, label string) {
		a.Add(Report{EndpointID: ep(e), ClientLabel: label, Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	}
	labels := func(b *telemetryv1.ActivityBatch, e byte) map[string]bool {
		out := map[string]bool{}
		for _, en := range b.GetEntries() {
			if en.EndpointId[0] == e {
				out[en.ClientLabel] = true
			}
		}
		return out
	}
	add(1, "a")
	add(1, "b")
	add(2, "a")
	add(2, "b")
	if b := a.Flush(); b == nil || len(b.Entries) != 4 {
		t.Fatalf("first flush: %v", b)
	}
	// Within the idle time the set is full for both Endpoints: "c" is dropped.
	c.adv(AcceptedIdle / 2)
	add(1, "a") // endpoint 1 keeps "a" alive; endpoint 2 sends nothing
	add(1, "c")
	add(2, "c")
	b := a.Flush()
	if got := labels(b, 1); !got["a"] || got["c"] {
		t.Fatalf("endpoint 1 before the idle time: %v", got)
	}
	if got := labels(b, 2); got["c"] {
		t.Fatalf("endpoint 2 admitted a third label before the idle time: %v", got)
	}
	// Past it, "a" of endpoint 1 was renewed and "b" of both Endpoints and "a" of endpoint
	// 2 have been idle for the whole time: the new label gets a place on both.
	c.adv(AcceptedIdle/2 + time.Minute)
	add(1, "c")
	add(1, "d")
	add(2, "c")
	b = a.Flush()
	if got := labels(b, 2); !got["c"] {
		t.Fatalf("endpoint 2 still holds the idle labels: %v", got)
	}
	// "a" of endpoint 1 was sent 12 hours ago, "b" 25: "c" takes b's place, "d" has none.
	if got := labels(b, 1); !got["c"] || got["d"] {
		t.Fatalf("endpoint 1 after the idle time: %v", got)
	}
}

// p4n-W5b-r3-9: a batch is bounded by its encoded size too, so one the hub may refuse
// for size is never built; what does not fit goes out in the next flushes.
func TestActivityBatchIsBoundedByBytes(t *testing.T) {
	c := newClock()
	r := recs{}
	for e := byte(0); e < 20; e++ {
		r[ep(e)] = EndpointInfo{Clients: hashes("default"), Cap: 1}
	}
	a := NewActivity(r, c.now, seqIDs())
	const n = 100_000 // about 5 MB encoded, under the entry cap
	for i := 0; i < n; i++ {
		var h [16]byte
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		a.Add(Report{EndpointID: ep(byte(i % 20)), ClientLabel: "default", SourceIPHash: h[:], Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	}
	got, batches := 0, 0
	for b := a.Flush(); b != nil; b = a.Flush() {
		batches++
		if sz := proto.Size(b); sz > MaxBatchBytes {
			t.Fatalf("batch %d is %d bytes, over %d", batches, sz, MaxBatchBytes)
		}
		got += len(b.Entries)
	}
	if batches < 2 || got != n {
		t.Errorf("batches %d, entries %d of %d", batches, got, n)
	}
}

// p4n-W5b-r5-5: client_cap holds at intake. Tenant A floods one Endpoint with random
// labels; the shared pending map does not fill, and tenant B's single label still
// reaches the batch.
func TestActivityLabelFloodOnOneEndpointCannotCrowdOutAnother(t *testing.T) {
	c := newClock()
	r := recs{ep(1): {Clients: hashes("default"), Cap: 2}, ep(2): {Clients: hashes("default"), Cap: 1}}
	a := NewActivity(r, c.now, seqIDs())
	add := func(e byte, label string) {
		a.Add(Report{EndpointID: ep(e), ClientLabel: label, Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	}
	// one flush first so the aggregator holds each record's limit
	add(1, "default")
	add(2, "default")
	if b := a.Flush(); b == nil || len(b.Entries) != 2 {
		t.Fatalf("first flush: %v", b)
	}
	c.adv(300 * time.Second)
	for i := 0; i < 50_000; i++ {
		add(1, fmt.Sprintf("flood%d", i))
	}
	a.mu.Lock()
	held := len(a.pending)
	a.mu.Unlock()
	if held > 3 {
		t.Fatalf("%d keys of one Endpoint are held although its record allows 3 labels", held)
	}
	add(2, "default")
	b := a.Flush()
	if b == nil {
		t.Fatal("no batch")
	}
	seenB := false
	for _, e := range b.Entries {
		if e.EndpointId[0] == 2 && e.ClientLabel == "default" {
			seenB = true
		}
	}
	if !seenB {
		t.Errorf("tenant B's entry did not reach the batch: %v", b.Entries)
	}
	if d, _ := a.Dropped(); d < 49_000 {
		t.Errorf("dropped %d", d)
	}
}

// p4n-W5b-r6-1 and r6-3: only labels the record lacks count against client_cap. An
// Endpoint with cap 0 and a flood of junk labels first still reports its known client.
func TestActivityKnownLabelPassesAfterJunkFlood(t *testing.T) {
	c := newClock()
	r := recs{ep(1): {Clients: hashes("default", "laptop"), Cap: 0}}
	a := NewActivity(r, c.now, seqIDs())
	add := func(label string) {
		a.Add(Report{EndpointID: ep(1), ClientLabel: label, Protocol: commonv1.Protocol_PROTOCOL_DOT, At: c.t})
	}
	add("default") // the first flush reads the record
	if b := a.Flush(); b == nil || len(b.Entries) != 1 {
		t.Fatalf("first flush: %v", b)
	}
	c.adv(300 * time.Second)
	for i := 0; i < 200; i++ {
		add(fmt.Sprintf("x%d", i))
	}
	add("laptop")
	add("default")
	b := a.Flush()
	if b == nil {
		t.Fatal("no batch")
	}
	got := map[string]bool{}
	for _, e := range b.Entries {
		got[e.ClientLabel] = true
	}
	if !got["laptop"] || !got["default"] || len(b.Entries) != 2 {
		t.Errorf("entries %v", got)
	}
}

// p4n-W5b-r6-4: one Endpoint cannot hold more than its share of keys, and when the
// shared map is full a flooder's keys make room for another tenant's first key.
func TestActivityKeyFloodOfOneTenantCannotFillTheSharedMap(t *testing.T) {
	c := newClock()
	r := recs{ep(100): {Clients: hashes("default"), Cap: 1}}
	for e := byte(1); e <= 10; e++ {
		r[ep(e)] = EndpointInfo{Clients: hashes("default"), Cap: 1}
	}
	a := NewActivity(r, c.now, seqIDs())
	a.maxKeys, a.epKeys = 1000, 100
	src := func(i int) []byte { h := make([]byte, 16); h[0], h[1] = byte(i), byte(i>>8); return h }
	// Endpoint A (ten Endpoints of one tenant) floods distinct source hashes.
	for e := byte(1); e <= 10; e++ {
		for i := 0; i < 500; i++ {
			a.Add(Report{EndpointID: ep(e), ClientLabel: "default", SourceIPHash: src(i), Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
		}
	}
	a.mu.Lock()
	held := len(a.pending)
	a.mu.Unlock()
	if held != 1000 {
		t.Fatalf("held %d, want the map full at 1000", held)
	}
	// Tenant B's first key still gets in, by evicting one of the flooder's.
	a.Add(Report{EndpointID: ep(100), ClientLabel: "default", Protocol: commonv1.Protocol_PROTOCOL_DOH, At: c.t})
	b := a.Flush()
	seenB, perEP := false, map[byte]int{}
	for _, e := range b.Entries {
		perEP[e.EndpointId[0]]++
		if e.EndpointId[0] == 100 {
			seenB = true
		}
	}
	if !seenB {
		t.Fatal("tenant B's entry did not reach the batch")
	}
	for e, n := range perEP {
		if n > 100 {
			t.Errorf("endpoint %d holds %d keys, over its cap of 100", e, n)
		}
	}
}
