package telem

import (
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// Limits of the activity heartbeat (p4-nodes 5.7, D31).
const (
	// ActivityEvery is how often a batch goes out.
	ActivityEvery = 60 * time.Second
	// MaxPendingKeys bounds the keys held between two flushes and the keys
	// remembered as already sent: the hub tracks at most 500,000 per node.
	MaxPendingKeys = 500_000
	// MaxBatchEntries is the hub's per-batch cap (200,000, D31); a larger window
	// goes out over several flushes.
	MaxBatchEntries = 200_000
	// MaxBatchBytes bounds a batch by its encoded size as well. 200,000 entries are 15 to
	// 20 MB, and no spec names the hub's receive cap for NodeHub, which may be gRPC's
	// default 4 MiB: a batch over it would be refused whole and requeued whole every
	// period, for good. What does not fit goes out in the next flushes.
	MaxBatchBytes = 3 << 20
	// DefaultLabelLimit is how many distinct client labels an Endpoint may hold pending
	// before a flush has told the aggregator its record's clients and client_cap. Until
	// then it cannot tell a known label from junk, so every label counts.
	DefaultLabelLimit = 1000
	// MaxKeysPerEndpoint bounds the keys one Endpoint may hold pending. A key is (label,
	// claim or source hash, protocol), so labels alone do not bound it: one tenant with
	// many clients and authorized prefixes could otherwise fill the map every tenant shares.
	MaxKeysPerEndpoint = 20_000
)

// Report is one thing dns saw: a query that passed step 4b (SC 7.6, Activity).
// It holds no name. Exactly one of ClaimID and SourceIPHash may be set, or neither.
type Report struct {
	EndpointID   [16]byte
	ClientLabel  string // "default" when the query named no client
	ClaimID      []byte // 16 bytes or empty
	SourceIPHash []byte // 16 bytes or empty
	Protocol     commonv1.Protocol
	At           time.Time
}

type key struct {
	ep       [16]byte
	label    string
	claim    string
	hash     string
	protocol commonv1.Protocol
}

type span struct{ first, last int64 }

// EndpointInfo is what the applied state says about one Endpoint.
type EndpointInfo struct {
	// Clients holds identity.ClientHash of every client of the record.
	Clients map[[16]byte]struct{}
	// Cap is the record's client_cap.
	Cap uint32
}

// Records looks up the Endpoints of a flush in one call, so a flush takes the
// applied-state lock once. An Endpoint the node holds no record of is absent
// from the result.
type Records interface {
	Lookup(eps [][16]byte) map[[16]byte]EndpointInfo
}

// Activity collects Reports and turns them into ActivityBatches.
type Activity struct {
	now   func() time.Time
	newID func() uint64
	rec   Records

	mu       sync.Mutex
	pending  map[key]span
	sent     map[key]int64 // latest bucket already sent for a key
	accepted map[[16]byte]map[string]struct{}
	// eps is the intake state per Endpoint (see Add), refreshed at every flush.
	eps     map[[16]byte]*epState
	maxKeys int    // MaxPendingKeys; a field so a test can use a small map
	epKeys  int    // MaxKeysPerEndpoint, likewise
	dropped uint64 // reports or entries dropped, counted with no name
	invalid uint64
}

// epState is what intake knows of one Endpoint.
type epState struct {
	// learned is true once a flush has read the record; clients and cap are then its
	// own. Before that every label counts, against DefaultLabelLimit.
	learned bool
	clients map[[16]byte]struct{}
	cap     uint32
	// counted holds the pending labels that count against the limit: those the record
	// lacks (every label while the record is not learned).
	counted map[string]struct{}
	keys    int // pending keys of this Endpoint
}

// isKnown reports whether the record lists label. Such a label never counts against
// client_cap (spec 7.3), so junk labels cannot crowd out a real client's activity.
func (st *epState) isKnown(label string) bool {
	if !st.learned {
		return false
	}
	_, ok := st.clients[identity.ClientHash(label)]
	return ok
}

func (st *epState) limit() int {
	if !st.learned {
		return DefaultLabelLimit
	}
	return int(st.cap)
}

// NewActivity returns an aggregator. now and newID default like NewFreeCounters.
func NewActivity(rec Records, now func() time.Time, newID func() uint64) *Activity {
	if now == nil {
		now = time.Now
	}
	if newID == nil {
		newID = randomID
	}
	return &Activity{now: now, newID: newID, rec: rec, pending: map[key]span{}, sent: map[key]int64{}, accepted: map[[16]byte]map[string]struct{}{},
		eps: map[[16]byte]*epState{}, maxKeys: MaxPendingKeys, epKeys: MaxKeysPerEndpoint}
}

// Add takes one report. It never blocks on anything but its own mutex.
func (a *Activity) Add(r Report) {
	lenOK := func(b []byte) bool { return len(b) == 0 || len(b) == 16 }
	if !names.ValidClientLabel(r.ClientLabel) || !lenOK(r.ClaimID) || !lenOK(r.SourceIPHash) ||
		len(r.ClaimID) != 0 && len(r.SourceIPHash) != 0 ||
		r.Protocol < commonv1.Protocol_PROTOCOL_UDP || r.Protocol > commonv1.Protocol_PROTOCOL_DOH3 {
		a.mu.Lock()
		a.invalid++
		a.mu.Unlock()
		return
	}
	b := bucketOf(r.At)
	k := key{ep: r.EndpointID, label: r.ClientLabel, claim: string(r.ClaimID), hash: string(r.SourceIPHash), protocol: r.Protocol}
	a.mu.Lock()
	defer a.mu.Unlock()
	if last, ok := a.sent[k]; ok && last >= b {
		return // this key and bucket went out already
	}
	if s, ok := a.pending[k]; ok {
		s.first, s.last = min(s.first, b), max(s.last, b)
		a.pending[k] = s
		return
	}
	// The shared map is bounded per Endpoint and as a whole, so a tenant that floods
	// its own Endpoints cannot push out another tenant's reports.
	st := a.eps[k.ep]
	if st == nil {
		st = &epState{counted: map[string]struct{}{}}
		a.eps[k.ep] = st
	}
	if st.keys >= a.epKeys {
		a.dropped++
		return
	}
	// client_cap at intake, not only at Flush: the map is shared by every tenant, so
	// labels over one Endpoint's cap that waited for the flush would hold places in it
	// for up to a minute. Only labels the record lacks count, so junk cannot crowd out
	// a known client; before a flush has read the record every label counts.
	known := st.isKnown(k.label)
	_, counted := st.counted[k.label]
	if !known && !counted && len(st.counted) >= st.limit() {
		a.dropped++
		return
	}
	if len(a.pending) >= a.maxKeys && !a.evictFor(k.ep, st) {
		a.dropped++
		return
	}
	if !known {
		st.counted[k.label] = struct{}{}
	}
	st.keys++
	a.pending[k] = span{first: b, last: b}
}

// evictFor makes room in the full map for a key of ep by removing one key of an
// Endpoint that holds more than its fair share. An Endpoint at or over its own
// share gets no room: it is the flooder. Caller holds a.mu.
func (a *Activity) evictFor(ep [16]byte, st *epState) bool {
	fair := a.maxKeys / max(1, len(a.eps))
	if st.keys >= fair {
		return false
	}
	// Map iteration starts at a random place, so a few probes find the big
	// Endpoints in proportion to what they hold.
	for try := 0; try < 8; try++ {
		for k := range a.pending {
			if v := a.eps[k.ep]; k.ep != ep && v != nil && v.keys > fair {
				delete(a.pending, k)
				v.keys--
				a.dropped++
				return true
			}
			break
		}
	}
	return false
}

// place puts a key back in the pending map without the intake caps: it was admitted
// once, and the caller checked the size of the map. Caller holds a.mu.
func (a *Activity) place(k key, s span) {
	st := a.eps[k.ep]
	if st == nil {
		st = &epState{counted: map[string]struct{}{}}
		a.eps[k.ep] = st
	}
	if _, ok := a.pending[k]; !ok {
		st.keys++
		if !st.isKnown(k.label) {
			st.counted[k.label] = struct{}{}
		}
	}
	a.pending[k] = s
}

// Flush builds the next batch, or nil when there is nothing to send. It asks
// Records about every Endpoint it holds a label for, which may wait behind an
// Apply, so it must not be called from a path that dns or the Control stream
// waits on.
func (a *Activity) Flush() *telemetryv1.ActivityBatch {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return nil
	}
	take := a.pending
	a.pending = map[key]span{}
	for _, st := range a.eps {
		st.keys = 0
		clear(st.counted)
	}
	eps := map[[16]byte]struct{}{}
	for k := range take {
		eps[k.ep] = struct{}{}
	}
	// The Endpoints that hold admitted labels are looked up too, so the sets can be
	// trimmed against the record (trimAccepted).
	for ep := range a.accepted {
		eps[ep] = struct{}{}
	}
	a.mu.Unlock()

	list := make([][16]byte, 0, len(eps))
	for ep := range eps {
		list = append(list, ep)
	}
	infos := a.rec.Lookup(list)
	a.trimAccepted(infos)
	a.mu.Lock()
	// What the record says now governs the next window's intake. An Endpoint with no
	// record held and nothing pending is forgotten.
	for ep, st := range a.eps {
		if info, ok := infos[ep]; ok {
			st.learned, st.clients, st.cap = true, info.Clients, info.Cap
		} else {
			st.learned, st.clients = false, nil
		}
		if st.keys == 0 && len(st.counted) == 0 && !st.learned {
			delete(a.eps, ep)
		}
	}
	for ep, info := range infos {
		if a.eps[ep] == nil {
			a.eps[ep] = &epState{learned: true, clients: info.Clients, cap: info.Cap, counted: map[string]struct{}{}}
		}
	}
	a.mu.Unlock()
	b := &telemetryv1.ActivityBatch{BatchId: a.newID()}
	rest := map[key]span{}
	var dropped uint64
	sentNow := map[key]int64{}
	size, full := 0, false
	for k, s := range take {
		if full || len(b.Entries) >= MaxBatchEntries {
			rest[k] = s
			continue
		}
		info, ok := infos[k.ep]
		if !ok {
			dropped++ // a record we do not hold: the hub would refuse the entry by the pair rule anyway
			continue
		}
		_, known := info.Clients[identity.ClientHash(k.label)]
		if !known && !a.admitUnknown(k.ep, k.label, info.Cap) {
			dropped++
			continue
		}
		e := &telemetryv1.ActivityEntry{EndpointId: k.ep[:], ClientLabel: k.label, Protocol: k.protocol,
			FirstSeenBucket: s.first, LastSeenBucket: s.last}
		if k.claim != "" {
			e.ClaimId = []byte(k.claim)
		} else if k.hash != "" {
			e.SourceIpHash = []byte(k.hash)
		}
		// 6 bytes cover the field tag and length prefix of the entry in the batch.
		es := proto.Size(e) + 6
		if size+es > MaxBatchBytes {
			full = true
			rest[k] = s
			continue
		}
		size += es
		b.Entries = append(b.Entries, e)
		sentNow[k] = s.last
	}
	a.mu.Lock()
	a.dropped += dropped
	for k, s := range rest {
		if cur, ok := a.pending[k]; ok {
			s.first, s.last = min(s.first, cur.first), max(s.last, cur.last)
		}
		a.place(k, s)
	}
	if len(a.sent)+len(sentNow) > MaxPendingKeys {
		a.sent = map[key]int64{} // only a repeat in one bucket costs a duplicate entry
	}
	for k, last := range sentNow {
		a.sent[k] = last
	}
	a.mu.Unlock()
	if len(b.Entries) == 0 {
		return nil
	}
	return b
}

// trimAccepted keeps in the admission sets only the labels the record still lacks.
// A label the record lists now has its own client row (the hub made it), so it no
// longer counts against the cap, and the set of an Endpoint that is gone is dropped.
// Without this the set only grew: after client_cap labels had ever been admitted,
// every new label was dropped until the agent restarted, although the tenant had
// deleted clients since.
func (a *Activity) trimAccepted(infos map[[16]byte]EndpointInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for ep, set := range a.accepted {
		info, ok := infos[ep]
		if !ok {
			delete(a.accepted, ep)
			continue
		}
		for label := range set {
			if _, known := info.Clients[identity.ClientHash(label)]; known {
				delete(set, label)
			}
		}
		if len(set) == 0 {
			delete(a.accepted, ep)
		}
	}
}

// admitUnknown allows at most capN distinct labels per Endpoint that its record
// lacks. A label already allowed stays allowed. The hub bounds its auto client
// rows by the same cap, so this keeps the traffic to labels from filling the
// batches, not the table.
func (a *Activity) admitUnknown(ep [16]byte, label string, capN uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	set := a.accepted[ep]
	if _, ok := set[label]; ok {
		return true
	}
	if uint32(len(set)) >= capN {
		return false
	}
	if set == nil {
		set = map[string]struct{}{}
		a.accepted[ep] = set
	}
	set[label] = struct{}{}
	return true
}

// Dropped is how many reports or entries were dropped (over the cap of labels,
// unknown Endpoint, or a full table), and Invalid how many reports were refused
// at intake.
func (a *Activity) Dropped() (dropped, invalid uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped, a.invalid
}

// Requeue puts a batch that could not be delivered back, so its entries go out
// with the next flush. Without it a failed upload would lose a bucket for good,
// because Flush already counted the entries as sent.
func (a *Activity) Requeue(b *telemetryv1.ActivityBatch) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range b.GetEntries() {
		if len(e.EndpointId) != 16 {
			continue
		}
		k := key{label: e.ClientLabel, claim: string(e.ClaimId), hash: string(e.SourceIpHash), protocol: e.Protocol}
		copy(k.ep[:], e.EndpointId)
		if a.sent[k] == e.LastSeenBucket {
			delete(a.sent, k)
		}
		s := span{first: e.FirstSeenBucket, last: e.LastSeenBucket}
		if cur, ok := a.pending[k]; ok {
			s.first, s.last = min(s.first, cur.first), max(s.last, cur.last)
		} else if len(a.pending) >= a.maxKeys {
			a.dropped++
			continue
		}
		a.place(k, s)
	}
}
