package dns

import (
	"errors"
	"hash/fnv"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// NameText is the presentation form of a name without the trailing dot.
func NameText(n names.Name) string { return n.String() }

// claimEntry is one claim in the prefix table. lastValidated is the Unix second
// of the latest query on this node that proved its source (TCP, or UDP with a
// server cookie this node made), for the rule that an unvalidated UDP query of a
// claim nobody has validated for an hour is answered TC=1 (p4-nodes.md 7.6).
type claimEntry struct {
	image.Claim
	lastValidated atomic.Int64
}

// prefixTable finds the longest claim prefix that holds an address. It is
// rebuilt with each image (T-011). It keeps one map of prefixes and the prefix
// lengths in use for each family, longest first, so a lookup tries only lengths
// that exist; claims are /28 to /32 in practice, so a lookup is a few probes.
type prefixTable struct {
	m    map[netip.Prefix]*claimEntry
	len4 []int
	len6 []int
}

func newPrefixTable(claims []image.Claim, old *prefixTable) *prefixTable {
	t := &prefixTable{m: make(map[netip.Prefix]*claimEntry, len(claims))}
	seen4, seen6 := map[int]bool{}, map[int]bool{}
	var oldByID map[[16]byte]*claimEntry // built once: a lookup per claim must not scan the old table
	if old != nil {
		oldByID = make(map[[16]byte]*claimEntry, len(old.m))
		for _, oe := range old.m {
			oldByID[oe.ID] = oe
		}
	}
	for _, c := range claims {
		p := c.Prefix.Masked()
		if _, dup := t.m[p]; dup {
			continue // two claims on one prefix: the first by claim id keeps it
		}
		e := &claimEntry{Claim: c}
		if oe, ok := oldByID[c.ID]; ok {
			e.lastValidated.Store(oe.lastValidated.Load())
		}
		t.m[p] = e
		if p.Addr().Is4() {
			seen4[p.Bits()] = true
		} else {
			seen6[p.Bits()] = true
		}
	}
	t.len4, t.len6 = keysDesc(seen4), keysDesc(seen6)
	return t
}

func keysDesc(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func (t *prefixTable) lookup(a netip.Addr) (*claimEntry, bool) {
	a = a.Unmap()
	lens := t.len4
	if a.Is6() {
		lens = t.len6
	}
	for _, bits := range lens {
		p, err := a.Prefix(bits)
		if err != nil {
			continue
		}
		if e, ok := t.m[p]; ok {
			return e, true
		}
	}
	return nil, false
}

// epState is an Endpoint compiled for serving. It is made on the first query
// that reaches the Endpoint and kept in a bounded cache, so a node with 100,000
// Endpoints holds only the ones that are asked about.
type epState struct {
	rec        *policyv1.EndpointRecord
	degraded   bool // no usable binding: served as soft_disabled (SC 9.7 item 7)
	view       *sharedpolicy.EndpointView
	authorized []netip.Prefix
	id         [16]byte
	// transient marks a degraded state caused by a failed read of a blob, not by
	// the blob: it serves this query and is not kept (p4n-W7-r2-6).
	transient bool
}

const (
	epCacheShards = 16
	epCacheBudget = 65536 // Endpoints kept compiled, over all shards
)

type epShard struct {
	mu sync.Mutex
	l  *lru.Cache[[16]byte, *epState]
	// flight holds the compiles in progress of this shard.
	flight map[[16]byte]*epCall
}

// Serving is one image as the query path uses it: the image, its prefix table
// and the compiled Endpoints. It is immutable after NewServing except for the
// caches inside it, and the handler swaps a whole Serving in one step, so a query
// that has read one never sees half of a change.
type Serving struct {
	img      Image
	prefixes *prefixTable
	// loader opens the profiles through this image's own files (never another
	// image's), backed by the process-wide cache.
	loader policy.ProfileLoader
	eps    [epCacheShards]epShard
	// nodeIPs are the dns_ip of every node of the applied PairTable, for the hop
	// guard of SC 5.2a (b).
	nodeIPs map[netip.Addr]bool
}

// NewServing builds a Serving over img. old, when not nil, hands its claims'
// validation times over, so a swap does not make every claim look unvalidated.
func NewServing(img Image, profiles *policy.Profiles, old *Serving) *Serving {
	var op *prefixTable
	if old != nil {
		op = old.prefixes
	}
	s := &Serving{img: img, prefixes: newPrefixTable(img.Claims(), op), loader: noProfiles{}}
	if profiles != nil {
		s.loader = profiles.Bind(img.ProfilePath)
	}
	s.nodeIPs = map[netip.Addr]bool{}
	for _, n := range img.PairTable().GetNodes() {
		if a, ok := netip.AddrFromSlice(n.GetDnsIp()); ok {
			s.nodeIPs[a.Unmap()] = true
		}
	}
	for i := range s.eps {
		s.eps[i].l = lru.New[[16]byte, *epState](epCacheBudget / epCacheShards)
		s.eps[i].flight = map[[16]byte]*epCall{}
	}
	return s
}

// Image returns the image.
func (s *Serving) Image() Image { return s.img }

// endpoint returns the compiled state of an Endpoint record.
func (s *Serving) endpoint(e *image.Endpoint) *epState {
	var id [16]byte
	copy(id[:], e.Record.EndpointId)
	h := fnv.New32a()
	_, _ = h.Write(id[:])
	sh := &s.eps[h.Sum32()%epCacheShards]
	sh.mu.Lock()
	if st, ok := sh.l.Get(id); ok {
		sh.mu.Unlock()
		return st
	}
	// One compile per Endpoint at a time: a compile opens the profile blobs, and
	// every concurrent first query running its own multiplied the memory by the
	// number of queries (p4n-W7-r2-4). Waiters take the leader's state.
	if c, busy := sh.flight[id]; busy {
		sh.mu.Unlock()
		<-c.done
		return c.st
	}
	c := &epCall{done: make(chan struct{})}
	sh.flight[id] = c
	sh.mu.Unlock()
	defer func() {
		// Runs on a panic too, so a waiter is never left hanging; c.st then holds
		// the degraded state set below.
		sh.mu.Lock()
		delete(sh.flight, id)
		if c.st != nil && !c.st.transient {
			sh.l.Add(id, c.st, 1)
		}
		sh.mu.Unlock()
		close(c.done)
	}()
	c.st = &epState{rec: e.Record, id: id, degraded: true, transient: true}
	c.st = s.compile(e, id)
	return c.st
}

// epCall is a compile in flight.
type epCall struct {
	done chan struct{}
	st   *epState
}

func (s *Serving) compile(e *image.Endpoint, id [16]byte) *epState {
	st := &epState{rec: e.Record, id: id, degraded: e.Degraded}
	for _, p := range e.Record.Authorized {
		if a, ok := netip.AddrFromSlice(p.GetAddr()); ok {
			if pf, err := a.Unmap().Prefix(int(p.GetBits())); err == nil {
				st.authorized = append(st.authorized, pf)
			}
		}
	}
	if st.degraded {
		return st
	}
	v, err := policy.CompileEndpoint(e.Record, s.loader)
	if err != nil {
		st.transient = errors.Is(err, policy.ErrBlobUnreadable)
		// A blob that is missing or damaged, or a record that does not compile:
		// serve it degraded rather than guess (SC 9.7 item 7).
		st.degraded = true
		return st
	}
	st.view = v
	return st
}

type noProfiles struct{}

func (noProfiles) Profile([32]byte) (*blob.Profile, error) { return nil, policy.ErrBlobMissing }
