package agent_test

import (
	"context"
	"sync"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// A node that is new while the hub has pruned its log below the oldest kept
// snapshot cannot be served by FetchEntries at all (the first entry the hub has is
// above applied_seq+1). It must ask for a snapshot, apply it, and then follow the
// log from the snapshot's seq (p4-nodes 6.5). Before the fix the agent retried
// FetchEntries for ever and served nothing.
func TestNewNodeBehindPrunedLogTakesASnapshot(t *testing.T) {
	l := newLab(t)
	a, b := storetest.Blob(t, "a.example.com"), storetest.Blob(t, "b.example.com")
	l.addEntry([][]byte{a}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, a)}, PairTable: storetest.Table(3, 0)})
	l.addEntry(nil, &policyv1.ConfigEntry{FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 40, Version: 2}})
	snap := &signv1.Snapshot{Seq: l.chain.Seq, EntryHash: append([]byte(nil), l.chain.Head[:]...),
		Blobs:     []*policyv1.BlobRef{storetest.Ref(a)},
		Endpoints: []*policyv1.EndpointRecord{storetest.Endpoint(1, a)}, PairTable: storetest.Table(3, 0),
		FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 40, Version: 2}}
	raw, err := proto.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	// The hub prunes entries 1 and 2 and keeps the snapshot of seq 2.
	l.hub.Script(func(h *fakehub.Hub) { h.Entries = nil; h.Snapshot = raw })
	l.addEntry([][]byte{b}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{storetest.Endpoint(2, b)}})

	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(3))
	eventually(t, "applied_seq 3 through the snapshot", func() bool { return lastHB(s).AppliedSeq == 3 })
	l.waitDNS("an image at dns", func() bool { return l.lastDNS(sock.TypeImage) != nil })
	if n := l.alerts.Count(alert.ChainMismatch); n != 0 {
		t.Errorf("chain mismatch alerts: %d", n)
	}
}

// While a node catches up and the head keeps moving, the chain plan is extended
// from its last hash. It is not rebuilt from the applied seq, which would fetch
// every remaining entry again at each new head.
func TestNewHeadExtendsThePlan(t *testing.T) {
	const total, firstHead = 12, 6
	var (
		mu       sync.Mutex
		afters   []uint64
		raisedAt = -1
		reached  = make(chan struct{})
		release  = make(chan struct{})
	)
	l := newLab(t, func(l *lab) { l.cfg.FetchBatch = 1 })
	hashes := map[uint64][32]byte{}
	for i := 1; i <= total; i++ {
		l.addEntry(nil, &policyv1.ConfigEntry{FreeDns: &policyv1.FreeDns{Enabled: true, Qps: 40, Version: uint64(i)}})
		hashes[l.chain.Seq] = l.chain.Head
	}
	l.hub.Script(func(h *fakehub.Hub) { h.Head = signHead(t, l.keys, firstHead, hashes[firstHead]) })
	var once sync.Once
	l.hub.Script(func(h *fakehub.Hub) {
		h.EntriesHook = func(ctx context.Context, req *hubv1.FetchEntriesRequest) error {
			mu.Lock()
			afters = append(afters, req.AfterSeq)
			n := len(afters)
			mu.Unlock()
			// The first firstHead calls hash the chain to the first head; the next one is
			// the first fetch to apply, which is where the head moves.
			if n == firstHead+1 {
				once.Do(func() {
					mu.Lock()
					raisedAt = n
					mu.Unlock()
					close(reached)
					select {
					case <-release:
					case <-ctx.Done():
					}
				})
			}
			return nil
		}
	})
	l.start()
	s := l.session()
	_ = s.Send(serverTime())
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the node never reached the apply phase")
	}
	l.hub.Script(func(h *fakehub.Hub) { h.Head = signHead(t, l.keys, total, hashes[total]) })
	_ = s.Send(headNotice(total))
	time.Sleep(300 * time.Millisecond) // the notice is memory-only inline work; give it the time to land
	close(release)
	eventuallyWithin(t, 60*time.Second, "applied_seq at the new head", func() bool { return lastHB(s).AppliedSeq == total })

	mu.Lock()
	defer mu.Unlock()
	seen := map[uint64]int{}
	for _, a := range afters[raisedAt:] {
		seen[a]++
	}
	for a := uint64(3); a <= 5; a++ {
		if seen[a] > 1 {
			t.Errorf("after=%d was requested %d times once the head had moved: the plan was rebuilt, not extended", a, seen[a])
		}
	}
}

// The id bound holds for one (rev_seq, kind) too: a hub that keeps merging new ids
// under one key cannot make the list a frame the socket refuses.
func TestRevocationIDBoundHoldsForOneKey(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	exp := time.Now().Unix() + 600
	mk := func(from, n int) *hubv1.HubMessage {
		r := &policyv1.Revocation{RevSeq: 50, Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, ExpiresAt: exp}
		for i := from; i < from+n; i++ {
			id := make([]byte, 16)
			id[0], id[1], id[2] = byte(i), byte(i>>8), byte(i>>16)
			r.Ids = append(r.Ids, id)
		}
		return &hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: r}}
	}
	_ = s.Send(mk(0, 100_000))
	_ = s.Send(mk(100_000, 500))
	eventually(t, "the overflow alert", func() bool { return l.alerts.Count(alert.RevocationOverflow) >= 1 })
	eventually(t, "the list at dns", func() bool {
		m := l.lastDNS(sock.TypeRevocations)
		return m != nil && len(m.Revocations.Items) == 1
	})
	if n := len(l.lastDNS(sock.TypeRevocations).Revocations.Items[0].IDs); n > 100_000 {
		t.Errorf("%d ids under one key", n)
	}
	// dns still has its socket after it
	if !l.dnsUp.Load() {
		t.Error("dns lost its socket")
	}
}
