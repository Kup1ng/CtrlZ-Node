package agent

import (
	"encoding/json"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// p4n-W5b-r4-2: the revocation worker, the log worker and the sweep all publish the
// list. Whatever order their goroutines run in, once the last change has been
// published dns must hold the list the agent holds: an older snapshot sent after a
// newer one would leave a disabled Endpoint served until the next change.
func TestConcurrentRevocationPublishesEndWithTheCurrentList(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent socket is a unix socket; the node runs on Linux")
	}
	srv, err := sock.Listen(sock.ServerConfig{Path: filepath.Join(t.TempDir(), "a.sock"), Check: func(net.Conn) error { return nil }})
	if err != nil {
		t.Skipf("no unix socket: %v", err)
	}
	t.Cleanup(srv.Close)
	for round := 0; round < 200; round++ {
		a := &Agent{srv: srv, revs: map[revKey]*policyv1.Revocation{}, lastPub: map[string]string{}}
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					k := revKey{seq: uint64(g*100 + i), kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT}
					a.mu.Lock()
					a.revs[k] = &policyv1.Revocation{RevSeq: k.seq, Kind: k.kind, Ids: [][]byte{make([]byte, 16)}}
					a.mu.Unlock()
					a.publishRevocations()
					if i%2 == 1 {
						a.mu.Lock()
						delete(a.revs, revKey{seq: uint64(g*100 + i - 1), kind: k.kind})
						a.mu.Unlock()
						a.publishRevocations()
					}
				}
			}(g)
		}
		wg.Wait()
		// what dns holds is the last message the agent sent for the slot (lastPub), and the
		// server's snapshot slot is set in the same step
		a.mu.Lock()
		held := len(a.revs)
		last := a.lastPub["revocations"]
		a.mu.Unlock()
		var m sock.Msg
		if err := json.Unmarshal([]byte(last), &m); err != nil {
			t.Fatal(err)
		}
		if got := len(m.Revocations.Items); got != held {
			t.Fatalf("round %d: the last list sent holds %d revocations, the agent holds %d", round, got, held)
		}
	}
}

// p4n-W5b-r5-7: the revocation list is bounded by keys as well as ids, so the
// snapshot dns gets on every reconnect always fits the socket's frame. 100,000 keys
// of one id each (distinct rev_seq near 2^64) used to pass the id bound and encode
// to about 10 MB.
func TestRevocationListStaysWithinTheSocketFrame(t *testing.T) {
	a := &Agent{revs: map[revKey]*policyv1.Revocation{}, al: alert.Discard{}}
	for i := 0; i < 30_000; i++ {
		id := make([]byte, 16)
		id[0], id[1], id[2] = byte(i), byte(i>>8), byte(i>>16)
		a.keepRevocation(&policyv1.Revocation{
			RevSeq: ^uint64(0) - uint64(i), Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT,
			Ids: [][]byte{id}, ExpiresAt: 1 << 60,
		})
	}
	if len(a.revs) > maxRevocationKeys {
		t.Fatalf("%d keys held, bound %d", len(a.revs), maxRevocationKeys)
	}
	b, err := json.Marshal(&sock.Msg{Type: sock.TypeRevocations, Revocations: &sock.Revocations{Items: a.revItems()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= sock.MaxFrameToDNS {
		t.Fatalf("the list encodes to %d bytes, over the frame %d", len(b), sock.MaxFrameToDNS)
	}
	// the lowest seqs go first (the oldest entry is the one most likely applied), so the
	// highest 9,000 seqs, the floor an eviction pass leaves, are all still held
	for i := 0; i < maxRevocationKeys-maxRevocationKeys/10; i++ {
		if _, ok := a.revs[revKey{^uint64(0) - uint64(i), policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT}]; !ok {
			t.Fatalf("the key %d from the top was dropped", i)
		}
	}
}

// p4n-MB-r2-4: a hub renewal that lands before the loaded revocations are rebased
// must end up at its own hub-dated expiry, whichever way the node's clock is off, and
// not at the max of two clocks shifted by the offset.
func TestRenewalOfALoadedRevocationSurvivesTheRebase(t *testing.T) {
	for _, off := range []int64{-7200, 7200} {
		a := &Agent{revs: map[revKey]*policyv1.Revocation{}, revUnsynced: map[revKey]struct{}{}, al: alert.Discard{}, lastPub: map[string]string{}}
		k := revKey{9, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT}
		const nodeNow = int64(1_000_000) // 60 s are left of the loaded one, dated by the node
		a.revs[k] = &policyv1.Revocation{RevSeq: 9, Kind: k.kind, Ids: [][]byte{make([]byte, 16)}, ExpiresAt: nodeNow + 60}
		a.revUnsynced[k] = struct{}{}
		// the first ServerTime has arrived, then the hub renews for 15 minutes in hub time
		a.hubOffset.Store(off)
		a.lastST.Store(1)
		hubRenewed := nodeNow + off + 900
		a.keepHubRevocation(&policyv1.Revocation{RevSeq: 9, Kind: k.kind, Ids: [][]byte{make([]byte, 16)}, ExpiresAt: hubRenewed})
		a.rebaseLoadedRevocations(off, true)
		if got := a.revs[k].ExpiresAt; got != hubRenewed {
			t.Fatalf("offset %d: the renewed revocation ends at %d, the hub gave %d", off, got, hubRenewed)
		}
	}
}

// p4n-MB-r2-3: whether the ServerTime had arrived is decided before the offset is
// read. A rebase that is told the ServerTime had not arrived leaves the loaded
// revocations waiting for the next publish instead of rebasing by a stale 0.
func TestRebaseWaitsWhenTheServerTimeHadNotArrivedAtTheRead(t *testing.T) {
	a := &Agent{revs: map[revKey]*policyv1.Revocation{}, revUnsynced: map[revKey]struct{}{}, lastPub: map[string]string{}}
	k := revKey{9, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT}
	a.revs[k] = &policyv1.Revocation{RevSeq: 9, Kind: k.kind, ExpiresAt: 1000}
	a.revUnsynced[k] = struct{}{}
	a.lastST.Store(1) // the ServerTime landed after the caller looked
	a.rebaseLoadedRevocations(0, false)
	if _, still := a.revUnsynced[k]; !still || a.revs[k].ExpiresAt != 1000 {
		t.Fatal("a rebase by a stale offset cleared the loaded revocations")
	}
	a.rebaseLoadedRevocations(-7200, true)
	if got := a.revs[k].ExpiresAt; got != 1000-7200 || len(a.revUnsynced) != 0 {
		t.Fatalf("the next publish rebased to %d with %d still waiting", got, len(a.revUnsynced))
	}
}
