package apply

import (
	"context"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"
)

type neverFetcher struct{ calls int }

func (f *neverFetcher) Fetch([32]byte, policyv1.BlobKind, uint64) ([]byte, bool) {
	f.calls++
	return nil, false
}

// Once the fetch budget is spent the snapshot's wanted walk ends after the pass
// that spent it, instead of running a no-op pass per 256 hashes (review round 4,
// r4-2). The recorder counts what it refused: one pass is 256, the old loop was
// about the whole list.
func TestSettleWantedStopsWhenTheBudgetIsSpent(t *testing.T) {
	q := &quarantine.State{
		Wanted:    map[[32]byte]*policyv1.BlobRef{},
		Endpoints: map[[16]byte]*policyv1.EndpointRecord{}, Degraded: map[[16]byte]bool{}, Pending: map[[16]byte]*quarantine.Pending{},
	}
	for i := 0; i < 3000; i++ {
		h := [32]byte{byte(i), byte(i >> 8), 1}
		q.Wanted[h] = &policyv1.BlobRef{Hash: h[:], Size: 10, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
	}
	inner := &neverFetcher{}
	rec := newRecorder(context.Background(), nil, inner, time.Second)
	rec.failedFor = time.Second // the budget is already spent
	var rep quarantine.Report
	if !settleWanted(context.Background(), q, rec, &rep) {
		t.Fatal("panic")
	}
	if rec.refused > quarantine.MaxWantedPerRetry {
		t.Fatalf("%d fetches refused: the loop kept walking after the budget was spent", rec.refused)
	}
	if inner.calls != 0 || len(q.Wanted) != 3000 {
		t.Fatalf("calls %d wanted %d", inner.calls, len(q.Wanted))
	}
}
