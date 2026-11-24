package control

import (
	"testing"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
)

// p4n-W5b-r3-10: the revocation queue is bounded by the ids it holds, not only by
// its count, so a sender of full revocations cannot make it a gigabyte of heap.
func TestRevocationQueueIsBoundedByIDs(t *testing.T) {
	q := newRevQueue()
	mk := func(n int) *policyv1.Revocation {
		r := &policyv1.Revocation{RevSeq: 1}
		for i := 0; i < n; i++ {
			r.Ids = append(r.Ids, make([]byte, 16))
		}
		return r
	}
	accepted := 0
	for i := 0; i < 100; i++ { // 100 revocations of 100,000 ids: 10 million offered
		if !q.push(mk(100_000)) {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("accepted %d revocations of 100,000 ids, want 1 under a bound of %d", accepted, maxRevocationQueueIDs)
	}
	if q.dropped.Load() != 99 {
		t.Errorf("dropped = %d", q.dropped.Load())
	}
	// Once the worker has taken it, room is back.
	if _, ok := q.pop(); !ok {
		t.Fatal("empty")
	}
	if q.push(mk(10)) {
		t.Error("a small revocation was refused with the queue empty")
	}
	// many small ones still queue up to the count bound
	q2 := newRevQueue()
	n := 0
	for i := 0; i < 300; i++ {
		if !q2.push(mk(1)) {
			n++
		}
	}
	if n != 256 {
		t.Errorf("small revocations accepted = %d, want the count bound 256", n)
	}
}
