package control

import (
	"context"
	"sync"
	"sync/atomic"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
)

// queue is a bounded FIFO that never blocks a producer. Past its bound it drops
// the oldest item (a newer one supersedes it: a pushed table, a NodeConfig) or
// the new one (what an outside party can cause), and counts the drop. A bound
// is what keeps an overloaded or hostile peer from becoming memory.
type queue[T any] struct {
	mu         sync.Mutex
	items      []T
	cap        int
	dropOldest bool
	// weigh and maxWeight bound a queue by what its items hold as well as by their
	// count (nil weigh: count only). An item that would take the held weight over the
	// bound is dropped, which only a drop-new queue supports.
	weigh     func(T) int
	maxWeight int
	held      int
	dropped   atomic.Uint64
	wake      chan struct{}
}

func newQueue[T any](capN int, dropOldest bool) *queue[T] {
	return &queue[T]{cap: capN, dropOldest: dropOldest, wake: make(chan struct{}, 1)}
}

// push adds v and reports whether anything was dropped to make room.
func (q *queue[T]) push(v T) (dropped bool) {
	q.mu.Lock()
	w := 0
	if q.weigh != nil {
		w = q.weigh(v)
		if q.held+w > q.maxWeight {
			q.dropped.Add(1)
			q.mu.Unlock()
			return true
		}
	}
	if len(q.items) >= q.cap {
		q.dropped.Add(1)
		if !q.dropOldest {
			q.mu.Unlock()
			return true
		}
		q.items = q.items[1:]
		dropped = true
	}
	q.items = append(q.items, v)
	q.held += w
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return dropped
}

func (q *queue[T]) pop() (v T, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return v, false
	}
	v = q.items[0]
	if q.weigh != nil {
		q.held -= q.weigh(v)
	}
	q.items = q.items[1:]
	return v, true
}

// pushFront puts v back as the oldest item, for a send that failed after pop. A full
// queue drops it instead (it is the oldest, which is what a full queue drops).
func (q *queue[T]) pushFront(v T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.cap {
		q.dropped.Add(1)
		return
	}
	q.items = append([]T{v}, q.items...)
	if q.weigh != nil {
		q.held += q.weigh(v)
	}
}

func (q *queue[T]) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// run drains the queue into fn on its own goroutine until ctx ends. A panic in
// fn costs that item. Because each kind of HubMessage has a queue and a
// goroutine of its own, a stall in one (a fetch that never ends, an apply a hook
// holds) holds back that kind alone (SC 8a.11 L11).
func (q *queue[T]) run(ctx context.Context, fn func(context.Context, T)) {
	for {
		for {
			v, ok := q.pop()
			if !ok {
				break
			}
			func() {
				defer func() { _ = recover() }()
				fn(ctx, v)
			}()
			if ctx.Err() != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-q.wake:
		}
	}
}

// maxRevocationQueueIDs bounds the ids held by revocations that wait for their
// worker. One Revocation may carry 100,000 ids (wire.MaxRecordsPerEntry) and decodes
// to about 4 MiB of heap, so 256 of them by count alone would be about 1 GiB. A
// revocation dropped here is counted (Stats.RevocationsLost) and not acknowledged.
const maxRevocationQueueIDs = 200_000

func newRevQueue() *queue[*policyv1.Revocation] {
	q := newQueue[*policyv1.Revocation](256, false)
	q.weigh = func(r *policyv1.Revocation) int { return len(r.GetIds()) + 1 }
	q.maxWeight = maxRevocationQueueIDs
	return q
}
