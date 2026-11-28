package grant

import (
	"net/netip"
	"sync"
	"time"
)

// FwdItem is one GrantForward waiting to go to the pair node (4.5).
type FwdItem struct {
	ID      [16]byte
	Payload []byte // marshalled GrantForward
	Account [16]byte
	New     bool // a new holder goes before an account's others

	// Ref says which holder the result of the forward belongs to.
	Name     []byte
	Src      netip.Addr
	Endpoint [16]byte
	Client   [16]byte

	sentAt time.Time
}

type acctQ struct {
	news, olds []*FwdItem
}

// FwdQueue is the queue of 4.5: at most ForwardQueue items under the share rule of
// 5.4, served one account at a time in turn so that one account that floods
// forwards does not delay the first Grant of another, an account's new holders
// before its others. At most ForwardUnanswered forwards wait for an answer.
type FwdQueue struct {
	lim Limits

	mu      sync.Mutex
	pool    *pool
	accts   map[[16]byte]*acctQ
	ring    [][16]byte
	next    int
	pending map[[16]byte]*FwdItem
}

// NewFwdQueue makes a queue.
func NewFwdQueue(lim Limits) *FwdQueue {
	return &FwdQueue{lim: lim, pool: newPool(lim.ForwardQueue), accts: map[[16]byte]*acctQ{}, pending: map[[16]byte]*FwdItem{}}
}

// Offer queues an item and reports whether it found a place; a holder that finds
// none is `unsent` (4.5).
func (q *FwdQueue) Offer(it *FwdItem) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.pool.add(it.Account) {
		return false
	}
	a := q.accts[it.Account]
	if a == nil {
		a = &acctQ{}
		q.accts[it.Account] = a
		q.ring = append(q.ring, it.Account)
	}
	if it.New {
		a.news = append(a.news, it)
	} else {
		a.olds = append(a.olds, it)
	}
	return true
}

// Next takes the next item to send, or false when none waits or the unanswered
// limit is reached.
func (q *FwdQueue) Next(now time.Time) (*FwdItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) >= q.lim.ForwardUnanswered {
		return nil, false
	}
	for range q.ring {
		if q.next >= len(q.ring) {
			q.next = 0
		}
		acct := q.ring[q.next]
		a := q.accts[acct]
		var it *FwdItem
		switch {
		case len(a.news) > 0:
			it, a.news = a.news[0], a.news[1:]
		case len(a.olds) > 0:
			it, a.olds = a.olds[0], a.olds[1:]
		}
		if len(a.news)+len(a.olds) == 0 {
			delete(q.accts, acct)
			q.ring = append(q.ring[:q.next], q.ring[q.next+1:]...)
		} else {
			q.next++
		}
		if it != nil {
			q.pool.sub(it.Account)
			it.sentAt = now
			q.pending[it.ID] = it
			return it, true
		}
	}
	return nil, false
}

// Answer ends a forward that was answered and returns its item.
func (q *FwdQueue) Answer(id [16]byte) (*FwdItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	it, ok := q.pending[id]
	delete(q.pending, id)
	return it, ok
}

// Expire returns the forwards that have waited longer than d for an answer, which
// the caller takes as `unsent`; a late answer for one is dropped.
func (q *FwdQueue) Expire(now time.Time, d time.Duration) []*FwdItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []*FwdItem
	for id, it := range q.pending {
		if now.Sub(it.sentAt) > d {
			out = append(out, it)
			delete(q.pending, id)
		}
	}
	return out
}

// Len is the number of queued and unanswered items.
func (q *FwdQueue) Len() (queued, pending int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pool.total, len(q.pending)
}
