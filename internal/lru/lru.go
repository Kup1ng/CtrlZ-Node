// Package lru is a small least-recently-used map with a cost budget. It is
// not safe for concurrent use: every user (the answer cache shards, the
// verify label table, the compiled-Endpoint cache) holds its own lock, which
// lets each choose a lock granularity that fits its traffic.
//
// Cost, not count, is the budget so that one type serves both the answer
// cache (bytes) and the tables that count entries (cost 1 each).
package lru

import "container/list"

type item[K comparable, V any] struct {
	k    K
	v    V
	cost int64
}

// Cache holds entries up to a total cost.
type Cache[K comparable, V any] struct {
	budget int64
	used   int64
	ll     *list.List
	m      map[K]*list.Element
}

// New returns a Cache that evicts from the cold end once the cost of its
// entries passes budget. A budget of zero or less holds nothing.
func New[K comparable, V any](budget int64) *Cache[K, V] {
	return &Cache[K, V]{budget: budget, ll: list.New(), m: map[K]*list.Element{}}
}

// Get returns the value and marks it recently used.
func (c *Cache[K, V]) Get(k K) (v V, ok bool) {
	e, ok := c.m[k]
	if !ok {
		return v, false
	}
	c.ll.MoveToFront(e)
	return e.Value.(*item[K, V]).v, true
}

// Peek returns the value without changing its place.
func (c *Cache[K, V]) Peek(k K) (v V, ok bool) {
	e, ok := c.m[k]
	if !ok {
		return v, false
	}
	return e.Value.(*item[K, V]).v, true
}

// Add stores v under k with the given cost, replacing an older value, and
// evicts the coldest entries while the budget is exceeded. It returns how many
// entries it evicted. An entry whose own cost is above the whole budget is not
// stored.
func (c *Cache[K, V]) Add(k K, v V, cost int64) (evicted int) {
	if cost > c.budget {
		c.Remove(k)
		return 0
	}
	if e, ok := c.m[k]; ok {
		it := e.Value.(*item[K, V])
		c.used += cost - it.cost
		it.v, it.cost = v, cost
		c.ll.MoveToFront(e)
	} else {
		c.m[k] = c.ll.PushFront(&item[K, V]{k: k, v: v, cost: cost})
		c.used += cost
	}
	for c.used > c.budget {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.removeElement(back)
		evicted++
	}
	return evicted
}

// Remove deletes k.
func (c *Cache[K, V]) Remove(k K) {
	if e, ok := c.m[k]; ok {
		c.removeElement(e)
	}
}

func (c *Cache[K, V]) removeElement(e *list.Element) {
	it := e.Value.(*item[K, V])
	c.ll.Remove(e)
	delete(c.m, it.k)
	c.used -= it.cost
}

// Len is the number of entries.
func (c *Cache[K, V]) Len() int { return len(c.m) }

// Used is the total cost held.
func (c *Cache[K, V]) Used() int64 { return c.used }

// Clear drops everything.
func (c *Cache[K, V]) Clear() {
	c.ll.Init()
	c.m = map[K]*list.Element{}
	c.used = 0
}
