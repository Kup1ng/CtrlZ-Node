package blockpage

import (
	"context"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
)

type pageWait struct {
	done chan struct{}
	page *Page // nil when the agent had none
}

// pageCache is the LRU of pages by hash (10.2). A miss asks the agent once for the
// hash, at the rates of 12, and the connections that want the same hash wait on
// that one ask; none waits longer than PageWait, and a connection that gives up
// serves our own page, never anything of a tenant's.
type pageCache struct {
	mu       sync.Mutex
	lru      *lru.Cache[[32]byte, *Page]
	none     map[[32]byte]time.Time // hashes the agent had no page for, until
	inflight map[[32]byte]*pageWait
	acct     *accountBuckets
	node     *bucket
	// ask sends need_page; false when the agent is not connected.
	ask func(hash []byte) bool
	now func() time.Time
}

func newPageCache(ask func(hash []byte) bool, now func() time.Time) *pageCache {
	return &pageCache{lru: lru.New[[32]byte, *Page](PageCacheBytes), none: map[[32]byte]time.Time{},
		inflight: map[[32]byte]*pageWait{}, ask: ask, now: now,
		acct: newAccountBuckets(pageAskAccountRate, pageAskAccountRate, MaxKeys),
		node: newBucket(pageAskNodeRate, pageAskNodeRate, now())}
}

// get returns the page for hash, or the default page. It never returns nil.
func (c *pageCache) get(ctx context.Context, account []byte, hash []byte) *Page {
	if len(hash) != 32 {
		return defaultPage
	}
	var h [32]byte
	copy(h[:], hash)
	now := c.now()
	c.mu.Lock()
	if p, ok := c.lru.Get(h); ok {
		c.mu.Unlock()
		return p
	}
	if until, ok := c.none[h]; ok {
		if now.Before(until) {
			c.mu.Unlock()
			return defaultPage
		}
		delete(c.none, h)
	}
	w := c.inflight[h]
	if w == nil {
		var acct [16]byte
		copy(acct[:], account)
		// The account bucket is spent first so that one account's flood of hashes
		// cannot use up the node's share.
		if !c.acct.allow(acct, now) || !c.node.allow(now) {
			c.mu.Unlock()
			return defaultPage
		}
		w = &pageWait{done: make(chan struct{})}
		c.inflight[h] = w
		c.mu.Unlock()
		if !c.ask(hash) {
			c.finish(h, nil, false)
			return defaultPage
		}
	} else {
		c.mu.Unlock()
	}
	t := time.NewTimer(PageWait)
	defer t.Stop()
	select {
	case <-w.done:
	case <-t.C:
		c.abandon(h, w)
		return defaultPage
	case <-ctx.Done():
		return defaultPage
	}
	c.mu.Lock()
	p := w.page
	c.mu.Unlock()
	if p == nil {
		return defaultPage
	}
	return p
}

// deliver takes the agent's answer to need_page. An empty or invalid blob is
// remembered for NoPageTTL.
func (c *pageCache) deliver(hash, blob []byte) {
	if len(hash) != 32 {
		return
	}
	var h [32]byte
	copy(h[:], hash)
	var p *Page
	if len(blob) > 0 {
		p, _ = ParsePage(blob)
	}
	c.finish(h, p, true)
}

// finish ends an ask. cache is false for an ask that was never sent.
func (c *pageCache) finish(h [32]byte, p *Page, cache bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.inflight[h]
	if w == nil {
		return // an answer nobody asked for is dropped
	}
	delete(c.inflight, h)
	w.page = p
	close(w.done)
	if !cache {
		return
	}
	if p != nil {
		c.lru.Add(h, p, p.cost())
		return
	}
	if len(c.none) >= 1024 {
		c.none = map[[32]byte]time.Time{}
	}
	c.none[h] = c.now().Add(NoPageTTL)
}

// abandon forgets an ask the agent did not answer in time, so that the next
// connection for the hash asks again (still at the rates of 12) instead of
// waiting on an answer that is not coming.
func (c *pageCache) abandon(h [32]byte, w *pageWait) {
	c.mu.Lock()
	if c.inflight[h] == w {
		delete(c.inflight, h)
		w.page = nil
		close(w.done)
	}
	c.mu.Unlock()
}
