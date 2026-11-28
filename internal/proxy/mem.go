package proxy

import (
	"context"
	"net"
	"sort"
	"time"
)

// The sweeper: the three things that look at connections from outside (5.4). Every
// second the socket memory of the unit and of both slots; every 10 s the bytes each
// connection has moved, which ends an idle splice (10 min) and one that reached the
// age cap (24 h), and says which connections to close when memory is over.

const (
	sampleEvery = 10 * time.Second
	trimMax     = 500
)

func (p *Proxy) sweepLoop(ctx context.Context) {
	tick := time.NewTicker(p.o.Sweep)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			p.memCheck()
			if now.Sub(last) >= sampleEvery {
				last = now
				p.samplePass(now)
			}
		}
	}
}

// snapshot is the connections that have a verdict, which are the ones that splice.
func (p *Proxy) snapshot() []*conn {
	p.mu.Lock()
	all := make([]*conn, 0, len(p.conns))
	for _, c := range p.conns {
		all = append(all, c)
	}
	p.mu.Unlock()
	out := all[:0]
	for _, c := range all {
		if c.held() {
			out = append(out, c)
		}
	}
	return out
}

// far is the socket on the other side of the client: the SOCKS leg or the block
// process's.
func (cn *conn) far() net.Conn {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	if cn.target != nil {
		return cn.target
	}
	return cn.serve
}

// samplePass reads the byte counters once for every connection.
func (p *Proxy) samplePass(now time.Time) {
	sw := p.sweepConfig()
	if sw == nil || p.o.Sys == nil {
		return
	}
	idle, maxAge := sw.idle, sw.maxAge
	for _, cn := range p.snapshot() {
		if now.Sub(cn.opened) >= maxAge {
			p.count(rAge)
			cn.kill()
			continue
		}
		far := cn.far()
		if far == nil {
			continue
		}
		cl, ok1 := p.o.Sys.Moved(cn.c)
		fr, ok2 := p.o.Sys.Moved(far)
		if !ok1 {
			continue
		}
		if !ok2 {
			// The block process is on a unix socket and has no TCP_INFO: the client
			// socket alone says whether the connection moves, or a silent kind 2
			// connection would live to the age cap.
			fr = 0
		}
		cn.sampMu.Lock()
		cn.delta = cl - cn.prevClient
		cn.prevClient = cl
		if total := cl + fr; total != cn.lastTotal {
			cn.lastTotal, cn.lastMove = total, now
		}
		stale := now.Sub(cn.lastMove) >= idle
		cn.sampMu.Unlock()
		if stale {
			p.count(rIdle)
			cn.kill()
		}
	}
}

// memCheck closes stalled connections while socket memory is over its value of 12:
// of those with bytes waiting on either socket, the ones whose client socket moved
// the fewest bytes in the last 10 s, up to 500 a pass. A peer that stops reading
// fills the buffers, so stalled readers go first and no reader gets a unit killed.
func (p *Proxy) memCheck() {
	sw := p.sweepConfig()
	if sw == nil || p.o.Sys == nil {
		return
	}
	over := false
	if p.o.MemUnit != "" {
		if v, err := p.o.Sys.SockMem(p.o.MemUnit); err == nil && v > sw.memUnit {
			over = true
		}
	}
	var slots uint64
	for _, f := range p.o.MemSlots {
		if v, err := p.o.Sys.SockMem(f); err == nil {
			slots += v
		}
	}
	if slots > sw.memSlots {
		over = true
	}
	if over {
		p.trim(trimMax)
	}
}

func (p *Proxy) trim(n int) {
	type cand struct {
		c     *conn
		delta uint64
	}
	var cs []cand
	for _, cn := range p.snapshot() {
		far := cn.far()
		if far == nil {
			continue
		}
		a, ok1 := p.o.Sys.Waiting(cn.c)
		b, ok2 := p.o.Sys.Waiting(far)
		if !(ok1 && a > 0) && !(ok2 && b > 0) {
			continue
		}
		cn.sampMu.Lock()
		cs = append(cs, cand{cn, cn.delta})
		cn.sampMu.Unlock()
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].delta < cs[j].delta })
	if len(cs) > n {
		cs = cs[:n]
	}
	for _, c := range cs {
		p.count(rMem)
		c.c.kill()
	}
}
