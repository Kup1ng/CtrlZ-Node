package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
)

// Guard keeps the table of the agent honest (p4b-proxy 5.5, "It fails closed").
//
// After an apply it records the hash of `nft -s list table inet ctrlz_agent`, the
// stateless listing, so a counter or a handle never changes it. Check reads the
// table back and compares: a missing table or a different one is not the table the
// Xray slots were promised, and the manager starts none and stops those that run.
// Heal does that comparison on a timer and applies the table again; when that
// fails the guard stays off and the fault nft_failed is raised through OnFailure.
// Another tool that flushes the rules opens at most one Heal period, in which the
// agent's final rules stand.
//
// The guard says "on" only for a table that has the proxy chains: a table of P4
// alone, which is what a node renders when it cannot name the accounts of the
// chains, would let an Xray slot reach the host.
type Guard struct {
	run sysx.Runner

	mu sync.Mutex // serialises applies and reads
	// wanted is the latest table the agent asked for, applied or not; params is the
	// one that is in the kernel, and want the hash of its read-back.
	wanted *Params
	params *Params
	want   string
	ok     bool
	failed bool
	// rejected is set when the table wanted now could not be rendered at all. What
	// is in the kernel is then an older table, so the guard stays off whatever the
	// read-back says, until an apply of a rendered table works.
	rejected bool
	onFail   func(bool)

	// changes carries the state to B5. A buffer of one that is drained before each
	// send keeps only the latest value, so a reader that is slow sees the present
	// and never a queue of old flips.
	changes chan bool

	// settled closes after the first apply attempt of this process, whatever its
	// result, or the first Reject. Until then the guard knows no table, so Check says
	// off even when the kernel still holds the intact table of the agent that ran
	// before (INT2-r2-2).
	settled     chan struct{}
	settledOnce sync.Once
}

// NewGuard returns a guard that runs nft through r.
func NewGuard(r sysx.Runner) *Guard {
	return &Guard{run: r, changes: make(chan bool, 1), settled: make(chan struct{})}
}

// readTimeout bounds one read-back; the unit has no other bound on a stuck nft.
const readTimeout = 5 * time.Second

// OnFailure sets the function called, with the guard's lock released, each time
// the failed state changes. The agent raises and clears nft_failed from it.
func (g *Guard) OnFailure(f func(failed bool)) {
	g.mu.Lock()
	g.onFail = f
	g.mu.Unlock()
}

// Apply renders and applies the table, then records its read-back hash.
func (g *Guard) Apply(ctx context.Context, p Params) error { return g.apply(ctx, p, false) }

// ApplyRejected applies p, a table the agent fell back to because the one it wanted
// cannot be used (the proxy part cannot be rendered, or nft refused it), and leaves the
// guard off and failed. It is Apply followed by Reject without the instant in between
// in which the failure would be cleared and raised again: that flip reached the fault
// set and a heartbeat built in it (B4-r2-1).
func (g *Guard) ApplyRejected(ctx context.Context, p Params) error { return g.apply(ctx, p, true) }

func (g *Guard) apply(ctx context.Context, p Params, rejected bool) error {
	defer g.settle()
	g.mu.Lock()
	prev := g.failed
	w := p
	g.wanted = &w
	g.rejected = rejected
	err := g.applyLocked(ctx, p)
	cb, failed := g.onFail, g.failed
	g.mu.Unlock()
	if cb != nil && failed != prev {
		cb(failed)
	}
	return err
}

// applyLocked applies p and keeps failed and ok in step with the result. A failed
// apply leaves the older table in place (nft applies a script whole or not at all),
// but that table is not the one that was wanted, so the guard stays off until an
// apply works.
func (g *Guard) applyLocked(ctx context.Context, p Params) error {
	if err := Apply(ctx, g.run, p); err != nil {
		g.failed = true
		g.setOK(false)
		return err
	}
	h, err := g.readHash(ctx)
	if err != nil {
		g.failed = true
		g.setOK(false)
		return errors.New("nft: the table could not be read back after the apply")
	}
	pp := p
	g.params, g.want, g.failed = &pp, h, g.rejected
	g.setOK(p.Proxy != nil && !g.rejected)
	return nil
}

// Reject tells the guard that the table the agent wants now cannot be rendered (no
// panel address, an account or an address that cannot be named): the older table in
// the kernel does not carry the new deny sets, so the guard is off and nft_failed is
// raised, as for an apply that nft refused (5.5). The next successful Apply ends it;
// Heal keeps the older table in place meanwhile but does not turn the guard on.
func (g *Guard) Reject() {
	defer g.settle()
	g.mu.Lock()
	prev := g.failed
	g.rejected, g.failed = true, true
	g.setOK(false)
	cb := g.onFail
	g.mu.Unlock()
	if cb != nil && !prev {
		cb(true)
	}
}

func (g *Guard) readHash(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	out, err := g.run.Run(ctx, nil, "nft", "-s", "list", "table", "inet", Table)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
}

// Settled is closed once the agent has made its first attempt to apply a table, or
// has said it cannot render one. The Xray manager waits on it (bounded) before it
// reads the guard at its start: a restarted agent has applied nothing yet, and a guard
// read before that says off for a table that never left the kernel, which would
// stop slots that outlived the agent.
func (g *Guard) Settled() <-chan struct{} { return g.settled }

func (g *Guard) settle() { g.settledOnce.Do(func() { close(g.settled) }) }

// Check reads the table back now and reports whether it is the one applied, with
// the proxy chains in it. It never applies.
func (g *Guard) Check() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.verifyLocked(context.Background())
}

func (g *Guard) verifyLocked(ctx context.Context) bool {
	good := g.intactLocked(ctx) && g.params.Proxy != nil && !g.rejected
	g.setOK(good)
	return good
}

// intactLocked says whether the table read back is the one that was applied. A
// table with no proxy chains (a node with no proxy address yet) is intact too: only
// Check and Changed care about the chains, and applying it again every pass would
// tear down and recreate the table every packet depends on for nothing.
func (g *Guard) intactLocked(ctx context.Context) bool {
	if g.params == nil {
		return false
	}
	h, err := g.readHash(ctx)
	return err == nil && h == g.want && (!g.failed || g.rejected)
}

// Heal is one pass of the timer: read back, and apply again when the table is
// missing or different.
func (g *Guard) Heal(ctx context.Context) {
	g.mu.Lock()
	if g.wanted == nil {
		g.mu.Unlock()
		return
	}
	prev := g.failed
	if g.intactLocked(ctx) {
		g.setOK(g.params.Proxy != nil && !g.rejected)
	} else {
		_ = g.applyLocked(ctx, *g.wanted)
	}
	cb, failed := g.onFail, g.failed
	g.mu.Unlock()
	if cb != nil && failed != prev {
		cb(failed)
	}
}

// Failed reports whether the last attempt to apply the table failed.
func (g *Guard) Failed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failed
}

// Changed delivers the guard's state each time it flips.
func (g *Guard) Changed() <-chan bool { return g.changes }

func (g *Guard) setOK(v bool) {
	if g.ok == v {
		return
	}
	g.ok = v
	select {
	case <-g.changes:
	default:
	}
	g.changes <- v
}

// Want sets the table Heal applies, without applying it: the agent calls it when a
// fallback table was refused as well, so the timer goes on trying the table that was
// wanted and not the fallback.
func (g *Guard) Want(p Params) {
	g.mu.Lock()
	w := p
	g.wanted = &w
	g.rejected = false
	g.mu.Unlock()
}
