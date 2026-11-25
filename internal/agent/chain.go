package agent

import (
	"context"
	"errors"
	"fmt"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
)

// Why this file exists (SC 9.6, 9.7 item 1): a stored entry carries no signature of
// its own. What the policy key signs is the head, (seq, entry_hash), and the hash
// chain over the stored bytes is what ties every entry to it. So an entry the hub
// serves is applied only when the chain from the node's applied state through that
// entry reaches the signed head the node has verified: a log entry put into the
// hub's view by a party that lacks the policy key would end in another hash.
//
// The chain is checked before anything is applied. The hashes of every entry up to
// the head are computed once (chainPlan) and each batch the node applies is held
// against them, so bytes the hub serves differently the second time are caught
// too.

// maxPlanEntries bounds the hashes one plan keeps (32 bytes each). A node further
// behind than this applies nothing until it has a snapshot; it is not a state a
// healthy log keeps a node in.
const maxPlanEntries = 1 << 20

var errTooFarBehind = errors.New("agent: the node is too far behind the signed head to verify the chain")

// signedHead is a head the agent has verified against the root.
type signedHead struct {
	seq  uint64
	hash [32]byte
}

// chainPlan holds the entry hashes from the applied state to a signed head.
type chainPlan struct {
	start     uint64
	startHash [32]byte
	head      signedHead
	hashes    [][32]byte // hashes[i] is the hash of the entry with seq start+1+i
}

// hashAt returns the chain hash after seq (start..head.seq).
func (p *chainPlan) hashAt(seq uint64) ([32]byte, bool) {
	switch {
	case seq == p.start:
		return p.startHash, true
	case seq > p.start && seq <= p.head.seq && seq-p.start <= uint64(len(p.hashes)):
		return p.hashes[seq-p.start-1], true
	}
	return [32]byte{}, false
}

// appliedHash is the entry hash of the node's applied seq (the zero hash before the
// first entry).
func (a *Agent) appliedHash() (h [32]byte) {
	a.app.Inspect(func(ap *store.Applied) { h = ap.Q.Head })
	return h
}

// learnHead returns the latest verified head, asking the hub for a fresh one when
// there is none yet or a HeadNotice named a seq above it. The notice is not trusted:
// it only says that it is worth asking. Only the first head of a run feeds the
// free-path facts, as before (SC 5.2a (c)).
func (a *Agent) learnHead(ctx context.Context) (signedHead, error) {
	if h := a.vhead; a.headLearned() && a.highHead.Load() <= h.seq {
		return h, nil
	}
	seq, hash, err := a.xfer.Head(ctx)
	if err != nil {
		return signedHead{}, err
	}
	if !a.headLearned() {
		a.facts.LearnHead(seq)
		a.raiseHead(seq)
		a.markHeadLearned()
	}
	// A head never goes back within a run: an older one is a hub that lags or one
	// that replays, and the entries beyond it are simply not covered yet.
	if seq >= a.vhead.seq {
		a.vhead = signedHead{seq: seq, hash: hash}
	}
	return a.vhead, nil
}

// hashRange fetches the entries after `from` up to `to` and returns their chain
// hashes, starting at fromHash, keeping none of the bytes. keep, when set, is the
// first batch, returned so the caller can apply it without fetching it again.
func (a *Agent) hashRange(ctx context.Context, from uint64, fromHash [32]byte, to uint64, keepFirst bool) (hashes [][32]byte, first []apply.Stored, err error) {
	if to-from > maxPlanEntries {
		return nil, nil, errTooFarBehind
	}
	prev := fromHash
	seq := from
	for seq < to {
		limit := uint32(min(to-seq, uint64(a.xfer.Batch())))
		batch, err := a.xfer.FetchEntries(ctx, seq, limit)
		if err != nil {
			return nil, nil, err
		}
		if len(batch) == 0 {
			return nil, nil, errNoEntries
		}
		if keepFirst && first == nil {
			first = batch
		}
		for _, e := range batch {
			prev = wire.EntryHash(prev, e.Bytes)
			hashes = append(hashes, prev)
			seq = e.Seq
		}
	}
	return hashes, first, nil
}

// mismatch reports a chain that does not reach the signed head.
func (a *Agent) mismatch() error {
	a.al.Alert(alert.Alert{Code: alert.ChainMismatch, Detail: "the entries the hub serves do not reach its signed head"})
	return errors.New("agent: the entries do not chain to the signed head")
}

// planFor makes sure a.plan covers the node's applied state up to head, building it
// when it does not. built is the first batch fetched while building it, for the
// caller to apply; nil when the plan already existed.
func (a *Agent) planFor(ctx context.Context, applied uint64, head signedHead) (built []apply.Stored, err error) {
	if p := a.plan; p != nil && p.head == head && applied >= p.start && applied <= head.seq {
		if h, ok := p.hashAt(applied); ok && h == a.appliedHash() {
			return nil, nil
		}
	}
	// A newer head that extends the plan costs only the entries between the two
	// heads: a node that catches up while the log moves would otherwise fetch the
	// whole remaining range again at every notice. The plan is cut to start at the
	// applied state first, so it never holds more than the node still has to apply.
	if p := a.plan; p != nil && head.seq > p.head.seq && applied >= p.start && applied <= p.head.seq {
		if h, ok := p.hashAt(applied); ok && h == a.appliedHash() {
			more, _, err := a.hashRange(ctx, p.head.seq, p.head.hash, head.seq, false)
			if err != nil {
				return nil, err
			}
			if len(more) == 0 || more[len(more)-1] != head.hash {
				a.plan = nil
				return nil, a.mismatch()
			}
			kept := p.hashes[applied-p.start:]
			if len(kept)+len(more) > maxPlanEntries {
				a.plan = nil
				return nil, errTooFarBehind
			}
			a.plan = &chainPlan{start: applied, startHash: h, head: head, hashes: append(append([][32]byte(nil), kept...), more...)}
			return nil, nil
		}
	}
	a.plan = nil
	start := a.appliedHash()
	hashes, first, err := a.hashRange(ctx, applied, start, head.seq, true)
	if err != nil {
		return nil, err
	}
	if len(hashes) == 0 || hashes[len(hashes)-1] != head.hash {
		return nil, a.mismatch()
	}
	a.plan = &chainPlan{start: applied, startHash: start, head: head, hashes: hashes}
	return first, nil
}

// checkBatch holds a batch of entries against the plan. Nothing is applied from a
// batch that fails.
func (a *Agent) checkBatch(entries []apply.Stored) error {
	p := a.plan
	if p == nil {
		return errors.New("agent: no verified chain")
	}
	for _, e := range entries {
		prev, ok := p.hashAt(e.Seq - 1)
		want, ok2 := p.hashAt(e.Seq)
		if !ok || !ok2 || wire.EntryHash(prev, e.Bytes) != want {
			return a.mismatch()
		}
	}
	return nil
}

// verifiedSnapshots is the SnapshotSource the Applier gets. A snapshot is the
// hub's word for the state at its seq, so it is held to the signed head the same
// way: not above it, and the entries from it to the head must hash to the head's
// hash. At the head's own seq its entry_hash must be the head's.
type verifiedSnapshots struct{ a *Agent }

func (v verifiedSnapshots) GetSnapshot(ctx context.Context, atLeast uint64) (*signv1.Snapshot, error) {
	a := v.a
	snap, err := a.xfer.GetSnapshot(ctx, atLeast)
	if err != nil {
		return nil, err
	}
	head, err := a.learnHead(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.EntryHash) != 32 {
		return nil, errors.New("agent: the snapshot has no entry hash")
	}
	var sh [32]byte
	copy(sh[:], snap.EntryHash)
	switch {
	case snap.Seq > head.seq:
		return nil, apply.ErrSnapshotAheadOfHead
	case snap.Seq == head.seq:
		if sh != head.hash {
			return nil, a.mismatch()
		}
	default:
		hashes, _, err := a.hashRange(ctx, snap.Seq, sh, head.seq, false)
		if err != nil {
			return nil, fmt.Errorf("agent: verify the snapshot's chain: %w", err)
		}
		if len(hashes) == 0 || hashes[len(hashes)-1] != head.hash {
			return nil, a.mismatch()
		}
	}
	return snap, nil
}

// headForApply is Config.Head of the Applier: the verified head, which the
// snapshot source above has already used, so the Applier's own check costs no
// second GetHead.
func (a *Agent) headForApply(ctx context.Context) (uint64, [32]byte, error) {
	h, err := a.learnHead(ctx)
	return h.seq, h.hash, err
}
