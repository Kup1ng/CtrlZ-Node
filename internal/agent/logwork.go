package agent

import (
	"context"
	"errors"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/transfer"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// maxReportsPerApply bounds the QuarantineReports one Apply sends (the hub keeps
// 60 an hour per node anyway, 5.3).
const maxReportsPerApply = 64

var errNoEntries = errors.New("agent: the hub has no entry past applied_seq")

// logLoop is the log worker: the only caller of Apply. A HeadNotice raises
// highHead and wakes it; it fetches every entry up to that seq and applies each as
// 9.7 applies any entry, so a notice that arrives while it is busy is never lost
// (L11). It also learns the head once after each start (GetHead, verified), which
// is what caught_up_once waits for (SC 5.2a (c)).
func (a *Agent) logLoop(ctx context.Context) {
	fails := 0
	poll := a.cfg.LogPoll
	if poll == 0 {
		poll = 30 * time.Second
	}
	retryEvery := a.cfg.RetryEvery
	if retryEvery == 0 {
		retryEvery = 60 * time.Second
	}
	lastRetry := a.now()
	for ctx.Err() == nil {
		progressed, err := a.syncOnce(ctx)
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			fails++
			if !sleep(ctx, transfer.Backoff(fails)) {
				return
			}
			continue
		case progressed:
			fails = 0
			continue
		}
		fails = 0
		if a.now().Sub(lastRetry) >= retryEvery {
			lastRetry = a.now()
			a.retryWanted(ctx)
		}
		t := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-a.logWake:
		case <-t.C:
		}
		t.Stop()
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// syncOnce fetches and applies one run of entries toward highHead. It reports
// whether applied_seq moved.
func (a *Agent) syncOnce(ctx context.Context) (progressed bool, err error) {
	// Only what the signed head covers is applied (chain.go): a HeadNotice that names
	// more makes the agent ask for a fresh head, and what the head does not reach yet
	// waits for the next one.
	head, err := a.learnHead(ctx)
	if err != nil {
		return false, err
	}
	applied := a.app.AppliedSeq()
	if applied >= head.seq {
		return false, nil
	}
	entries, err := a.planFor(ctx, applied, head)
	if err == nil && entries == nil {
		entries, err = a.xfer.FetchEntries(ctx, applied, uint32(min(head.seq-applied, uint64(a.xfer.Batch()))))
		if err == nil && len(entries) == 0 {
			err = errNoEntries
		}
	}
	if needsSnapshot(err) {
		// The log cannot take the node to the head: it is new, or the hub has pruned
		// below it, or it is further behind than a chain can be checked (p4-nodes 6.5).
		// The snapshot is the way across; the entries after it come the usual way.
		return a.catchUpBySnapshot(ctx, applied, head)
	}
	if err != nil {
		return false, err
	}
	if err := a.checkBatch(entries); err != nil {
		return false, err
	}
	began := a.now()
	results, aerr := a.app.ApplyEntries(ctx, entries)
	a.afterApply(results, a.now().Sub(began))
	if a.app.AppliedSeq() > applied {
		return true, nil
	}
	if aerr != nil {
		return false, aerr
	}
	return false, errNoEntries
}

// needsSnapshot reports an error that says the entry log cannot serve the node.
func needsSnapshot(err error) bool {
	return errors.Is(err, transfer.ErrLogGap) || errors.Is(err, errNoEntries) || errors.Is(err, errTooFarBehind)
}

// catchUpBySnapshot fetches a snapshot that the signed head vouches for
// (verifiedSnapshots) and applies it. Applying it moves applied_seq to the
// snapshot's, from where the next pass fetches entries again.
func (a *Agent) catchUpBySnapshot(ctx context.Context, applied uint64, head signedHead) (bool, error) {
	atLeast := applied + 1
	if head.seq > maxPlanEntries && head.seq-maxPlanEntries > atLeast {
		// A snapshot older than this could not be checked against the head either.
		atLeast = head.seq - maxPlanEntries
	}
	snap, err := verifiedSnapshots{a: a}.GetSnapshot(ctx, atLeast)
	if err != nil {
		return false, err
	}
	began := a.now()
	res := a.app.ApplySnapshot(ctx, snap)
	a.afterApply([]apply.Result{res}, a.now().Sub(began))
	if a.app.AppliedSeq() > applied {
		return true, nil
	}
	if res.Err != nil {
		return false, res.Err
	}
	return false, errors.New("agent: the snapshot was not applied")
}

func (a *Agent) headLearned() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.headOK
}

func (a *Agent) markHeadLearned() {
	a.mu.Lock()
	a.headOK = true
	a.mu.Unlock()
}

func (a *Agent) raiseHead(seq uint64) {
	for {
		cur := a.highHead.Load()
		if seq <= cur || a.highHead.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// retryWanted gives the wanted blobs another chance, which is a separate pass
// from an entry (9.7 item 2). A Retry the next entry cancels keeps what it
// fetched.
func (a *Agent) retryWanted(ctx context.Context) {
	res := a.app.Retry(ctx)
	if res.Err != nil {
		return
	}
	a.afterApply([]apply.Result{res}, 0)
}

// afterApply is what follows every Apply, Retry or snapshot: the results to the
// hub, the image to dns, the views of the state, the table and the probe targets
// to follow the membership that may have changed.
func (a *Agent) afterApply(results []apply.Result, took time.Duration) {
	var sent int
	per := uint32(0)
	if n := len(results); n > 0 {
		per = uint32(took.Milliseconds() / int64(n))
	}
	for _, r := range results {
		// The image comes first: a rebuilt image (fixImage) rides on a resend or on a refused
		// entry too, and dns must be told of it whatever else the result says.
		if r.Image != "" {
			a.publishImage(r.Image)
		}
		if r.ImageErr != nil {
			// The state is committed and dns still serves the image before it. Revocations
			// are kept until dns confirms an image, so a disabled Endpoint stays refused;
			// someone has to know the disk is failing.
			a.al.Alert(alert.Alert{Code: alert.ImagePublishFailed, Detail: "the image of the applied state could not be published; dns serves the previous one"})
		}
		if r.Skipped {
			continue
		}
		rep := r.Report
		if r.Err != nil && rep.Seq == 0 {
			continue
		}
		bad := uint32(len(rep.Quarantined) + len(rep.Failed))
		if rep.Entry != nil {
			a.al.Alert(alert.Alert{Code: alert.QuarantineTwoNodes, Detail: "an entry was refused"})
			a.ctl.Report(quarantineMsg(rep.Seq, *rep.Entry))
			a.ctl.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ApplyResult{ApplyResult: &hubv1.ApplyResult{Seq: nonzero(rep.Seq), Ok: false, ApplyMs: per}}})
			continue
		}
		if rep.Advanced {
			a.ctl.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ApplyResult{ApplyResult: &hubv1.ApplyResult{Seq: nonzero(rep.Seq), Ok: true, Quarantined: bad, ApplyMs: per}}})
		}
		for _, list := range [][]quarantine.Failure{rep.Quarantined, rep.Failed} {
			for _, f := range list {
				if sent >= maxReportsPerApply {
					break
				}
				a.ctl.Report(quarantineMsg(rep.Seq, f))
				sent++
			}
		}
	}
	a.refreshAppliedViews()
	// Revocations are not ended here. They end when dns confirms the image of the entry
	// (ImageAck, which wakes the sweep): the commit moves AppliedSeq entry by entry and
	// before the image swap, the swap can fail, and dns can fail to open the image, and in
	// each case dns still serves the old image that the revocation covers (5.5).
	a.syncProbeTargets()
	a.afterMembership()
	a.pokeTable()
}

func nonzero(s uint64) uint64 {
	if s == 0 {
		return 1
	}
	return s
}

func quarantineMsg(seq uint64, f quarantine.Failure) *hubv1.NodeMessage {
	s := f.Section
	if len(s) > 16 {
		s = s[:16]
	}
	if f.Seq != 0 {
		seq = f.Seq
	}
	return &hubv1.NodeMessage{Body: &hubv1.NodeMessage_QuarantineReport{QuarantineReport: &hubv1.QuarantineReport{
		Seq: nonzero(seq), Scope: hubv1.Scope(f.Scope), Item: f.Item, Reason: string(f.Reason), Section: s, Offset: f.Offset}}}
}

// currentImage is the name image/current points at, "" when there is none.
func (a *Agent) currentImage() string {
	n, err := image.CurrentName(a.root.Path(store.DirImage))
	if err != nil {
		return ""
	}
	return n
}
