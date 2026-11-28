package xray

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// ctlNoVerdict are the answers of a ctl that judged nothing about a fragment: no answer at
// all, a release its allow file does not name and a binary that did not run (B5 r2-4). A
// timeout and a signal are left out: they count towards a verdict when they repeat, and have
// their own tests (review6_test.go).
var ctlNoVerdict = map[string]error{
	"no answer":   errors.New("xray: ctl.sock does not answer"),
	"not allowed": &CtlError{Exit: xrayrun.CtlNotJudged, Text: "release is not allowed"},
	"not run":     &CtlError{Exit: xrayrun.CtlNoRun, Text: "the binary did not run"},
}

func (r *rig) setTestAnswer(f func() error) {
	r.ctl.mu.Lock()
	defer r.ctl.mu.Unlock()
	if f == nil {
		r.ctl.onCall = nil
		return
	}
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpTest {
			return f()
		}
		return nil
	}
}

// editedConfigRunning leaves config 1 running an edit whose good file is the older one.
func editedConfigRunning(t *testing.T, r *rig) {
	t.Helper()
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("A has a good file", func() bool { _, ok := r.good(hexID(1)); return ok })
	r.config(xc(1, 7, 1, vless("198.51.100.8")))
	r.eventually("the edit runs", func() bool {
		g, ok := r.good(hexID(1))
		x := r.runningRec(hexID(1))
		return ok && x != nil && x.Hash != g.Hash
	})
}

// B5-r2-2: two failed starts in 10 s write the config again from good/, each fragment
// tested alone first: a refusal takes it out, no verdict keeps it and the good file.
func TestStartFailRestoreIsTested(t *testing.T) {
	failTwice := func(r *rig) {
		for i := 0; i < 2; i++ {
			time.Sleep(60 * time.Millisecond)
			r.units.crash("a", "exit-code", 23)
		}
	}
	t.Run("refused", func(t *testing.T) {
		r := newRig(t, func(tm *Timing) { tm.QuietHour = 700 * time.Millisecond })
		editedConfigRunning(t, r)
		r.setTestAnswer(func() error { return &CtlError{Exit: 23, Text: "failed to load config: old spelling"} })
		failTwice(r)
		r.waitState(1, kRefused)
		r.eventually("good file gone, config out", func() bool {
			_, ok := r.good(hexID(1))
			return !ok && r.runningRec(hexID(1)) == nil
		})
	})
	for name, noVerdict := range ctlNoVerdict {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(tm *Timing) { tm.QuietHour = 700 * time.Millisecond })
			editedConfigRunning(t, r)
			good, _ := r.good(hexID(1))
			r.setTestAnswer(func() error { return noVerdict })
			failTwice(r)
			r.eventually("the config is out of the slot and owed a test", func() bool {
				return r.runningRec(hexID(1)) == nil && r.persisted().Restore[hexID(1)] == good.Hash
			})
			if _, ok := r.good(hexID(1)); !ok {
				t.Error("the good file was deleted without a verdict")
			}
			if strings.Contains(r.slotJSON("a"), hexID(1)) {
				t.Error("the slot file holds a fragment that no test judged")
			}
			r.setTestAnswer(nil)
			r.eventually("the tested good fragment runs", func() bool {
				x := r.runningRec(hexID(1))
				return x != nil && x.Hash == good.Hash
			})
		})
	}
}

// B5-r2-4, the same class in applyOne: a timeout of the test is no refusal of the
// fragment; the config stays pending and is applied once the ctl answers.
func TestTimeoutOfTheTestIsNotARefusal(t *testing.T) {
	r := newRig(t, nil)
	r.setTestAnswer(func() error { return &CtlError{Exit: xrayrun.CtlNotJudged, Text: "cancelled"} })
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kPending)
	r.setTestAnswer(nil)
	r.waitState(1, kApplied)
}

// B5-r2-7: a refusal that is about the agent build (no allow list for the release) never
// costs the good file, and the running set is not left up on trust.
func TestNoAllowListKeepsTheGoodFiles(t *testing.T) {
	r := newRig(t, nil)
	rec := runRec{ID: hexID(1), Hash: "h", Port: 20001, Frag: []byte(vless("198.51.100.7"))}
	r.m.writeGood(rec)
	r.m.dropRefusedGood(rec.ID, noTableRefusal)
	if _, ok := r.good(rec.ID); !ok {
		t.Fatal("the good file went with a refusal about the agent build")
	}
	r.m.dropRefusedGood(rec.ID, "the last good fragment is refused by the allow list now: x")
	if _, ok := r.good(rec.ID); ok {
		t.Fatal("a refusal by the table kept the good file")
	}
	r.m.writeGood(rec)
	r.m.version = "v1.2.3" // a release the agent has no table for
	r.m.st.Running = []runRec{rec}
	r.m.recheckRunning(context.Background())
	if r.m.running(rec.ID) != nil {
		t.Error("a fragment stays up with no allow list to judge it")
	}
	if _, ok := r.good(rec.ID); !ok {
		t.Error("the good file went with the running fragment")
	}
	if s := r.m.status[rec.ID]; s == nil || s.kind != kRefused {
		t.Errorf("status %+v, want refused", s)
	}
}
