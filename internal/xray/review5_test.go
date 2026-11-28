package xray

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// ctlNoVerdict are the answers of a ctl that judged nothing about a fragment: no answer at
// all, and the exit -1 that xrayctl gives for a timeout, a release its allow file does not
// name and a binary that did not run (B5 r2-4).
var ctlNoVerdict = map[string]error{
	"no answer": errors.New("xray: ctl.sock does not answer"),
	"timeout":   &CtlError{Exit: -1, Text: "timeout"},
	"not run":   &CtlError{Exit: -1, Text: "the binary did not run"},
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

// B5-r2-1, r2-3, r2-4: when the ctl gives no verdict on the good fragment at the third
// end, the fragment stays in the slot and the good file is not touched. It is tested
// again, and the binary's own refusal later takes it out.
func TestThirdEndKeepsTheGoodFragmentWhenTheCtlDoesNotJudge(t *testing.T) {
	for name, noVerdict := range ctlNoVerdict {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(tm *Timing) { tm.QuietHour = 700 * time.Millisecond })
			editedConfigRunning(t, r)
			good, _ := r.good(hexID(1))
			r.setTestAnswer(func() error { return noVerdict })
			for i := 0; i < 3; i++ {
				time.Sleep(60 * time.Millisecond)
				r.units.crash("a", "signal", 0)
			}
			r.eventually("the good fragment runs, last_good", func() bool {
				x := r.runningRec(hexID(1))
				k, _ := r.stateOf(1)
				return x != nil && x.Hash == good.Hash && k == kLastGood
			})
			if _, ok := r.good(hexID(1)); !ok {
				t.Fatal("the good file was deleted without a verdict")
			}
			if !strings.Contains(r.slotJSON("a"), hexID(1)) {
				t.Error("the slot file lost the config")
			}
			// The ctl answers with the binary's refusal: now the config goes.
			r.setTestAnswer(func() error { return &CtlError{Exit: 23, Text: "failed to load config: old spelling"} })
			r.waitState(1, kRefused)
			if _, e := r.stateOf(1); !strings.Contains(e, "old spelling") {
				t.Errorf("error %q does not carry the test's text", e)
			}
			r.eventually("the config is out and its good file gone", func() bool {
				_, ok := r.good(hexID(1))
				return !ok && r.runningRec(hexID(1)) == nil && !strings.Contains(r.slotJSON("a"), hexID(1))
			})
		})
	}
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
			r.eventually("the good fragment runs", func() bool {
				x := r.runningRec(hexID(1))
				return x != nil && x.Hash == good.Hash
			})
			if _, ok := r.good(hexID(1)); !ok {
				t.Error("the good file was deleted without a verdict")
			}
		})
	}
}

// B5-r2-4, the same class in applyOne: a timeout of the test is no refusal of the
// fragment; the config stays pending and is applied once the ctl answers.
func TestTimeoutOfTheTestIsNotARefusal(t *testing.T) {
	r := newRig(t, nil)
	r.setTestAnswer(func() error { return &CtlError{Exit: -1, Text: "timeout"} })
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
