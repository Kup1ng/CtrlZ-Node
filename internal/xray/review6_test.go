package xray

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// B5-r1-1, r1-4: when the ctl gives no verdict on the good fragment at the third end, the
// binary is not handed it. The config stays out of the slot file and out of the running set,
// the good file is not touched, the debt is in state.json, and a restart of the agent does
// not forget it. Once the ctl answers, the fragment goes back (accepted) or is dropped with
// the binary's text (refused).
func TestThirdEndKeepsTheGoodFragmentOutUntilTheBinaryJudges(t *testing.T) {
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
			r.eventually("the config is out and owed a test", func() bool {
				k, _ := r.stateOf(1)
				return r.runningRec(hexID(1)) == nil && r.persisted().Restore[hexID(1)] == good.Hash && k == kPending
			})
			if _, ok := r.good(hexID(1)); !ok {
				t.Fatal("the good file was deleted without a verdict")
			}
			if strings.Contains(r.slotJSON("a"), hexID(1)) {
				t.Error("the slot file holds a fragment that no test judged")
			}
			time.Sleep(150 * time.Millisecond) // retries with no verdict change nothing
			if r.runningRec(hexID(1)) != nil || strings.Contains(r.slotJSON("a"), hexID(1)) {
				t.Fatal("a retry with no verdict put the fragment into the slot")
			}
			r.restart()
			if r.persisted().Restore[hexID(1)] != good.Hash {
				t.Fatal("the debt did not survive the restart of the agent")
			}
			r.config(xc(1, 7, 1, vless("198.51.100.8"))) // the hub resends the same version
			r.setTestAnswer(nil)
			r.eventually("the good fragment is back, last_good", func() bool {
				x := r.runningRec(hexID(1))
				k, _ := r.stateOf(1)
				return x != nil && x.Hash == good.Hash && k == kLastGood && len(r.persisted().Restore) == 0
			})
			if !strings.Contains(r.slotJSON("a"), hexID(1)) {
				t.Error("the slot file lacks the tested fragment")
			}
		})
	}
	t.Run("refused later", func(t *testing.T) {
		r := newRig(t, func(tm *Timing) { tm.QuietHour = 700 * time.Millisecond })
		editedConfigRunning(t, r)
		r.setTestAnswer(func() error { return errors.New("xray: ctl.sock does not answer") })
		for i := 0; i < 3; i++ {
			time.Sleep(60 * time.Millisecond)
			r.units.crash("a", "signal", 0)
		}
		r.eventually("owed a test", func() bool { return len(r.persisted().Restore) == 1 })
		r.setTestAnswer(func() error { return &CtlError{Exit: 23, Text: "failed to load config: old spelling"} })
		r.waitState(1, kRefused)
		if _, e := r.stateOf(1); !strings.Contains(e, "old spelling") {
			t.Errorf("error %q does not carry the test's text", e)
		}
		r.eventually("the debt is gone with the good file", func() bool {
			_, ok := r.good(hexID(1))
			return !ok && len(r.persisted().Restore) == 0 && r.runningRec(hexID(1)) == nil
		})
	})
}

// B5-r1-6: with the ctl silent, one pass asks once and stops: the other configs owed a test
// would get the same answer, and each would hold the loop for the ctl's whole timeout.
func TestRetestStopsAtTheFirstSilence(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")), xc(3, 9, 1, vless("198.51.100.9")))
	for n := byte(1); n <= 3; n++ {
		r.waitState(n, kApplied)
	}
	r.stop()
	m := r.m
	for n := byte(1); n <= 3; n++ {
		rec := r.runningRec(hexID(n))
		m.writeGood(*rec)
		m.st.Restore[hexID(n)] = rec.Hash
		m.dropRunning(hexID(n))
	}
	var tests atomic.Int32
	r.setTestAnswer(func() error { tests.Add(1); return errors.New("xray: ctl.sock does not answer") })
	m.retestRestored(t.Context())
	if n := tests.Load(); n != 1 {
		t.Errorf("%d tests in one pass with a silent ctl, want 1", n)
	}
}

// B5-r1-2: one timeout of the test is no verdict, but the same input timing out or being
// killed three times in a row is the fragment's doing: it is refused and stops costing the
// ctl 10 s at every retry.
func TestRepeatedStallsOfTheTestAreARefusal(t *testing.T) {
	for name, code := range map[string]int32{"timeout": xrayrun.CtlTimeout, "signal": xrayrun.CtlSignal} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			var calls atomic.Int32
			r.setTestAnswer(func() error {
				calls.Add(1)
				return &CtlError{Exit: code, Text: "from the child"}
			})
			r.start()
			r.config(xc(1, 7, 1, vless("198.51.100.7")))
			r.waitState(1, kRefused)
			if n := calls.Load(); n != stallsToVerdict {
				t.Errorf("%d tests before the verdict, want %d", n, stallsToVerdict)
			}
			if _, e := r.stateOf(1); strings.Contains(e, "from the child") || e == "" {
				t.Errorf("refusal text %q", e)
			}
		})
	}
}

func TestAStallThatDoesNotRepeatIsNoVerdict(t *testing.T) {
	r := newRig(t, nil)
	var calls atomic.Int32
	r.setTestAnswer(func() error {
		if calls.Add(1)%2 == 1 { // every other test stalls: never three in a row
			return &CtlError{Exit: xrayrun.CtlTimeout, Text: "timeout"}
		}
		return nil
	})
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
}

// B5-r1-5: the new release's binary that cannot be executed is a release that did not
// start: the upgrade is blocked after the short tries, not after the long waits of a failing
// control socket.
func TestUpgradeToABinaryThatCannotRunIsBlockedSoon(t *testing.T) {
	r := newRig(t, nil)
	r.writeAllow("v26.11.9", "v26.11.10")
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.ctl.mu.Lock()
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpTest && c.Version == "v26.11.10" {
			return &CtlError{Exit: xrayrun.CtlNoRun, Text: "the binary did not run"}
		}
		return nil
	}
	r.ctl.mu.Unlock()
	if err := os.WriteFile(r.layout.Candidate(), []byte("v26.11.10 run-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.eventually("the upgrade is blocked", func() bool { return r.alerts.Count("xray_upgrade_blocked") == 1 })
	if r.activeSlot() != "a" {
		t.Error("the slot switched to a binary that cannot run")
	}
}
