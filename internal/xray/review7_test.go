package xray

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// owedRig leaves config 1 owed a test: its good file is on disk, the debt is in state.json
// and nothing runs, as after a third end with a silent ctl and a restart of the agent.
func owedRig(t *testing.T) *rig {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.stop()
	rec := r.runningRec(hexID(1))
	r.m.writeGood(*rec)
	r.m.st.Restore[hexID(1)] = rec.Hash
	r.m.dropRunning(hexID(1))
	return r
}

// B5-r2-1: a config removed while its restore debt is owed takes the good file with it. After
// a restart nothing else knows the id, and the file holds the credentials.
func TestRemovedConfigWithARestoreDebtLosesItsGoodFile(t *testing.T) {
	r := owedRig(t)
	if _, ok := r.good(hexID(1)); !ok {
		t.Fatal("the good file is not there to begin with")
	}
	delete(r.m.wanted, hexID(1))
	r.m.retestRestored(t.Context())
	if _, ok := r.good(hexID(1)); ok {
		t.Error("the good file of a removed config stayed on disk")
	}
	if len(r.m.st.Restore) != 0 {
		t.Error("the debt of a removed config stayed")
	}
}

// B5-r2-2: three stalls of the retest refuse the config but never cost the good file, since
// a stall of the whole node looks the same. The binary's own refusal still deletes it.
func TestStallRefusalOfARestoredFragmentKeepsTheGoodFile(t *testing.T) {
	r := owedRig(t)
	r.setTestAnswer(func() error { return &CtlError{Exit: xrayrun.CtlTimeout, Text: "timeout"} })
	for i := 0; i < stallsToVerdict; i++ {
		r.m.retestRestored(t.Context())
	}
	if s := r.m.status[hexID(1)]; s == nil || s.kind != kRefused {
		t.Errorf("status %v, want refused", s)
	}
	if _, ok := r.good(hexID(1)); !ok {
		t.Error("three stalls deleted the good file")
	}
}

// B5-r2-3: a new release whose binary hangs on -test is a release that did not start: the
// upgrade is blocked soon, and no config is refused for the release's fault.
func TestUpgradeToAHangingBinaryIsBlockedSoonAndRefusesNothing(t *testing.T) {
	r := newRig(t, nil)
	r.writeAllow("v26.11.9", "v26.11.10")
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	var stalls atomic.Int32
	r.ctl.mu.Lock()
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpTest && c.Version == "v26.11.10" {
			stalls.Add(1)
			return &CtlError{Exit: xrayrun.CtlTimeout, Text: "timed out"}
		}
		return nil
	}
	r.ctl.mu.Unlock()
	if err := os.WriteFile(r.layout.Candidate(), []byte("v26.11.10 run-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.eventually("the upgrade is blocked", func() bool { return r.alerts.Count("xray_upgrade_blocked") == 1 })
	if k, _ := r.stateOf(1); k == kRefused || k == kLastGood {
		t.Errorf("config 1 is %v for the new release's fault", k)
	}
	if r.activeSlot() != "a" {
		t.Error("the slot switched to a binary that hangs")
	}
}
