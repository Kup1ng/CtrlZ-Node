package xray

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Tests of the fixes of round 4 of the review of B5 (the review's round 1 after the
// rework). Each names the finding it closes.

// B5-r1-1: a slot that a cut-short rebuild left running is stopped before the next
// rebuild writes its file, so the probes and the switch meet the new process.
func TestRebuildStopsAnIdleSlotThatAnEarlierRebuildLeftRunning(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	// The stale process: slot b runs an older rendering, as after a restart of the agent
	// in the middle of a rebuild.
	if err := r.units.Start(context.Background(), "b"); err != nil {
		t.Fatal(err)
	}
	stale := r.units.get("b").pid
	r.configWith(func(nc *hubv1.NodeConfig) { nc.DnsAdvertisedIp = []byte{9, 9, 9, 9} }, xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("the map moved to slot b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && l.Configs[0].Socks == "127.0.0.21:20001"
	})
	if now := r.units.get("b"); !now.active || now.pid == stale {
		t.Errorf("slot b still runs the stale process: %+v (was pid %d)", now, stale)
	}
	if !strings.Contains(r.slotJSON("b"), `"9.9.9.9/32"`) {
		t.Error("the new slot's file is not the new rendering")
	}
}

// B5-r1-1: the start of the agent stops the slot that is neither active nor draining.
func TestAgentStartStopsTheIdleSlotOfACutShortRebuild(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.stop()
	if err := r.units.Start(context.Background(), "b"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.layout.SlotJSON("b"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.m = New(r.opts)
	r.start()
	r.eventually("the idle slot is stopped", func() bool { return !r.units.get("b").active })
	if _, err := os.Stat(r.layout.SlotJSON("b")); err == nil {
		t.Error("the idle slot's file, which holds credentials, stays")
	}
	if !r.units.get("a").active {
		t.Error("the active slot was stopped")
	}
}

// B5-r1-2: a good fragment goes into the slot file only after `-test`, as every other
// fragment does; a refusal by the binary leaves the config out with the test's text.
func TestRestoredGoodFragmentIsTestedBeforeItIsWritten(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.QuietHour = 700 * time.Millisecond })
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
	// The release now installed refuses the old good fragment.
	r.ctl.mu.Lock()
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpTest {
			return &CtlError{Exit: 23, Text: "failed to load config: old spelling"}
		}
		return nil
	}
	r.ctl.mu.Unlock()
	for i := 0; i < 3; i++ {
		time.Sleep(60 * time.Millisecond)
		r.units.crashSeen("a", "signal", 0)
	}
	r.waitState(1, kRefused)
	if _, e := r.stateOf(1); !strings.Contains(e, "old spelling") {
		t.Errorf("error %q does not carry the test's text", e)
	}
	if strings.Contains(r.slotJSON("a"), hexID(1)) {
		t.Error("the slot file holds a fragment that the binary refused")
	}
}

// B5-r1-3: a running config that the new release refuses in both fragments is not shown
// as last_good once the switch left it with nothing running.
func TestUpgradeThatDropsAnUnhealthyConfigShowsItRefused(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.pr.setFail(r.pr.failProbe, "127.0.0.20", true) // its remote is down
	r.eventually("unhealthy", func() bool { return r.healthyConfigs() == 0 })
	r.ctl.mu.Lock()
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpTest && c.Version != "v26.11.9" {
			return &CtlError{Exit: 23, Text: "failed to load config"}
		}
		return nil
	}
	r.ctl.mu.Unlock()
	r.writeAllow("v26.11.9", "v26.11.10")
	if err := os.WriteFile(r.layout.Candidate(), []byte("v26.11.10 run1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.eventually("the upgrade switched", func() bool { return r.activeSlot() == "b" })
	if k, _ := r.stateOf(1); k != kRefused {
		t.Errorf("the config is %v with nothing running, want refused", k)
	}
}

// B5-r1-8: an upgrade that fails on the node itself is retried a bounded number of
// times, then reported as blocked: the alert is the one signal the owner gets.
func TestUpgradeFailingOnTheNodeIsBlockedAfterTheLongWaits(t *testing.T) {
	r := newRig(t, nil)
	m := r.m
	m.queueRebuild(rbUpgrade, "v26.11.10")
	rb := m.rb
	for i := 0; i < maxLongWaits; i++ {
		rb.tries = 2
		m.rbFail(rb, "ctl")
		if m.rb != rb || m.upgrade.blocked {
			t.Fatalf("blocked after %d long waits", i+1)
		}
	}
	rb.tries = 2
	m.rbFail(rb, "files")
	if !m.upgrade.blocked || m.rb != nil || r.alerts.Count("xray_upgrade_blocked") != 1 {
		t.Errorf("not blocked after the long waits: blocked=%v alerts=%d", m.upgrade.blocked, r.alerts.Count("xray_upgrade_blocked"))
	}
}

// B5-r1-9: with no allow list for the running release a good fragment is not restored.
func TestGoodFragmentIsNotRestoredWithoutAnAllowList(t *testing.T) {
	r := newRig(t, nil)
	r.m.version = "v1.2.3"
	rr, refusal := r.m.restoreGood(runRec{ID: hexID(1)}, goodRec{Hash: "h", Frag: []byte(vless("198.51.100.7"))})
	if refusal == "" || rr.Hash == "h" {
		t.Errorf("restored with no table: %+v %q", rr, refusal)
	}
}
