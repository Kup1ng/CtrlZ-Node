package xray

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

func TestLiveAddOrderListFilesAndHeartbeat(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy in the list", func() bool { return r.healthyConfigs() == 1 })

	// 7.5 step 2: test, then ado, adrules -append, adi.
	ops := strings.Join(r.ctl.opNames(), " ")
	if !strings.Contains(ops, "test ado adrules adi") {
		t.Errorf("order of the calls: %s", ops)
	}
	l := r.locs()
	c := l.Configs[0]
	if c.Socks != "127.0.0.20:20001" || l.Direct != "127.0.0.20:20000" || !l.Guard || c.Location != 7 || !bytes.Equal(c.ID, cid(1)) || len(c.Exit) != 8 {
		t.Errorf("list %+v", l)
	}
	if !strings.Contains(r.slotJSON("a"), "in:"+hexID(1)+".1") {
		t.Error("the slot file does not hold the running set")
	}
	if v, _ := os.ReadFile(r.layout.SlotVersion("a")); strings.TrimSpace(string(v)) != "v26.11.9" {
		t.Errorf("version file %q", v)
	}
	hb := r.hb()
	if hb.XrayVersion != "v26.11.9" || len(hb.Locations) != 1 || hb.Locations[0].Location != 7 || !hb.Locations[0].Healthy {
		t.Errorf("heartbeat %+v", hb)
	}
	if len(hb.XrayConfigs) != 1 || len(hb.XrayConfigs[0].FragmentSha256) != 32 || !hb.XrayConfigs[0].Healthy {
		t.Errorf("config state %+v", hb.XrayConfigs)
	}
}

func TestRefusedConfigsDoNotStopOthersAndErrorsHoldNoValue(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	secret := strings.Replace(vless("198.51.100.8"), "5783a3e7-e373-51cd-8642-c83782b807c5", "BADFRAG-secret", 1)
	r.config(
		xc(1, 1, 1, `{"outbounds":[{"protocol":"loopback","settings":{"inboundTag":"x"}}]}`), // the schema refuses it
		xc(2, 1, 2, secret), // the binary refuses it and echoes what it was given
		xc(3, 2, 1, vless("198.51.100.9")))
	r.waitState(3, kApplied)
	r.waitState(1, kRefused)
	r.waitState(2, kRefused)
	_, e2 := r.stateOf(2)
	if strings.Contains(e2, "BADFRAG-secret") || !strings.Contains(e2, "<value>") || len(e2) > 500 {
		t.Errorf("error of 2: %q", e2)
	}
	if _, e1 := r.stateOf(1); e1 == "" || strings.Contains(e1, "inboundTag") && strings.Contains(e1, "\"x\"") {
		t.Errorf("error of 1: %q", e1)
	}
	if n := len(r.ctl.ops(sock.OpAddOut)); n != 1 {
		t.Errorf("%d ado calls, want only config 3's", n)
	}
}

func TestEditRetiresTheOldGenerationAfterTheDrain(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.config(xc(1, 7, 1, vless("198.51.100.77")))
	r.eventually("generation 2", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && l.Configs[0].Socks == "127.0.0.20:20002"
	})
	if d := r.locs().Draining; len(d) != 1 || d[0] != "127.0.0.20:20001" {
		t.Errorf("draining %v", d)
	}
	r.eventually("the old generation is removed", func() bool {
		var rm []string
		for _, c := range r.ctl.ops(sock.OpRmOut) {
			rm = append(rm, c.Tags...)
		}
		l := r.locs()
		return len(rm) == 1 && rm[0] == "L"+hexID(1)+".1.0" && len(l.Draining) == 0
	})
	if len(r.ctl.ops(sock.OpRmRules)) != 1 || len(r.ctl.ops(sock.OpRmIn)) != 1 {
		t.Error("rule and inbound of the old generation were not removed")
	}
}

func TestRemovedConfigLeavesEveryFile(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	r.waitState(2, kApplied)
	r.waitState(1, kApplied)
	r.config(xc(2, 8, 1, vless("198.51.100.8")))
	r.eventually("config 1 gone", func() bool { l := r.locs(); return len(l.Configs) == 1 })
	if strings.Contains(r.slotJSON("a"), hexID(1)) {
		t.Error("the slot file still holds the removed config")
	}
	st, _ := os.ReadFile(r.m.statePath("state.json"))
	if strings.Contains(string(st), hexID(1)) {
		t.Error("state.json still names the removed config")
	}
	if rm := r.ctl.ops(sock.OpRmOut); len(rm) != 1 || rm[0].Tags[0] != "L"+hexID(1)+".1.0" {
		t.Errorf("rmo %+v", rm)
	}
	if k, _ := r.stateOf(1); k != 0 {
		t.Error("the removed config is still reported")
	}
}

func TestTrialThatEndsTheProcessIsMarkedAndNotRenderedAgain(t *testing.T) {
	r := newRig(t, nil)
	hook := true
	r.ctl.onCall = func(c sock.CtlRun) error {
		if hook && c.Op == sock.OpAddIn {
			r.units.crash("a", "signal", 0)
		}
		return nil
	}
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kRefused)
	if _, e := r.stateOf(1); e != "crashed" {
		t.Errorf("error %q", e)
	}
	if strings.Contains(r.slotJSON("a"), "in:"+hexID(1)) {
		t.Error("the file holds the config that ended the process")
	}
	n := len(r.ctl.ops(sock.OpAddOut))
	hook = false
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	time.Sleep(150 * time.Millisecond)
	if len(r.ctl.ops(sock.OpAddOut)) != n {
		t.Error("a marked hash was rendered again")
	}
	r.config(xc(1, 7, 1, vless("198.51.100.99"))) // another fragment ends the mark
	r.waitState(1, kApplied)
}

func TestApiErrorRefusesTheConfigAndRebuilds(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 1, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	bad := strings.Replace(vless("198.51.100.8"), "5783a3e7-e373-51cd-8642-c83782b807c5", "APIFAIL", 1)
	r.config(xc(1, 1, 1, vless("198.51.100.7")), xc(2, 2, 1, bad))
	r.waitState(2, kRefused)
	// Step 5: the API error rebuilds the idle slot; the good config is carried over.
	r.eventually("switch to slot b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
	if k, _ := r.stateOf(2); k != kRefused {
		t.Error("the config whose API call failed came back")
	}
}

func TestBaseChangeRebuildsAndTheOldSlotDrains(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.configWith(func(nc *hubv1.NodeConfig) { nc.DnsAdvertisedIp = []byte{9, 9, 9, 9} }, xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("the map moved to slot b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && l.Configs[0].Socks == "127.0.0.21:20001" && l.Direct == "127.0.0.21:20000"
	})
	if !strings.Contains(r.slotJSON("b"), `"9.9.9.9/32"`) {
		t.Error("the new slot's base lacks the new node address")
	}
	// The old slot, `direct` included, is draining, then stops (7.7 step 5).
	d := strings.Join(r.locs().Draining, " ")
	if !strings.Contains(d, "127.0.0.20:20000") || !strings.Contains(d, "127.0.0.20:20001") {
		t.Errorf("draining %q", d)
	}
	r.eventually("the drain ends", func() bool {
		return !r.units.get("a").active && len(r.locs().Draining) == 0
	})
	if _, err := os.Stat(r.layout.SlotJSON("a")); err == nil {
		t.Error("the drained slot's file, which holds credentials, was not deleted")
	}
	if !r.units.get("b").active {
		t.Error("the new slot is not running")
	}
}

func TestRestartOfTheAgentKeepsTheMapAndAddsNothingAgain(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	n := len(r.ctl.ops(sock.OpAddOut))
	r.restart()
	r.config(xc(1, 7, 1, vless("198.51.100.7"))) // the hub resends the same version
	r.eventually("the list comes back", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && l.Configs[0].Socks == "127.0.0.20:20001" && l.Configs[0].Healthy
	})
	r.waitState(1, kApplied)
	if len(r.ctl.ops(sock.OpAddOut)) != n {
		t.Errorf("ado calls %d (was %d)", len(r.ctl.ops(sock.OpAddOut)), n)
	}
	if got := r.units.get("a").starts; got != 1 {
		t.Errorf("the slot was started %d times", got)
	}
}

func TestUpgradeSwitchesToTheNewVersion(t *testing.T) {
	r := newRig(t, nil)
	r.writeAllow("v26.11.9", "v26.11.10")
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	if err := os.WriteFile(r.layout.Candidate(), []byte("v26.11.10 run-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.eventually("the map moved", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
	if v, _ := os.ReadFile(r.layout.SlotVersion("b")); strings.TrimSpace(string(v)) != "v26.11.10" {
		t.Errorf("version file of b: %q", v)
	}
	var sawTest bool
	for _, c := range r.ctl.ops(sock.OpTest) {
		if c.Version == "v26.11.10" {
			sawTest = true
		}
	}
	if !sawTest {
		t.Error("the new slot's configs were not tested with the new release")
	}
	r.eventually("reported", func() bool {
		h := r.hb()
		return h.XrayVersion == "v26.11.10" && h.XrayUpgrade != nil && h.XrayUpgrade.Ok
	})
	// Once per run id: a second look at the same candidate starts nothing.
	starts := r.units.get("a").starts + r.units.get("b").starts
	time.Sleep(100 * time.Millisecond)
	if r.units.get("a").starts+r.units.get("b").starts != starts {
		t.Error("the same run id rebuilt again")
	}
}

func TestUpgradeThatIsNoBetterIsStoppedAndTheOldSlotStays(t *testing.T) {
	r := newRig(t, nil)
	r.writeAllow("v26.11.9", "v26.11.10")
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.pr.setFail(r.pr.failProbe, "127.0.0.21", true) // nothing answers through the new slot
	if err := os.WriteFile(r.layout.Candidate(), []byte("v26.11.10 run-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.eventually("the upgrade is blocked", func() bool { return r.alerts.Count("xray_upgrade_blocked") == 1 })
	r.eventually("the new slot is stopped", func() bool { return !r.units.get("b").active })
	l := r.locs()
	if !strings.HasPrefix(l.Configs[0].Socks, "127.0.0.20:") || r.hb().XrayVersion != "v26.11.9" {
		t.Errorf("the old slot did not stay: %+v", l)
	}
	r.eventually("the failed upgrade is reported", func() bool {
		u := r.hb().XrayUpgrade
		return u != nil && !u.Ok && u.Version == "v26.11.10"
	})
}

func TestFailedUpgradeFileIsReported(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	if err := os.WriteFile(r.layout.Failed(), []byte("v26.11.10\n"+hexID(1)+"\nnot-hex\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.eventually("reported", func() bool {
		u := r.hb().XrayUpgrade
		return u != nil && u.Version == "v26.11.10" && len(u.FailedIds) == 1 && bytes.Equal(u.FailedIds[0], cid(1))
	})
	if r.alerts.Count("xray_upgrade_blocked") != 1 {
		t.Error("no alert")
	}
}

func TestGuardOffStopsBothSlotsAndBackStartsTheActiveOne(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.guard.set(false)
	r.eventually("both slots stopped, guard false in the list", func() bool {
		l := r.locs()
		return !r.units.get("a").active && !r.units.get("b").active && l != nil && !l.Guard && l.Direct == "" && r.healthyConfigs() == 0
	})
	startsBefore := r.units.get("a").starts
	r.guard.set(true)
	r.eventually("the active slot is started again", func() bool { return r.units.get("a").starts > startsBefore })
	r.eventually("healthy again", func() bool { l := r.locs(); return l.Guard && r.healthyConfigs() == 1 })
}

func TestNoSlotStartsWhileTheGuardIsOff(t *testing.T) {
	r := newRig(t, nil)
	r.guard.on.Store(false)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	time.Sleep(150 * time.Millisecond)
	if r.units.get("a").starts+r.units.get("b").starts != 0 || len(r.ctl.ops(sock.OpAddOut)) != 0 {
		t.Error("something started with the guard off")
	}
}

func TestHangRestartsTheSlot(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.pr.setFail(r.pr.failGreet, "127.0.0.20:20000", true)
	r.eventually("restarted after three missed greetings", func() bool { return r.units.get("a").stops >= 1 })
	r.pr.setFail(r.pr.failGreet, "127.0.0.20:20000", false)
}

func TestThreeEndsPutTheLastGoodSetBack(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.QuietHour = 700 * time.Millisecond })
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("A has a good file", func() bool { _, ok := r.good(hexID(1)); return ok })
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	r.waitState(2, kApplied)
	for i := 0; i < 3; i++ {
		time.Sleep(60 * time.Millisecond)
		r.units.crash("a", "signal", 0)
	}
	r.waitState(2, kRefused)
	if _, e := r.stateOf(2); e != "crashed" {
		t.Errorf("error %q", e)
	}
	if k, _ := r.stateOf(1); k != kApplied {
		t.Errorf("config 1 is %v: a config whose fragment is its good one stays", k)
	}
	if strings.Contains(r.slotJSON("a"), hexID(2)) || !strings.Contains(r.slotJSON("a"), hexID(1)) {
		t.Error("the file does not hold the last good set")
	}
	if !r.faults.Has(hubv1.NodeFault_NODE_FAULT_XRAY_DOWN) {
		t.Error("no xray_down fault")
	}
	r.eventually("a quiet hour ends the fault", func() bool { return !r.faults.Has(hubv1.NodeFault_NODE_FAULT_XRAY_DOWN) })
	// The mark stays: the same fragment is not rendered again.
	n := len(r.ctl.ops(sock.OpAddOut))
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	time.Sleep(100 * time.Millisecond)
	if len(r.ctl.ops(sock.OpAddOut)) != n {
		t.Error("the marked config was rendered again")
	}
}

func TestSearchTakesOneConfigOutAtATimeAndGivesUpWhenNoneIsTheCause(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.QuietHour = 500 * time.Millisecond })
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	r.waitState(1, kApplied)
	r.waitState(2, kApplied)
	r.eventually("both have good files", func() bool {
		_, a := r.good(hexID(1))
		_, b := r.good(hexID(2))
		return a && b
	})
	crash := func() { time.Sleep(60 * time.Millisecond); r.units.crash(r.activeSlot(), "signal", 0) }
	crash()
	crash()
	crash() // the third end: nothing to put back, so the search starts
	r.eventually("one config is out", func() bool { l := r.locs(); return len(l.Configs) == 1 })
	suspects := 0
	for _, c := range r.hb().XrayConfigs {
		if c.Error == "crash_suspect" {
			suspects++
		}
	}
	if suspects != 1 {
		t.Errorf("%d suspects", suspects)
	}
	crash()
	r.eventually("both out", func() bool { return len(r.locs().Configs) == 0 })
	crash() // all out and the process ends once more: none is the cause
	r.eventually("both back", func() bool { return len(r.locs().Configs) == 2 })
	st, _ := os.ReadFile(r.m.statePath("state.json"))
	var p persisted
	_ = json.Unmarshal(st, &p)
	if len(p.Crashed) != 0 {
		t.Errorf("marks %v", p.Crashed)
	}
}

func TestStuckRemoteIsMarkedAtOnceAndRebuiltAfterThreeCounts(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	r.waitState(1, kApplied)
	r.waitState(2, kApplied)
	r.eventually("both healthy", func() bool { return r.healthyConfigs() == 2 })
	// Over exit_silent (the remote is tls) for config 1 only.
	r.sockets.set(SockCounts{Silent: map[string]int{"198.51.100.7:443": LimitExitSilent + 1}, Open: map[string]int{"198.51.100.7:443": LimitExitSilent + 1}})
	r.eventually("config 1 is unhealthy, config 2 is not", func() bool {
		l := r.locs()
		if l == nil || len(l.Configs) != 2 {
			return false
		}
		h := map[byte]bool{}
		for _, c := range l.Configs {
			h[c.ID[0]] = c.Healthy
		}
		return !h[1] && h[2]
	})
	if !r.faults.Has(hubv1.NodeFault_NODE_FAULT_XRAY_STUCK) {
		t.Error("no xray_stuck fault")
	}
	if _, e := r.stateOf(1); e != "stuck" {
		t.Errorf("error %q", e)
	}
	// Three counts in a row ask for a rebuild with the normal drain: the old slot stays
	// up as a draining slot and carries the other exits' connections.
	r.eventually("rebuilt into slot b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 2 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
	if !r.units.get("a").active {
		t.Error("the old slot was stopped at once")
	}
	// The mark outlasts the rebuild: the backoff is 10 min (5.5), whatever the probes say.
	r.sockets.set(SockCounts{})
	time.Sleep(150 * time.Millisecond)
	l := r.locs()
	for _, c := range l.Configs {
		if c.ID[0] == 1 && c.Healthy {
			t.Error("the mark ended with the rebuild")
		}
	}
	if !r.faults.Has(hubv1.NodeFault_NODE_FAULT_XRAY_STUCK) {
		t.Error("the fault ended with the rebuild")
	}
}

func TestOpenCountOverTheLimitMarksAnyRemote(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.sockets.set(SockCounts{Open: map[string]int{"198.51.100.7:443": LimitExitOpen + 1}})
	r.eventually("marked", func() bool { return r.healthyConfigs() == 0 })
}

func TestAllSilentRebuildStopsTheOldSlotAtOnce(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.sockets.set(SockCounts{Silent: map[string]int{"198.51.100.7:443": LimitAllSilent + 5}, AllSilent: LimitAllSilent + 5})
	r.eventually("switched to b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
	r.eventually("the old slot is stopped with no drain", func() bool { return !r.units.get("a").active && len(r.locs().Draining) == 0 })
}

// A wireguard exit cannot wait out a drain: two devices with one key are up at once
// in the two slots and the server follows the newest handshake (7.5 step 5).
func TestChangeOfAStatefulConfigGoesThroughTheIdleSlotWithNoDrain(t *testing.T) {
	wg := func(ep string) string {
		return `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"` + key32() + `","address":["10.0.0.2/32"],"noKernelTun":true,"peers":[{"publicKey":"` + key32() + `","endpoint":"` + ep + `","allowedIPs":["0.0.0.0/0"]}]}}]}`
	}
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, wg("198.51.100.9:51820")))
	r.waitState(1, kApplied)
	rec := r.runningRec(hexID(1))
	if rec == nil || !rec.Stateful {
		t.Skipf("the fragment is not stateful under this table: %+v", rec)
	}
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.config(xc(1, 7, 1, wg("198.51.100.10:51820")))
	r.eventually("moved to slot b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
	r.eventually("the old slot stopped at the switch", func() bool { return !r.units.get("a").active && len(r.locs().Draining) == 0 })
	if n := len(r.ctl.ops(sock.OpRmOut)); n != 0 {
		t.Errorf("rmo called %d times: it would leave the device up", n)
	}
}

func key32() string { return "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" }
