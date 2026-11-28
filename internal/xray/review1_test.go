package xray

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Tests of round 1 of the review of B5. Each names the finding it closes.

func badFrag(host string) string {
	return strings.Replace(vless(host), "5783a3e7-e373-51cd-8642-c83782b807c5", "BADFRAG", 1)
}

// B5-r1-1, r1-13: a rebuild must not take away the exit of a config whose wanted
// fragment is refused while an older generation of it runs (last_good).
func TestRebuildCarriesTheLastGoodGenerationOfARefusedConfig(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	r.waitState(1, kApplied)
	r.waitState(2, kApplied)
	r.eventually("both healthy", func() bool { return r.healthyConfigs() == 2 })
	first := r.runningRec(hexID(1)).Hash

	r.config(xc(1, 7, 1, badFrag("198.51.100.77")), xc(2, 8, 1, vless("198.51.100.8")))
	r.waitState(1, kLastGood)

	// Any rebuild: here a change of the base.
	r.configWith(func(nc *hubv1.NodeConfig) { nc.DnsAdvertisedIp = []byte{9, 9, 9, 9} },
		xc(1, 7, 1, badFrag("198.51.100.77")), xc(2, 8, 1, vless("198.51.100.8")))
	r.eventually("both configs run in slot b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 2 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
	if rec := r.runningRec(hexID(1)); rec == nil || rec.Hash != first {
		t.Fatalf("the last good fragment of config 1 did not go on: %+v", rec)
	}
	if !strings.Contains(r.slotJSON("b"), "198.51.100.7\"") || strings.Contains(r.slotJSON("b"), "198.51.100.77") {
		t.Error("slot b does not hold exactly the last good fragment of config 1")
	}
	if k, _ := r.stateOf(1); k != kLastGood {
		t.Errorf("state %v, want last_good", k)
	}
	// And it survives the end of the drain: the old slot is gone, the exit is not.
	r.eventually("the drain ends", func() bool { return !r.units.get("a").active })
	if l := r.locs(); len(l.Configs) != 2 {
		t.Errorf("configs after the drain: %d", len(l.Configs))
	}
}

// B5-r1-1 (upgrade): a release that refuses a running config in both of its
// fragments blocks the upgrade, as 7.7 step 3 says, and is not silently dropped.
func TestUpgradeIsBlockedWhenTheNewReleaseCannotRunAConfig(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	// The new release's binary refuses what config 1 runs.
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
	r.eventually("the upgrade is blocked", func() bool {
		return r.hb().XrayUpgrade != nil && !r.hb().XrayUpgrade.Ok && r.alertSeen("xray_upgrade_blocked")
	})
	if r.activeSlot() != "a" || !r.units.get("a").active {
		t.Error("the old slot did not stay")
	}
	if r.healthyConfigs() != 1 {
		t.Error("config 1 lost its exit")
	}
}

func (r *rig) alertSeen(code string) bool {
	for _, c := range r.alerts.Codes() {
		if c == code {
			return true
		}
	}
	return false
}

// B5-r1-3, r1-14: the death of a trial is the trial's alone; the same death is not
// counted again as an end outside a trial (three of them would set xray_down and put
// back other admins' configs).
func TestTrialEndsAreNotCountedAsEnds(t *testing.T) {
	r := newRig(t, nil)
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpAddIn {
			r.units.crash("a", "signal", 0)
		}
		return nil
	}
	r.start()
	r.config(xc(1, 1, 1, vless("198.51.100.1")), xc(2, 2, 1, vless("198.51.100.2")), xc(3, 3, 1, vless("198.51.100.3")))
	for n := byte(1); n <= 3; n++ {
		r.waitState(n, kRefused)
	}
	time.Sleep(300 * time.Millisecond)
	if r.faults.Has(hubv1.NodeFault_NODE_FAULT_XRAY_DOWN) {
		t.Error("three trial deaths were counted as three ends")
	}
	for n := byte(1); n <= 3; n++ {
		if _, e := r.stateOf(n); e != "crashed" {
			t.Errorf("config %d: error %q", n, e)
		}
	}
}

// B5-r1-4: an API call that failed because the process died under it is a trial's
// end: the hash is marked and no rebuild is started for an "API error".
func TestApiFailureFromADeadProcessMarksTheTrial(t *testing.T) {
	r := newRig(t, nil)
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpAddOut {
			r.units.crash("a", "signal", 0)
			return &CtlError{Exit: 1, Text: "connection refused"}
		}
		return nil
	}
	r.start()
	r.config(xc(1, 1, 1, vless("198.51.100.1")))
	r.waitState(1, kRefused)
	if _, e := r.stateOf(1); e != "crashed" {
		t.Errorf("error %q, want crashed", e)
	}
	if r.persisted().Crashed[hexID(1)] == "" {
		t.Error("the hash is not marked")
	}
	time.Sleep(200 * time.Millisecond)
	if r.units.get("b").starts != 0 {
		t.Error("a rebuild was started for an API error")
	}
}

// B5-r1-5, r1-15: the new slot of a rebuild that ends before its switch marks the
// configs the rebuild adds or changes, and the old slot stays.
func TestNewSlotThatEndsBeforeTheSwitchMarksWhatItAdds(t *testing.T) {
	wg := func(ep string) string {
		return `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"` + key32() + `","address":["10.0.0.2/32"],"noKernelTun":true,"peers":[{"publicKey":"` + key32() + `","endpoint":"` + ep + `","allowedIPs":["0.0.0.0/0"]}]}}]}`
	}
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, wg("198.51.100.9:51820")))
	r.waitState(1, kApplied)
	if rec := r.runningRec(hexID(1)); rec == nil || !rec.Stateful {
		t.Skipf("the fragment is not stateful under this table: %+v", rec)
	}
	r.pr.mu.Lock()
	r.pr.onProbe = func(socks string) {
		if strings.HasPrefix(socks, slotBAddr+":") {
			r.units.crash("b", "signal", 0)
		}
	}
	r.pr.mu.Unlock()
	r.config(xc(1, 7, 1, wg("198.51.100.10:51820")))
	r.waitState(1, kLastGood)
	if _, e := r.stateOf(1); e != "crashed" {
		t.Errorf("error %q, want crashed", e)
	}
	if r.persisted().Crashed[hexID(1)] == "" {
		t.Error("the hash is not marked")
	}
	if r.activeSlot() != "a" || !r.units.get("a").active || r.units.get("b").active {
		t.Error("the old slot did not stay, or the dead new slot was not stopped")
	}
	n := r.units.get("b").starts
	time.Sleep(250 * time.Millisecond)
	if r.units.get("b").starts != n {
		t.Error("the same rebuild started again")
	}
}

// B5-r1-6, r1-16: slots that outlived the agent are stopped when it starts with the
// guard off, and when it has no guard at all.
func TestAgentStartedWithTheGuardOffStopsTheSlotsThatOutlivedIt(t *testing.T) {
	for name, nilGuard := range map[string]bool{"guard off": false, "no guard": true} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			_ = r.units.Start(context.Background(), "a")
			_ = r.units.Start(context.Background(), "b")
			r.guard.on.Store(false)
			if nilGuard {
				r.opts.Guard = nil
				r.m = New(r.opts)
			}
			r.start()
			r.eventually("both slots stopped", func() bool { return !r.units.get("a").active && !r.units.get("b").active })
		})
	}
}

// B5-r1-7: the guard is acted on while the loop is busy with a long step.
func TestGuardOffStopsTheSlotsWhileTheLoopIsBusy(t *testing.T) {
	r := newRig(t, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpAddIn {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the add never started")
	}
	r.guard.set(false)
	r.eventually("both slots stopped while the loop is inside the add", func() bool {
		return !r.units.get("a").active && !r.units.get("b").active
	})
	close(release)
	r.guard.set(true)
	r.waitState(1, kApplied)
	r.eventually("healthy again", func() bool { return r.healthyConfigs() == 1 })
}

// B5-r1-8: the stuck latch is cleared when its request is merged into another one,
// fails, or is dropped, so a later stuck remote can be rebuilt again.
func TestStuckLatchIsClearedWhenItsRequestEndsInAnyWay(t *testing.T) {
	m := New(Options{Timing: fastTiming(), Units: newUnits(), Alert: nil})
	// Merged into a request of another reason.
	m.queueRebuild(rbAdd, "")
	m.stuck.rebuilding = true
	m.queueRebuild(rbStuck, "")
	m.rbDone(m.rb, true)
	if m.stuck.rebuilding {
		t.Error("the latch stayed after the merged rebuild")
	}
	// Dropped by the guard.
	m.queueRebuild(rbStuck, "")
	m.stuck.rebuilding = true
	m.dropRebuild()
	if m.stuck.rebuilding || m.rb != nil {
		t.Error("the latch stayed after the request was dropped")
	}
	// Failed three times.
	m.queueRebuild(rbAllSilent, "")
	m.stuck.allRebuild = true
	rb := m.rb
	for i := 0; i < 3; i++ {
		m.rbFail(rb, "start")
	}
	if m.stuck.allRebuild || m.rb != nil {
		t.Error("the latch stayed after three failures")
	}
}

// B5-r1-9: the base the running slot was rendered with survives the agent, so a node
// address that changed while it was down rebuilds at the next start.
func TestBaseChangeDuringARestartOfTheAgentRebuilds(t *testing.T) {
	r := newRig(t, nil)
	var addrs atomic.Value
	addrs.Store([]netip.Addr{})
	r.opts.NodeAddrs = func() []netip.Addr { return addrs.Load().([]netip.Addr) }
	r.m = New(r.opts)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	if r.activeSlot() != "a" {
		t.Fatal("not slot a")
	}
	r.stop()
	addrs.Store([]netip.Addr{netip.MustParseAddr("9.9.9.9")})
	r.restart()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("the new address rebuilt the idle slot", func() bool { return r.activeSlot() == "b" })
	if !strings.Contains(r.slotJSON("b"), `"9.9.9.9/32"`) {
		t.Error("slot b lacks the new address")
	}
}

// B5-r1-11: a control socket that is not up yet is no verdict on the fragment: the
// loop tries again with no new NodeConfig.
func TestTransientCtlFailureIsTriedAgain(t *testing.T) {
	r := newRig(t, nil)
	var fails atomic.Int32
	r.ctl.onCall = func(c sock.CtlRun) error {
		if fails.Add(1) <= 3 {
			return errors.New("xray: ctl.sock does not answer")
		}
		return nil
	}
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
}

// B5-r1-12: the resolver goroutine and the loop share the resolve state.
func TestResolverRunsBesideTheLoop(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.ResolveEvery = 30 * time.Millisecond })
	var calls atomic.Int32
	r.opts.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("198.51.100.50")}, nil
	}
	r.m = New(r.opts)
	r.start()
	r.config(xc(1, 7, 1, vless("exit.example.org")))
	r.waitState(1, kApplied)
	r.eventually("the name was resolved more than once", func() bool { return calls.Load() >= 2 })
}

// B5-r1-17: a death is classified from what systemd shows while it waits to restart
// the unit; afterwards Result is success and ExecMainStatus 0.
func TestEndIsSeenInTheWaitBeforeTheRestart(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	for i := 0; i < 3; i++ {
		r.units.crashWindow("a", "signal", 0)
		time.Sleep(80 * time.Millisecond) // a few ticks inside the wait
		r.units.finishRestart("a")
		time.Sleep(80 * time.Millisecond)
	}
	r.eventually("three ends set xray_down", func() bool { return r.faults.Has(hubv1.NodeFault_NODE_FAULT_XRAY_DOWN) })
}

// B5-r1-19: the guard going off deletes the draining slot's file with its drain.
func TestGuardOffDeletesTheDrainingSlotsFile(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.Drain = time.Hour })
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	r.configWith(func(nc *hubv1.NodeConfig) { nc.DnsAdvertisedIp = []byte{9, 9, 9, 9} }, xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("slot a drains", func() bool {
		l := r.locs()
		return l != nil && len(l.Draining) > 0 && r.units.get("a").active && r.activeSlot() == "b"
	})
	if _, err := os.Stat(r.layout.SlotJSON("a")); err != nil {
		t.Fatal("the draining slot has no file to begin with")
	}
	r.guard.set(false)
	r.eventually("the draining slot's file is deleted", func() bool {
		_, err := os.Stat(r.layout.SlotJSON("a"))
		return err != nil
	})
}

// B5-r1-20: a node that runs without the socket count says so.
func TestMissingSocketCountIsReported(t *testing.T) {
	r := newRig(t, nil)
	r.opts.Sockets = nil
	r.m = New(r.opts)
	r.start()
	r.eventually("the alert", func() bool { return r.alertSeen("xray_sockets_unbounded") })
}

// B5-r1-21: a config that only the draining slot carries is taken out of it when it
// is no longer wanted.
func TestConfigOnlyInTheDrainingSlotIsRemovedFromIt(t *testing.T) {
	r := newRig(t, nil)
	m := r.m
	m.loadState()
	m.guardOn = true
	m.guardNow.Store(true)
	m.cur = &snapshot{}
	m.st.Slot = "b"
	m.version = "v26.11.9"
	m.st.Version = "v26.11.9"
	m.slotUp = true
	rec := runRec{ID: hexID(1), Gen: 1, Port: 20001, Outs: 1, Hash: "h", Frag: []byte(vless("198.51.100.7"))}
	m.st.Drain = &drainRec{Slot: "a", Version: "v26.11.9", Running: []runRec{rec}, Until: time.Now().Add(time.Hour).UnixNano()}
	m.reconcile(context.Background())
	if len(m.st.Drain.Running) != 0 {
		t.Fatalf("the draining slot still carries it: %+v", m.st.Drain.Running)
	}
	if rm := r.ctl.ops(sock.OpRmOut); len(rm) != 1 || rm[0].Slot != "a" {
		t.Errorf("rmo %+v", rm)
	}
	if strings.Contains(r.slotJSON("a"), hexID(1)) {
		t.Error("the draining slot's file still holds the config")
	}
}

// B5-r1-23: a release with no table in this build is refused, not judged by the
// newest table.
func TestUnknownReleaseHasNoTable(t *testing.T) {
	r := newRig(t, nil)
	if _, ok := r.m.tableFor("v1.2.3"); ok {
		t.Error("an unknown release got a table")
	}
	if _, ok := r.m.tableFor(""); !ok {
		t.Error("no release must use the newest table")
	}
	r.m.version = "v1.2.3"
	r.m.cur = &snapshot{}
	r.m.applyOne(context.Background(), &cfgRec{hex: hexID(1), Fragment: []byte(vless("198.51.100.7")), hash: "x"})
	if s := r.m.status[hexID(1)]; s == nil || s.kind != kRefused {
		t.Errorf("status %+v", s)
	}
}

// B5-r1-24: a pasted value is taken out of an error text whatever way it was spelled.
func TestRedactTakesOutControlAndQuotedSpellings(t *testing.T) {
	frag := []byte(`{"password":"pa\tss\"word99"}`)
	for _, text := range []string{
		"bad value pa ss\"word99 here",            // xrayctl turned the tab into a space
		"bad value " + `pa\tss\"word99` + " here", // Go's quoted spelling
		"bad value pa\tss\"word99 here",
	} {
		out := redact(text, frag)
		if strings.Contains(out, "word99") {
			t.Errorf("%q -> %q", text, out)
		}
	}
	if got := redact("a b c", []byte(`{"x":"   "}`)); got != "a b c" {
		t.Errorf("blank value redacted text: %q", got)
	}
}

// B5-r1-10, r1-22: the freedom hop of a chain gets the same final rules as `direct`.
func TestFreedomHopOfAFragmentGetsFinalRules(t *testing.T) {
	frag := `{"outbounds":[{"protocol":"vless","settings":{"address":"198.51.100.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com"},"sockopt":{"dialerProxy":"frag"}}},{"protocol":"freedom","tag":"frag","settings":{"fragment":{"packets":"TLSHello","length":"100-200","interval":"10-20"}}}]}`
	rec := runRec{ID: hexID(7), Gen: 1, Port: 20001, Outs: 2, Frag: mustNormalize(t, frag)}
	b := baseInput{Slot: "a", Blocked: blockedRanges([]netip.Addr{netip.MustParseAddr("9.9.9.9")})}
	p, err := renderConfig(b, rec)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range p.outbounds {
		om := o.(map[string]any)
		if om["protocol"] != "freedom" {
			continue
		}
		found = true
		st := om["settings"].(map[string]any)
		rules, _ := st["finalRules"].([]any)
		if len(rules) != 2 || st["fragment"] == nil {
			t.Errorf("settings %v", st)
		}
		blk, _ := rules[0].(map[string]any)["ip"].([]string)
		var has bool
		for _, c := range blk {
			if c == "9.9.9.9/32" {
				has = true
			}
		}
		if !has {
			t.Error("the node address is not in the freedom hop's block list")
		}
	}
	if !found {
		t.Fatal("no freedom outbound rendered")
	}
}
