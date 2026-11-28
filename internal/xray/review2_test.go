package xray

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Tests of round 2 of the review of B5. Each names the finding it closes.

// hookUnits lets a test fail a start or a stop, or act at the moment a unit is read.
type hookUnits struct {
	*fakeUnits
	startFail atomic.Bool // the start of slot b fails
	stopFail  atomic.Bool // every stop fails
	startsB   atomic.Int64
	mu        sync.Mutex
	onStatus  func(slot string)
}

func (u *hookUnits) Start(ctx context.Context, slot string) error {
	if slot == "b" {
		u.startsB.Add(1)
		if u.startFail.Load() {
			return errors.New("unit failed to start")
		}
	}
	return u.fakeUnits.Start(ctx, slot)
}

func (u *hookUnits) Stop(ctx context.Context, slot string) error {
	if u.stopFail.Load() {
		return errors.New("stop job refused")
	}
	return u.fakeUnits.Stop(ctx, slot)
}

func (u *hookUnits) Status(ctx context.Context, slot string) (UnitStatus, error) {
	u.mu.Lock()
	h := u.onStatus
	u.mu.Unlock()
	if h != nil {
		h(slot)
	}
	return u.fakeUnits.Status(ctx, slot)
}

func (u *hookUnits) setOnStatus(f func(slot string)) { u.mu.Lock(); u.onStatus = f; u.mu.Unlock() }

// hooked wraps the rig's units before the manager starts.
func (r *rig) hooked() *hookUnits {
	u := &hookUnits{fakeUnits: r.units}
	r.opts.Units = u
	r.m = New(r.opts)
	return u
}

// cutByWatcher plays the guard watcher at the moment it acts: the guard word first,
// then the stops, then the flag for the loop.
func (r *rig) cutByWatcher() {
	r.guard.on.Store(false)
	r.m.guardNow.Store(false)
	_ = r.units.Stop(context.Background(), "a")
	_ = r.units.Stop(context.Background(), "b")
	r.m.cut.Store(true)
}

func wgFrag(ep string) string {
	return `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"` + key32() + `","address":["10.0.0.2/32"],"noKernelTun":true,"peers":[{"publicKey":"` + key32() + `","endpoint":"` + ep + `","allowedIPs":["0.0.0.0/0"]}]}}]}`
}

// B5-r2-1: an upgrade whose new release does not start is reported as blocked.
func TestUpgradeWhoseNewReleaseDoesNotStartIsBlocked(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.Tick = 5 * time.Millisecond })
	u := r.hooked()
	u.startFail.Store(true)
	r.writeAllow("v26.11.9", "v26.11.10")
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	if err := os.WriteFile(r.layout.Candidate(), []byte("v26.11.10 run-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.eventually("the upgrade is reported as blocked", func() bool { return r.alerts.Count("xray_upgrade_blocked") >= 1 })
	if r.activeSlot() != "a" || !r.units.get("a").active {
		t.Error("the old slot did not stay")
	}
	if up := r.hb().XrayUpgrade; up == nil || up.Ok {
		t.Errorf("upgrade state %+v", up)
	}
}

// B5-r2-2: a stop by the guard watcher that lands between the guard check and the unit
// read of a live add is not the fragment's crash.
func TestGuardStopDuringATrialIsNotACrash(t *testing.T) {
	r := newRig(t, nil)
	u := r.hooked()
	var armed, fired atomic.Bool
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpAddIn && !fired.Load() {
			armed.Store(true)
		}
		return nil
	}
	u.setOnStatus(func(slot string) {
		if slot == "a" && armed.CompareAndSwap(true, false) {
			// Read once after the wait of the trial: the watcher acts just before it.
			r.m.guardNow.Store(false)
			_ = r.units.Stop(context.Background(), "a")
			fired.Store(true)
		}
	})
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("the trial was cut", fired.Load)
	time.Sleep(150 * time.Millisecond)
	if len(r.persisted().Crashed) != 0 {
		t.Errorf("the agent's own stop was marked as a crash: %v", r.persisted().Crashed)
	}
	r.guard.on.Store(true)
	r.guard.set(true)
	r.waitState(1, kApplied)
}

// B5-r2-2 (rebuild): the same stop between the probe round and the unit read of the
// new slot marks nothing.
func TestGuardStopDuringARebuildMarksNothing(t *testing.T) {
	r := newRig(t, nil)
	u := r.hooked()
	r.start()
	r.config(xc(1, 7, 1, wgFrag("198.51.100.9:51820")))
	r.waitState(1, kApplied)
	if rec := r.runningRec(hexID(1)); rec == nil || !rec.Stateful {
		t.Skipf("the fragment is not stateful under this table: %+v", rec)
	}
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	var nb atomic.Int64
	u.setOnStatus(func(slot string) {
		if slot == "b" && nb.Add(1) == 2 { // the read after the probe round
			r.m.guardNow.Store(false)
			_ = r.units.Stop(context.Background(), "a")
			_ = r.units.Stop(context.Background(), "b")
		}
	})
	r.config(xc(1, 7, 1, wgFrag("198.51.100.10:51820")))
	r.eventually("the rebuild was cut", func() bool { return nb.Load() >= 2 })
	time.Sleep(150 * time.Millisecond)
	if len(r.persisted().Crashed) != 0 {
		t.Errorf("the agent's own stop was marked as a crash: %v", r.persisted().Crashed)
	}
}

// B5-r2-3: a rebuild that fails for good leaves a pending edit of a config whose old
// generation runs as last_good, not refused.
func TestFailedRebuildKeepsARunningConfigLastGood(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.Tick = 5 * time.Millisecond })
	u := r.hooked()
	r.start()
	r.config(xc(1, 7, 1, wgFrag("198.51.100.9:51820")))
	r.waitState(1, kApplied)
	if rec := r.runningRec(hexID(1)); rec == nil || !rec.Stateful {
		t.Skipf("the fragment is not stateful under this table: %+v", rec)
	}
	u.startFail.Store(true)
	r.config(xc(1, 7, 1, wgFrag("198.51.100.10:51820")))
	r.eventually("the rebuild gave up", func() bool {
		k, e := r.stateOf(1)
		return k != kPending && k != kApplied && strings.Contains(e, "rebuild")
	})
	if k, _ := r.stateOf(1); k != kLastGood {
		t.Errorf("state %v, want last_good: the old generation still runs", k)
	}
}

// B5-r2-4: a live add that meets a slot in the wait before its restart does not run;
// the end is left to supervision and the config is not marked.
func TestLiveAddWaitsOutARestartOfTheSlot(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.units.crashWindow("a", "signal", 0)
	adds := len(r.ctl.ops(sock.OpAddOut))
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	time.Sleep(250 * time.Millisecond)
	if n := len(r.ctl.ops(sock.OpAddOut)); n != adds {
		t.Errorf("an add ran against a slot that is between two lives (%d calls)", n-adds)
	}
	if len(r.persisted().Crashed) != 0 {
		t.Errorf("a config was marked: %v", r.persisted().Crashed)
	}
	r.units.finishRestart("a")
	r.waitState(2, kApplied)
	if len(r.persisted().Crashed) != 0 {
		t.Errorf("a config was marked: %v", r.persisted().Crashed)
	}
}

// B5-r2-5: a fragment that the allow list refuses now is not carried into a new slot.
func TestCarryRunningChecksTheTable(t *testing.T) {
	r := newRig(t, nil)
	m := r.m
	tbl, err := xrayschema.For("v26.11.9")
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(vless("198.51.100.7"), `"encryption":"none"`, `"encryption":"none","bogusKeyOfALaterRelease":1`, 1)
	c := &cfgRec{hex: hexID(1), hash: "wanted"}
	old := &runRec{ID: hexID(1), Hash: "old", Frag: []byte(bad)}
	m.version = "v26.11.9"
	_, ok, fatal := m.carryRunning(context.Background(), "v26.11.9", tbl, "b", c, old, FirstPort)
	if ok || fatal {
		t.Fatalf("a refused running fragment was carried: ok=%v fatal=%v", ok, fatal)
	}
	if s := m.status[hexID(1)]; s == nil || s.kind != kRefused {
		t.Errorf("status %+v, want refused with the issue", s)
	}
}

// B5-r2-5 (start): the running set is judged again when the agent starts.
func TestAgentStartTakesOutARunningFragmentTheTableRefuses(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.stop()
	p := r.persisted()
	bad := strings.Replace(string(p.Running[0].Frag), `"encryption":"none"`, `"encryption":"none","bogusKeyOfALaterRelease":1`, 1)
	if bad == string(p.Running[0].Frag) {
		t.Fatal("the test fragment was not changed")
	}
	p.Running[0].Frag = []byte(bad)
	r.m.st = p
	if err := r.m.saveState(); err != nil {
		t.Fatal(err)
	}
	r.m = New(r.opts)
	r.start()
	r.eventually("the refused fragment is out of the running set", func() bool {
		rec := r.runningRec(hexID(1))
		return rec == nil || !strings.Contains(string(rec.Frag), "bogusKey")
	})
}

// B5-r2-6: a guard that went off before a rebuild's start is read before the idle slot
// is written or started.
func TestRebuildDoesNotStartTheIdleSlotAfterTheGuardWasCut(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	var armed atomic.Bool
	armed.Store(true)
	r.ctl.onCall = func(c sock.CtlRun) error {
		if c.Op == sock.OpTest && armed.CompareAndSwap(true, false) {
			r.cutByWatcher() // during the per-config test of the rebuild
		}
		return nil
	}
	r.configWith(func(nc *hubv1.NodeConfig) { nc.DnsAdvertisedIp = []byte{9, 9, 9, 9} }, xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("the cut happened", func() bool { return !armed.Load() })
	time.Sleep(200 * time.Millisecond)
	if n := r.units.get("b").starts; n != 0 {
		t.Errorf("the idle slot was started %d times with the guard off", n)
	}
	if _, err := os.Stat(r.layout.SlotJSON("b")); err == nil {
		t.Error("the idle slot's file, which holds the credentials, was written")
	}
	r.guard.set(true)
	r.eventually("the active slot is back", func() bool { return r.healthyConfigs() == 1 })
}

// B5-r2-7: a base change is not held back by one exit that does not answer through
// the new slot: it alters no fragment.
func TestBaseChangeSwitchesDespiteAFlappingExit(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	r.waitState(1, kApplied)
	r.waitState(2, kApplied)
	r.eventually("both healthy", func() bool { return r.healthyConfigs() == 2 })
	r.pr.setFail(r.pr.failProbe, "127.0.0.21:20002", true)
	r.configWith(func(nc *hubv1.NodeConfig) { nc.DnsAdvertisedIp = []byte{9, 9, 9, 9} },
		xc(1, 7, 1, vless("198.51.100.7")), xc(2, 8, 1, vless("198.51.100.8")))
	r.eventually("the map moved to slot b", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 2 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
}

// B5-r2-7 (retry): a base rebuild that gave up is asked for again.
func TestBaseRebuildThatGaveUpIsAskedForAgain(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.Tick = 5 * time.Millisecond })
	u := r.hooked()
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("healthy", func() bool { return r.healthyConfigs() == 1 })
	u.startFail.Store(true)
	r.configWith(func(nc *hubv1.NodeConfig) { nc.DnsAdvertisedIp = []byte{9, 9, 9, 9} }, xc(1, 7, 1, vless("198.51.100.7")))
	r.eventually("three tries", func() bool { return u.startsB.Load() >= 3 })
	u.startFail.Store(false)
	r.eventually("the base is applied by a later try", func() bool {
		l := r.locs()
		return l != nil && len(l.Configs) == 1 && strings.HasPrefix(l.Configs[0].Socks, "127.0.0.21:")
	})
}

// B5-r2-8: a stop that failed when the guard turned off is tried again, and said.
func TestFailedStopWithTheGuardOffIsRetriedAndAlerted(t *testing.T) {
	r := newRig(t, nil)
	u := r.hooked()
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	u.stopFail.Store(true)
	r.guard.set(false)
	r.eventually("the failed stop is alerted", func() bool { return r.alerts.Count("xray_slot_stop_failed") == 1 })
	if !r.units.get("a").active {
		t.Fatal("the fake stopped the slot although the stop failed")
	}
	u.stopFail.Store(false)
	r.eventually("the slot is stopped by a later tick", func() bool { return !r.units.get("a").active })
}
