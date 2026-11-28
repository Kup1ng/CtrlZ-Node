package xray

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

// Tests of round 3 of the review of B5. Each names the finding it closes.

const bogusPath = "outbounds[0].settings.bogusKeyOfALaterRelease"

func bogusFrag() string {
	return strings.Replace(vless("198.51.100.7"), `"encryption":"none"`, `"encryption":"none","bogusKeyOfALaterRelease":1`, 1)
}

// B5-r3-1, B5-r3-5: only a request that changes no fragment skips the healthy comparison.
func TestOnlyAPureBaseRebuildSkipsTheHealthyComparison(t *testing.T) {
	r := newRig(t, nil)
	m := r.m
	m.st.Running = []runRec{{ID: hexID(1), Hash: "h1"}}
	m.wanted[hexID(1)] = &cfgRec{hex: hexID(1), hash: "h1"}
	same := []runRec{{ID: hexID(1), Hash: "h1"}}

	m.rb = nil
	m.queueRebuild(rbBase, "")
	if !m.changesNoFragment(m.rb, same) {
		t.Error("a pure base rebuild with every hash unchanged must be exempt")
	}
	if m.changesNoFragment(m.rb, []runRec{{ID: hexID(1), Hash: "h2"}}) {
		t.Error("a rebuild that puts in another fragment must be compared")
	}
	if m.changesNoFragment(m.rb, nil) {
		t.Error("a rebuild that leaves a running config out must be compared")
	}
	// An upgrade that a base change was merged into, in either order.
	for _, order := range [][2]rbReason{{rbUpgrade, rbBase}, {rbBase, rbUpgrade}} {
		m.rb = nil
		m.queueRebuild(order[0], "v26.11.10")
		m.queueRebuild(order[1], "v26.11.10")
		if m.changesNoFragment(m.rb, same) {
			t.Errorf("%v then %v: a merged upgrade skipped the comparison", order[0], order[1])
		}
	}
	m.rb = nil
	m.queueRebuild(rbStuck, "")
	m.queueRebuild(rbBase, "")
	if m.changesNoFragment(m.rb, same) {
		t.Error("a stuck remote merged into a base change skipped the comparison")
	}
	m.rb = nil
	m.queueRebuild(rbAdd, "")
	m.queueRebuild(rbBase, "")
	if m.changesNoFragment(m.rb, append(same, runRec{ID: hexID(2), Hash: "new"})) {
		t.Error("an add merged into a base change skipped the comparison")
	}
}

// B5-r3-5: a base rebuild carries the running fragment of a config that waits for the
// admin after an API error, it does not put the failing wanted one in.
func TestBaseRebuildDoesNotRetryAConfigThatWaitsForTheAdmin(t *testing.T) {
	r := newRig(t, nil)
	m := r.m
	tbl, _ := xrayschema.For("v26.11.9")
	c := &cfgRec{hex: hexID(1), hash: "wanted", Fragment: []byte(vless("198.51.100.7"))}
	m.wanted[c.hex] = c
	m.setStatus(c.hex, kLastGood, "api error", c.hash)
	rb := &rebuildReq{reason: rbBase}
	_, ok, fatal := m.renderForRebuild(context.Background(), rb, "v26.11.9", tbl, "b", c, FirstPort)
	if ok || fatal {
		t.Fatalf("a config waiting for the admin was rendered into a base rebuild: ok=%v fatal=%v", ok, fatal)
	}
	if n := len(r.ctl.calls); n != 0 {
		t.Errorf("%d control calls for a config that stays out", n)
	}
}

// B5-r3-2, B5-r3-7: a good fragment comes back with its own accepted list, and one that
// the table refuses is not put back.
func TestRestoredGoodFragmentKeepsItsAcceptedListAndIsJudgedAgain(t *testing.T) {
	r := newRig(t, nil)
	m := r.m
	tbl, _ := xrayschema.For("v26.11.9")
	res := tbl.Check([]byte(bogusFrag()), []string{bogusPath})
	if !res.OK() {
		t.Fatalf("the test key is not accepted by the table: %v %v", res.Rejected, res.Warnings)
	}
	m.writeGood(runRec{ID: hexID(1), Hash: "h1", Frag: res.Normalized, Accepted: []string{bogusPath}})
	g, ok := m.readGood(hexID(1))
	if !ok || len(g.Accepted) != 1 {
		t.Fatalf("the accepted list was not stored with the good fragment: %+v", g)
	}
	// The running record belongs to a newer fragment with an empty list.
	run := runRec{ID: hexID(1), Hash: "h2", Frag: []byte(vless("198.51.100.8"))}
	back, why := m.restoreGood(run, g)
	if why != "" || back.Hash != "h1" || len(back.Accepted) != 1 {
		t.Fatalf("restore: %q %+v", why, back)
	}
	if res := tbl.Check(back.Frag, back.Accepted); !res.OK() {
		t.Errorf("the restored fragment fails its own check: %v", res.Warnings)
	}
	// A good file whose list is gone (or a table that got tighter) is refused, not run.
	g.Accepted = nil
	if _, why := m.restoreGood(run, g); why == "" {
		t.Error("a good fragment that the table refuses was restored")
	}
}

// B5-r3-7 end to end: three ends put back a good fragment that the table refuses now,
// and the config is refused, not carried.
func TestPutBackDoesNotRunAGoodFragmentTheTableRefuses(t *testing.T) {
	r := newRig(t, func(tm *Timing) { tm.QuietHour = 700 * time.Millisecond })
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	r.eventually("a good file", func() bool { _, ok := r.good(hexID(1)); return ok })
	r.stop()
	g, _ := r.good(hexID(1))
	g.Frag = []byte(bogusFrag())
	g.Hash = "old"
	if err := os.WriteFile(r.m.goodPath(hexID(1)), mustJSON(t, g), 0o600); err != nil {
		t.Fatal(err)
	}
	r.m = New(r.opts)
	r.start()
	r.eventually("running", func() bool { return r.runningRec(hexID(1)) != nil })
	for i := 0; i < 3; i++ {
		time.Sleep(60 * time.Millisecond)
		r.units.crash("a", "signal", 0)
	}
	r.waitState(1, kRefused)
	if rec := r.runningRec(hexID(1)); rec != nil {
		t.Errorf("a refused good fragment runs: %s", rec.Frag)
	}
}

// B5-r3-3: a change of the accepted list alone, on an unchanged fragment, counts.
func TestAcceptedListChangeOnAnUnchangedFragmentIsJudged(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.config(xc(1, 7, 1, bogusFrag()))
	r.waitState(1, kRefused)
	r.config(xc(1, 7, 1, bogusFrag(), bogusPath))
	r.waitState(1, kApplied)
	// Withdrawn again: the fragment stays running as last_good and shows the refusal.
	r.config(xc(1, 7, 1, bogusFrag()))
	r.waitState(1, kLastGood)
	// Accepted once more: back to applied, with no new generation needed.
	r.config(xc(1, 7, 1, bogusFrag(), bogusPath))
	r.waitState(1, kApplied)
}

// B5-r3-4: a failure of the node (control socket, files) does not block an upgrade.
func TestUpgradeIsNotBlockedByAFailureOfTheNode(t *testing.T) {
	r := newRig(t, nil)
	m := r.m
	m.queueRebuild(rbUpgrade, "v26.11.10")
	rb := m.rb
	rb.tries = 2
	m.rbFail(rb, "ctl")
	if m.rb != rb || m.upgrade.blocked || r.alerts.Count("xray_upgrade_blocked") != 0 {
		t.Fatalf("a failure of ctl blocked the upgrade: rb=%v blocked=%v", m.rb != nil, m.upgrade.blocked)
	}
	if !rb.retryAt.After(m.opt.Now()) || rb.tries != 0 {
		t.Errorf("the request is not tried again later: %+v", rb)
	}
	rb.tries = 2
	m.rbFail(rb, "start")
	if !m.upgrade.blocked || m.rb != nil {
		t.Error("a release that did not start must be blocked")
	}
}

// B5-r3-8: a slot whose unit cannot be read is stopped anyway while the guard is off.
func TestGuardOffStopsASlotWhoseStatusCannotBeRead(t *testing.T) {
	r := newRig(t, nil)
	u := r.hooked()
	r.start()
	r.config(xc(1, 7, 1, vless("198.51.100.7")))
	r.waitState(1, kApplied)
	u.statusFail.Store(true)
	r.guard.set(false)
	r.eventually("the slot is stopped though its status cannot be read", func() bool { return !r.units.get("a").active })
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
