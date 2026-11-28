package xray

import (
	"context"
	"encoding/hex"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// rbReason is why a rebuild in the idle slot was asked for (7.5 step 5, 7.7).
type rbReason int

const (
	rbAdd       rbReason = iota + 1 // an add or an edit of a stateful config, or a change while one was queued
	rbBase                          // the node addresses of the base changed
	rbAPI                           // an API error while the process runs
	rbRemove                        // removal or disable of a stateful config
	rbStuck                         // a stuck remote (5.5)
	rbAllSilent                     // the memory of the uid (5.5)
	rbUpgrade                       // a new release (7.7)
)

// waitsForDrain: an add, an edit, an upgrade or a stuck remote waits for the idle
// slot to finish draining, at most 10 min, and cuts nothing. Every other reason stops
// the draining slot first and its connections end (7.5 step 5).
func (r rbReason) waitsForDrain() bool {
	return r == rbAdd || r == rbStuck || r == rbUpgrade
}

type rebuildReq struct {
	reason  rbReason
	version string
	remote  string // for rbStuck
	tries   int
	// longWaits counts the rounds of failures of the node itself (ctl, files, units) that an
	// upgrade waited out; a bounded number of them ends in a blocked upgrade, the one signal
	// the owner gets (7.7 step 5, B5 r1-8).
	longWaits int
	retryAt   time.Time
	// stuck and allSilent say which latches of 5.5 this request holds, also when it was
	// merged into a request of another reason.
	stuck, allSilent bool
}

// isUpgrade: a request that carries a version is the switch to a new release (7.7), also
// when another reason was merged into it, so its end is reported as an upgrade's.
func (r *rebuildReq) isUpgrade() bool { return r.reason == rbUpgrade || r.version != "" }

// queueRebuild asks for a rebuild. A request that stops the draining slot outranks
// one that waits, and an upgrade keeps its version.
func (m *Manager) queueRebuild(reason rbReason, version string) {
	if m.rb == nil {
		m.rb = &rebuildReq{reason: reason, version: version}
	} else {
		if !reason.waitsForDrain() && m.rb.reason.waitsForDrain() {
			m.rb.reason = reason
		}
		if reason == rbAllSilent {
			m.rb.reason = reason
		}
		if version != "" {
			m.rb.version = version
		}
	}
	switch reason {
	case rbStuck:
		m.rb.stuck = true
	case rbAllSilent:
		m.rb.allSilent = true
	}
}

type upgradeState struct {
	version string // the release in flight or last tried
	ok      bool
	failed  [][]byte
	blocked bool
}

func (m *Manager) upgradeView() *hubv1.XrayUpgradeState {
	u := &hubv1.XrayUpgradeState{Version: m.upgrade.version, Ok: m.upgrade.ok, FailedIds: m.upgrade.failed}
	// Fetched is the newest release that is installed and allowed and is not the one
	// running: the bundle the admin fetched and the owner installed.
	for _, v := range m.allowed() {
		if v != m.version {
			u.Fetched = v
		}
	}
	if u.Fetched == "" && u.Version == "" && !u.Ok && len(u.FailedIds) == 0 {
		return nil
	}
	return u
}

func (m *Manager) allowed() []string {
	b, err := os.ReadFile(m.opt.Layout.Allow())
	if err != nil {
		return nil
	}
	var vs []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); xrayrun.ValidVersion(l) {
			vs = append(vs, l)
		}
	}
	sort.Slice(vs, func(i, j int) bool { return versionLess(vs[i], vs[j]) })
	return vs
}

func (m *Manager) lowestAllowed() string {
	if vs := m.allowed(); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func versionLess(a, b string) bool {
	pa, pb := strings.Split(a[1:], "."), strings.Split(b[1:], ".")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}

// pollCandidate is 7.7 step 4: xray.candidate holds "<version> <run id>", and the
// agent acts once per run id. xray.failed holds the version on its first line and
// the ids of the configs the new release refused on the others (7.7 step 3).
func (m *Manager) pollCandidate(ctx context.Context, now time.Time) {
	if now.Sub(m.lastCand) < m.t.CandidateEvery {
		return
	}
	m.lastCand = now
	if b, err := os.ReadFile(m.opt.Layout.Failed()); err == nil {
		lines := strings.Fields(string(b))
		if len(lines) > 0 && xrayrun.ValidVersion(lines[0]) {
			var ids [][]byte
			for _, l := range lines[1:] {
				if id, err := hex.DecodeString(l); err == nil && len(id) == 16 && len(ids) < 64 {
					ids = append(ids, id)
				}
			}
			if m.upgrade.version != lines[0] || !m.upgrade.blocked {
				m.opt.Alert.Alert(alert.Alert{Code: "xray_upgrade_blocked"})
			}
			m.upgrade = upgradeState{version: lines[0], failed: ids, blocked: true}
		}
	}
	b, err := os.ReadFile(m.opt.Layout.Candidate())
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	if len(f) != 2 || !xrayrun.ValidVersion(f[0]) || len(f[1]) > 64 || f[1] == m.st.CandidateRun {
		return
	}
	if f[0] == m.version {
		m.st.CandidateRun = f[1]
		_ = m.saveState()
		return
	}
	// Once per run id: a restart of the agent in the middle does not start it again.
	m.st.CandidateRun = f[1]
	_ = m.saveState()
	m.upgrade = upgradeState{version: f[0]}
	m.queueRebuild(rbUpgrade, f[0])
}

// ---- the rebuild -------------------------------------------------------------------

// runRebuild is 7.5 step 5 and 7.7 steps 4 to 6: render the idle slot with the
// wanted set, test, start, probe everything at once, and switch when the new slot
// has at least as many healthy configs as the old one within SwitchWait.
func (m *Manager) runRebuild(ctx context.Context) {
	rb := m.rb
	if rb == nil || !m.guardOn || m.cur == nil || ctx.Err() != nil || m.guardLost() {
		return
	}
	if m.opt.Now().Before(rb.retryAt) {
		return
	}
	if m.st.Drain != nil {
		if rb.reason.waitsForDrain() {
			for _, id := range m.order {
				if m.status[id] == nil || m.status[id].kind == kApplied && m.running(id) == nil {
					m.setStatus(id, kPending, "", m.wanted[id].hash)
				}
			}
			return
		}
		m.endDrain(ctx)
	}
	version := rb.version
	if version == "" {
		version = m.version
	}
	tbl, known := m.tableFor(version)
	if !known {
		// A release this build has no allow list for is judged by no other release's
		// list (7.2): nothing is rendered, the old slot stays.
		m.blockUpgrade(rb)
		m.rbDone(rb, false)
		return
	}
	idle := otherSlot(m.st.Slot)
	sig := m.baseSignature()
	var recs []runRec
	port := FirstPort
	for _, id := range m.order {
		c := m.wanted[id]
		if m.inSearch(id) {
			continue
		}
		if m.guardLost() {
			return // the per-config tests take long: the watcher may have cut the slots meanwhile
		}
		rec, ok, fatal := m.renderForRebuild(ctx, rb, version, tbl, idle, c, port)
		if fatal {
			m.rbFail(rb, "ctl")
			return
		}
		if !ok {
			// The wanted fragment is out (marked, refused, or waiting for the admin), but a
			// generation of it runs: its last good fragment goes on (7.5 step 1,
			// last_good), or the rebuild would take its exit away.
			if old := m.running(id); old != nil {
				rec, ok, fatal = m.carryRunning(ctx, version, tbl, idle, c, old, port)
				if fatal {
					m.rbFail(rb, "ctl")
					return
				}
			}
		}
		if ok {
			recs = append(recs, rec)
			port++
		}
	}
	// The new slot must hold at least as many healthy configs as the old one. A config
	// that the new release refuses in both of its fragments is missing from it, and so
	// blocks an upgrade (7.7 steps 3 and 5).
	need := 0
	for _, r := range m.st.Running {
		if m.effectiveHealthy(r.ID) {
			need++
		}
	}
	if m.guardLost() {
		return // nothing is written: the slot file holds every credential
	}
	// The idle slot may still run an older rendering: a rebuild that an agent restart cut
	// short leaves it up, and `systemctl start` does nothing for an active unit, so the
	// probes below would greet the stale process and the switch would put it in charge
	// (B5 r1-1). It is stopped, with its file, before the new file is written.
	m.abandonIdle(ctx, idle)
	if st, err := m.opt.Units.Status(ctx, idle); err != nil || st.Active {
		m.rbFail(rb, "units")
		return
	}
	if err := m.writeSlotFiles(idle, version, recs); err != nil {
		m.rbFail(rb, "files")
		return
	}
	// The guard is read right before the start and right after it: a slot that comes up
	// after the watcher stopped both would serve with no nft rule (5.5), and every
	// second of it counts.
	if m.guardLost() {
		m.dropSlotFile(idle)
		return
	}
	startErr := m.opt.Units.Start(ctx, idle)
	if m.guardLost() {
		m.abandonIdle(ctx, idle)
		return // syncGuard drops the request
	}
	if startErr != nil || !m.waitUp(ctx, idle, m.t.StartWait) {
		m.abandonIdle(ctx, idle)
		if m.guardLost() {
			return // syncGuard drops the request
		}
		m.rbFail(rb, "start")
		return
	}
	started, serr := m.opt.Units.Status(ctx, idle)
	results, healthy := m.probeAll(ctx, idle, recs, need, rb.reason == rbAllSilent)
	after, aerr := m.opt.Units.Status(ctx, idle)
	// Read after the unit: a stop by the watcher sets the guard before it stops, so a
	// guard that is still on here means the end below was not the agent's own (7.5 step 4).
	if m.guardLost() {
		m.abandonIdle(ctx, idle)
		return
	}
	if serr == nil && (aerr != nil || processEnded(started, after)) {
		// The new slot's process ended before the switch: whatever this rebuild adds or
		// changes is marked as the cause, as a trial's end is (7.5 step 4), and the old
		// slot stays.
		m.abandonIdle(ctx, idle)
		m.markRebuildCrash(recs)
		m.blockUpgrade(rb)
		m.rbDone(rb, false)
		return
	}
	if healthy < need && rb.reason != rbAllSilent && !m.changesNoFragment(rb, recs) {
		// The new slot is no better: it is stopped and the old one stays (7.7 step 5). Only a
		// request that changes no fragment is exempt (see changesNoFragment): one flapping
		// exit must not keep the new address list out of the slot (R9, B5 r2-7).
		m.abandonIdle(ctx, idle)
		m.blockUpgrade(rb)
		m.rbDone(rb, false)
		return
	}
	m.switchTo(ctx, rb, idle, version, sig, recs, results)
	m.rbDone(rb, true)
}

// changesNoFragment: a pure base rebuild (the node addresses changed) whose every config
// goes in with the hash that runs now. Any other request, also a base change merged into
// an upgrade, an add or a stuck remote, must still pass the healthy comparison, or a worse
// new release or a failing new fragment would take the place of the old one (B5 r3-1, r3-5).
func (m *Manager) changesNoFragment(rb *rebuildReq, recs []runRec) bool {
	if rb.reason != rbBase || rb.isUpgrade() || rb.stuck || rb.allSilent {
		return false
	}
	in := map[string]bool{}
	for _, r := range recs {
		old := m.running(r.ID)
		if old == nil || old.Hash != r.Hash {
			return false
		}
		in[r.ID] = true
	}
	for _, r := range m.st.Running {
		// A running config that the new slot leaves out is a change too, unless it is gone.
		if !in[r.ID] && m.wanted[r.ID] != nil {
			return false
		}
	}
	return true
}

// renderForRebuild is the wanted fragment of a config as the new slot would run it.
// ok is false when the config stays out of it for now; fatal when the control
// socket did not answer, which says nothing about the fragment.
func (m *Manager) renderForRebuild(ctx context.Context, rb *rebuildReq, version string, tbl xrayschema.Table, idle string, c *cfgRec, port int) (rec runRec, ok, fatal bool) {
	old := m.running(c.hex)
	if m.st.Crashed[c.hex] == c.hash {
		return runRec{}, false, false // nothing renders a marked hash (7.5 step 4)
	}
	res := tbl.Check(c.Fragment, c.Accepted)
	if !res.OK() {
		m.refuse(c, old, issueText(res))
		return runRec{}, false, false
	}
	if m.waitsForAdmin(c) && !rb.isUpgrade() {
		// Refused by the binary for this very fragment (an API error): it stays out
		// until it changes (step 5), though a new release gets another try. A base
		// rebuild carries the running fragment instead (B5 r3-5).
		return runRec{}, false, false
	}
	rec = runRec{ID: c.hex, Gen: m.st.Gens[c.hex] + 1, Port: port, Outs: len(outboundsOf(res.Normalized)), Hash: c.hash,
		Frag: res.Normalized, Location: c.Location, Priority: c.Priority, Stateful: tbl.Stateful(c.Fragment), Accepted: c.Accepted}
	cfg, err := slotConfig(m.base(idle), []runRec{rec})
	if err != nil {
		return runRec{}, false, false
	}
	if err := m.testConfig(ctx, version, cfg); err != nil {
		if _, isExit := err.(*CtlError); !isExit {
			return runRec{}, false, true
		}
		m.refuse(c, old, errText(err, c.Fragment))
		return runRec{}, false, false
	}
	return rec, true, false
}

// carryRunning renders the fragment that a config runs now, for the new slot, when
// its wanted fragment cannot go in. A release that refuses it too leaves it out.
func (m *Manager) carryRunning(ctx context.Context, version string, tbl xrayschema.Table, idle string, c *cfgRec, old *runRec, port int) (rec runRec, ok, fatal bool) {
	// Checked against the table the slot is built with, whatever the release: the table
	// ships with the agent and is tightened over time, so a fragment that was good when it
	// went in is not carried into a new process once the table refuses it (B5 r2-5).
	res := tbl.Check(old.Frag, old.Accepted)
	if !res.OK() {
		if version == m.version {
			m.setStatus(c.hex, kRefused, "the running fragment is refused by the allow list now: "+issueText(res), c.hash)
		}
		return runRec{}, false, false
	}
	frag := res.Normalized
	rec = runRec{ID: c.hex, Gen: m.st.Gens[c.hex] + 1, Port: port, Outs: len(outboundsOf(frag)), Hash: old.Hash,
		Frag: frag, Location: c.Location, Priority: c.Priority, Stateful: old.Stateful, Accepted: old.Accepted}
	cfg, err := slotConfig(m.base(idle), []runRec{rec})
	if err != nil {
		return runRec{}, false, false
	}
	if err := m.testConfig(ctx, version, cfg); err != nil {
		_, isExit := err.(*CtlError)
		return runRec{}, false, !isExit
	}
	return rec, true, false
}

// abandonIdle stops the idle slot and deletes its file, which holds credentials.
func (m *Manager) abandonIdle(ctx context.Context, idle string) {
	// The stop must not depend on the loop's context: an agent that is stopping has a
	// cancelled one, and the process would keep the credentials of the file in memory.
	_ = m.opt.Units.Stop(context.WithoutCancel(ctx), idle)
	m.dropSlotFile(idle)
}

// blockUpgrade is the end of an upgrade that did not come up (7.7 step 5).
func (m *Manager) blockUpgrade(rb *rebuildReq) {
	if !rb.isUpgrade() {
		return
	}
	m.upgrade.blocked = true
	m.upgrade.ok = false
	m.opt.Alert.Alert(alert.Alert{Code: "xray_upgrade_blocked"})
}

// markRebuildCrash marks the hashes that a rebuild added or changed when the new
// slot's process ended before the switch (7.5 step 4, last bullet of "In a trial"):
// they are the ones that cannot have run before.
func (m *Manager) markRebuildCrash(recs []runRec) {
	for _, r := range recs {
		old := m.running(r.ID)
		if old != nil && old.Hash == r.Hash {
			continue
		}
		c := m.wanted[r.ID]
		if c == nil || c.hash != r.Hash {
			continue
		}
		m.st.Crashed[r.ID] = r.Hash
		if old != nil {
			m.setStatus(r.ID, kLastGood, "crashed", c.hash)
		} else {
			m.setStatus(r.ID, kRefused, "crashed", c.hash)
		}
	}
	_ = m.saveState()
}

func (m *Manager) dropSlotFile(slot string) {
	_ = os.Remove(m.opt.Layout.SlotJSON(slot))
	_ = os.Remove(m.opt.Layout.SlotVersion(slot))
}

// maxLongWaits is how many long waits an upgrade survives when the node itself fails.
const maxLongWaits = 3

// rbFail keeps the request and tries again later, three times; then the configs that
// waited for it are refused with a plain text, and the admin sees it. The refusal is
// the node's, not the fragment's, so it is tried again after a longer wait.
func (m *Manager) rbFail(rb *rebuildReq, why string) {
	rb.tries++
	if rb.tries < 3 {
		rb.retryAt = m.opt.Now().Add(30 * m.t.Tick)
		return
	}
	wait := 300 * m.t.Tick
	for _, id := range m.order {
		if s := m.status[id]; s != nil && s.kind == kPending {
			// A config whose old generation runs stays last_good, not refused (7.5 step 1).
			m.refuse(m.wanted[id], m.running(id), "the rebuild of the Xray slot failed: "+why)
			m.status[id].retryAt = m.opt.Now().Add(wait)
		}
	}
	if rb.isUpgrade() && why != "start" && rb.longWaits < maxLongWaits {
		rb.longWaits++
		// The control socket or the slot files failed: nothing was judged about the new
		// release. The candidate run id is consumed, so the request itself is kept and tried
		// again after the long wait instead of being blocked (B5 r3-4). After maxLongWaits
		// rounds it is blocked with the alert, so a socket or a disk that stays broken shows
		// (B5 r1-8).
		rb.tries = 0
		rb.retryAt = m.opt.Now().Add(wait)
		m.retryIn(wait)
		return
	}
	// An upgrade whose new release did not start is blocked, not dropped silently (7.7 step 5).
	m.blockUpgrade(rb)
	m.retryIn(wait)
	m.rbDone(rb, false)
}

// rbDone ends a request, however it ended, and releases what it held.
func (m *Manager) rbDone(rb *rebuildReq, ok bool) {
	if m.rb == rb {
		m.rb = nil
	}
	if !ok {
		m.baseRetry()
	}
	m.rbEnded(rb)
}

// dropRebuild forgets the queued request (the guard went off).
func (m *Manager) dropRebuild() {
	if rb := m.rb; rb != nil {
		m.rb = nil
		m.rbEnded(rb)
	}
}

// rbEnded clears the stuck latches of 5.5 that the request carried. A request merged
// into another one carries its flag along, so the latch is cleared when the merged
// request ends, not only when one that ran under its own reason does.
func (m *Manager) rbEnded(rb *rebuildReq) {
	m.stuck.rebuildEnded(rb.stuck, rb.allSilent)
}

// probeAll probes every config of the new slot at once, again and again until the
// healthy count reaches need or SwitchWait is over. The results of the last round
// are what the new slot starts with.
func (m *Manager) probeAll(ctx context.Context, slot string, recs []runRec, need int, force bool) (map[string]probeResult, int) {
	deadline := m.opt.Now().Add(m.t.SwitchWait)
	results := map[string]probeResult{}
	for {
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 16)
		for _, r := range recs {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer func() { <-sem; wg.Done() }()
				lat, ok := m.opt.Prober.Probe(ctx, socksAddr(slot, r.Port), m.probeURLs())
				mu.Lock()
				if prev, had := results[r.ID]; !had || ok || !prev.ok {
					results[r.ID] = probeResult{id: r.ID, gen: r.Gen, ok: ok || prev.ok, lat: lat}
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		n := 0
		for _, p := range results {
			if p.ok {
				n++
			}
		}
		if n >= need || ctx.Err() != nil || !m.opt.Now().Before(deadline) {
			return results, n
		}
		if !m.sleep(ctx, m.poll()) {
			return results, n
		}
	}
}

// switchTo moves the map to the new slot: the old slot drains 10 min and stops, or
// stops at once when a wireguard outbound is in the wanted set or in the old slot's
// running set, or when the memory of the uid asked for the rebuild (7.5 step 5).
func (m *Manager) switchTo(ctx context.Context, rb *rebuildReq, idle, version, sig string, recs []runRec, res map[string]probeResult) {
	oldSlot, oldVersion := m.st.Slot, m.version
	oldRunning := append([]runRec(nil), m.st.Running...)
	for _, rt := range m.st.Retired {
		oldRunning = append(oldRunning, rt.Rec)
	}
	wg := m.hadWG
	for _, r := range append(append([]runRec(nil), recs...), oldRunning...) {
		if hasWireguard(r.Frag) {
			wg = true
		}
	}
	m.hadWG = false
	m.st.Slot, m.version, m.st.Version = idle, version, version
	m.st.BaseSig = sig
	m.st.Running = recs
	m.st.Retired = nil
	for _, r := range recs {
		m.st.Gens[r.ID] = r.Gen
		h := &health{}
		if p, ok := res[r.ID]; ok {
			h.observe(p.ok, p.lat)
		}
		m.hl[r.ID] = h
		m.nextPr[r.ID] = m.opt.Now().Add(m.spread(r.ID))
		if c := m.wanted[r.ID]; c != nil && c.hash != r.Hash {
			// A last-good generation carried over: the wanted fragment stays refused.
			text := ""
			if s := m.status[r.ID]; s != nil {
				text = s.err
			}
			m.setStatus(r.ID, kLastGood, text, c.hash)
		} else {
			m.setStatus(r.ID, kApplied, "", r.Hash)
		}
	}
	for id := range m.hl {
		if m.running(id) == nil {
			delete(m.hl, id)
		}
	}
	// A config that kept its last_good status because a generation ran, but whose last
	// fragment the new release refused as well, has nothing running now: it shows refused
	// with the text, not a last good fragment that is not in use (B5 r1-3).
	for _, id := range m.order {
		if s := m.status[id]; s != nil && s.kind == kLastGood && m.running(id) == nil && !m.inSearch(id) {
			m.setStatus(id, kRefused, s.err, s.hash)
		}
	}
	if wg || rb.reason == rbAllSilent {
		_ = m.opt.Units.Stop(ctx, oldSlot)
		m.dropSlotFile(oldSlot)
		m.st.Drain = nil
	} else {
		m.st.Drain = &drainRec{Slot: oldSlot, Version: oldVersion, Running: oldRunning,
			Until: m.opt.Now().Add(m.t.Drain).UnixNano()}
	}
	if rb.isUpgrade() {
		m.upgrade.ok, m.upgrade.blocked = true, false
	}
	m.slotUp = true
	m.rewatch(ctx)
	m.lastPub = nil
	_ = m.saveState()
	m.refreshView()
	m.publish()
}

// endDrain stops the draining slot and deletes its file, which holds credentials.
func (m *Manager) endDrain(ctx context.Context) {
	d := m.st.Drain
	if d == nil {
		return
	}
	_ = m.opt.Units.Stop(ctx, d.Slot)
	m.dropSlotFile(d.Slot)
	m.st.Drain = nil
	_ = m.saveState()
}

// superviseDrain ends the drain when its time is up or its process ended: a draining
// slot that ends is stopped and nothing is counted (7.5 step 4).
func (m *Manager) superviseDrain(ctx context.Context, now time.Time) {
	d := m.st.Drain
	if d == nil {
		return
	}
	if now.UnixNano() >= d.Until {
		m.endDrain(ctx)
		m.publish()
		return
	}
	st, err := m.opt.Units.Status(ctx, d.Slot)
	if err == nil && !st.Active {
		m.endDrain(ctx)
		m.publish()
	}
}

// recover is the start of the agent (7.5, last paragraph): it takes the map, the ports
// and the generations from the state, removes what a stop of the agent may have left
// (an older generation, a trial that was cut short) and only then lets the first list
// go out.
func (m *Manager) recover(ctx context.Context) {
	m.version = m.st.Version
	if m.version == "" {
		m.version = m.lowestAllowed()
	}
	// The slots are read whatever the guard says: a trial's verdict must not depend on
	// whether the guard happens to be off at this start.
	live, livePID := false, 0
	if st, err := m.opt.Units.Status(ctx, m.st.Slot); err == nil && st.Active {
		live, livePID = true, st.PID
		if m.guardOn {
			m.slotUp = true
			m.watch = watchState{pid: st.PID, restarts: st.Restarts, known: true}
		}
	}
	if t := m.st.Trial; t != nil {
		m.st.Trial = nil
		boot := m.opt.BootID()
		same := live && livePID == t.PID && t.Boot == boot
		switch {
		case t.Boot == boot && !same && m.guardOn:
			// A trial of this boot with another process: the process ended in it.
			m.st.Crashed[t.Rec.ID] = t.Rec.Hash
		case t.Rec.Stateful:
			// `rmo` would leave its device or session beside a second `ado`: step 5.
			m.queueRebuild(rbAdd, "")
		case same && m.guardOn:
			m.removeHandlers(ctx, m.st.Slot, m.version, t.Rec)
		}
	}
	if m.slotUp {
		for _, rt := range m.st.Retired {
			m.removeHandlers(ctx, m.st.Slot, m.version, rt.Rec)
		}
	}
	m.st.Retired = nil
	if m.st.Drain != nil {
		m.endDrain(ctx)
	}
	// The other slot is recorded nowhere but as the drain: a rebuild that the stop of the
	// agent cut short leaves its idle slot running with credentials, and the next rebuild
	// must not meet it (B5 r1-1).
	m.abandonIdle(ctx, otherSlot(m.st.Slot))
	m.recheckRunning(ctx)
	if !m.guardOn {
		// The units are not tied to the agent: slots that outlived it keep serving, and
		// with the guard off (or no guard yet) they would be open proxies. Only a change of
		// the guard stops them otherwise (5.5).
		m.stopSlots(ctx)
		m.slotUp = false
	}
	_ = m.saveState()
	m.ensureActive(ctx)
	m.afterRestart()
	m.refreshView()
	m.publish()
}

// baseRetry lets a base change that ended without a switch be asked for again: the
// running process keeps the old finalRules on `direct` and on the freedom hops, so a
// new panel or node address stays reachable through it until the rebuild succeeds
// (R9, B5 r2-7). It is tried every few minutes, not at every tick, because a rebuild
// holds a probe round.
func (m *Manager) baseRetry() {
	if m.baseTried != "" && m.baseSignature() != m.st.BaseSig {
		m.baseTried = ""
		m.retryIn(300 * m.t.Tick)
	}
}

// recheckRunning judges every fragment of the running set again against the allow list
// of the release the slot runs. The table ships with the agent and is tightened over
// time, and a config whose hash equals the wanted one is never checked again by
// reconcile, so without this a fragment that a new agent calls dangerous would run on
// until its admin edited it (B5 r2-5). What the table refuses is taken out like a
// removed config and shows `refused` with the issue.
func (m *Manager) recheckRunning(ctx context.Context) {
	tbl, known := m.table()
	if !known {
		return
	}
	for _, r := range append([]runRec(nil), m.st.Running...) {
		res := tbl.Check(r.Frag, r.Accepted)
		if res.OK() {
			continue
		}
		m.removeConfig(ctx, r.ID)
		m.setStatus(r.ID, kRefused, "the running fragment is refused by the allow list now: "+issueText(res), r.Hash)
	}
}
