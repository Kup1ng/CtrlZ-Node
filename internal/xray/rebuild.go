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
	retryAt time.Time
}

// queueRebuild asks for a rebuild. A request that stops the draining slot outranks
// one that waits, and an upgrade keeps its version.
func (m *Manager) queueRebuild(reason rbReason, version string) {
	if m.rb == nil {
		m.rb = &rebuildReq{reason: reason, version: version}
		return
	}
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
	if rb == nil || !m.guardOn || m.cur == nil || ctx.Err() != nil {
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
	idle := otherSlot(m.st.Slot)
	tbl := m.tableFor(version)
	var recs []runRec
	port := FirstPort
	refused := map[string]bool{}
	for _, id := range m.order {
		c := m.wanted[id]
		if m.st.Crashed[id] == c.hash || m.inSearch(id) {
			continue
		}
		res := tbl.Check(c.Fragment, c.Accepted)
		if !res.OK() {
			m.setStatus(id, kRefused, issueText(res), c.hash)
			refused[id] = true
			continue
		}
		if s := m.status[id]; s != nil && s.hash == c.hash && s.kind == kRefused && m.running(id) == nil && rb.reason != rbUpgrade && rb.reason != rbBase {
			// Refused by the binary for this very fragment (an API error): it stays out
			// until it changes (step 5), though a new release or base gets another try.
			continue
		}
		rec := runRec{ID: id, Gen: m.st.Gens[id] + 1, Port: port, Outs: len(outboundsOf(res.Normalized)), Hash: c.hash,
			Frag: res.Normalized, Location: c.Location, Priority: c.Priority, Stateful: tbl.Stateful(c.Fragment)}
		cfg, err := slotConfig(m.base(idle), []runRec{rec})
		if err != nil {
			continue
		}
		if err := m.testConfig(ctx, version, cfg); err != nil {
			if _, isExit := err.(*CtlError); !isExit {
				m.rbFail(rb, "ctl")
				return
			}
			m.setStatus(id, kRefused, errText(err, c.Fragment), c.hash)
			continue
		}
		recs = append(recs, rec)
		port++
	}
	need := 0
	for _, r := range m.st.Running {
		if m.effectiveHealthy(r.ID) {
			need++
		}
	}
	if len(recs) < need {
		need = len(recs) // a config that the new release refuses cannot count against it
	}
	if err := m.writeSlotFiles(idle, version, recs); err != nil {
		m.rbFail(rb, "files")
		return
	}
	if m.opt.Units.Start(ctx, idle) != nil || !m.waitUp(ctx, idle, m.t.StartWait) {
		_ = m.opt.Units.Stop(ctx, idle)
		m.dropSlotFile(idle)
		m.rbFail(rb, "start")
		return
	}
	results, healthy := m.probeAll(ctx, idle, recs, need, rb.reason == rbAllSilent)
	if healthy < need && rb.reason != rbAllSilent {
		// The new slot is no better: it is stopped and the old one stays (7.7 step 5).
		_ = m.opt.Units.Stop(ctx, idle)
		m.dropSlotFile(idle)
		if rb.reason == rbUpgrade {
			m.upgrade.blocked = true
			m.upgrade.ok = false
			m.opt.Alert.Alert(alert.Alert{Code: "xray_upgrade_blocked"})
		}
		m.rbDone(rb, false)
		return
	}
	m.switchTo(ctx, rb, idle, version, recs, results)
	m.rbDone(rb, true)
}

func (m *Manager) dropSlotFile(slot string) {
	_ = os.Remove(m.opt.Layout.SlotJSON(slot))
	_ = os.Remove(m.opt.Layout.SlotVersion(slot))
}

// rbFail keeps the request and tries again later, three times; then the configs that
// waited for it are refused with a plain text, and the admin sees it.
func (m *Manager) rbFail(rb *rebuildReq, why string) {
	rb.tries++
	if rb.tries < 3 {
		rb.retryAt = m.opt.Now().Add(30 * time.Second)
		return
	}
	for _, id := range m.order {
		if s := m.status[id]; s != nil && s.kind == kPending {
			m.setStatus(id, kRefused, "the rebuild of the Xray slot failed: "+why, m.wanted[id].hash)
		}
	}
	m.rb = nil
}

func (m *Manager) rbDone(rb *rebuildReq, ok bool) {
	if m.rb == rb {
		m.rb = nil
	}
	if rb.reason == rbStuck || rb.reason == rbAllSilent {
		m.stuck.rebuildEnded(rb.remote, m.opt.Now())
	}
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
func (m *Manager) switchTo(ctx context.Context, rb *rebuildReq, idle, version string, recs []runRec, res map[string]probeResult) {
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
		m.setStatus(r.ID, kApplied, "", r.Hash)
	}
	for id := range m.hl {
		if m.running(id) == nil {
			delete(m.hl, id)
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
	if rb.reason == rbUpgrade {
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
	if m.guardOn {
		if st, err := m.opt.Units.Status(ctx, m.st.Slot); err == nil && st.Active {
			m.slotUp = true
			m.watch = watchState{pid: st.PID, restarts: st.Restarts, known: true}
		}
	}
	if t := m.st.Trial; t != nil {
		m.st.Trial = nil
		boot := m.opt.BootID()
		same := m.slotUp && m.watch.pid == t.PID && t.Boot == boot
		switch {
		case t.Boot == boot && !same:
			// A trial of this boot with another process: the process ended in it.
			m.st.Crashed[t.Rec.ID] = t.Rec.Hash
		case t.Rec.Stateful:
			// `rmo` would leave its device or session beside a second `ado`: step 5.
			m.queueRebuild(rbAdd, "")
		case same:
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
	_ = m.saveState()
	m.ensureActive(ctx)
	m.afterRestart()
	m.refreshView()
	m.publish()
}
