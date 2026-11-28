package xray

import (
	"context"
	"os"
	"sort"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

const (
	kPending  = hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_PENDING
	kApplied  = hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_APPLIED
	kRefused  = hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_REFUSED
	kLastGood = hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_LAST_GOOD
)

func (m *Manager) poll() time.Duration {
	if d := m.t.Tick / 4; d > 0 {
		return d
	}
	return time.Millisecond
}

// sleep waits d or until ctx ends, and reports whether the wait ran to its end.
func (m *Manager) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// reconcile brings the running set to the wanted one, one config at a time (7.5).
func (m *Manager) reconcile(ctx context.Context) {
	if !m.guardOn {
		return // both slots are down; onGuard starts them again and reconciles
	}
	m.ensureActive(ctx)
	if m.baseSig == "" {
		m.baseSig = m.baseSignature()
	} else if sig := m.baseSignature(); sig != m.baseSig {
		m.baseSig = sig
		m.queueRebuild(rbBase, "")
	}
	// Removed or disabled.
	for _, r := range append([]runRec(nil), m.st.Running...) {
		if _, ok := m.wanted[r.ID]; !ok {
			m.removeConfig(ctx, r.ID)
		}
	}
	for id := range m.status {
		if _, ok := m.wanted[id]; !ok && m.running(id) == nil {
			delete(m.status, id)
			delete(m.st.Crashed, id)
			m.deleteGood(id)
		}
	}
	for id := range m.st.Crashed {
		if _, ok := m.wanted[id]; !ok {
			delete(m.st.Crashed, id)
		}
	}
	for _, id := range m.order {
		c := m.wanted[id]
		if mark := m.st.Crashed[id]; mark != "" {
			if mark == c.hash {
				// Nothing renders a marked hash (7.5 step 4); the admin sees why.
				if s := m.status[id]; s == nil || s.hash != c.hash {
					kind := kRefused
					if m.running(id) != nil {
						kind = kLastGood
					}
					m.setStatus(id, kind, "crashed", c.hash)
				}
				continue
			}
			delete(m.st.Crashed, id) // another fragment ends the mark
		}
		if m.inSearch(id) {
			continue
		}
		if r := m.running(id); r != nil && r.Hash == c.hash {
			if s := m.status[id]; s == nil || s.hash != c.hash || s.kind != kApplied {
				m.setStatus(id, kApplied, "", c.hash)
			}
			continue
		}
		if s := m.status[id]; s != nil && s.hash == c.hash && (s.kind == kRefused || s.kind == kLastGood) {
			continue // refused for this very fragment: waits for the admin
		}
		m.applyOne(ctx, c)
	}
	_ = m.saveState()
	m.runRebuild(ctx)
}

// ensureActive starts the active slot from its file when it is not up (7.5 end).
func (m *Manager) ensureActive(ctx context.Context) {
	if m.slotUp || !m.guardOn {
		return
	}
	if m.version == "" {
		m.version = m.st.Version
	}
	if m.version == "" {
		m.version = m.lowestAllowed()
	}
	if m.version == "" {
		return // no release is installed yet: nothing can run
	}
	if m.st.Version != m.version {
		m.st.Version = m.version
	}
	if err := m.writeSlotFiles(m.st.Slot, m.version, m.st.Running); err != nil {
		return
	}
	if m.opt.Units.Start(ctx, m.st.Slot) != nil {
		return
	}
	m.rewatch(ctx)
	m.afterRestart()
	m.slotUp = m.waitUp(ctx, m.st.Slot, m.t.StartWait)
}

func (m *Manager) writeSlotFiles(slot, version string, running []runRec) error {
	cfg, err := slotConfig(m.base(slot), running)
	if err != nil {
		return err
	}
	if err := writeFile(m.opt.Layout.SlotJSON(slot), cfg, 0o640); err != nil {
		return err
	}
	return writeFile(m.opt.Layout.SlotVersion(slot), []byte(version+"\n"), 0o644)
}

func (m *Manager) writeActive() error { return m.writeSlotFiles(m.st.Slot, m.version, m.st.Running) }

// waitUp waits until the slot answers a SOCKS greeting on `direct`.
func (m *Manager) waitUp(ctx context.Context, slot string, d time.Duration) bool {
	deadline := m.opt.Now().Add(d)
	for {
		if m.opt.Prober.Greet(ctx, socksAddr(slot, DirectPort)) {
			return true
		}
		if ctx.Err() != nil || !m.opt.Now().Before(deadline) {
			return false
		}
		m.sleep(ctx, m.poll())
	}
}

// rewatch takes the process of the active slot as the baseline for end detection.
func (m *Manager) rewatch(ctx context.Context) {
	if st, err := m.opt.Units.Status(ctx, m.st.Slot); err == nil {
		m.watch = watchState{pid: st.PID, restarts: st.Restarts, known: true}
	}
}

// afterRestart: a process that comes up from its file holds the running set and
// nothing else, with no health yet. Every config is probed at once (6.4).
func (m *Manager) afterRestart() {
	now := m.opt.Now()
	for _, r := range m.st.Running {
		h := m.hl[r.ID]
		if h == nil {
			h = &health{}
			m.hl[r.ID] = h
		}
		h.reset()
		m.nextPr[r.ID] = now
	}
}

// applyOne is steps 1 to 3 of 7.5 for one config.
func (m *Manager) applyOne(ctx context.Context, c *cfgRec) {
	tbl := m.table()
	res := tbl.Check(c.Fragment, c.Accepted)
	old := m.running(c.hex)
	if !res.OK() {
		m.refuse(c, old, issueText(res))
		return
	}
	stateful := tbl.Stateful(c.Fragment)
	if old != nil && (stateful || old.Stateful) || m.rb != nil {
		// The change of a stateful config, and any change while a rebuild is queued,
		// goes through the idle slot (step 5).
		m.setStatus(c.hex, kPending, "", c.hash)
		m.queueRebuild(rbAdd, "")
		return
	}
	port := m.freePort()
	if port == 0 {
		m.refuse(c, old, "no free port")
		return
	}
	rec := runRec{ID: c.hex, Gen: m.st.Gens[c.hex] + 1, Port: port, Outs: len(outboundsOf(res.Normalized)),
		Hash: c.hash, Frag: res.Normalized, Location: c.Location, Priority: c.Priority, Stateful: stateful}
	cfg, err := slotConfig(m.base(m.st.Slot), []runRec{rec})
	if err != nil {
		m.refuse(c, old, "the fragment could not be rendered")
		return
	}
	if err := m.testConfig(ctx, m.version, cfg); err != nil {
		if _, isExit := err.(*CtlError); !isExit {
			return // ctrlz-xrayctl is not answering: try again at the next change or tick
		}
		m.refuse(c, old, errText(err, c.Fragment))
		return
	}
	m.liveAdd(ctx, c, rec, old)
}

func (m *Manager) refuse(c *cfgRec, old *runRec, text string) {
	if old != nil {
		m.setStatus(c.hex, kLastGood, text, c.hash)
		return
	}
	m.setStatus(c.hex, kRefused, text, c.hash)
}

func (m *Manager) freePort() int {
	used := map[int]bool{}
	for _, r := range m.st.Running {
		used[r.Port] = true
	}
	for _, r := range m.st.Retired {
		used[r.Rec.Port] = true
	}
	if t := m.st.Trial; t != nil {
		used[t.Rec.Port] = true
	}
	for p := FirstPort; p <= LastPort; p++ {
		if !used[p] {
			return p
		}
	}
	return 0
}

// liveAdd is steps 2 and 3: write the trial record, add through the API, probe, and
// require that the same process runs on after TrialWait.
func (m *Manager) liveAdd(ctx context.Context, c *cfgRec, rec runRec, old *runRec) {
	slot, ver := m.st.Slot, m.version
	st, err := m.opt.Units.Status(ctx, slot)
	if err != nil {
		return
	}
	m.st.Trial = &trialRec{Rec: rec, Boot: m.opt.BootID(), PID: st.PID}
	_ = m.saveState()
	ado, adr, adi, err := addCalls(slot, rec)
	if err == nil {
		err = m.ctlDo(ctx, ver, slot, sock.OpAddOut, nil, ado)
	}
	if err == nil {
		err = m.ctlDo(ctx, ver, slot, sock.OpAddRules, nil, adr)
	}
	if err == nil {
		err = m.ctlDo(ctx, ver, slot, sock.OpAddIn, nil, adi)
	}
	if err != nil {
		// An API error while the process runs: undo what went in, keep the config out
		// until it changes, and rebuild (step 5).
		m.removeHandlers(ctx, slot, ver, rec)
		m.st.Trial = nil
		m.refuse(c, old, errText(err, c.Fragment))
		m.queueRebuild(rbAPI, "")
		return
	}
	lat, ok := m.opt.Prober.Probe(ctx, socksAddr(slot, rec.Port), m.probeURLs())
	if !m.sleep(ctx, m.t.TrialWait) {
		return // the agent is stopping; the trial record is what the next start reads
	}
	after, serr := m.opt.Units.Status(ctx, slot)
	if serr != nil || after.PID != st.PID || after.Restarts != st.Restarts || !after.Active {
		m.trialCrashed(c, rec, old)
		return
	}
	// Passed: the slot's file is rewritten with the running set, so that a restart of
	// Xray comes up with it (step 3).
	if old != nil {
		m.st.Retired = append(m.st.Retired, retiredRec{Rec: *old, Until: m.opt.Now().Add(m.t.Drain).UnixNano()})
		m.dropRunning(c.hex)
	}
	m.st.Running = append(m.st.Running, rec)
	m.st.Gens[c.hex] = rec.Gen
	m.st.Trial = nil
	_ = m.writeActive()
	h := &health{}
	h.observe(ok, lat)
	m.hl[c.hex] = h
	m.nextPr[c.hex] = m.opt.Now().Add(m.spread(c.hex))
	m.setStatus(c.hex, kApplied, "", c.hash)
	_ = m.saveState()
	m.publish()
}

// trialCrashed: the process ended while a config was on trial. The hash is marked,
// and systemd starts the slot from its file, which never held the config.
func (m *Manager) trialCrashed(c *cfgRec, rec runRec, old *runRec) {
	m.st.Crashed[c.hex] = rec.Hash
	m.st.Trial = nil
	if old != nil {
		m.setStatus(c.hex, kLastGood, "crashed", c.hash)
	} else {
		m.setStatus(c.hex, kRefused, "crashed", c.hash)
	}
	_ = m.saveState()
	m.afterRestart()
}

// removeHandlers takes one generation out of a slot, rule first so no new
// connection is routed to it, then the inbound, then the outbounds. A failure is
// not an error here: the tag may already be gone, and `rmo` of an unknown tag
// exits 0 while `rmi` exits 1 (B0 E05).
func (m *Manager) removeHandlers(ctx context.Context, slot, version string, r runRec) {
	rule, in, outs := removeTags(r)
	_ = m.ctlDo(ctx, version, slot, sock.OpRmRules, []string{rule}, nil)
	_ = m.ctlDo(ctx, version, slot, sock.OpRmIn, []string{in}, nil)
	for len(outs) > 0 {
		n := min(len(outs), sock.MaxCtlTags)
		_ = m.ctlDo(ctx, version, slot, sock.OpRmOut, outs[:n], nil)
		outs = outs[n:]
	}
}

// removeConfig is "Removed or disabled" of 7.5: at once every file that holds it is
// rewritten without it, its good file and mark are deleted, its address leaves the
// list and its handlers are removed from the active slot and from a draining one.
// A stateful config is removed by the rebuild instead.
func (m *Manager) removeConfig(ctx context.Context, id string) {
	r := m.running(id)
	if r == nil {
		return
	}
	rec := *r
	m.dropRunning(id)
	delete(m.st.Gens, id)
	delete(m.st.Crashed, id)
	delete(m.status, id)
	delete(m.hl, id)
	delete(m.nextPr, id)
	m.deleteGood(id)
	if rec.Stateful {
		// `rmo` would leave its device or session up (finding 4); the rebuild leaves it
		// behind with the old slot. A wireguard device must not outlive the switch.
		if hasWireguard(rec.Frag) {
			m.hadWG = true
		}
		_ = m.writeActive()
		_ = m.saveState()
		m.queueRebuild(rbRemove, "")
		return
	}
	_ = m.writeActive()
	m.removeHandlers(ctx, m.st.Slot, m.version, rec)
	keep := m.st.Retired[:0]
	for _, rt := range m.st.Retired {
		if rt.Rec.ID == id {
			m.removeHandlers(ctx, m.st.Slot, m.version, rt.Rec)
			continue
		}
		keep = append(keep, rt)
	}
	m.st.Retired = keep
	if d := m.st.Drain; d != nil {
		keepD := d.Running[:0]
		for _, dr := range d.Running {
			if dr.ID == id {
				m.removeHandlers(ctx, d.Slot, d.Version, dr)
				continue
			}
			keepD = append(keepD, dr)
		}
		d.Running = keepD
		_ = m.writeSlotFiles(d.Slot, d.Version, d.Running)
	}
	_ = m.saveState()
}

// ---- supervision, 7.5 step 4 ---------------------------------------------------

func (m *Manager) tick(ctx context.Context) {
	now := m.opt.Now()
	if m.guardOn {
		m.supervise(ctx)
	}
	m.expireRetired(ctx, now)
	m.superviseDrain(ctx, now)
	if m.guardOn && m.slotUp {
		m.launchProbes(ctx, now)
		m.hangCheck(ctx, now)
		m.checkSockets(ctx, now)
	}
	m.pollCandidate(ctx, now)
	if now.Sub(maxTime(m.lastEnd, m.lastQuiet)) >= m.t.QuietHour {
		m.quiet(ctx)
	}
	m.runRebuild(ctx)
	m.tickAlerts()
	m.refreshView()
	m.publish()
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// supervise reads the active slot's unit and tells an end (a death by a signal or
// exit status 2) from a start that failed (7.5 step 4).
func (m *Manager) supervise(ctx context.Context) {
	st, err := m.opt.Units.Status(ctx, m.st.Slot)
	if err != nil {
		return
	}
	m.slotUp = st.Active
	if !m.watch.known {
		m.watch = watchState{pid: st.PID, restarts: st.Restarts, known: true}
		return
	}
	if st.Restarts > m.watch.restarts || (st.PID != 0 && m.watch.pid != 0 && st.PID != m.watch.pid) {
		ended := IsEnd(st.Result, st.ExitStatus)
		m.watch = watchState{pid: st.PID, restarts: st.Restarts, known: true}
		m.afterRestart()
		if ended {
			m.onEnd(ctx)
		} else {
			m.onStartFail(ctx)
		}
		return
	}
	if st.PID != 0 {
		m.watch.pid = st.PID
	}
}

func (m *Manager) hangCheck(ctx context.Context, now time.Time) {
	if m.rb != nil || now.Sub(m.lastHang) < m.t.HangEvery {
		return
	}
	m.lastHang = now
	if m.opt.Prober.Greet(ctx, socksAddr(m.st.Slot, DirectPort)) {
		m.hangFails = 0
		m.setStartDown(false)
		return
	}
	if m.hangFails++; m.hangFails < 3 {
		return
	}
	// A hang is an end: the agent restarts the slot (3 greetings missed, 10 s apart).
	m.hangFails = 0
	m.restartSlot(ctx)
	m.onEnd(ctx)
}

func (m *Manager) restartSlot(ctx context.Context) {
	_ = m.opt.Units.Stop(ctx, m.st.Slot)
	if m.guard() {
		_ = m.opt.Units.Start(ctx, m.st.Slot)
	}
	m.rewatch(ctx)
	m.afterRestart()
}

// onEnd counts an end outside a trial (a trial's end is handled by liveAdd).
func (m *Manager) onEnd(ctx context.Context) {
	m.lastEnd = m.opt.Now()
	if m.searching() {
		m.searchStep(ctx)
		return
	}
	if m.ends++; m.ends < 3 {
		return
	}
	m.ends = 0
	m.setEndsDown(true)
	if m.putBack(ctx) {
		return
	}
	m.searchStep(ctx)
}

// putBack is the third end: every config whose running fragment is not its good one
// is marked and runs its good fragment, or nothing. It reports whether any changed.
func (m *Manager) putBack(ctx context.Context) bool {
	changed := false
	var next []runRec
	for _, r := range m.st.Running {
		g, ok := m.readGood(r.ID)
		if ok && g.Hash == r.Hash {
			next = append(next, r)
			continue
		}
		changed = true
		m.st.Crashed[r.ID] = r.Hash
		wantedHash := r.Hash
		if c := m.wanted[r.ID]; c != nil {
			wantedHash = c.hash
		}
		if ok {
			r.Hash, r.Frag, r.Location, r.Priority, r.Stateful = g.Hash, g.Frag, g.Location, g.Priority, g.Stateful
			r.Outs = len(outboundsOf(g.Frag))
			next = append(next, r)
			m.setStatus(r.ID, kLastGood, "crashed", wantedHash)
		} else {
			m.setStatus(r.ID, kRefused, "crashed", wantedHash)
		}
	}
	if !changed {
		return false
	}
	m.st.Running = next
	m.st.Retired = nil
	m.rewriteAndRestart(ctx)
	return true
}

func (m *Manager) rewriteAndRestart(ctx context.Context) {
	_ = m.writeActive()
	_ = m.saveState()
	m.restartSlot(ctx)
}

type searchRec struct {
	id   string
	hash string
}

func (m *Manager) searching() bool { return len(m.searchOut) > 0 }

func (m *Manager) inSearch(id string) bool {
	for _, s := range m.searchOut {
		if s.id == id {
			return true
		}
	}
	return false
}

// searchStep takes one more config out: those with accepted_unknown first, then the
// rest, each time the newest good file (7.5 step 4). With none left the cause is
// none of the configs: all come back, none is marked, and no search starts for 24 h.
func (m *Manager) searchStep(ctx context.Context) {
	now := m.opt.Now()
	if now.Before(m.noSearchTil) {
		return
	}
	cands := append([]runRec(nil), m.st.Running...)
	if len(cands) == 0 {
		if m.searching() {
			for _, s := range m.searchOut {
				delete(m.status, s.id) // so that reconcile adds them again
			}
			m.searchOut = nil
			m.noSearchTil = now.Add(m.t.NoSearch)
			m.queueReconcile()
		}
		return
	}
	mt := func(id string) time.Time {
		if fi, err := os.Stat(m.goodPath(id)); err == nil {
			return fi.ModTime()
		}
		return time.Time{}
	}
	unk := func(id string) bool { c := m.wanted[id]; return c != nil && len(c.Accepted) > 0 }
	sort.SliceStable(cands, func(i, j int) bool {
		if ui, uj := unk(cands[i].ID), unk(cands[j].ID); ui != uj {
			return ui
		}
		return mt(cands[i].ID).After(mt(cands[j].ID))
	})
	pick := cands[0]
	m.searchOut = append(m.searchOut, searchRec{id: pick.ID, hash: pick.Hash})
	m.dropRunning(pick.ID)
	m.setStatus(pick.ID, kRefused, "crash_suspect", pick.Hash)
	m.rewriteAndRestart(ctx)
}

func (m *Manager) queueReconcile() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) onStartFail(ctx context.Context) {
	now := m.opt.Now()
	m.startFails = append(m.startFails, now)
	keep := m.startFails[:0]
	for _, t := range m.startFails {
		if now.Sub(t) <= 10*time.Second {
			keep = append(keep, t)
		}
	}
	m.startFails = keep
	if len(m.startFails) < 2 {
		return
	}
	// A file it cannot start from twice in 10 s is written again from good/, each
	// config tested alone first; three such rounds set xray_down.
	m.startFails = nil
	m.rewrites++
	if m.rewrites >= 3 {
		m.setStartDown(true)
	}
	var next []runRec
	for _, r := range m.st.Running {
		g, ok := m.readGood(r.ID)
		if !ok {
			continue
		}
		r.Hash, r.Frag, r.Location, r.Priority, r.Stateful = g.Hash, g.Frag, g.Location, g.Priority, g.Stateful
		r.Outs = len(outboundsOf(g.Frag))
		if cfg, err := slotConfig(m.base(m.st.Slot), []runRec{r}); err != nil || m.testConfig(ctx, m.version, cfg) != nil {
			continue
		}
		next = append(next, r)
	}
	m.st.Running = next
	m.rewriteAndRestart(ctx)
}

func (m *Manager) setEndsDown(on bool) { m.setDown(&m.downEndsB, on) }
func (m *Manager) setStartDown(on bool) {
	m.setDown(&m.downStartB, on)
	if !on {
		m.rewrites = 0
	}
}

func (m *Manager) setDown(flag *bool, on bool) {
	*flag = on
	m.downFault = m.downEndsB || m.downStartB
	m.setFault(hubv1.NodeFault_NODE_FAULT_XRAY_DOWN, m.downFault)
}

// quiet is an hour with no end: the count becomes 0 and the running set is the last
// good set, each fragment written to its good file where it differs (7.5 step 4).
func (m *Manager) quiet(ctx context.Context) {
	m.lastQuiet = m.opt.Now()
	m.ends = 0
	m.setEndsDown(false)
	if n := len(m.searchOut); n > 0 {
		// The config taken out last is the cause: it is marked, and the others come back
		// as first adds, one at a time.
		last := m.searchOut[n-1]
		m.st.Crashed[last.id] = last.hash
		m.setStatus(last.id, kRefused, "crash_suspect", last.hash)
		for _, s := range m.searchOut[:n-1] {
			delete(m.status, s.id)
		}
		m.searchOut = nil
		m.queueReconcile()
	}
	for _, r := range m.st.Running {
		if g, ok := m.readGood(r.ID); !ok || g.Hash != r.Hash {
			m.writeGood(r)
		}
	}
	_ = m.saveState()
}

// expireRetired ends the drain of an older generation of a config (10 min).
func (m *Manager) expireRetired(ctx context.Context, now time.Time) {
	if len(m.st.Retired) == 0 {
		return
	}
	keep := m.st.Retired[:0]
	for _, rt := range m.st.Retired {
		if now.UnixNano() >= rt.Until {
			m.removeHandlers(ctx, m.st.Slot, m.version, rt.Rec)
			continue
		}
		keep = append(keep, rt)
	}
	if len(keep) != len(m.st.Retired) {
		m.st.Retired = keep
		_ = m.saveState()
	}
}

// ---- probes, 6.4 ----------------------------------------------------------------

// spread puts a config's probes at a fixed point of the period, so 64 configs are
// not probed in one second.
func (m *Manager) spread(id string) time.Duration {
	var h uint32
	for i := 0; i < len(id); i++ {
		h = h*31 + uint32(id[i])
	}
	return time.Duration(uint64(h) % uint64(m.t.ProbeEvery+1))
}

func (m *Manager) launchProbes(ctx context.Context, now time.Time) {
	for _, r := range m.st.Running {
		if m.probing[r.ID] {
			continue
		}
		due, ok := m.nextPr[r.ID]
		if !ok {
			m.nextPr[r.ID] = now.Add(m.spread(r.ID))
			continue
		}
		if now.Before(due) {
			continue
		}
		select {
		case m.probeSm <- struct{}{}:
		default:
			continue
		}
		m.probing[r.ID] = true
		m.nextPr[r.ID] = now.Add(m.t.ProbeEvery)
		rec, urls, slot := r, m.probeURLs(), m.st.Slot
		go func() {
			lat, ok := m.opt.Prober.Probe(ctx, socksAddr(slot, rec.Port), urls)
			<-m.probeSm
			select {
			case m.probeCh <- probeResult{id: rec.ID, gen: rec.Gen, ok: ok, lat: lat}:
			case <-ctx.Done():
			}
		}()
	}
}

func (m *Manager) onProbe(r probeResult) {
	delete(m.probing, r.id)
	run := m.running(r.id)
	if run == nil || run.Gen != r.gen {
		return
	}
	h := m.hl[r.id]
	if h == nil {
		h = &health{}
		m.hl[r.id] = h
	}
	h.observe(r.ok, r.lat)
}

// ---- guard -----------------------------------------------------------------------

// onGuard: with the guard off both slots stop (finalRules alone is not enough for
// more than the few seconds another tool takes to flush the rules, 5.5); when it
// is back the active slot starts again.
func (m *Manager) onGuard(ctx context.Context, on bool) {
	if on == m.guardOn {
		return
	}
	m.guardOn = on
	if !on {
		_ = m.opt.Units.Stop(ctx, "a")
		_ = m.opt.Units.Stop(ctx, "b")
		m.slotUp = false
		m.watch = watchState{}
		m.st.Drain = nil
		m.rb = nil
		_ = m.saveState()
		return
	}
	m.slotUp = false
	m.ensureActive(ctx)
}
