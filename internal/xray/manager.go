package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// Timing holds every period of 7.5 to 7.7, 6.4 and 5.5. The defaults are the values
// of D31; a test shortens them.
type Timing struct {
	Tick           time.Duration // supervision and scheduling
	TrialWait      time.Duration // the process must run this long after a trial (5 s)
	Drain          time.Duration // 10 min
	ProbeEvery     time.Duration // 30 s, spread over the period
	HangEvery      time.Duration // 10 s
	QuietHour      time.Duration // 1 h
	SwitchWait     time.Duration // 60 s: the new slot's configs must be as healthy as the old one's
	StartWait      time.Duration // how long a started slot may take to answer
	CandidateEvery time.Duration // 5 s
	SocketEvery    time.Duration // 5 s
	ResolveEvery   time.Duration // 60 s
	NoSearch       time.Duration // 24 h
	LocationDown   time.Duration // 10 min
}

// DefaultTiming is the production timing.
func DefaultTiming() Timing {
	return Timing{
		Tick: time.Second, TrialWait: 5 * time.Second, Drain: 10 * time.Minute,
		ProbeEvery: 30 * time.Second, HangEvery: 10 * time.Second, QuietHour: time.Hour,
		SwitchWait: 60 * time.Second, StartWait: 20 * time.Second, CandidateEvery: 5 * time.Second,
		SocketEvery: 5 * time.Second, ResolveEvery: time.Minute, NoSearch: 24 * time.Hour,
		LocationDown: 10 * time.Minute,
	}
}

// Options are what the manager is built from. Everything outside the process is an
// interface, so a test runs it against fakes (a ctl that answers, units that start
// and die, a prober, a guard).
type Options struct {
	Layout   xrayrun.Layout
	StateDir string
	Ctl      Ctl
	Units    Units
	Prober   Prober
	// Guard is the nftables guard (5.5); the manager starts no slot while it is
	// false and stops both when it turns false.
	Guard  agent.Guard
	Faults *agent.Faults
	// Publish is DNS.Publish of the agent: the locations list goes to dns through it.
	Publish func(*sock.Msg) error
	Alert   alert.Alerter
	// Sockets is the count of 5.5 rule 2; nil leaves the stuck check off.
	Sockets SocketCounter
	// Resolve asks the identified Unbound for the addresses of a name, for the remote
	// sets of 5.5. Nil: only IP literals are known.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Unbound is the identified Unbound as ip:port.
	Unbound string
	// NodeAddrs are the addresses of the nodes of the table and of the panel, which
	// `direct` refuses beside the non-public ranges (7.4).
	NodeAddrs func() []netip.Addr
	BootID    func() string
	Timing    Timing
	Now       func() time.Time
}

// cfgRec is a config the hub wants.
type cfgRec struct {
	ID       []byte
	hex      string
	Location uint32
	Tag      string
	Priority uint32
	Fragment []byte
	Accepted []string
	hash     string // sha256 of Fragment, hex
}

type snapshot struct {
	version  uint64
	probe    []string
	addrs    []netip.Addr
	fetch    string
	configs  []*cfgRec
	received time.Time
}

type cfgStatus struct {
	kind hubv1.XrayConfigStateKind
	err  string
	hash string // hash of the wanted fragment this status is about
}

// hbView is what Heartbeat copies into the message, made by the loop.
type hbView struct {
	version   string
	configs   []*hubv1.XrayConfigState
	locations []*hubv1.LocationHealth
	upgrade   *hubv1.XrayUpgradeState
}

// probeResult is one finished probe, back in the loop.
type probeResult struct {
	id  string
	gen int
	ok  bool
	lat time.Duration
}

// Manager is the Xray part of the agent. It implements agent.Part and
// agent.FragmentPart.
type Manager struct {
	opt Options
	t   Timing

	// Written by Config on the config worker's goroutine, read by the loop.
	mu    sync.Mutex
	snap  *snapshot
	fresh bool
	wake  chan struct{}
	view  hbViewBox

	probeCh chan probeResult

	// Everything below belongs to the loop goroutine.
	st      persisted
	wanted  map[string]*cfgRec
	order   []string
	status  map[string]*cfgStatus
	hl      map[string]*health
	nextPr  map[string]time.Time
	probing map[string]bool
	probeSm chan struct{}

	guardOn  bool
	slotUp   bool
	watch    watchState
	lastPub  []byte
	pubErr   bool
	version  string // release the active slot runs
	cur      *snapshot
	baseSig  string
	stopping bool

	// 7.5 step 4
	ends        int
	lastEnd     time.Time
	lastQuiet   time.Time
	searchOut   []searchRec
	noSearchTil time.Time
	startFails  []time.Time
	rewrites    int
	hangFails   int
	lastHang    time.Time
	downFault   bool
	downEndsB   bool
	downStartB  bool

	// rebuilds, 7.5 step 5 and 7.7
	rb          *rebuildReq
	hadWG       bool
	upgrade     upgradeState
	lastCand    time.Time
	lastProbeAt time.Time

	// 5.5 rule 2
	stuck stuckState

	// 6.4
	noHealthy map[uint32]time.Time
	alerted   map[uint32]bool
}

// New builds the manager. Nothing runs until Run.
func New(o Options) *Manager {
	t := o.Timing
	if t.Tick == 0 {
		t = DefaultTiming()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Alert == nil {
		o.Alert = alert.Discard{}
	}
	if o.Unbound == "" {
		o.Unbound = "127.0.0.10:5300"
	}
	if o.BootID == nil {
		o.BootID = readBootID
	}
	return &Manager{
		opt: o, t: t, wake: make(chan struct{}, 1), probeCh: make(chan probeResult, 256),
		wanted: map[string]*cfgRec{}, status: map[string]*cfgStatus{}, hl: map[string]*health{},
		nextPr: map[string]time.Time{}, probing: map[string]bool{}, probeSm: make(chan struct{}, 8),
		noHealthy: map[uint32]time.Time{}, alerted: map[uint32]bool{},
		stuck: newStuckState(),
	}
}

func readBootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Fragments says that this part gets the Xray fragments: it is the one part that
// holds the credentials of the exits.
func (m *Manager) Fragments() bool { return true }

// Config takes each applied NodeConfig. It copies what it needs, returns at once and
// is idempotent: the loop compares the snapshot with what it applied.
func (m *Manager) Config(nc *hubv1.NodeConfig) {
	s := &snapshot{version: nc.GetVersion(), fetch: nc.GetXrayFetchVersion(), received: m.opt.Now()}
	s.probe = append(s.probe, nc.GetProbeUrls()...)
	for _, b := range [][]byte{nc.GetDnsBindIp(), nc.GetDnsAdvertisedIp(), nc.GetProxyBindIp(), nc.GetProxyAdvertisedIp()} {
		if a, ok := netip.AddrFromSlice(b); ok {
			s.addrs = append(s.addrs, a.Unmap())
		}
	}
	for _, x := range nc.GetXrayConfigs() {
		if !x.GetEnabled() || len(x.GetId()) != 16 {
			continue // disabled rows are not sent; a bad id cannot have passed the door
		}
		frag := append([]byte(nil), x.GetFragmentJson()...)
		sum := sha256.Sum256(frag)
		s.configs = append(s.configs, &cfgRec{
			ID: append([]byte(nil), x.GetId()...), hex: idHex(x.GetId()), Location: x.GetLocation(),
			Tag: x.GetTag(), Priority: x.GetPriority(), Fragment: frag,
			Accepted: append([]string(nil), x.GetAcceptedUnknown()...), hash: hex.EncodeToString(sum[:]),
		})
	}
	m.mu.Lock()
	m.snap, m.fresh = s, true
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// hbViewBox lets Heartbeat read the loop's last view with no lock the loop holds.
type hbViewBox struct {
	mu sync.Mutex
	v  *hbView
}

func (b *hbViewBox) set(v *hbView) { b.mu.Lock(); b.v = v; b.mu.Unlock() }
func (b *hbViewBox) get() *hbView  { b.mu.Lock(); defer b.mu.Unlock(); return b.v }

// Heartbeat fills the Xray fields (3.4). It reads the last view only (L11).
func (m *Manager) Heartbeat(hb *hubv1.Heartbeat) {
	v := m.view.get()
	if v == nil {
		return
	}
	hb.XrayVersion = v.version
	for _, c := range v.configs {
		hb.XrayConfigs = append(hb.XrayConfigs, &hubv1.XrayConfigState{
			Id: c.Id, FragmentSha256: c.FragmentSha256, State: c.State, Error: c.Error,
			Healthy: c.Healthy, LatencyMs: c.LatencyMs,
		})
	}
	for _, l := range v.locations {
		hb.Locations = append(hb.Locations, &hubv1.LocationHealth{Location: l.Location, Healthy: l.Healthy, LatencyMs: l.LatencyMs})
	}
	if v.upgrade != nil {
		hb.XrayUpgrade = &hubv1.XrayUpgradeState{Fetched: v.upgrade.Fetched, Version: v.upgrade.Version,
			Ok: v.upgrade.Ok, FailedIds: v.upgrade.FailedIds}
	}
}

// watchState follows the active slot's process between two looks.
type watchState struct {
	pid      int
	restarts int
	known    bool
}

// Run is the loop of the manager. It ends with ctx and leaves the slots running: a
// restart of the agent must not cut a connection (the units are not tied to it).
func (m *Manager) Run(ctx context.Context) {
	m.loadState()
	m.lastQuiet = m.opt.Now()
	m.guardOn = m.guard()
	m.recover(ctx)
	tick := time.NewTicker(m.t.Tick)
	defer tick.Stop()
	var guardCh <-chan bool
	if m.opt.Guard != nil {
		guardCh = m.opt.Guard.Changed()
	}
	m.step(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			m.step(ctx)
		case g := <-guardCh:
			m.onGuard(ctx, g)
			m.step(ctx)
		case r := <-m.probeCh:
			m.onProbe(r)
		case <-tick.C:
			m.tick(ctx)
		}
	}
}

func (m *Manager) guard() bool { return m.opt.Guard != nil && m.opt.Guard.Check() }

// step takes the newest snapshot, if any, and reconciles.
func (m *Manager) step(ctx context.Context) {
	m.mu.Lock()
	s, fresh := m.snap, m.fresh
	m.fresh = false
	m.mu.Unlock()
	if fresh {
		m.cur = s
		m.wanted = map[string]*cfgRec{}
		m.order = m.order[:0]
		for _, c := range s.configs {
			m.wanted[c.hex] = c
			m.order = append(m.order, c.hex)
		}
		sort.Slice(m.order, func(i, j int) bool { return m.order[i] < m.order[j] })
		m.saveWanted(s.configs)
	}
	if m.cur == nil {
		return
	}
	m.reconcile(ctx)
	m.refreshView()
	m.publish()
}

// table is the allow list of the release the node runs, or the newest while it has
// none (7.2).
func (m *Manager) table() xrayschema.Table { return m.tableFor(m.version) }

func (m *Manager) tableFor(version string) xrayschema.Table {
	if t, err := xrayschema.For(version); err == nil {
		return t
	}
	return xrayschema.Newest()
}

func (m *Manager) probeURLs() []string {
	if m.cur != nil && len(m.cur.probe) > 0 {
		return m.cur.probe
	}
	return DefaultProbeURLs
}

// base is the input of the base configuration of a slot.
func (m *Manager) base(slot string) baseInput {
	var extra []netip.Addr
	if m.cur != nil {
		extra = append(extra, m.cur.addrs...)
	}
	if m.opt.NodeAddrs != nil {
		extra = append(extra, m.opt.NodeAddrs()...)
	}
	return baseInput{Slot: slot, APISock: m.opt.Layout.APISock(slot), Unbound: m.opt.Unbound, Blocked: blockedRanges(extra)}
}

// baseSignature changes when the base does (node addresses): 7.5 step 5 rebuilds.
func (m *Manager) baseSignature() string {
	var b strings.Builder
	for _, p := range m.base("a").Blocked {
		b.WriteString(p.String())
		b.WriteByte(',')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// ctlDo runs one ctl operation against a slot of a release.
func (m *Manager) ctlDo(ctx context.Context, version, slot, op string, tags []string, stdin []byte) error {
	return m.opt.Ctl.Do(ctx, sock.CtlRun{Version: version, Op: op, Slot: slot, Tags: tags, Stdin: stdin})
}

func (m *Manager) testConfig(ctx context.Context, version string, cfg []byte) error {
	return m.opt.Ctl.Do(ctx, sock.CtlRun{Version: version, Op: sock.OpTest, Stdin: cfg})
}

// errText is a short text for an error of the ctl, with the pasted values taken
// out, for the admin to read (7.5 step 1).
func errText(err error, fragment []byte) string {
	var ce *CtlError
	if asCtl(err, &ce) {
		return redact(ce.Text, fragment)
	}
	return "the Xray binary could not be run"
}

func asCtl(err error, target **CtlError) bool {
	for err != nil {
		if ce, ok := err.(*CtlError); ok {
			*target = ce
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// issueText is the text of the first thing xrayschema refused, with no value of the
// fragment: an Issue holds a path and a fixed message.
func issueText(r xrayschema.Result) string {
	var is []xrayschema.Issue
	is = append(is, r.Rejected...)
	is = append(is, r.Warnings...)
	if len(is) == 0 {
		return "refused"
	}
	t := is[0].Path + ": " + is[0].Msg
	return redact(t, nil)
}

func (m *Manager) setStatus(id string, kind hubv1.XrayConfigStateKind, err, hash string) {
	m.status[id] = &cfgStatus{kind: kind, err: err, hash: hash}
}

// running finds a config in the active slot's running set.
func (m *Manager) running(id string) *runRec {
	for i := range m.st.Running {
		if m.st.Running[i].ID == id {
			return &m.st.Running[i]
		}
	}
	return nil
}

func (m *Manager) dropRunning(id string) {
	out := m.st.Running[:0]
	for _, r := range m.st.Running {
		if r.ID != id {
			out = append(out, r)
		}
	}
	m.st.Running = out
}

func (m *Manager) setFault(f hubv1.NodeFault, on bool) {
	if m.opt.Faults != nil {
		m.opt.Faults.Set(f, on)
	}
}

// refreshView rebuilds what Heartbeat reports.
func (m *Manager) refreshView() {
	v := &hbView{version: m.version}
	ids := make([]string, 0, len(m.status))
	for id := range m.status {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := m.status[id]
		raw, _ := hex.DecodeString(id)
		sum, _ := hex.DecodeString(s.hash)
		x := &hubv1.XrayConfigState{Id: raw, State: s.kind, Error: s.err}
		if len(sum) == 32 {
			x.FragmentSha256 = sum
		}
		if r := m.running(id); r != nil && (s.kind == hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_APPLIED ||
			s.kind == hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_LAST_GOOD) {
			x.Healthy = m.effectiveHealthy(id)
			if h := m.hl[id]; h != nil {
				x.LatencyMs = h.published
			}
			if h, err := hex.DecodeString(r.Hash); err == nil && len(h) == 32 {
				x.FragmentSha256 = h
			}
		}
		if m.stuck.marked(id) && x.Error == "" {
			x.Error = "stuck"
		}
		v.configs = append(v.configs, x)
	}
	if len(v.configs) > 64 {
		v.configs = v.configs[:64]
	}
	v.locations = m.locationHealth()
	v.upgrade = m.upgradeView()
	m.view.set(v)
}

// effectiveHealthy is what dns and the hub are told: the probes' verdict, unless the
// guard is off, Xray is down or the remote is marked stuck (6.4, 5.5).
func (m *Manager) effectiveHealthy(id string) bool {
	h := m.hl[id]
	return h != nil && h.healthy && m.guardOn && m.slotUp && !m.downFault && !m.stuck.marked(id)
}

type locAgg struct {
	healthy bool
	prio    uint32
	lat     uint32
	set     bool
}

// locationHealth is the per-location report of 6.4: healthy when one of the configs
// is; its latency the best of the healthy configs of the lowest priority number.
func (m *Manager) locationHealth() []*hubv1.LocationHealth {
	agg := map[uint32]*locAgg{}
	for _, r := range m.st.Running {
		a := agg[r.Location]
		if a == nil {
			a = &locAgg{}
			agg[r.Location] = a
		}
		if !m.effectiveHealthy(r.ID) {
			continue
		}
		lat := uint32(0)
		if h := m.hl[r.ID]; h != nil {
			lat = h.published
		}
		switch {
		case !a.set || r.Priority < a.prio:
			a.healthy, a.set, a.prio, a.lat = true, true, r.Priority, lat
		case r.Priority == a.prio && lat < a.lat:
			a.lat = lat
		}
	}
	locs := make([]uint32, 0, len(agg))
	for l := range agg {
		locs = append(locs, l)
	}
	sort.Slice(locs, func(i, j int) bool { return locs[i] < locs[j] })
	var out []*hubv1.LocationHealth
	for _, l := range locs {
		if l > 0xFFFF {
			continue
		}
		out = append(out, &hubv1.LocationHealth{Location: l, Healthy: agg[l].healthy, LatencyMs: agg[l].lat})
	}
	return out
}

// publish sends the whole list to dns when it differs from the last one (6.4).
func (m *Manager) publish() {
	if m.opt.Publish == nil {
		return
	}
	l := &sock.Locations{Guard: m.guardOn && m.slotUp}
	if m.slotUp && m.guardOn {
		l.Direct = socksAddr(m.st.Slot, DirectPort)
	}
	running := append([]runRec(nil), m.st.Running...)
	sort.Slice(running, func(i, j int) bool { return running[i].ID < running[j].ID })
	for _, r := range running {
		id, _ := hex.DecodeString(r.ID)
		if len(id) != 16 {
			continue
		}
		var lat uint32
		if h := m.hl[r.ID]; h != nil {
			lat = h.published
		}
		l.Configs = append(l.Configs, sock.LocationConfig{
			ID: id, Location: r.Location, Socks: socksAddr(m.st.Slot, r.Port), Exit: exitOf(r.ID, r.Frag),
			Priority: r.Priority, Healthy: m.effectiveHealthy(r.ID), LatencyMS: lat,
		})
	}
	for _, r := range m.st.Retired {
		l.Draining = append(l.Draining, socksAddr(m.st.Slot, r.Rec.Port))
	}
	if d := m.st.Drain; d != nil {
		l.Draining = append(l.Draining, socksAddr(d.Slot, DirectPort))
		for _, r := range d.Running {
			l.Draining = append(l.Draining, socksAddr(d.Slot, r.Port))
		}
	}
	if len(l.Draining) > sock.MaxDraining {
		l.Draining = l.Draining[:sock.MaxDraining]
	}
	b, _ := json.Marshal(l)
	if bytes.Equal(b, m.lastPub) {
		return
	}
	if err := m.opt.Publish(&sock.Msg{Type: sock.TypeLocations, Locations: l}); err != nil {
		return // the message is refused whole; the next change tries again
	}
	m.lastPub = b
}

// location_down alert and the xray_down fault are decided on each tick.
func (m *Manager) tickAlerts() {
	now := m.opt.Now()
	have := map[uint32]bool{}
	for _, lh := range m.locationHealth() {
		have[lh.Location] = true
		if lh.Healthy {
			delete(m.noHealthy, lh.Location)
			m.alerted[lh.Location] = false
			continue
		}
		since, ok := m.noHealthy[lh.Location]
		if !ok {
			m.noHealthy[lh.Location] = now
		} else if now.Sub(since) >= m.t.LocationDown && !m.alerted[lh.Location] {
			m.alerted[lh.Location] = true
			m.opt.Alert.Alert(alert.Alert{Code: "location_down"})
		}
	}
	for l := range m.noHealthy {
		if !have[l] {
			delete(m.noHealthy, l)
			delete(m.alerted, l)
		}
	}
}
