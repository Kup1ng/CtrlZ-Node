package xray

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// The rig runs the manager against fakes of everything outside the process: the
// control socket and the Xray binary behind it, the units, the prober, the guard.
// No real Xray runs anywhere in these tests; what a real binary does is for the lab.

// fakeCtl records every call and plays the binary: a `test` of a text that holds
// BADFRAG exits 23 and echoes the text (as a real `run -test` echoes what it chokes
// on), an `ado` of one that holds APIFAIL fails.
type fakeCtl struct {
	mu    sync.Mutex
	calls []sock.CtlRun
	// onCall may change a call's outcome.
	onCall func(r sock.CtlRun) error
}

func (f *fakeCtl) Do(_ context.Context, r sock.CtlRun) error {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	hook := f.onCall
	f.mu.Unlock()
	if hook != nil {
		if err := hook(r); err != nil {
			return err
		}
	}
	if r.Op == sock.OpTest && bytes.Contains(r.Stdin, []byte("BADFRAG")) {
		i := bytes.Index(r.Stdin, []byte("BADFRAG"))
		return &CtlError{Exit: 23, Text: "failed to load config near " + string(r.Stdin[max(0, i-8):min(len(r.Stdin), i+30)])}
	}
	if r.Op == sock.OpAddOut && bytes.Contains(r.Stdin, []byte("APIFAIL")) {
		return &CtlError{Exit: 1, Text: "api error"}
	}
	return nil
}

func (f *fakeCtl) ops(op string) []sock.CtlRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sock.CtlRun
	for _, c := range f.calls {
		if c.Op == op {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeCtl) opNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.Op)
	}
	return out
}

type fakeSlot struct {
	active   bool
	pid      int
	restarts int
	result   string
	exit     int
	starts   int
	stops    int
}

type fakeUnits struct {
	mu    sync.Mutex
	slots map[string]*fakeSlot
	pids  int
}

func newUnits() *fakeUnits {
	return &fakeUnits{slots: map[string]*fakeSlot{"a": {}, "b": {}}, pids: 100}
}

func (u *fakeUnits) Start(_ context.Context, slot string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.slots[slot]
	if !s.active {
		u.pids++
		s.pid, s.active = u.pids, true
	}
	s.starts++
	return nil
}

func (u *fakeUnits) Stop(_ context.Context, slot string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.slots[slot]
	s.active, s.pid, s.result, s.exit = false, 0, "success", 0
	s.stops++
	return nil
}

func (u *fakeUnits) Status(_ context.Context, slot string) (UnitStatus, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.slots[slot]
	return UnitStatus{Active: s.active, PID: s.pid, Restarts: s.restarts, Result: s.result, ExitStatus: s.exit}, nil
}

// crash plays systemd: the process ended with this result and was started again.
func (u *fakeUnits) crash(slot, result string, exit int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.pids++
	s := u.slots[slot]
	s.pid, s.restarts, s.result, s.exit, s.active = u.pids, s.restarts+1, result, exit, true
}

func (u *fakeUnits) get(slot string) fakeSlot {
	u.mu.Lock()
	defer u.mu.Unlock()
	return *u.slots[slot]
}

type fakeProber struct {
	units *fakeUnits
	mu    sync.Mutex
	// failing sockets (ip:port prefix match) and slots whose probes fail.
	failProbe map[string]bool
	failGreet map[string]bool
	probes    atomic.Int64
}

func (p *fakeProber) Probe(_ context.Context, socks string, _ []string) (time.Duration, bool) {
	p.probes.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	host, _, _ := strings.Cut(socks, ":")
	return 20 * time.Millisecond, !p.failProbe[socks] && !p.failProbe[host]
}

func (p *fakeProber) Greet(_ context.Context, addr string) bool {
	p.mu.Lock()
	fail := p.failGreet[addr]
	p.mu.Unlock()
	host, _, _ := strings.Cut(addr, ":")
	slot := "a"
	if host == slotBAddr {
		slot = "b"
	}
	return !fail && p.units.get(slot).active
}

func (p *fakeProber) setFail(m map[string]bool, k string, v bool) {
	p.mu.Lock()
	m[k] = v
	p.mu.Unlock()
}

type fakeGuard struct {
	on atomic.Bool
	ch chan bool
}

func (g *fakeGuard) Check() bool          { return g.on.Load() }
func (g *fakeGuard) Changed() <-chan bool { return g.ch }
func (g *fakeGuard) set(v bool)           { g.on.Store(v); g.ch <- v }

type fakeSockets struct {
	mu sync.Mutex
	c  SockCounts
}

func (f *fakeSockets) Count(context.Context) (SockCounts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.c, nil
}

func (f *fakeSockets) set(c SockCounts) { f.mu.Lock(); f.c = c; f.mu.Unlock() }

type pubBox struct {
	mu   sync.Mutex
	last *sock.Locations
	n    int
}

func (p *pubBox) publish(m *sock.Msg) error {
	if err := sock.Check(m); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	b, _ := json.Marshal(m.Locations)
	var cp sock.Locations
	_ = json.Unmarshal(b, &cp)
	p.last, p.n = &cp, p.n+1
	return nil
}

func (p *pubBox) get() *sock.Locations {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

type rig struct {
	t       *testing.T
	m       *Manager
	ctl     *fakeCtl
	units   *fakeUnits
	pr      *fakeProber
	guard   *fakeGuard
	faults  *agent.Faults
	pub     *pubBox
	alerts  *alert.Memory
	sockets *fakeSockets
	layout  xrayrun.Layout
	dir     string
	cancel  context.CancelFunc
	done    chan struct{}
	ver     uint64
	opts    Options
}

func fastTiming() Timing {
	return Timing{
		Tick: 20 * time.Millisecond, TrialWait: 60 * time.Millisecond, Drain: 400 * time.Millisecond,
		ProbeEvery: 100 * time.Millisecond, HangEvery: 40 * time.Millisecond, QuietHour: time.Hour,
		SwitchWait: 600 * time.Millisecond, StartWait: 400 * time.Millisecond, CandidateEvery: 20 * time.Millisecond,
		SocketEvery: 20 * time.Millisecond, ResolveEvery: time.Hour, NoSearch: time.Hour, LocationDown: time.Hour,
	}
}

func newRig(t *testing.T, mod func(*Timing)) *rig {
	t.Helper()
	dir := t.TempDir()
	r := &rig{t: t, dir: dir, ctl: &fakeCtl{}, units: newUnits(), faults: agent.NewFaults(), pub: &pubBox{},
		alerts: &alert.Memory{}, sockets: &fakeSockets{}}
	r.layout = xrayrun.Layout{Etc: filepath.Join(dir, "etc"), Lib: filepath.Join(dir, "lib"), Run: filepath.Join(dir, "run")}
	if err := os.MkdirAll(filepath.Join(r.layout.Etc, "versions"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.writeAllow("v26.11.9")
	r.pr = &fakeProber{units: r.units, failProbe: map[string]bool{}, failGreet: map[string]bool{}}
	r.guard = &fakeGuard{ch: make(chan bool, 4)}
	r.guard.on.Store(true)
	tm := fastTiming()
	if mod != nil {
		mod(&tm)
	}
	r.opts = Options{
		Layout: r.layout, StateDir: filepath.Join(dir, "state"), Ctl: r.ctl, Units: r.units, Prober: r.pr,
		Guard: r.guard, Faults: r.faults, Publish: r.pub.publish, Alert: r.alerts, Sockets: r.sockets,
		Unbound: "127.0.0.10:5300", BootID: func() string { return "boot-1" }, Timing: tm,
	}
	r.m = New(r.opts)
	return r
}

func (r *rig) writeAllow(vs ...string) {
	r.t.Helper()
	if err := os.WriteFile(r.layout.Allow(), []byte(strings.Join(vs, "\n")+"\n"), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() { defer close(r.done); r.m.Run(ctx) }()
	r.t.Cleanup(r.stop)
}

func (r *rig) stop() {
	if r.cancel != nil {
		r.cancel()
		<-r.done
		r.cancel = nil
	}
}

// config sends a NodeConfig that holds exactly these configs.
func (r *rig) config(cs ...*hubv1.XrayConfig) { r.configWith(nil, cs...) }

func (r *rig) configWith(mod func(*hubv1.NodeConfig), cs ...*hubv1.XrayConfig) {
	r.ver++
	nc := &hubv1.NodeConfig{Version: r.ver, XrayConfigs: cs}
	if mod != nil {
		mod(nc)
	}
	r.m.Config(nc)
}

func cid(n byte) []byte { return bytes.Repeat([]byte{n}, 16) }

func xc(n byte, loc uint32, prio uint32, frag string, accepted ...string) *hubv1.XrayConfig {
	return &hubv1.XrayConfig{Id: cid(n), Location: loc, Tag: fmt.Sprintf("c%d", n), Priority: prio, Enabled: true,
		FragmentJson: []byte(frag), AcceptedUnknown: accepted}
}

// vless is a fragment that the allow list of v26.11.9 passes as it stands.
func vless(host string) string {
	return fmt.Sprintf(`{"outbounds":[{"protocol":"vless","settings":{"address":%q,"port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`, host)
}

// eventually polls until f holds.
func (r *rig) eventually(what string, f func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("timed out waiting for: %s", what)
}

func (r *rig) locs() *sock.Locations { return r.pub.get() }

func (r *rig) healthyConfigs() int {
	l := r.locs()
	if l == nil {
		return 0
	}
	n := 0
	for _, c := range l.Configs {
		if c.Healthy {
			n++
		}
	}
	return n
}

func (r *rig) hb() *hubv1.Heartbeat {
	h := &hubv1.Heartbeat{}
	r.m.Heartbeat(h)
	return h
}

func (r *rig) stateOf(n byte) (hubv1.XrayConfigStateKind, string) {
	for _, c := range r.hb().XrayConfigs {
		if bytes.Equal(c.Id, cid(n)) {
			return c.State, c.Error
		}
	}
	return 0, "<none>"
}

func (r *rig) waitState(n byte, kind hubv1.XrayConfigStateKind) {
	r.t.Helper()
	r.eventually(fmt.Sprintf("config %d in state %v", n, kind), func() bool { k, _ := r.stateOf(n); return k == kind })
}

func (r *rig) slotJSON(slot string) string {
	b, _ := os.ReadFile(r.layout.SlotJSON(slot))
	return string(b)
}

func hexID(n byte) string { return hex.EncodeToString(cid(n)) }

// restart plays a restart of the agent: a new manager over the same files, units and
// fakes, while the slots keep running.
func (r *rig) restart() {
	r.stop()
	r.m = New(r.opts)
	r.start()
}

// The helpers below read the files the manager writes (atomically), never its
// memory, so the test goroutine and the loop share nothing.

func (r *rig) persisted() persisted {
	var p persisted
	b, _ := os.ReadFile(r.m.statePath("state.json"))
	_ = json.Unmarshal(b, &p)
	return p
}

func (r *rig) activeSlot() string {
	if s := r.persisted().Slot; s != "" {
		return s
	}
	return "a"
}

func (r *rig) runningRec(id string) *runRec {
	for _, x := range r.persisted().Running {
		if x.ID == id {
			c := x
			return &c
		}
	}
	return nil
}

func (r *rig) good(id string) (goodRec, bool) {
	var g goodRec
	b, err := os.ReadFile(r.m.goodPath(id))
	if err != nil || json.Unmarshal(b, &g) != nil {
		return goodRec{}, false
	}
	return g, true
}
