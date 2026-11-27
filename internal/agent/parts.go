package agent

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// The seams of P4b (p4b-proxy 17). The parts of the agent that B3 to B6p build, the
// proxy link, the Xray manager, the block process's agent side and the peer
// server, meet the built agent only here, so none of those packages edits the
// agent's own files and each is tested against fakes of the others.

// Part is one of those parts, as the agent runs it.
//
// Run is started with the agent and ends with its context. Config gets each
// applied NodeConfig with its Xray fragments (the agent stores and hands dns a
// stripped copy, 7.5), and only hands it on: the part must copy what it needs and
// return quickly, because the config worker waits for it. The same config version
// can arrive again once per run, when the hub resends it to a new stream, so Config
// must be idempotent. Heartbeat fills the part's fields in the Heartbeat that is
// due. It reads atomics and takes no lock that the part's own work holds (L11): a
// Heartbeat that waited for an apply or a fetch would make the node look silent.
//
// A panic in a part costs that call and nothing else.
type Part interface {
	Run(ctx context.Context)
	Config(nc *hubv1.NodeConfig)
	Heartbeat(hb *hubv1.Heartbeat)
}

// Guard is the nftables guard of 5.5 as the Xray manager sees it: Check reads the
// rules back now, Changed reports each change of that answer. B4 makes it; B5 alone
// starts and stops slots and writes `guard`.
type Guard interface {
	Check() bool
	Changed() <-chan bool
}

// Faults is the set of node faults the Heartbeat reports (3.4). A fault stays while
// its condition holds, so a part sets it on when the condition starts and off when
// it ends; the agent sends the set on every Heartbeat. The zero value is empty and
// ready. Set and List take no lock.
type Faults struct {
	bits atomic.Uint32
}

// NewFaults returns an empty set. Make one before the parts and give it to them
// and to Config.Faults.
func NewFaults() *Faults { return &Faults{} }

// maxFault is the highest NodeFault value that fits the bit set; the enum stops at
// 5 and p6-ops starts at 6, so 31 leaves room.
const maxFault = 31

// Set turns a fault on or off. A value outside the enum's range is ignored, so a
// part built against a newer shared than the hub's cannot make a Heartbeat that the
// hub refuses (the hub refuses an unknown fault).
func (f *Faults) Set(fault hubv1.NodeFault, on bool) {
	if fault <= 0 || fault > maxFault || !validFault(fault) {
		return
	}
	bit := uint32(1) << uint(fault)
	if on {
		f.bits.Or(bit)
	} else {
		f.bits.And(^bit)
	}
}

func validFault(fault hubv1.NodeFault) bool {
	_, ok := hubv1.NodeFault_name[int32(fault)]
	return ok
}

// Has reports whether a fault is set.
func (f *Faults) Has(fault hubv1.NodeFault) bool {
	return fault > 0 && fault <= maxFault && f.bits.Load()&(1<<uint(fault)) != 0
}

// List is the set, in ascending order and with no value twice, as the Heartbeat
// needs it.
func (f *Faults) List() []hubv1.NodeFault {
	b := f.bits.Load()
	var out []hubv1.NodeFault
	for v := hubv1.NodeFault(1); v <= maxFault; v++ {
		if b&(1<<uint(v)) != 0 {
			out = append(out, v)
		}
	}
	return out
}

// DNS is the parts' way to agent.sock. It exists before the agent does, so parts
// built first can hold it, and the agent binds it to its socket server in Run.
// Until then, and while no dns is connected, Publish records a state slot for the
// next connection and Send reports false.
type DNS struct {
	mu   sync.Mutex
	srv  *sock.Server
	subs []func(*sock.Msg)
	// held are the state slots published before the server existed.
	held []*sock.Msg
}

// Publish sets a state slot of agent.sock (`locations`): dns gets it now if it is
// connected, and with every later snapshot.
func (d *DNS) Publish(m *sock.Msg) error {
	d.mu.Lock()
	srv := d.srv
	if srv == nil {
		d.held = append(d.held, m)
	}
	d.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Publish(m)
}

// Send queues an event (`grant_in`, `grant_sent`) and reports whether it was
// queued. An event that was not is lost, and its sender has a rule for that.
func (d *DNS) Send(m *sock.Msg) bool {
	d.mu.Lock()
	srv := d.srv
	d.mu.Unlock()
	return srv != nil && srv.Send(m)
}

// Subscribe registers f for the P4b messages dns sends (`grant_res`, `grant_out`,
// `proxy_state`). It is called on the socket's reader goroutine and must not block.
func (d *DNS) Subscribe(f func(*sock.Msg)) {
	d.mu.Lock()
	d.subs = append(slices.Clone(d.subs), f)
	d.mu.Unlock()
}

// bind attaches the server and sends what was published before it existed.
func (d *DNS) bind(srv *sock.Server) {
	d.mu.Lock()
	d.srv = srv
	held := d.held
	d.held = nil
	d.mu.Unlock()
	for _, m := range held {
		_ = srv.Publish(m)
	}
}

func (d *DNS) dispatch(m *sock.Msg) {
	d.mu.Lock()
	subs := d.subs
	d.mu.Unlock()
	for _, f := range subs {
		func() {
			defer func() { _ = recover() }()
			f(m)
		}()
	}
}

// partsConfig hands an applied NodeConfig on to every part.
func (a *Agent) partsConfig(nc *hubv1.NodeConfig) {
	for _, p := range a.cfg.Parts {
		func() {
			defer func() { _ = recover() }()
			p.Config(nc)
		}()
	}
}

// partsHeartbeat lets every part fill the Heartbeat, then adds the fault set.
// Each part works on a copy that is kept only when it still validates: the hub
// refuses a whole Heartbeat that fails its door and then judges the node silent, so
// one part's bad field must cost that part's fields and not the node's report.
func (a *Agent) partsHeartbeat(hb *hubv1.Heartbeat) *hubv1.Heartbeat {
	cur := hb
	for _, p := range a.cfg.Parts {
		try := proto.Clone(cur).(*hubv1.Heartbeat)
		ok := func() (ok bool) {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			p.Heartbeat(try)
			return wire.ValidateHeartbeat(try) == nil
		}()
		if ok {
			cur = try
		}
	}
	// The set is the one source of faults: a part says "on" and "off" to Faults, so
	// two parts cannot send the same value twice.
	cur.Faults = a.cfg.Faults.List()
	return cur
}

// runPart runs one part. A part that panics ends alone: the agent keeps serving, and
// the part's own supervision (systemd for its unit, the fault it raised) tells the
// admin. It is not restarted here, because a part that panics at once would spin.
func runPart(ctx context.Context, p Part) {
	defer func() { _ = recover() }()
	p.Run(ctx)
}
