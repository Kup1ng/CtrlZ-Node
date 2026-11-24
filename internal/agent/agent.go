// Package agent is the agent role: the node's side of the panel link (p4-nodes
// 7.1 and 7.3). It holds the Control stream to the hub, applies the config log
// through the store, runs the table writer for pushed zone tables, keeps the facts
// that decide the free DNS path, hands all of it to the dns process over the
// agent socket, probes the other nodes, and looks after the host: the two Unbound
// processes, the nftables table, chrony and the checks of 7.3.
//
// The agent never serves a query. Everything a client sees comes from dns, which
// keeps its last image when the agent is away.
//
// Where each rule of SC 8a.11 is kept:
//   - L10, Heartbeats beside other traffic: package control (one writer, a due
//     Heartbeat before everything, bounded drop queues), uploads in package upload
//     on a connection of their own.
//   - L11, the receive loop: package control reads only; this package supplies the
//     callbacks. The push worker is the table writer (push.Writer serialises it
//     with Apply's SetMembership); the log worker is the only caller of Apply; a
//     HeadNotice only raises highHead.
//   - L6, transfers apart from Control: three connections (hubconn.Role).
package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/control"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/freefacts"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/probe"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/telem"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/transfer"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/unbound"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/upload"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/zonekeys"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/blobfetch"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/push"
)

// Config is what the agent needs to run. Production fills it from agent.conf and
// the real system (FromEnv); tests fill it with fakes.
type Config struct {
	// Root is /var/lib/ctrlz.
	Root string
	// Conf is the parsed /etc/ctrlz/agent.conf, and ConfPath its path (the store
	// reads dns_bind_ip from it for the Plain-only fallback).
	Conf     conf.Agent
	ConfPath string
	// SockPath is /run/ctrlz/agent.sock; SockGroup its group ("ctrlz"); PeerCheck the
	// SO_PEERCRED check (sock.UIDCheck of ctrlz-dns).
	SockPath, SockGroup string
	PeerCheck           sock.PeerCheck
	// Version is the node version reported in the Heartbeat.
	Version string

	// Identity holds the node key and certificate and the hub pin. Dial makes a
	// connection for a role; tests give the fake hub's.
	Identity *hubconn.Identity
	Dial     func(role hubconn.Role) (*grpc.ClientConn, error)
	// TrustRoot is the root of trust for heads and pushes.
	TrustRoot func() (*signv1.Root, error)

	Runner sysx.Runner
	Files  sysx.Files
	Alert  alert.Alerter
	Now    func() time.Time

	// Unbound's parameters; zero values take the defaults.
	UnboundIdentified, UnboundFree unbound.Params
	UnboundBinary, UnboundControl  string
	// ConntrackMax is the nf_conntrack_max the agent insists on (T-374 measures it).
	ConntrackMax int
	// SkipHostChecks leaves out the periodic host checks.
	SkipHostChecks bool
	// NoSystem skips Unbound, nftables and chrony (a lab run, and most tests).
	NoSystem bool

	// FSHook is a fault-injection point on the node's own disk writes, for tests.
	FSHook func(path string, s fsx.Step) error

	// Tuning, for tests: zero takes the production value.
	HeartbeatEvery    time.Duration
	ServerTimeTimeout time.Duration
	TableEvery        time.Duration
	ProbeEvery        time.Duration
	ProbeTimeout      time.Duration
	CountersPoll      time.Duration
	ActivityEvery     time.Duration
	TransferIdle      time.Duration
	RetryEvery        time.Duration
	LogPoll           time.Duration
	HostEvery         time.Duration // the host checks and the nftables retry, default 1 minute
	UnboundEvery      time.Duration // supervision pass over the two Unbound units, default 10 s
	UnboundStartRetry time.Duration // retry of an Unbound start that did not happen, default 1 minute
	FetchBatch        int           // entries per FetchEntries call, default 200
	HeldBundleGrace   time.Duration // how long a CertBundle may wait for its zone before it alerts, default 30 s
	ControlTrace      func(*hubv1.NodeMessage)
	ProbeDial         func(ctx context.Context, network, addr string) (net.Conn, error)
	ProbePorts        [2]int // DoT, DoH
}

// Agent is a running agent.
type Agent struct {
	cfg Config
	now func() time.Time

	root  *store.Root
	fsw   *fsx.Writer
	push  *push.Writer
	app   *apply.Applier
	ncs   *nodecfg.Store
	zk    *zonekeys.Store
	facts *freefacts.Facts
	free  *telem.FreeCounters
	act   *telem.Activity
	probe *probe.Prober
	srv   *sock.Server
	ctl   *control.Client
	xfer  *transfer.Client
	upl   *upload.Uploader
	unb   *unbound.Supervisor
	al    alert.Alerter

	ctlPool, xferPool, uplPool *hubconn.Pool
	self                       zone.NodeID

	// Facts of the run, all atomics so a Heartbeat reads them under no lock.
	hubOffset   atomic.Int64 // seconds to add to the node clock to get the hub's (8a.4 Clock)
	lastST      atomic.Int64 // unix nanos of the last valid ServerTime, 0 before one
	streamUp    atomic.Bool
	downSince   atomic.Int64 // unix nanos since which no Control stream is open
	started     time.Time
	highHead    atomic.Uint64
	logWake     chan struct{}
	quarantined atomic.Uint32
	cfgVersion  atomic.Uint64
	cfgTaken    atomic.Bool // a NodeConfig from the hub has been taken in this run (its proof_key is the real one)
	unbVersion  atomic.Pointer[string]
	dnsStats    atomic.Pointer[statsAt]
	imageAcked  atomic.Pointer[string]
	freeValue   atomic.Pointer[policyv1.FreeDns]
	// imageAckSeq is the applied_seq of the image dns last confirmed it opened and serves
	// from (ImageAck). A revocation ends at this and nowhere earlier: AppliedSeq moves
	// before the image swap, a swap can fail, and dns can fail to open a published image,
	// and in each case the old image, which still serves what the entry changed, is the one
	// the revocation covers.
	imageAckSeq atomic.Uint64
	revPoke     chan struct{} // wakes the sweep when an ack may have ended revocations
	revSave     chan struct{} // wakes the writer of the revocation file
	tablePoke   chan struct{}

	nodeCfg atomic.Pointer[hubv1.NodeConfig] // the latest, with its real proof_key; memory only

	mu   sync.Mutex
	revs map[revKey]*policyv1.Revocation
	// revUnsynced are the keys loaded from disk, dated with the node clock before the
	// first ServerTime; rebaseLoadedRevocations moves them into hub time.
	revUnsynced map[revKey]struct{}
	revIDs      int // ids held in revs; a hint that keepRevocation makes exact when a bound is exceeded
	acmes       map[string]*hubv1.AcmeChallenge
	acmeSeq     map[string]uint64 // arrival order, breaks a tie in expiry when the bound is held
	acmeN       uint64
	zoneKeys    []*zonekeys.Cert
	drain       zone.Drain
	drainFor    *zone.Table
	lastPub     map[string]string // the last message published per slot, so only changes are published
	// pubMu orders every publish to dns: build, compare with lastPub and send are one step, so
	// two goroutines can never leave dns holding the older of two messages of a slot.
	pubMu  sync.Mutex
	headOK bool // GetHead has been learned this run
	// vhead and plan belong to the log worker alone (chain.go).
	vhead   signedHead
	plan    *chainPlan
	lastNft string // the nftables script last applied
	// drainSince is the Unix second the drain started, 0 when not draining.
	drainSince int64
	sysWakeCh  chan struct{}

	// certMu serialises a CertBundle with the pass that follows each NodeConfig
	// (prune the retired zones' keys, offer the held bundles again). The two arrive
	// on separate workers (L11), so a bundle can run before the NodeConfig that
	// names its zone: it is held under this lock and the NodeConfig's pass, which
	// takes the same lock after it has stored the config, always sees it.
	certMu  sync.Mutex
	pending []*heldBundle
	// dnsKey is what the dns process was started with: "" for the Plain-only
	// fallback, else the bind address of its NodeConfig. When a NodeConfig changes
	// it, dns is restarted (it binds its listeners once, at start).
	dnsKey     string
	dnsRestart atomic.Bool
}

// heldBundle is a CertBundle that was refused only because no NodeConfig names its
// zone yet.
type heldBundle struct {
	cb      *hubv1.CertBundle
	at      time.Time
	alerted bool
}

// maxHeldBundles bounds the bundles waiting for a NodeConfig.
const maxHeldBundles = 8

// revKey identifies a revocation: one config_log entry yields several (an
// endpoint kind and a claim kind share its seq, 5.5), so the seq alone does not.
type revKey struct {
	seq  uint64
	kind policyv1.RevocationKind
}

type statsAt struct {
	s  sock.Stats
	at time.Time
}

// New opens the store and builds the agent. It starts nothing: Run does.
func New(cfg Config) (*Agent, error) {
	if cfg.Alert == nil {
		cfg.Alert = alert.Discard{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Runner == nil || cfg.Files == nil {
		return nil, errors.New("agent: a Runner and Files are required")
	}
	if cfg.Identity == nil || cfg.Dial == nil || cfg.TrustRoot == nil {
		return nil, errors.New("agent: an Identity, a Dial and a TrustRoot are required")
	}
	if cfg.PeerCheck == nil {
		return nil, errors.New("agent: a peer check for the agent socket is required")
	}
	a := &Agent{cfg: cfg, now: cfg.Now, al: cfg.Alert, logWake: make(chan struct{}, 1), tablePoke: make(chan struct{}, 1), revPoke: make(chan struct{}, 1), revSave: make(chan struct{}, 1), sysWakeCh: make(chan struct{}, 1),
		revs: map[revKey]*policyv1.Revocation{}, revUnsynced: map[revKey]struct{}{}, acmes: map[string]*hubv1.AcmeChallenge{}, acmeSeq: map[string]uint64{}, lastPub: map[string]string{}}
	a.started = cfg.Now()
	a.downSince.Store(a.started.UnixNano())

	w := &fsx.Writer{Hook: cfg.FSHook}
	root, err := store.Open(cfg.Root, w)
	if err != nil {
		return nil, fmt.Errorf("agent: open the store: %w", err)
	}
	a.root = root
	a.fsw = w
	a.ncs = nodecfg.New(root.Path(store.DirConfig), w)
	if id, err := hex.DecodeString(cfg.Identity.NodeID()); err == nil && len(id) == 16 {
		copy(a.self[:], id)
	}
	a.loadServingConfig()
	a.loadRevocations()
	if _, err := os.Stat(a.dnsOwedPath()); err == nil {
		// a restart of dns the last run owed and did not make (see dnsOwedPath)
		a.dnsRestart.Store(true)
	}

	a.facts = freefacts.New(cfg.Now)
	a.free = telem.NewFreeCounters(cfg.Now, nil)
	a.act = telem.NewActivity(&recordLookup{a: a}, cfg.Now, nil)

	// The three connections: Control, transfers and uploads never share one.
	pool := func(r hubconn.Role) *hubconn.Pool {
		return hubconn.NewPool(func() (*grpc.ClientConn, error) { return cfg.Dial(r) })
	}
	a.ctlPool, a.xferPool, a.uplPool = pool(hubconn.RoleControl), pool(hubconn.RoleTransfer), pool(hubconn.RoleUpload)

	a.xfer = transfer.New(transfer.Config{Conn: a.xferPool, Root: cfg.TrustRoot, HubNow: a.hubNow, Idle: cfg.TransferIdle, Batch: cfg.FetchBatch})
	a.push = push.New(push.Config{Dir: root.Path(store.DirPush), W: w, Root: push.RootFunc(cfg.TrustRoot)})
	app, rep, err := apply.Open(apply.Config{
		Root: root, Fetcher: blobfetch.New(a.xfer), Tables: a.push, Snapshots: verifiedSnapshots{a: a},
		Head: a.headForApply,
		Now:  func() int64 { return a.now().Unix() },
	})
	if err != nil {
		return nil, fmt.Errorf("agent: open the applied state: %w", err)
	}
	a.app = app
	if len(rep.Load.Lost) > 0 {
		a.al.Alert(alert.Alert{Code: alert.StateDamaged, Detail: "the applied state was repaired at start"})
	}
	a.refreshAppliedViews()

	key, _ := cfg.Identity.Key().PrivateKey.(*ecdsa.PrivateKey)
	a.zk = &zonekeys.Store{Root: root, Key: key, Zones: a.zones, Now: cfg.Now}
	a.zoneKeys, _ = a.zk.LoadAll()

	a.probe = probe.New(probe.Config{
		Zone: func() string {
			if z := a.zones(); len(z) > 0 {
				return z[0]
			}
			return ""
		},
		Roots: a.probeRoots,
		Now:   cfg.Now, Every: cfg.ProbeEvery, Timeout: cfg.ProbeTimeout, Dial: cfg.ProbeDial,
		DoTPort: cfg.ProbePorts[0], DoHPort: cfg.ProbePorts[1],
	})
	a.syncProbeTargets()

	a.ctl = control.New(control.Config{
		HubFn: a.ctlPool.Client, Heartbeat: a.heartbeat, Now: cfg.Now,
		HeartbeatEvery: cfg.HeartbeatEvery, ServerTimeTimeout: cfg.ServerTimeTimeout, Trace: cfg.ControlTrace,
		CB: control.Callbacks{
			ServerTime: a.onServerTime, HeadNotice: a.onHeadNotice, FreeDNSOff: a.onFreeOff, StreamState: a.onStream,
			Push: a.onPush, Revocation: a.onRevocation, NodeConfig: a.onNodeConfig, CertBundle: a.onCertBundle, Acme: a.onAcme,
		},
	})
	a.upl = upload.New(upload.Config{Conn: a.uplPool, Counters: a.free, Activity: a.act,
		CountersPoll: cfg.CountersPoll, ActivityEvery: cfg.ActivityEvery})
	a.unb = unbound.New(unbound.Config{Runner: cfg.Runner, Files: cfg.Files, Alert: cfg.Alert, ConfDir: UnboundConfDir,
		Identified: a.unboundParams(unbound.Identified), Free: a.unboundParams(unbound.Free),
		Binary: cfg.UnboundBinary, Control: cfg.UnboundControl, Gate: a.coreGate, StartRetry: cfg.UnboundStartRetry})
	return a, nil
}

func (a *Agent) unboundParams(k unbound.Kind) unbound.Params {
	p := a.cfg.UnboundIdentified
	if k == unbound.Free {
		p = a.cfg.UnboundFree
	}
	if p.Kind == 0 {
		p = unbound.DefaultParams(k)
		if k == unbound.Free && a.cfg.Conf.FreeOutgoingInterface.IsValid() {
			p.OutgoingInterface = a.cfg.Conf.FreeOutgoingInterface
		}
	}
	return p
}

// loadServingConfig makes the NodeConfig of the start the one in memory (its
// proof_key is zero: the real one comes only from the hub, 7.2).
func (a *Agent) loadServingConfig() {
	s, err := a.ncs.LoadServing(a.cfg.ConfPath)
	if err != nil {
		a.al.Alert(alert.Alert{Code: alert.ConfigFallback, Detail: "no NodeConfig and no bind address"})
		return
	}
	if s.Source != nodecfg.Current {
		a.al.Alert(alert.Alert{Code: alert.ConfigFallback, Detail: "serving from " + s.Source.String()})
	}
	if s.Config != nil {
		a.nodeCfg.Store(s.Config)
		a.cfgVersion.Store(s.Config.Version)
		if s.Source != nodecfg.PlainOnly {
			a.dnsKey = dnsKeyOf(s.Config)
		}
	}
}

// dnsKeyOf is what a NodeConfig fixes in the dns process: the address its
// listeners bind to.
func dnsKeyOf(c *hubv1.NodeConfig) string {
	if ip, ok := addrOf(c.DnsBindIp); ok {
		return ip.String()
	}
	return ""
}

// Run starts everything and returns when ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	srv, err := sock.Listen(sock.ServerConfig{Path: a.cfg.SockPath, Group: a.cfg.SockGroup, Check: a.cfg.PeerCheck,
		RunID: uint64(a.started.UnixNano()), H: a.sockHandlers()})
	if err != nil {
		return fmt.Errorf("agent: the agent socket: %w", err)
	}
	a.srv = srv
	go srv.Serve(ctx)
	a.publishAll()

	var wg sync.WaitGroup
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	start(func() { a.ctl.Run(ctx) })
	start(func() { a.upl.Run(ctx) })
	start(func() { a.probe.Run(ctx) })
	start(func() { a.logLoop(ctx) })
	start(func() { a.tableLoop(ctx) })
	start(func() { a.sweepLoop(ctx) })
	start(func() { a.revSaveLoop(ctx) })
	start(func() { a.systemLoop(ctx) })
	start(func() { a.renewLoop(ctx) })
	<-ctx.Done()
	wg.Wait()
	srv.Close()
	a.ctlPool.Close()
	a.xferPool.Close()
	a.uplPool.Close()
	return nil
}

// probeRoots is the CA pool the probes trust: the roots of the stored bundle of
// the zone being probed in private-CA mode, and nil (the system's public roots)
// when that zone has none, which is public-CA mode. Only that zone's bundle counts:
// the root of another zone's private CA (a placeholder zone, one on its way out)
// must not make every probe of a public-CA zone fail its chain.
func (a *Agent) probeRoots() *x509.CertPool {
	zs := a.zones()
	if len(zs) == 0 {
		return nil
	}
	a.mu.Lock()
	var certs []*zonekeys.Cert
	for _, c := range a.zoneKeys {
		if zonekeys.Live(c.SANs, zs[:1]) {
			certs = append(certs, c)
		}
	}
	a.mu.Unlock()
	if len(certs) == 0 {
		return nil
	}
	pool := zonekeys.CARoots(certs)
	if len(pool.Subjects()) == 0 { //nolint:staticcheck // only the count is wanted
		return nil
	}
	return pool
}
