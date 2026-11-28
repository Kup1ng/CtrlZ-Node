// Package peer is the agent's side of the pair: the PeerNode gRPC server and client
// of p4b-proxy 4.5. A node forwards the Grants it decided to its pair peer here, so
// that a device that moves to the other node of the pair finds its Grant already
// written. It is the agent that speaks to the peer, never dns: dns only hands the
// agent a grant_out and takes a grant_in (agent.sock, 2.1), and keeps the table and
// the decisions.
//
// Trust is the applied log entry's PairTable alone. A connection is accepted from the
// address of a live node of it, and both ends verify the other's certificate against
// the node CA, its subject against the node id they expect and its key against the
// spki_sha256 of that node. When a later entry empties that key (a revocation), the
// open connections are judged again and the peer's calls end.
//
// The part implements agent.Part by shape (Run, Config, Heartbeat) and holds no agent
// type, so the agent can import it. The agent hands it a DNS and an Env.
package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// The limits of 4.5 and 12 (D31).
const (
	// Port is the TCP port of the peer listener on dns_bind_ip.
	Port = 9444
	// MaxConns and MaxConnsPerNode bound the connections the server accepts, counted
	// before TLS so a flood from a listed address cannot cost a handshake each.
	MaxConns        = 8
	MaxConnsPerNode = 2
	// Rate is the forwards a second each way, with a burst of the same size.
	Rate = 500
	// MaxUnanswered is the forwards that wait for an answer, each way (and for each
	// sender on the receiving side).
	MaxUnanswered = 256

	defaultTick     = time.Second
	defaultAckWait  = 8 * time.Second  // receiver: how long dns may take to answer a grant_in
	defaultSentWait = 10 * time.Second // sender: how long a peer may take to answer a forward
	dialTimeout     = 5 * time.Second
	maxBackoff      = 30 * time.Second
	queueLen        = 512
)

// Env is what the part reads of the agent. The agent supplies it after it is built
// (the part is made before the agent, as every part is), so the reads are small and
// lock-free where the agent allows it.
type Env interface {
	// Table is the PairTable of the applied log entry, nil before there is one. The
	// same pointer is returned until a new entry is applied.
	Table() *policyv1.PairTable
	// EndpointPair is the pair_id of an Endpoint's record in the applied state (empty
	// when the record names none, which means the global pair), and whether the node
	// knows the Endpoint at all.
	EndpointPair(endpoint []byte) (pairID []byte, known bool)
	// AppliedSeq is the node's applied config_seq.
	AppliedSeq() uint64
	// HubNow is the hub's clock in Unix seconds, the clock a Grant's expires_at is in.
	HubNow() int64
	// BindIP is dns_bind_ip: the address the listener binds and the client dials from.
	BindIP() netip.Addr
}

// DNS is the part of agent.DNS the peer uses: events to dns and the messages dns sends.
type DNS interface {
	Send(m *sock.Msg) bool
	Subscribe(f func(*sock.Msg))
}

// Config is what the part needs from the node's identity and the environment.
type Config struct {
	Self  zone.NodeID
	Cert  func() tls.Certificate // the node certificate and key; it changes at a renewal
	Roots *x509.CertPool         // the node CA
	DNS   DNS

	// The rest is for tests; the zero value is production.
	Now         func() time.Time
	Port        int
	Listen      func(ip netip.Addr, port int) (net.Listener, error)
	Dial        func(ctx context.Context, local, remote netip.Addr, port int) (net.Conn, error)
	Tick        time.Duration
	AckWait     time.Duration
	SentWait    time.Duration
	DialTimeout time.Duration
}

// Peer is the part. Make it with New, give it the agent's Env with SetEnv, and run it.
type Peer struct {
	cfg Config
	env atomic.Pointer[Env]
	vw  atomic.Pointer[view]
	vmu sync.Mutex

	wake chan struct{}

	// The server.
	srv     *grpc.Server
	lisMu   sync.Mutex
	lis     net.Listener
	lisIP   netip.Addr
	lisFail time.Time // the last failed bind, so a bad address is retried every 5 s and not every tick

	cmu    sync.Mutex
	conns  map[*peerConn]struct{}
	perNod map[zone.NodeID]int

	imu    sync.Mutex
	pendIn map[string]*inPend
	rateIn map[zone.NodeID]*bucket

	// The client.
	outq    chan *peerv1.GrantForward
	omu     sync.Mutex
	cur     *outConn
	pendOut map[string]*outPend
	rateOut bucket
	retryAt time.Time
	backoff time.Duration

	stat Stats
}

// Stats are counters for tests and for the journal. They hold no name, address or id.
type Stats struct {
	Accepted, Refused, Forwarded, Unsent, Revoked atomic.Uint64
}

// New returns a part that does nothing until it has an Env.
func New(cfg Config) *Peer {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Roots == nil {
		cfg.Roots = x509.NewCertPool() // an empty pool trusts nothing; nil would mean the system's roots
	}
	if cfg.Port == 0 {
		cfg.Port = Port
	}
	if cfg.Tick == 0 {
		cfg.Tick = defaultTick
	}
	if cfg.AckWait == 0 {
		cfg.AckWait = defaultAckWait
	}
	if cfg.SentWait == 0 {
		cfg.SentWait = defaultSentWait
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = dialTimeout
	}
	if cfg.Listen == nil {
		cfg.Listen = func(ip netip.Addr, port int) (net.Listener, error) {
			return net.Listen("tcp", netip.AddrPortFrom(ip, uint16(port)).String())
		}
	}
	if cfg.Dial == nil {
		cfg.Dial = func(ctx context.Context, local, remote netip.Addr, port int) (net.Conn, error) {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: local.AsSlice()}}
			return d.DialContext(ctx, "tcp", netip.AddrPortFrom(remote, uint16(port)).String())
		}
	}
	p := &Peer{cfg: cfg, wake: make(chan struct{}, 1),
		conns: map[*peerConn]struct{}{}, perNod: map[zone.NodeID]int{},
		pendIn: map[string]*inPend{}, rateIn: map[zone.NodeID]*bucket{},
		outq: make(chan *peerv1.GrantForward, queueLen), pendOut: map[string]*outPend{},
		rateOut: bucket{rate: Rate, burst: Rate}}
	if cfg.DNS != nil {
		cfg.DNS.Subscribe(p.onDNS)
	}
	return p
}

// SetEnv gives the part the agent's view of its state. Until then Run does nothing.
func (p *Peer) SetEnv(e Env) {
	p.env.Store(&e)
	p.poke()
}

// Stats returns the counters.
func (p *Peer) Stats() *Stats { return &p.stat }

// Config is called with each applied NodeConfig. The part reads dns_bind_ip from the
// Env, which has the stored config at start too (the hub's resend arrives later), so
// this only wakes the loop to look at it.
func (p *Peer) Config(*hubv1.NodeConfig) { p.poke() }

// Heartbeat adds nothing: what the pair view says of the peer is the prober's.
func (p *Peer) Heartbeat(*hubv1.Heartbeat) {}

func (p *Peer) poke() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *Peer) environ() Env {
	if e := p.env.Load(); e != nil {
		return *e
	}
	return nil
}

// view returns the view of the applied table, built again when the agent has applied
// a new one.
func (p *Peer) view() *view {
	e := p.environ()
	if e == nil {
		return newView(nil, p.cfg.Self)
	}
	pt := e.Table()
	if v := p.vw.Load(); v != nil && v.pt == pt {
		return v
	}
	p.vmu.Lock()
	defer p.vmu.Unlock()
	if v := p.vw.Load(); v != nil && v.pt == pt {
		return v
	}
	v := newView(pt, p.cfg.Self)
	p.vw.Store(v)
	return v
}

// Run serves and forwards until ctx ends.
func (p *Peer) Run(ctx context.Context) {
	p.srv = grpc.NewServer(
		grpc.Creds(newServerCreds(p)),
		grpc.MaxRecvMsgSize(16<<10),
		grpc.MaxConcurrentStreams(2),
		grpc.ConnectionTimeout(dialTimeout),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 10 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
	)
	peerv1.RegisterPeerNodeServer(p.srv, &service{p: p})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); p.sendLoop(ctx) }()

	t := time.NewTicker(p.cfg.Tick)
	defer t.Stop()
	var last *view
	for {
		p.reconcileListener(ctx)
		if v := p.view(); v != last {
			// A new applied table: connections whose peer it no longer trusts end now.
			last = v
			p.recheck(v)
		}
		p.sweep()
		select {
		case <-ctx.Done():
			p.stop()
			wg.Wait()
			return
		case <-t.C:
		case <-p.wake:
		}
	}
}

func (p *Peer) stop() {
	p.lisMu.Lock()
	if p.lis != nil {
		_ = p.lis.Close()
		p.lis = nil
	}
	p.lisMu.Unlock()
	if p.srv != nil {
		p.srv.Stop()
	}
	p.dropOut(nil)
}

// reconcileListener makes the listener the one that dns_bind_ip asks for. On a change
// the new listener is opened first and the old one closed after it (9.1: the peer
// listener moves in the order of the DNS one), so the peer is never without an
// address; connections already accepted live on until they end.
func (p *Peer) reconcileListener(ctx context.Context) {
	e := p.environ()
	if e == nil || ctx.Err() != nil {
		return
	}
	want := e.BindIP()
	p.lisMu.Lock()
	defer p.lisMu.Unlock()
	if !want.IsValid() || (p.lis != nil && p.lisIP == want) {
		return
	}
	if !p.lisFail.IsZero() && p.cfg.Now().Sub(p.lisFail) < 5*time.Second {
		return
	}
	l, err := p.cfg.Listen(want, p.cfg.Port)
	if err != nil {
		p.lisFail = p.cfg.Now()
		// The address is not logged: the text says only that the bind failed, and the
		// agent's bind_error already tells the admin which address.
		log.Printf("peer: the listener could not be opened; the old one stays")
		return
	}
	p.lisFail = time.Time{}
	old := p.lis
	p.lis, p.lisIP = l, want
	go func() { _ = p.srv.Serve(&acceptCheck{Listener: l, p: p}) }()
	if old != nil {
		_ = old.Close()
	}
}

// bucket is a token bucket for the rate of 12.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	init   bool
}

func (b *bucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.init {
		b.tokens, b.last, b.init = b.burst, now, true
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(b.burst, b.tokens+d*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
