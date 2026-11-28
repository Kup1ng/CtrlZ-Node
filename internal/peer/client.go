package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"

	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// outConn is the client's one connection and Forward stream to the pair peer.
type outConn struct {
	cc     *grpc.ClientConn
	st     peerv1.PeerNode_ForwardClient
	cancel context.CancelFunc
	node   zone.NodeID
	spki   [32]byte // the key the peer showed, for the recheck of a new table
}

// outPend is a forward sent and not yet answered.
type outPend struct {
	oc *outConn
	at time.Time
}

// onDNS is the subscription to agent.sock. It runs on the socket's reader goroutine
// and never blocks: a grant_out is queued for the sender, and a grant_res is routed to
// its stream.
func (p *Peer) onDNS(m *sock.Msg) {
	switch m.Type {
	case sock.TypeGrantOut:
		if m.GrantOut == nil {
			return
		}
		g := new(peerv1.GrantForward)
		if proto.Unmarshal(m.GrantOut.Forward, g) != nil || len(g.GrantId) != 16 {
			return // no id to report on; dns has its own timeout for a forward that never answers
		}
		select {
		case p.outq <- g:
		default:
			p.sent(g.GrantId, sock.GrantUnsent)
		}
	case sock.TypeGrantRes:
		if m.GrantRes != nil {
			p.onRes(m.GrantRes)
		}
	}
}

// sent reports what became of a forward (grant_sent). Best effort: a lost report only
// leaves the holder as it was, which dns offers again later.
func (p *Peer) sent(gid []byte, result string) {
	if result == sock.GrantUnsent {
		p.stat.Unsent.Add(1)
	}
	p.cfg.DNS.Send(&sock.Msg{Type: sock.TypeGrantSent, GrantSent: &sock.GrantSent{GrantID: gid, Result: result}})
}

// sendLoop takes the queued forwards one at a time and sends them to the pair peer.
func (p *Peer) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case g := <-p.outq:
			p.sendOne(ctx, g)
		}
	}
}

func (p *Peer) sendOne(ctx context.Context, g *peerv1.GrantForward) {
	e := p.environ()
	if e == nil {
		p.sent(g.GrantId, sock.GrantUnsent)
		return
	}
	if wire.ValidateGrantForward(g, e.HubNow()) != nil {
		p.sent(g.GrantId, sock.GrantUnsent)
		return
	}
	// Only to this node's pair peer, never to a revoked node, and only for an Endpoint
	// of that pair. An Endpoint that is none of these is refused, not unsent: nothing
	// will change that within the minute that an unsent forward is offered again.
	v := p.view()
	peer := v.peerLive()
	if peer == nil {
		p.sent(g.GrantId, sock.GrantUnsent)
		return
	}
	pairID, known := e.EndpointPair(g.EndpointId)
	if !known || !v.inOurPair(pairID) {
		p.sent(g.GrantId, sock.GrantRefused)
		return
	}
	if !p.rateOut.allow(p.cfg.Now()) {
		p.sent(g.GrantId, sock.GrantUnsent)
		return
	}
	oc := p.connection(ctx, peer)
	if oc == nil {
		p.sent(g.GrantId, sock.GrantUnsent)
		return
	}
	p.omu.Lock()
	if len(p.pendOut) >= MaxUnanswered {
		p.omu.Unlock()
		p.sent(g.GrantId, sock.GrantUnsent)
		return
	}
	if _, dup := p.pendOut[string(g.GrantId)]; dup {
		p.omu.Unlock()
		p.sent(g.GrantId, sock.GrantUnsent)
		return
	}
	p.pendOut[string(g.GrantId)] = &outPend{oc: oc, at: p.cfg.Now()}
	p.omu.Unlock()
	if err := oc.st.Send(g); err != nil {
		p.dropOut(oc)
		return
	}
	p.stat.Forwarded.Add(1)
}

// connection returns the open stream to peer, or opens one. After a failure the next
// attempt waits 1 s, doubling to 30 s, and a forward that finds the wait still running
// is unsent at once: the queue must not stand behind a dial that cannot work.
func (p *Peer) connection(ctx context.Context, peer *node) *outConn {
	p.omu.Lock()
	if oc := p.cur; oc != nil {
		p.omu.Unlock()
		return oc
	}
	if p.cfg.Now().Before(p.retryAt) {
		p.omu.Unlock()
		return nil
	}
	p.omu.Unlock()

	oc, err := p.dial(ctx, peer)

	p.omu.Lock()
	defer p.omu.Unlock()
	if err != nil {
		if p.backoff == 0 {
			p.backoff = time.Second
		} else {
			p.backoff = min(p.backoff*2, maxBackoff)
		}
		p.retryAt = p.cfg.Now().Add(p.backoff)
		return nil
	}
	p.backoff, p.retryAt = 0, time.Time{}
	p.cur = oc
	go p.readAcks(oc)
	return oc
}

func (p *Peer) dial(ctx context.Context, peer *node) (*outConn, error) {
	e := p.environ()
	local := e.BindIP()
	if !local.IsValid() || !peer.addr.IsValid() {
		return nil, errors.New("peer: no address")
	}
	oc := &outConn{node: peer.id}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
		// The name is never checked: the certificate names a node id, not a host, and
		// VerifyConnection below holds the whole check (4.5). Set so that crypto/tls
		// does not run its own, which would ask for serverAuth.
		ServerName:         "ctrlz-peer",
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection does the verification
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := p.cfg.Cert()
			return &c, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			leaf, err := p.verifyPeer(cs, peer.id)
			if err != nil {
				return err
			}
			oc.spki = spkiOf(leaf)
			return nil
		},
	})
	cc, err := grpc.NewClient("passthrough:///ctrlz-peer",
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return p.cfg.Dial(ctx, local, peer.addr, p.cfg.Port)
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: p.cfg.DialTimeout}),
	)
	if err != nil {
		return nil, err
	}
	cc.Connect()
	wctx, wcancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer wcancel()
	for s := cc.GetState(); s != connectivity.Ready; s = cc.GetState() {
		if s == connectivity.TransientFailure || s == connectivity.Shutdown || !cc.WaitForStateChange(wctx, s) {
			_ = cc.Close()
			return nil, errors.New("peer: the peer is not reachable")
		}
	}
	sctx, cancel := context.WithCancel(ctx)
	st, err := peerv1.NewPeerNodeClient(cc).Forward(sctx)
	if err != nil {
		cancel()
		_ = cc.Close()
		return nil, err
	}
	oc.cc, oc.st, oc.cancel = cc, st, cancel
	return oc, nil
}

// readAcks reports each GrantAck as a grant_sent. When the stream ends, whatever it
// still waited for is unsent.
func (p *Peer) readAcks(oc *outConn) {
	for {
		a, err := oc.st.Recv()
		if err != nil {
			p.dropOut(oc)
			return
		}
		p.omu.Lock()
		pe := p.pendOut[string(a.GrantId)]
		if pe != nil && pe.oc == oc {
			delete(p.pendOut, string(a.GrantId))
		} else {
			pe = nil
		}
		p.omu.Unlock()
		if pe == nil {
			continue // an answer to nothing we sent, or one that was reported unsent already
		}
		if a.Accepted {
			p.sent(a.GrantId, sock.GrantAccepted)
		} else {
			p.sent(a.GrantId, sock.GrantRefused)
		}
	}
}

// dropOut closes the connection oc and reports its waiting forwards unsent. A nil oc
// is the current one, and with none open every waiting forward: a stop.
func (p *Peer) dropOut(oc *outConn) {
	p.omu.Lock()
	if oc == nil {
		oc = p.cur
	}
	if oc != nil && p.cur == oc {
		p.cur = nil
	}
	var ids []string
	for k, pe := range p.pendOut {
		if oc == nil || pe.oc == oc {
			ids = append(ids, k)
			delete(p.pendOut, k)
		}
	}
	p.omu.Unlock()
	if oc != nil {
		oc.cancel()
		_ = oc.cc.Close()
	}
	for _, k := range ids {
		p.sent([]byte(k), sock.GrantUnsent)
	}
}

// recheckOut closes the client connection when the table no longer trusts it: the peer
// was revoked or is no longer our pair peer.
func (p *Peer) recheckOut(v *view) {
	p.omu.Lock()
	oc := p.cur
	p.omu.Unlock()
	if oc == nil {
		return
	}
	if peer := v.peerLive(); peer == nil || peer.id != oc.node || !v.trusts(oc.node, oc.spki) {
		p.stat.Revoked.Add(1)
		p.dropOut(oc)
	}
}

// sweepOut reports a forward that the peer has not answered in time as unsent. The
// stream stays: a slow answer is not a broken peer, and the answer that comes late is
// dropped.
func (p *Peer) sweepOut(now time.Time) {
	var ids []string
	p.omu.Lock()
	for k, pe := range p.pendOut {
		if now.Sub(pe.at) >= p.cfg.SentWait {
			ids = append(ids, k)
			delete(p.pendOut, k)
		}
	}
	p.omu.Unlock()
	for _, k := range ids {
		p.sent([]byte(k), sock.GrantUnsent)
	}
}

// sweep runs the timeouts of both directions.
func (p *Peer) sweep() {
	now := p.cfg.Now()
	p.sweepIn(now)
	p.sweepOut(now)
}
