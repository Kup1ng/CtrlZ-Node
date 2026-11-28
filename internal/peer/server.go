package peer

import (
	"context"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/enroll"
)

// service is the PeerNode server. Revoke is not implemented, on purpose: a receiver
// could check nothing in it, so one lying node could cut every proxied connection of
// its peer. A hard disable reaches a node by the hub's Revocation or by the table
// entry (4.5), and the embedded Unimplemented answers the call.
type service struct {
	peerv1.UnimplementedPeerNodeServer
	p *Peer
}

// inStream is the answer side of one Forward stream.
type inStream struct {
	node zone.NodeID
	// spki is the key the connection was verified with. The table is judged against it at
	// every forward, as the client side does with outConn, so a peer key that the applied
	// table has replaced stops at its next message and not at the next tick.
	spki [32]byte
	out  chan *peerv1.GrantAck
	n    atomic.Int32 // forwards handed to dns and not yet answered
}

// inPend is a forward that waits for dns's grant_res.
type inPend struct {
	st *inStream
	at time.Time
}

func (s *inStream) ack(gid []byte, ok bool) {
	// Never blocks: the stream's writer drains this, and a full queue means the peer
	// is not reading its answers, which its own unanswered cap (256) ends.
	select {
	case s.out <- &peerv1.GrantAck{GrantId: gid, Accepted: ok}:
	default:
	}
}

// nodeOfStream is the node id and the key the stream's connection showed. Both were
// verified in the handshake; they are read back here to be judged again under the table
// of the moment.
func nodeOfStream(ctx context.Context) (zone.NodeID, [32]byte, bool) {
	pr, ok := grpcpeer.FromContext(ctx)
	if !ok {
		return zone.NodeID{}, [32]byte{}, false
	}
	ti, ok := pr.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return zone.NodeID{}, [32]byte{}, false
	}
	leaf := ti.State.PeerCertificates[0]
	raw, ok := enroll.ParseNodeID(leaf.Subject.CommonName)
	if !ok || len(raw) != 16 {
		return zone.NodeID{}, [32]byte{}, false
	}
	return zone.NodeID(raw), spkiOf(leaf), true
}

// Forward takes the peer's Grants. Each is judged here in the order of 4.5 (the shape,
// the sender, the rate), handed to dns as a grant_in, and answered with dns's verdict.
// A forward that fails a check is answered refused and writes nothing.
func (sv *service) Forward(stream grpc.BidiStreamingServer[peerv1.GrantForward, peerv1.GrantAck]) error {
	p := sv.p
	node, spki, ok := nodeOfStream(stream.Context())
	if !ok {
		return status.Error(codes.PermissionDenied, "no peer identity")
	}
	// Only the pair peer forwards. The address check already admits no other node; this
	// stays for a connection that was admitted under an earlier table (the pair moved), so
	// that its stream ends here, before one of its messages is read.
	v0 := p.view()
	if pl := v0.peerLive(); pl == nil || pl.id != node {
		return status.Error(codes.PermissionDenied, "not the pair peer")
	}
	if !v0.trusts(node, spki) {
		return status.Error(codes.PermissionDenied, "key not in the applied table")
	}
	st := &inStream{node: node, spki: spki, out: make(chan *peerv1.GrantAck, queueLen)}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	defer p.endStream(st)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case a := <-st.out:
				if stream.Send(a) != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		g, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := p.takeForward(st, g); err != nil {
			return err
		}
	}
}

// takeForward judges one forward. It returns an error only for a message that cannot
// be answered (no usable grant_id), which ends the stream.
func (p *Peer) takeForward(st *inStream, g *peerv1.GrantForward) error {
	e := p.environ()
	if e == nil {
		return status.Error(codes.Unavailable, "not ready")
	}
	if len(g.GetGrantId()) != 16 {
		return status.Error(codes.InvalidArgument, "bad grant_id")
	}
	gid := g.GrantId
	refuse := func() { p.stat.Refused.Add(1); st.ack(gid, false) }

	// 1. The shape. ValidateGrantForward holds the floors of the prefix (a full-length
	// one), the folded names, the 5 h bound on expires_at and the rest of 3.4.
	if wire.ValidateGrantForward(g, e.HubNow()) != nil {
		refuse()
		return nil
	}
	// 2. The sender is the pair peer, and the Endpoint is of that pair in our own
	// applied state. A node that is behind the sender's config_seq may not know the
	// Endpoint yet, or know it with an older pair: it cannot judge that part, so it
	// passes the forward on, and dns holds it until its image catches up (4.5, Sequence).
	// The sender being our pair peer needs no entry and is judged always.
	v := p.view()
	peer := v.peerLive()
	if peer == nil || peer.id != st.node {
		refuse()
		return nil
	}
	// The key the connection was verified with is still the one the table holds for the
	// peer. The stream ends, as the client side drops a connection: a replaced key is not a
	// forward to answer.
	if !v.trusts(st.node, st.spki) {
		return status.Error(codes.PermissionDenied, "key not in the applied table")
	}
	// sender_config_seq is the sender's own claim and proves nothing: a lying peer can
	// always claim "ahead of you" and so skip the Endpoint-and-pair check here. No bound
	// is put on it, because any bound either leaves the liar a number inside it or refuses
	// an honest peer whose receiver has not heard the hub's latest head. The real gate for
	// a forward that claims to be ahead is dns's hold-and-judge (4.5 Sequence: 60 s, at
	// most 1024 refused), which judges the pair itself once its image reaches that seq.
	behind := g.SenderConfigSeq > e.AppliedSeq()
	if !behind {
		pairID, known := e.EndpointPair(g.EndpointId)
		if !known || !v.inOurPair(pairID) {
			refuse()
			return nil
		}
	}
	// 3. The rate of 12, kept for each sender.
	if !p.rateFor(st.node).allow(p.cfg.Now()) {
		refuse()
		return nil
	}
	// The unanswered cap, and a grant_id that is already waiting: the answer is looked up
	// by it, so two waiting under one id would answer one for the other.
	if st.n.Load() >= MaxUnanswered {
		refuse()
		return nil
	}
	b, err := proto.Marshal(g)
	if err != nil {
		refuse()
		return nil
	}
	p.imu.Lock()
	if _, dup := p.pendIn[string(gid)]; dup {
		p.imu.Unlock()
		refuse()
		return nil
	}
	p.pendIn[string(gid)] = &inPend{st: st, at: p.cfg.Now()}
	p.imu.Unlock()
	st.n.Add(1)
	if !p.cfg.DNS.Send(&sock.Msg{Type: sock.TypeGrantIn, GrantIn: &sock.GrantIn{Sender: append([]byte(nil), st.node[:]...), Forward: b}}) {
		// dns is away, or its queue is full: refused, and the sender offers it again
		// (10 min after a refusal at the earliest).
		if p.takePend(gid) != nil {
			refuse()
		}
	}
	return nil
}

func (p *Peer) rateFor(n zone.NodeID) *meter {
	p.imu.Lock()
	defer p.imu.Unlock()
	b := p.rateIn[n]
	if b == nil {
		b = &meter{rate: Rate, burst: Rate}
		p.rateIn[n] = b
	}
	return b
}

// takePend removes and returns the waiting forward of a grant_id, nil when none waits.
func (p *Peer) takePend(gid []byte) *inPend {
	p.imu.Lock()
	pe := p.pendIn[string(gid)]
	delete(p.pendIn, string(gid))
	p.imu.Unlock()
	if pe != nil {
		pe.st.n.Add(-1)
	}
	return pe
}

// endStream forgets what a closed stream still waited for: dns's late answers find
// nothing and are dropped.
func (p *Peer) endStream(st *inStream) {
	p.imu.Lock()
	for k, pe := range p.pendIn {
		if pe.st == st {
			delete(p.pendIn, k)
		}
	}
	p.imu.Unlock()
}

// onRes is dns's answer to a grant_in.
func (p *Peer) onRes(r *sock.GrantRes) {
	pe := p.takePend(r.GrantID)
	if pe == nil {
		return
	}
	if r.Accepted {
		p.stat.Accepted.Add(1)
	} else {
		p.stat.Refused.Add(1)
	}
	pe.st.ack(r.GrantID, r.Accepted)
}

// sweepIn answers refused to a forward that dns did not answer in time.
func (p *Peer) sweepIn(now time.Time) {
	var late []*inPend
	var ids [][]byte
	p.imu.Lock()
	for k, pe := range p.pendIn {
		if now.Sub(pe.at) >= p.cfg.AckWait {
			late = append(late, pe)
			ids = append(ids, []byte(k))
			delete(p.pendIn, k)
		}
	}
	p.imu.Unlock()
	for i, pe := range late {
		pe.st.n.Add(-1)
		p.stat.Refused.Add(1)
		pe.st.ack(ids[i], false)
	}
}
