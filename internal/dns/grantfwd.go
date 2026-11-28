package dns

import (
	"crypto/rand"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/grant"
)

// The pair side of Grants (p4b-proxy 4.5): what dns hands the agent to forward to
// the pair node (grant_out), and what the agent hands dns from it (grant_in).

const (
	fwdRate        = 500 // a second, each way (12)
	fwdPerTick     = fwdRate / 50
	fwdAnswerWait  = 15 * time.Second
	waitAccepted   = 60 * time.Second
	waitRefused    = 30 * time.Second
	maxWaitRefused = 1024
	grantInAnswer  = 8 * time.Second // the agent answers a grant_in as accepted=false after this
)

type waitFwd struct {
	fwd      *peerv1.GrantForward
	sender   [16]byte
	accepted bool
	until    time.Time
}

// offer queues a forward of a holder decided here: the peer holds no copy, or its
// copy is past half its life (the table said so).
func (g *Grants) offer(sv *Serving, st *epState, src netip.Addr, qn *names.Name, out grant.Outcome, h *grant.Holder) {
	var gid [16]byte
	_, _ = rand.Read(gid[:])
	bits := byte(32)
	if src.Is6() {
		bits = 128
	}
	f := &peerv1.GrantForward{
		GrantId: gid[:], EndpointId: st.id[:], SourcePrefix: append(src.AsSlice(), bits), NameWire: qn.Wire(),
		Location: uint32(out.Location), GrantKind: uint32(out.Kind), ExpiresAt: h.Expires,
		SenderConfigSeq: sv.img.Seq(), DialHostWire: []byte(out.Dial),
	}
	if h.Client != ([16]byte{}) {
		f.ClientHash = h.Client[:]
	}
	b, err := proto.Marshal(f)
	if err != nil {
		return
	}
	it := &grant.FwdItem{ID: gid, Payload: b, Account: h.Account, New: h.SentAt == 0,
		Name: append([]byte(nil), qn.Wire()...), Src: src, Endpoint: st.id, Client: h.Client}
	if !g.fwd.Offer(it) {
		g.table.Sent(it.Name, src, st.id, h.Client, sock.GrantUnsent)
	}
}

// sendForwards moves queued forwards to the agent at the rate of 500 a second; a
// forward the agent cannot take is unsent (4.5).
func (g *Grants) sendForwards() {
	now := g.h.now()
	for i := 0; i < fwdPerTick; i++ {
		it, ok := g.fwd.Next(now)
		if !ok {
			return
		}
		if !g.send(&sock.Msg{Type: sock.TypeGrantOut, GrantOut: &sock.GrantOut{Forward: it.Payload}}) {
			g.fwd.Answer(it.ID)
			g.table.Sent(it.Name, it.Src, it.Endpoint, it.Client, sock.GrantUnsent)
		}
	}
}

func (g *Grants) expireForwards() {
	for _, it := range g.fwd.Expire(g.h.now(), fwdAnswerWait) {
		g.table.Sent(it.Name, it.Src, it.Endpoint, it.Client, sock.GrantUnsent)
	}
}

// OnAgent takes the P4b messages the agent sends dns.
func (g *Grants) OnAgent(m *sock.Msg) {
	switch m.Type {
	case sock.TypeLocations:
		if m.Locations != nil {
			g.OnLocations(m.Locations)
		}
	case sock.TypeGrantSent:
		if m.GrantSent != nil && len(m.GrantSent.GrantID) == 16 {
			if it, ok := g.fwd.Answer([16]byte(m.GrantSent.GrantID)); ok {
				g.table.Sent(it.Name, it.Src, it.Endpoint, it.Client, m.GrantSent.Result)
			}
		}
	case sock.TypeGrantIn:
		if m.GrantIn == nil || len(m.GrantIn.Sender) != 16 {
			return
		}
		select {
		case g.fsem <- struct{}{}:
		default:
			g.replyIn(m.GrantIn.Forward, false) // too many at once: a refusal the sender retries
			return
		}
		in := m.GrantIn
		go func() {
			defer func() { <-g.fsem }()
			g.replyIn(in.Forward, g.acceptForward(in.Forward, [16]byte(in.Sender)))
		}()
	}
}

// replyIn answers a grant_in with the id inside the forward.
func (g *Grants) replyIn(b []byte, ok bool) {
	f := &peerv1.GrantForward{}
	if proto.Unmarshal(b, f) != nil || len(f.GrantId) != 16 {
		return
	}
	g.send(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: f.GrantId, Accepted: ok}})
}

// inRate is the receiving rate of 500 a second.
func (g *Grants) inRate() bool {
	sec := g.h.now().Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inSec != sec {
		g.inSec, g.inN = sec, 0
	}
	g.inN++
	return g.inN <= fwdRate
}

// acceptForward is the receiver's order of 4.5: validation, the rate, then a look at
// the sender and the pair, 4b for the source, never-proxied and AcceptGrant. A
// receiver behind the sender's config_seq decides with what it has, keeps an accepted
// Grant short, and decides again when its image reaches that seq.
func (g *Grants) acceptForward(b []byte, sender [16]byte) bool {
	f := &peerv1.GrantForward{}
	if proto.Unmarshal(b, f) != nil || wire.ValidateGrantForward(f, g.h.now().Unix()) != nil {
		g.table.Count("fwd_invalid")
		return false
	}
	if !g.inRate() {
		g.table.Count("fwd_rate")
		return false
	}
	sv := g.h.srv.Load()
	if sv == nil {
		return false
	}
	behind := f.SenderConfigSeq > sv.img.Seq()
	ok := g.decideForward(f, sender, behind)
	if behind {
		g.mu.Lock()
		if len(g.waiting) < maxWaitRefused*2 {
			until := g.h.now().Add(waitRefused)
			if ok {
				until = g.h.now().Add(waitAccepted)
			}
			g.waiting = append(g.waiting, waitFwd{fwd: f, sender: sender, accepted: ok, until: until})
		}
		g.mu.Unlock()
	}
	if !ok {
		g.table.Count("fwd_refused")
	}
	return ok
}

// decideForward judges one forward and, when it passes, writes the holder. short
// keeps the holder for 60 s only.
func (g *Grants) decideForward(f *peerv1.GrantForward, sender [16]byte, short bool) bool {
	h := g.h
	sv := h.srv.Load()
	if sv == nil || len(f.EndpointId) != 16 {
		return false
	}
	now := h.now()
	ep, ok := sv.img.ByEndpointID([16]byte(f.EndpointId))
	if !ok {
		return false
	}
	st := sv.endpoint(ep)
	if st.degraded || st.view == nil {
		return false
	}
	rec := st.rec
	self := g.facts().Self

	// The sender is the pair peer of the Endpoint's pair in this node's own image: the
	// agent cannot judge it for a forward that is ahead of its image.
	pt := sv.img.PairTable()
	p := pairOf(pt, rec.PairId)
	if p == nil || len(p.Primary) != 16 || len(p.Fallback) != 16 {
		return false
	}
	a, b := [16]byte(p.Primary), [16]byte(p.Fallback)
	if self == sender || !(self == a && sender == b || self == b && sender == a) {
		return false
	}
	live := false
	for _, n := range pt.GetNodes() {
		if len(n.NodeId) == 16 && [16]byte(n.NodeId) == sender && len(n.SpkiSha256) != 0 {
			live = true
		}
	}
	if !live {
		return false
	}

	// 4b for the source: Require Authorized IPs, admin_state, revocations.
	pfx := f.SourcePrefix
	src, _ := netip.AddrFromSlice(pfx[:len(pfx)-1])
	src = src.Unmap()
	applied := sv.img.Seq()
	if rec.AdminState != commonv1.AdminState_ADMIN_STATE_ENABLED ||
		h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, st.id, applied, now) {
		return false
	}
	var claim [16]byte
	if ce, ok := sv.prefixes.lookup(src); ok && ce.EndpointID == st.id && rec.LegacyDns &&
		!h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_CLAIM, ce.ID, applied, now) {
		claim = ce.ID
	}
	if rec.RequireAuthorizedIps && claim == ([16]byte{}) && !inAny(st.authorized, src) {
		return false
	}
	qn, err := names.FromCanonicalWire(f.NameWire)
	if err != nil {
		return false
	}
	if f.GrantKind == uint32(grant.KindRedirect) && h.cfg.NeverProxied(qn) {
		return false
	}
	var client [16]byte
	if len(f.ClientHash) == 16 {
		client = [16]byte(f.ClientHash)
		known := false
		for _, c := range rec.Clients {
			if len(c.ClientHash) == 16 && [16]byte(c.ClientHash) == client {
				known = true
			}
		}
		if !known {
			return false // a client of another Endpoint: the stack cannot be judged
		}
	}

	in := &sharedpolicy.Input{Name: qn, QType: sharedpolicy.TypeA, Now: now.Unix(), Src: src,
		Protocol: evalProtocol(listen.TCP), EndpointID: st.id}
	if h.cfg.Geo != nil {
		in.SrcCountry = h.cfg.Geo.Country(src)
	}
	stack, _ := sharedpolicy.SelectStack(st.view, client, now.Unix())
	env := h.envFor(sv, st)
	var dial names.Name
	if len(f.DialHostWire) > 0 {
		if dial, err = names.FromCanonicalWire(f.DialHostWire); err != nil {
			return false
		}
	}
	offer := sharedpolicy.GrantOffer{Kind: uint8(f.GrantKind), Location: uint16(f.Location), DialHost: dial}
	fin, ok := sharedpolicy.AcceptGrant(in, stack, &env, h.cfg.Resolver, offer)
	if !ok {
		return false
	}
	out := grant.Outcome{Kind: uint8(f.GrantKind), Dial: string(f.DialHostWire)}
	if out.Kind == grant.KindRedirect {
		out.Location = uint16(f.Location)
		dn := qn
		if len(f.DialHostWire) > 0 {
			dn = dial
		}
		if g.unsafe(dn, sharedpolicy.ResolveParams{}) {
			return false
		}
	} else {
		out.Page = fin.PageHash
	}
	req := &grant.PutReq{
		Name: qn.Wire(), Source: src, ASN: g.asn(src), Out: out,
		Holder: holderFor(st, &fin, claim, client, sender), Validated: true, // the sender writes only holders of validated sources
		EndpointCap: int(rec.GrantCap), Privileged: claim != ([16]byte{}) || inAny(st.authorized, src),
		ExpiresAt: time.Unix(f.ExpiresAt, 0), Joins: g.joins(in, stack, &env),
	}
	if short {
		req.Short = waitAccepted
	}
	res := g.table.Put(req)
	if res.Verdict == grant.Ok && out.Kind == grant.KindRedirect {
		g.warmA(dialOrName(qn, out))
	}
	return res.Verdict == grant.Ok
}

// redecide judges the offers that waited for the image: each is decided again once
// the image is at or above its sender's seq. A forward that was taken for a minute
// and is now refused is removed.
func (g *Grants) redecide() {
	sv := g.h.srv.Load()
	if sv == nil {
		return
	}
	now := g.h.now()
	seq := sv.img.Seq()
	g.mu.Lock()
	var ready []waitFwd
	keep := g.waiting[:0]
	for _, w := range g.waiting {
		switch {
		case !now.Before(w.until):
		case w.fwd.SenderConfigSeq <= seq:
			ready = append(ready, w)
		default:
			keep = append(keep, w)
		}
	}
	g.waiting = keep
	g.mu.Unlock()
	for _, w := range ready {
		ok := g.decideForward(w.fwd, w.sender, false)
		if w.accepted && !ok {
			var c [16]byte
			if len(w.fwd.ClientHash) == 16 {
				c = [16]byte(w.fwd.ClientHash)
			}
			pfx := w.fwd.SourcePrefix
			if a, okA := netip.AddrFromSlice(pfx[:len(pfx)-1]); okA {
				g.table.Drop(w.fwd.NameWire, a.Unmap(), [16]byte(w.fwd.EndpointId), c, w.sender)
			}
		}
	}
}
