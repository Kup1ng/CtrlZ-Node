package agent

import (
	"net/netip"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/enroll"
	"github.com/Kup1ng/CtrlZ-Node/internal/peer"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// addPeerPart makes the pair node of 4.5 (internal/peer) and adds it to cfg.Parts. It
// needs the identity, so the boot calls it after cfg.Identity is set and before New.
// The part is made before the agent, as every part is, and gets its view of the agent
// from bindPeerPart once the agent exists. The DNS and the Faults that parts share are
// made here when the boot has made none yet.
func addPeerPart(cfg *Config) *peer.Peer {
	if cfg.Faults == nil {
		cfg.Faults = NewFaults()
	}
	if cfg.DNS == nil {
		cfg.DNS = &DNS{}
	}
	id := cfg.Identity
	raw, ok := enroll.ParseNodeID(id.NodeID())
	if !ok {
		return nil // New refuses a certificate with no node id; nothing to add before it says so
	}
	pp := peer.New(peer.Config{
		Self:  zone.NodeID(raw),
		Cert:  id.Key,
		Roots: id.CA(),
		DNS:   cfg.DNS,
	})
	cfg.Parts = append(cfg.Parts, pp)
	return pp
}

// bindPeerPart gives the part what it reads of the built agent.
func bindPeerPart(pp *peer.Peer, a *Agent) {
	if pp != nil {
		pp.SetEnv(peerEnv{a})
	}
}

// peerEnv is peer.Env over the agent. Every read is lock-free or takes the applied
// state's own lock for a moment, and none runs on the Control receive loop (L11).
type peerEnv struct{ a *Agent }

// Table is the PairTable of the applied log entry (never a push: SC 8a.7), the same
// pointer until the next entry is applied.
func (e peerEnv) Table() *policyv1.PairTable { return e.a.push.Member() }

func (e peerEnv) EndpointPair(endpoint []byte) (pairID []byte, known bool) {
	if len(endpoint) != 16 {
		return nil, false
	}
	var id [16]byte
	copy(id[:], endpoint)
	e.a.app.Inspect(func(ap *store.Applied) {
		if rec := ap.Q.Endpoints[id]; rec != nil {
			pairID, known = rec.PairId, true
		}
	})
	return pairID, known
}

func (e peerEnv) AppliedSeq() uint64 { return e.a.app.AppliedSeq() }
func (e peerEnv) HubNow() int64      { return e.a.hubNow() }
func (e peerEnv) BindIP() netip.Addr { return e.a.dnsIP() }
