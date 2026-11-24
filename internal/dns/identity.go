package dns

import (
	"net/netip"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// ident is who a query belongs to, found at step 4 (SC 3.3) but computed before
// step 2, because a DoH request with no identity is HTTP 404 before any step,
// and because activity is judged by whether 4b lets the query through.
type ident struct {
	st *epState // nil when the query has no identity

	client  string   // client label from the name or path, empty when none
	rid     string   // the resolver id the encrypted connection presented
	ridHash [16]byte // its hash, for a proof observation
	claim   *claimEntry

	// forceHard is SC 5.2a case 1: a priority revocation names the claim or its
	// Endpoint and the node has not applied the entry that changes the record. The
	// answer is the silent drop of 4b, whether or not the record is still held.
	forceHard bool
	// claimNoRecord is case 2: the claim is held, its Endpoint's record is not.
	claimNoRecord bool

	// httpStatus is set when a DoH or DoH3 request names nobody: 404, before
	// step 2.
	httpStatus int
	// tokenMatched: a DoH or DoH3 request whose token is the Endpoint's.
	tokenMatched bool
}

func (id *ident) known() bool { return id.st != nil || id.forceHard }

// identify finds the identity of a query by its transport (SC 3.3).
func (h *Handler) identify(req *listen.Request, set *Settings, sv *Serving, now time.Time) ident {
	switch req.Transport {
	case listen.DoH, listen.DoH3:
		if req.HTTP == nil {
			return ident{httpStatus: 404}
		}
		t, err := identity.ResolveDoH(req.HTTP.Path, req.HTTP.Authority, set.zones)
		if err != nil {
			return ident{httpStatus: 404}
		}
		ep, ok := sv.img.ByResolverID(t.RID)
		// A wrong token is the same 404 as an unknown id.
		if !ok || len(ep.Record.DohTokenHash) != 32 || !identity.TokenMatches(t.Token, [32]byte(ep.Record.DohTokenHash)) {
			return ident{httpStatus: 404}
		}
		return ident{st: sv.endpoint(ep), client: t.Client, rid: t.RID, ridHash: identity.RIDHash(t.RID), tokenMatched: true}
	case listen.DoT, listen.DoQ:
		host := identity.ParseHost(req.SNI, set.zones)
		if host.Kind != identity.HostResolver {
			return ident{}
		}
		ep, ok := sv.img.ByResolverID(host.RID)
		if !ok {
			return ident{}
		}
		return ident{st: sv.endpoint(ep), client: host.Client, rid: host.RID, ridHash: identity.RIDHash(host.RID)}
	}

	// Plain DNS: the longest claim prefix that holds the source.
	ce, ok := sv.prefixes.lookup(req.Source.Addr())
	if !ok {
		return ident{}
	}
	applied := sv.img.Seq()
	ep, have := sv.img.ByEndpointID(ce.EndpointID)
	if h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_CLAIM, ce.ID, applied, now) ||
		h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, ce.EndpointID, applied, now) {
		id := ident{forceHard: true, claim: ce}
		if have {
			id.st = sv.endpoint(ep)
		}
		return id
	}
	if !have {
		return ident{claimNoRecord: true, claim: ce}
	}
	st := sv.endpoint(ep)
	if !st.rec.LegacyDns {
		return ident{} // the claim's Endpoint does not want Plain DNS: the source is a stranger
	}
	return ident{st: st, claim: ce}
}

// gateResult is the outcome of 4b, with every reason that applies, because
// LearnedIP is judged by which reasons they are (p4-nodes.md 7.6).
type gateResult struct {
	auth    bool // Require Authorized IPs and the source is outside the list
	hard    bool // admin_state hard_disabled
	revoked bool // a priority revocation in force
}

func (g gateResult) refused() bool { return g.auth || g.hard || g.revoked }

// gate is step 4b without its effect: the caller applies the refusal. Plain DNS
// identified by a claim passes Require Authorized IPs, because the claim is the
// authorization of that address (and a claim the Endpoint does not hold is no
// identity at all).
func (h *Handler) gate(id *ident, req *listen.Request, sv *Serving, now time.Time) gateResult {
	if id.forceHard {
		return gateResult{revoked: true}
	}
	if id.st == nil {
		return gateResult{}
	}
	var g gateResult
	rec := id.st.rec
	applied := sv.img.Seq()
	g.revoked = h.rev.acts(policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, id.st.id, applied, now)
	// An unknown admin_state is treated as hard_disabled: the wire validator
	// refuses it, so it can only be a record this node cannot judge.
	switch rec.AdminState {
	case commonv1.AdminState_ADMIN_STATE_ENABLED, commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED:
	default:
		g.hard = true
	}
	if rec.RequireAuthorizedIps && id.claim == nil && !inAny(id.st.authorized, req.Source.Addr()) {
		g.auth = true
	}
	return g
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// longestAuthorized is the longest prefix of the list that holds a, for the
// source_ip_hash of an activity entry.
func longestAuthorized(ps []netip.Prefix, a netip.Addr) (netip.Prefix, bool) {
	a = a.Unmap()
	var best netip.Prefix
	found := false
	for _, p := range ps {
		if p.Contains(a) && (!found || p.Bits() > best.Bits()) {
			best, found = p, true
		}
	}
	return best, found
}

func protocolOf(t listen.Transport) commonv1.Protocol {
	switch t {
	case listen.UDP:
		return commonv1.Protocol_PROTOCOL_UDP
	case listen.TCP:
		return commonv1.Protocol_PROTOCOL_TCP
	case listen.DoT:
		return commonv1.Protocol_PROTOCOL_DOT
	case listen.DoH:
		return commonv1.Protocol_PROTOCOL_DOH
	case listen.DoQ:
		return commonv1.Protocol_PROTOCOL_DOQ
	case listen.DoH3:
		return commonv1.Protocol_PROTOCOL_DOH3
	}
	return commonv1.Protocol_PROTOCOL_UNSPECIFIED
}

func evalProtocol(t listen.Transport) sharedpolicy.Protocol {
	// The numbers are the same in the proto and in the evaluator (contract 5.1).
	return sharedpolicy.Protocol(protocolOf(t))
}
