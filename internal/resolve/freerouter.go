package resolve

import (
	"errors"
	"fmt"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/route"
)

// NewFreeRouterFromWire is NewRouterFromWire for the free path (SC 5.2a, Free
// resolver): the same modes, groups and rules, so a free miss takes the node's
// default resolve path, but local is the free Unbound and every upstream row is
// reached through its own FreePool instead of the client that identified queries
// and the health check use. Nothing that identified traffic holds is shared.
//
// It differs from NewRouterFromWire in one more way: when every upstream row is
// refused and the mode needs one, there is no Router (nil, nil), because the free
// path has no hub to tell about a refused row and its misses just fail. The free
// Router's Health is never reported (the free Unbound is no resolve path of 8a.4).
//
// Kept apart from NewRouterFromWire on purpose, so the free path adds nothing to
// the identified path's constructor; when the two settle they should share their
// body and take the member constructor as an argument.
func NewFreeRouterFromWire(cfg *hubv1.NodeConfig, local Member, geo route.GeoSites, unit time.Duration) (*Router, error) {
	rc := RouterConfig{Mode: cfg.GetMode(), Local: local, Geo: geo, IntervalUnit: unit, Groups: map[string][][16]byte{}}
	var built []*FreePool
	closeBuilt := func() {
		for _, b := range built {
			_ = b.Close()
		}
	}
	for _, u := range cfg.GetUpstreams() {
		id, ok := to16(u.GetId())
		if !ok {
			closeBuilt()
			return nil, errors.New("resolve: upstream id")
		}
		uc, err := ConfigFromWire(u)
		var p *FreePool
		if err == nil {
			p, err = NewFreePool(uc)
		}
		if err != nil {
			continue // the identified Router reports a refused row; the free one has nobody to tell
		}
		built = append(built, p)
		rc.Upstreams = append(rc.Upstreams, Member{ID: id, X: p, Every: time.Duration(u.GetHealthIntervalS()) * time.Second,
			Trusted: u.GetTrusted() && u.GetKind() != commonv1.UpstreamKind_UPSTREAM_KIND_UDP})
	}
	if len(rc.Upstreams) == 0 && cfg.GetMode() == commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM {
		return nil, nil
	}
	for _, g := range cfg.GetGroups() {
		for _, raw := range g.GetUpstreamIds() {
			if id, ok := to16(raw); ok {
				rc.Groups[g.GetName()] = append(rc.Groups[g.GetName()], id)
			}
		}
	}
	for _, rr := range cfg.GetRules() {
		pr, err := route.ParseRule(rr.GetOrder(), rr.GetMatchType(), rr.GetMatchValue(), rr.GetGroup(), rr.GetFinalDefault())
		if err != nil {
			closeBuilt()
			return nil, fmt.Errorf("resolve: rule %d: %w", rr.GetOrder(), err)
		}
		rc.Rules = append(rc.Rules, pr)
	}
	r, err := NewRouter(rc)
	if err != nil {
		closeBuilt()
		return nil, err
	}
	for _, b := range built {
		r.owned = append(r.owned, b)
	}
	return r, nil
}

// FreePoolsFull counts the calls, over the life of r, that found every
// connection of an upstream's free pool full. The free path turns a lookup that
// failed while it moved into REFUSED (SC 5.2a point 7). It is 0 for a Router that
// has no free pool.
func FreePoolsFull(r *Router) uint64 {
	var n uint64
	for _, o := range r.owned {
		if p, ok := o.(*FreePool); ok {
			n += p.Full()
		}
	}
	return n
}
