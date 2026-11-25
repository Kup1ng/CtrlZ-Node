// Package policy is the node's hot-path glue around the shared evaluator
// (contract section 1: "node internal/policy holds hot-path glue only").
//
// It converts compiled records into the evaluator's runtime types
// (policy.EndpointView, policy.Stack), loads profile blobs, and supplies the
// Resolver port backed by the cache and router. It must not contain a decision
// rule of its own: every rule lives in the shared module and is pinned by the
// golden vectors, which this package runs (R45).
package policy

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
)

// Backend is the router the resolver sends misses to. *resolve.Router is one;
// a test can stand in. Route names the path a question takes, which is part of
// the cache key.
type Backend interface {
	Route(n *names.Name, qtype uint16) string
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error)
}

// FetchDeadline bounds one miss from start to finish, failover included. It is
// the deadline of a fetch that belongs to no caller (see cache.Do), so a client
// that goes away cannot cancel the answer others wait for.
const FetchDeadline = 8 * time.Second

// Resolver adapts the node's cache and router to the evaluator's Resolver port.
// One Resolver serves one cache segment: the identified path builds one over
// cache.Shared and its Unbound, the free path (W9) another over cache.Free and
// the free Unbound, so no lookup can cross from one to the other (T-559).
type Resolver struct {
	Cache    *cache.Cache
	Segment  cache.Segment
	Backend  Backend
	Deadline time.Duration // 0 means FetchDeadline

	// Rejected counts answers the Sanity Gate refused; it is nil-safe and holds
	// no name or address (SC 5.2a).
	Rejected func()

	// Refusal, when set, picks the Backend errors that mean "turned away, not
	// failed" (the free path's full pools). Such a lookup is still Failed, so every
	// consumer treats it as SERVFAIL, but its RCode is REFUSED and the free path
	// answers with that. The cause rides in the answer, so a caller that shared the
	// fetch sees it too.
	Refusal func(err error) bool

	// SrcPayload is the EDNS payload size of the query sent upstream.
	SrcPayload uint16

	failed atomic.Uint64
}

// Lookup implements the shared policy.Resolver. It reads through the cache, and
// on a miss asks the router for the question, applies the Sanity Gate, and
// stores the true answer. A failure is an answer with Failed set, never an
// error: the evaluator turns it into SERVFAIL (SC 5.12), and nothing failed is
// stored.
func (r *Resolver) Lookup(ctx context.Context, n names.Name, qtype uint16, p sharedpolicy.ResolveParams) (*sharedpolicy.TrueAnswer, error) {
	// Read before the route and the backend are used: a Purge after this point
	// (a resolve change) makes the Put of this fetch a no-op (p4n-W7-r2-3).
	gen := r.Cache.Generation(r.Segment)
	key := cache.KeyOf(n, qtype, sharedpolicy.ClassIN, p, r.Backend.Route(&n, qtype))
	if a, ok := r.Cache.Get(r.Segment, key); ok {
		return a, nil
	}
	a, err := r.Cache.Do(r.Segment, key, ctx.Done(), func() (*sharedpolicy.TrueAnswer, error) {
		return r.fetch(n, qtype, p, key, gen), nil
	})
	if err != nil {
		return failedAnswer(n), nil
	}
	return a, nil
}

func failedAnswer(n names.Name) *sharedpolicy.TrueAnswer {
	return &sharedpolicy.TrueAnswer{RCode: sharedpolicy.RCodeServFail, Failed: true, Chain: []names.Name{n}}
}

func (r *Resolver) fetch(n names.Name, qtype uint16, p sharedpolicy.ResolveParams, key cache.Key, gen uint64) *sharedpolicy.TrueAnswer {
	d := r.Deadline
	if d <= 0 {
		d = FetchDeadline
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	q := new(dns.Msg)
	q.SetQuestion(NameToDNS(n), qtype)
	q.RecursionDesired = true
	q.CheckingDisabled = p.EffectiveCD
	payload := r.SrcPayload
	if payload == 0 {
		payload = 1232
	}
	q.SetEdns0(payload, true) // DO: the evaluator needs the validation state and strips what the client did not ask for
	if p.ECS.IsValid() {
		q.IsEdns0().Option = append(q.IsEdns0().Option, subnetOption(p.ECS))
	}
	resp, _, err := r.Backend.Exchange(ctx, q)
	if err != nil || resp == nil {
		r.failed.Add(1)
		a := failedAnswer(n)
		if err != nil && r.Refusal != nil && r.Refusal(err) {
			a.RCode = sharedpolicy.RCodeRefused
		}
		return a
	}
	a := TrueAnswerFromMsg(n, resp)
	if a.Failed {
		return a
	}
	// The gate judges what the client would be handed as well as what is stored:
	// an injected answer reaches nobody (SC 5.2 step 8).
	if v := r.Cache.Gate().Check(n, a); !v.OK {
		if r.Rejected != nil {
			r.Rejected()
		}
		return failedAnswer(n)
	}
	_ = r.Cache.PutGen(r.Segment, key, n, a, gen)
	return a
}

func subnetOption(p netip.Prefix) *dns.EDNS0_SUBNET {
	p = p.Masked()
	fam := uint16(1)
	if p.Addr().Is6() {
		fam = 2
	}
	return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: fam, SourceNetmask: uint8(p.Bits()), SourceScope: 0, Address: p.Addr().AsSlice()}
}

var _ sharedpolicy.Resolver = (*Resolver)(nil)

// CachedA returns the true A addresses the cache already holds for a name, with
// no lookup: ok is false when it holds none. Grant safety (R9) reads it at Grant
// creation, because a Grant for a name that truly resolves to a private or
// loopback address would let a client reach it through the proxy.
//
// p is the ResolveParams of the lookup that cached the answer: the key carries
// the ECS prefix and the effective CD.
func (r *Resolver) CachedA(n names.Name, p sharedpolicy.ResolveParams) ([]netip.Addr, bool) {
	key := cache.KeyOf(n, sharedpolicy.TypeA, sharedpolicy.ClassIN, p, r.Backend.Route(&n, sharedpolicy.TypeA))
	a, ok := r.Cache.Peek(r.Segment, key)
	if !ok || a.Failed {
		return nil, false
	}
	var out []netip.Addr
	for i := range a.Answer {
		if addr, ok := a.Answer[i].Addr(); ok {
			out = append(out, addr)
		}
	}
	return out, len(out) > 0
}
