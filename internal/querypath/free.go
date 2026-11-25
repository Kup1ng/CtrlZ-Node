package querypath

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
	"github.com/Kup1ng/CtrlZ-Node/internal/resolve"
)

// FreeOptions are what the free path (SC 5.2a, p4-nodes 7.9) needs from the process
// that builds the join. Zero values take the contract's numbers (provisional, D31).
type FreeOptions struct {
	// Unbound is where the free Unbound answers (the agent renders its config from
	// the same address). Zero means 127.0.0.11:5300.
	Unbound netip.AddrPort
	// MissCap is free_inflight; 0 means 256.
	MissCap int
	// ResponseRate and ResponseBurst are the response limit in bytes; 0 means 64 KiB
	// a second and 256 KiB.
	ResponseRate, ResponseBurst int
	// Now is the clock of the free path's rates; nil means time.Now.
	Now func() time.Time
}

// freeBackend is the policy.Backend of the free resolver: its own Router, over the
// free Unbound and the free pools of the upstreams, swapped whole when the
// NodeConfig's resolve part changes. Nothing in it is the identified path's.
type freeBackend struct {
	r atomic.Pointer[resolve.Router]
}

func (b *freeBackend) Route(n *names.Name, qtype uint16) string {
	if r := b.r.Load(); r != nil {
		return r.Route(n, qtype)
	}
	return ""
}

func (b *freeBackend) Exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, string, error) {
	r := b.r.Load()
	if r == nil {
		return nil, "", resolve.ErrNoPath
	}
	// The pools of the Router mark ctx when they turn a call away. A lookup that
	// found no answer and met a full pool says so in its error, which is how the free
	// path tells REFUSED from SERVFAIL for this lookup alone.
	ctx, full := resolve.WithFullMark(ctx)
	resp, rt, err := r.Exchange(ctx, req)
	if err != nil && full.Full() {
		err = fmt.Errorf("%w: %w", resolve.ErrFreePoolFull, err)
	}
	return resp, rt, err
}

// freeEnv gives the free path the agent's facts and the node's Isolated state.
type freeEnv struct{ j *Join }

func (e freeEnv) Gate(imageSeq uint64) (bool, bool) { return e.j.env.FreeGate(imageSeq) }
func (e freeEnv) QPS() uint32                       { return e.j.env.FreeQPS() }
func (e freeEnv) Isolated() bool                    { return e.j.iso.Load() }

// newFree builds the free path over the free segment of the cache and the free
// backend. It is a different resolver from the identified one in every part: its
// Segment, its Backend, its Router and the Unbound behind it.
func (j *Join) newFree(opt FreeOptions) (*dns.FreeServer, error) {
	res := &policy.Resolver{Cache: j.Cache, Segment: cache.Free, Backend: &j.freeBe, Rejected: func() { j.cnt.rejected.Add(1) },
		Refusal: func(err error) bool { return errors.Is(err, resolve.ErrFreePoolFull) }}
	return dns.NewFreeServer(dns.FreeConfig{
		Env: freeEnv{j}, Resolver: res, Cache: j.Cache, Route: j.freeBe.Route,
		Count: j.sink.FreeCount, Now: opt.Now, MissCap: opt.MissCap,
		ResponseRate: opt.ResponseRate, ResponseBurst: opt.ResponseBurst,
		SharedEnv: func() sharedpolicy.Env { return sharedpolicy.Env{NeverProxied: j.opt.NeverProxied} },
	})
}

// freeLocalMember is the free Unbound as the local member of the free Router: a
// plain udp exchange on its own loopback address, never the identified Unbound's.
func (j *Join) freeLocalMember() (resolve.Member, error) {
	if j.freeLocal == nil {
		u, err := resolve.NewUpstream(resolve.Config{
			Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: j.opt.Free.Unbound.String(), Timeout: localTimeout,
		})
		if err != nil {
			return resolve.Member{}, err
		}
		j.freeLocal = u
	}
	return resolve.Member{X: j.freeLocal}, nil
}

// syncFree builds the free Router from the same config as the identified one (the
// same mode, groups and rules, and the same upstreams once the looping ones are
// left out), swaps it in and only then purges the Free segment. Called with j.mu
// held, after the identified Router's own rebuild decided the config changed.
func (j *Join) syncFree(cfg *hubv1.NodeConfig, loops map[[16]byte]bool) {
	var next *resolve.Router
	if eff := withoutLoops(cfg, loops); eff != nil {
		local, err := j.freeLocalMember()
		if err == nil {
			next, err = resolve.NewFreeRouterFromWire(eff, local, j.opt.Geo, j.opt.IntervalUnit)
		}
		if err != nil {
			if j.freeBe.r.Load() != nil {
				return // a config that does not build keeps the Router in use
			}
			next = nil
		}
	}
	old := j.freeBe.r.Swap(next)
	j.Cache.Purge(cache.Free)
	if old != nil {
		time.AfterFunc(closeGrace, old.Close)
	}
}

// closeFree closes what the free path built.
func (j *Join) closeFree() {
	if r := j.freeBe.r.Swap(nil); r != nil {
		r.Close()
	}
	if j.freeLocal != nil {
		_ = j.freeLocal.Close()
	}
}
