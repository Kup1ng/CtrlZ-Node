// Package querypath joins the dns role (internal/dnsrole) to the query path of SC
// 5.2 (internal/dns) and its resolve side (internal/resolve, internal/cache,
// internal/policy). It owns no DNS logic: it builds the pieces, feeds them what
// the agent hands over on the socket, and reports their numbers back.
//
// The packages it joins are built apart, so this one only uses their exported API:
// the Handler and its setters, the Router with Health and Refused, the Cache with
// Stats. What the agent sends maps as follows.
//
//	image        -> Handler.SetImage (opened by the role, swapped here before the ack)
//	table        -> Handler.SetZoneState, refreshed every second as well, because the
//	                PanelStale rule of SC 8a.5 is a clock rule
//	config       -> Handler.SetSettings and a new Router, then Purge of the Shared segment
//	revocations  -> Handler.Revocations().Set
//	zone keys    -> the role's GetCertificate (already the listeners' provider)
//
// The query path's own clock is hub time (the node clock plus the agent's offset),
// because every expiry the agent hands over is in hub time (p4-nodes 7.3).
package querypath

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/route"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/grant"
	"github.com/Kup1ng/CtrlZ-Node/internal/link"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
	"github.com/Kup1ng/CtrlZ-Node/internal/resolve"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// Options are what the join needs from the process that builds it.
type Options struct {
	// LocalUnbound is where the identified Unbound answers (the agent renders its
	// config from the same address). Zero means 127.0.0.10:5300.
	LocalUnbound netip.AddrPort
	// Cache sizes the answer cache; zero fields take the defaults (D31).
	Cache cache.Config
	// Profiles is how many opened profile blobs stay warm; 0 means 4096 (D31).
	Profiles int
	// NeverProxied is the predicate of D42 (T-524). Nil means NeverIranian, the
	// interim one, until P2's noredirect.Name can be passed here.
	NeverProxied func(names.Name) bool
	// Geo answers geo-site and country questions; nil means none (no catalog yet).
	Geo route.GeoSites
	// GeoView is the same for the evaluator (country of a source), nil for none.
	GeoView sharedpolicy.GeoView
	// Free configures the free path (SC 5.2a).
	Free FreeOptions
	// IntervalUnit stands for one second of health_interval_s; tests shorten it.
	IntervalUnit time.Duration
	// Proxy switches P4b's Grants and the proxy's link on (p4b-proxy 4, 5.1). Nil is a
	// node as P4 left it: no Grant is written and nothing serves proxy.sock.
	Proxy *ProxyOptions
	// OnBuilt, when set, receives the join once it exists (tests).
	OnBuilt func(*Join)
}

// ProxyOptions are the sockets and limits of the proxy side.
type ProxyOptions struct {
	// Listen opens proxy.sock and returns the proxy's uid; nil is the production
	// socket (link.Listen over ProxyPath).
	Listen func() (net.Listener, uint32, error)
	// Get reads a peer's uid; nil is SO_PEERCRED.
	Get sock.UIDGetter
	// Limits are the numbers of 12; zero takes the defaults.
	Limits grant.Limits
}

// ProxyPath is where dns serves the proxy's link (2.1).
const ProxyPath = "/run/ctrlz-link/proxy.sock"

// Join is the built query path.
type Join struct {
	Handler *dns.Handler
	Cache   *cache.Cache
	// Free is the free path of SC 5.2a, behind Handler.
	Free *dns.FreeServer

	env  *dnsrole.Env
	sink *dnsrole.Sink
	opt  Options
	be   backend
	cnt  counters

	meter meter
	start sample

	mu sync.Mutex // serialises the sync steps: the agent hook and the tick both run them

	// What the Handler was last given, so a step does nothing when nothing changed.
	lastImg  *image.Image
	lastRes  [32]byte // fingerprint of what the Router was built from (resolveKey)
	built    bool
	loopKey  string
	loops    map[[16]byte]bool
	setCfg   *hubv1.NodeConfig
	setIso   bool
	setDone  bool
	local    *resolve.Upstream
	rebuilds atomic.Uint64

	// The proxy's link, served from the first image on.
	srv      atomic.Pointer[link.Server]
	linkOnce sync.Once

	// The free path's own resolver: its Router, its Unbound member and the Isolated
	// flag it reads. iso is written under mu and read by queries, so it is atomic.
	freeBe    freeBackend
	freeLocal *resolve.Upstream
	iso       atomic.Bool
}

// Factory returns the dnsrole.HandlerFactory of the node.
func Factory(opt Options) dnsrole.HandlerFactory {
	return func(env *dnsrole.Env, sink *dnsrole.Sink) (listen.Handler, listen.VerifyHandler, error) {
		j, err := New(env, sink, opt)
		if err != nil {
			return nil, nil, err
		}
		if opt.OnBuilt != nil {
			opt.OnBuilt(j)
		}
		return j.counting(), j.Handler.Verify(), nil
	}
}

// New builds the query path over env and sink and starts its goroutines, which end
// with env.Context().
func New(env *dnsrole.Env, sink *dnsrole.Sink, opt Options) (*Join, error) {
	if !opt.LocalUnbound.IsValid() {
		opt.LocalUnbound = netip.MustParseAddrPort("127.0.0.10:5300")
	}
	if opt.Profiles <= 0 {
		opt.Profiles = 4096
	}
	if !opt.Free.Unbound.IsValid() {
		opt.Free.Unbound = netip.MustParseAddrPort("127.0.0.11:5300")
	}
	if opt.NeverProxied == nil {
		opt.NeverProxied = NeverIranian
	}
	j := &Join{env: env, sink: sink, opt: opt, Cache: cache.New(opt.Cache), start: sample{at: time.Now()}}
	res := &policy.Resolver{Cache: j.Cache, Segment: cache.Shared, Backend: &j.be, Rejected: func() { j.cnt.rejected.Add(1) }}
	rep := reporter{sink: sink}
	free, err := j.newFree(opt.Free)
	if err != nil {
		return nil, err
	}
	j.Free = free
	var px *dns.ProxyOptions
	if opt.Proxy != nil {
		px = &dns.ProxyOptions{Limits: opt.Proxy.Limits, Send: sink.Send, Facts: j.proxyFacts, End: j.linkEnd}
	}
	h, err := dns.New(dns.Config{
		Proxy: px, Resolver: res, Reporter: rep, Profiles: policy.NewProfiles(opt.Profiles),
		NeverProxied: opt.NeverProxied, Geo: opt.GeoView, Now: j.now, CachedA: res.CachedA,
		Self: j.self, Free: free,
	})
	if err != nil {
		return nil, err
	}
	j.Handler = h
	env.OnApply(j.onApply)
	if g := h.Grants(); g != nil {
		env.OnMessage(g.OnAgent)
		go g.Run(env.Context())
	}
	j.syncAll()
	sink.SetStats(j.stats)
	go j.tick(env.Context())
	return j, nil
}

// now is hub time: the node's clock plus the offset the agent last sent.
func (j *Join) now() time.Time { return time.Now().Add(j.env.HubOffset()) }

// self gives the addresses a Block or Redirect answer may carry.
func (j *Join) self() sharedpolicy.SelfAddrs {
	var s sharedpolicy.SelfAddrs
	if c := j.env.Config(); c != nil {
		s.DNSIP = addr(c.DnsAdvertisedIp)
		s.ProxyIP = addr(c.ProxyAdvertisedIp)
	}
	return s
}

func addr(b []byte) netip.Addr {
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}

// onApply runs on the socket's receive goroutine for every message of the agent.
func (j *Join) onApply(typ string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	switch typ {
	case sock.TypeImage:
		j.syncImage()
		j.syncRouter(false) // the node addresses come from the image's table
	case sock.TypeTable:
		j.syncZone()
	case sock.TypeConfig:
		if s := j.srv.Load(); s != nil {
			s.Reconfigure() // a changed proxy_bind_ip
		}
		j.syncRouter(false)
		// Env stores the config and its zones as two writes, so the tick may have
		// built Settings from the new config and the old zones and recorded that as
		// done. The hook runs after both writes: force the rebuild.
		j.setDone = false
		j.syncSettings()
		j.syncZone()
	case sock.TypeRevocations:
		j.syncRevocations()
	}
}

func (j *Join) syncAll() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.syncImage()
	j.syncRouter(true)
	j.syncSettings()
	j.syncZone()
	j.syncRevocations()
}

// tick refreshes what depends on the clock or on the health of the paths: the
// zone state (PanelStale after 30 s without the agent) and the isolated flag.
func (j *Join) tick(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			j.shutdown()
			return
		case <-t.C:
		}
		j.mu.Lock()
		j.syncZone()
		j.syncSettings() // isolated may have changed
		j.mu.Unlock()
	}
}

// syncImage hands the Handler the image the Env holds, once per image.
func (j *Join) syncImage() {
	img := j.env.Image()
	if img == nil {
		return
	}
	if img == j.lastImg {
		return
	}
	j.Handler.SetImage(img)
	j.lastImg = img
	j.startLink()
}

// syncZone hands the Handler the table in use and the node's own view of the panel.
func (j *Join) syncZone() {
	st := j.env.Tables()
	j.Handler.SetZoneState(&dns.ZoneState{Table: st.Table, Local: st.Local, Acme: j.acme})
}

// acme answers the TXT values of the active DNS-01 challenges of a name. Judged in
// hub time, as the agent's expiries are.
func (j *Join) acme(fqdn string) []string {
	fqdn = canonFQDN(fqdn)
	var out []string
	for _, a := range j.env.AcmeChallenges(j.env.HubNow()) {
		if canonFQDN(a.FQDN) == fqdn {
			out = append(out, a.Value)
		}
	}
	return out
}

// syncRevocations converts the agent's list (hub time) for the Handler, whose clock
// is hub time too.
func (j *Join) syncRevocations() {
	in := j.env.Revocations()
	out := make([]dns.Revocation, 0, len(in))
	for _, it := range in {
		r := dns.Revocation{Kind: policyv1.RevocationKind(it.Kind), RevSeq: it.Seq}
		if it.ExpiresAt > 0 {
			r.ExpiresAt = time.Unix(it.ExpiresAt, 0)
		} else {
			// The agent gives every revocation an expiry; one without is held until an
			// applied entry ends it, which is the side that disables.
			r.ExpiresAt = time.Unix(1<<40, 0)
		}
		for _, id := range it.IDs {
			if len(id) == 16 {
				r.IDs = append(r.IDs, [16]byte(id))
			}
		}
		out = append(out, r)
	}
	j.Handler.Revocations().Set(out)
	if g := j.Handler.Grants(); g != nil {
		g.Revalidate() // a revocation ends Grants when dns gets it (4.6)
	}
}

// proxyFacts reads what the Grants need of the node's config and tables, at each use.
func (j *Join) proxyFacts() dns.ProxyFacts {
	st := j.env.Tables()
	f := dns.ProxyFacts{Self: [16]byte(st.Local.Self)}
	if c := j.env.Config(); c != nil {
		f.ProxyBind, f.DNSBind = addr(c.ProxyBindIp), addr(c.DnsBindIp)
		switch c.GrantWidth {
		case hubv1.GrantWidth_GRANT_WIDTH_PREFIX24:
			f.Width = grant.WidthPrefix24
		case hubv1.GrantWidth_GRANT_WIDTH_CARRIER:
			f.Width = grant.WidthCarrier
		}
	}
	down := st.Local.PeerDown
	f.PeerDown = func(n [16]byte) bool { return down[zone.NodeID(n)] }
	return f
}

// linkEnd tells the proxy to close connections; false when no proxy is connected.
func (j *Join) linkEnd(ids []uint64, socks []string) bool {
	if s := j.srv.Load(); s != nil {
		return s.End(ids, socks)
	}
	return false
}

// startLink serves proxy.sock once the first image is served (5.1): until then the
// proxy has nothing to be told and listens on nothing.
func (j *Join) startLink() {
	px := j.opt.Proxy
	g := j.Handler.Grants()
	if px == nil || g == nil {
		return
	}
	j.linkOnce.Do(func() {
		go func() {
			ctx := j.env.Context()
			listen := px.Listen
			if listen == nil {
				listen = func() (net.Listener, uint32, error) {
					return link.Listen(ProxyPath, "ctrlz-link", sock.UserProxy)
				}
			}
			for {
				ln, uid, err := listen()
				if err == nil {
					srv := link.New(link.Config{Backend: g, Get: px.Get, ProxyUID: uid})
					j.srv.Store(srv)
					go func() { <-ctx.Done(); _ = ln.Close() }()
					_ = srv.Serve(ln)
					return
				}
				log.Printf("querypath: proxy link: %v", err) // fixed texts, no address or name
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}()
	})
}

// Switched reports how many routers have been built (tests).
func (j *Join) Switched() uint64 { return j.rebuilds.Load() }

// Looping reports how many upstreams are left out of the Router because they
// point at a node (tests).
func (j *Join) Looping() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.loops)
}

func modeOf(c *hubv1.NodeConfig) commonv1.ResolveMode {
	if c == nil {
		return commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE
	}
	return c.Mode
}

// canonFQDN is the form both sides of the DNS-01 match are compared in: the hub's
// AcmeChallenge.fqdn is validated only for length, so a trailing dot or capitals
// there must not make the challenge unanswerable (and fail the certificate order).
func canonFQDN(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
