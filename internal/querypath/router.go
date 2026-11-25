package querypath

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns"
	"github.com/Kup1ng/CtrlZ-Node/internal/policy"
	"github.com/Kup1ng/CtrlZ-Node/internal/resolve"
)

// localTimeout is how long the node waits for its own Unbound.
const localTimeout = 5 * time.Second

// closeGrace is how long a replaced Router lives on, so a miss that started on it
// finishes: one fetch is bounded by policy.FetchDeadline.
const closeGrace = policy.FetchDeadline + 2*time.Second

// localMember is the identified Unbound as an upstream of the Router: a plain udp
// exchange on its loopback address, built once and shared by every Router.
func (j *Join) localMember() (resolve.Member, error) {
	if j.local == nil {
		u, err := resolve.NewUpstream(resolve.Config{
			Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: j.opt.LocalUnbound.String(), Timeout: localTimeout,
		})
		if err != nil {
			return resolve.Member{}, err
		}
		j.local = u
	}
	return resolve.Member{X: j.local}, nil
}

// syncRouter builds a new Router when the resolve part of the NodeConfig changed or
// the set of upstreams that point at a node changed, swaps it in, and only then
// purges the Shared segment (a Purge before the swap would let a fetch through the
// old Router refill the cache with an old route's answer). Called with j.mu held.
//
// With no NodeConfig (the Plain-only fallback of 7.2) the node resolves through its
// own Unbound alone: there is no upstream list to follow.
func (j *Join) syncRouter(first bool) {
	cfg := j.env.Config()
	if cfg == nil {
		cfg = &hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE}
	}
	loops := j.loopSet(cfg)
	key := keyOf(loops)
	res := resolveKey(cfg)
	if !first && j.built && res == j.lastRes && key == j.loopKey {
		return
	}
	j.lastRes, j.built, j.loopKey, j.loops = res, true, key, loops
	j.syncFree(cfg, loops)

	var next *resolve.Router
	if eff := withoutLoops(cfg, loops); eff != nil {
		local, err := j.localMember()
		if err == nil {
			next, err = resolve.NewRouterFromWire(eff, local, j.opt.Geo, j.opt.IntervalUnit)
		}
		if err != nil {
			if j.be.r.Load() != nil {
				return // a config that does not build keeps the Router in use
			}
			next = nil
		}
	}
	old := j.be.r.Swap(next)
	j.Cache.Purge(cache.Shared)
	j.rebuilds.Add(1)
	if old != nil {
		time.AfterFunc(closeGrace, old.Close)
	}
}

// loopSet is the upstreams of the config whose address, or bootstrap address, is
// one of this node's addresses in any form (SC 5.2a, Loops). The agent alerts on
// the same condition; dns, which holds the config and the table itself, treats the
// upstream as failed: it is left out of the Router and reported unhealthy, so a
// query can never be sent to a node's own dns_ip and come back.
func (j *Join) loopSet(cfg *hubv1.NodeConfig) map[[16]byte]bool {
	var out map[[16]byte]bool
	nodes := j.nodeAddrs(cfg)
	for _, u := range cfg.Upstreams {
		id, ok := to16(u.Id)
		if !ok {
			continue
		}
		var ips []netip.Addr
		if ap, err := netip.ParseAddrPort(u.Address); err == nil {
			ips = append(ips, ap.Addr())
		} else if ip, err := netip.ParseAddr(u.Address); err == nil {
			ips = append(ips, ip)
		}
		if ip := addr(u.BootstrapIp); ip.IsValid() {
			ips = append(ips, ip)
		}
		for _, ip := range ips {
			if nets.CoversAddr(nodes, ip) {
				if out == nil {
					out = map[[16]byte]bool{}
				}
				out[id] = true
				break
			}
		}
	}
	return out
}

// nodeAddrs are the node's own addresses: its bind and advertised addresses and
// the dns_ip of every node of the table in the serving image.
func (j *Join) nodeAddrs(cfg *hubv1.NodeConfig) []netip.Addr {
	var out []netip.Addr
	for _, b := range [][]byte{cfg.DnsBindIp, cfg.DnsAdvertisedIp} {
		if a := addr(b); a.IsValid() {
			out = append(out, a)
		}
	}
	if img := j.env.Image(); img != nil {
		if pt := img.PairTable(); pt != nil {
			for _, n := range pt.Nodes {
				if a := addr(n.DnsIp); a.IsValid() {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

func keyOf(m map[[16]byte]bool) string {
	var ks []string
	for id := range m {
		ks = append(ks, hex.EncodeToString(id[:]))
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

// withoutLoops returns cfg without the looping upstreams, or nil when that leaves
// an upstream-only config with nothing to ask (the node then has no path, and says
// so by failing every miss and reporting its upstreams down).
func withoutLoops(cfg *hubv1.NodeConfig, loops map[[16]byte]bool) *hubv1.NodeConfig {
	if len(loops) == 0 {
		return cfg
	}
	c := proto.Clone(cfg).(*hubv1.NodeConfig)
	c.Upstreams = nil
	for _, u := range cfg.Upstreams {
		if id, ok := to16(u.Id); ok && loops[id] {
			continue
		}
		c.Upstreams = append(c.Upstreams, u)
	}
	if len(c.Upstreams) == 0 && c.Mode == commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM {
		return nil
	}
	return c
}

func to16(b []byte) ([16]byte, bool) {
	var a [16]byte
	if len(b) != 16 {
		return a, false
	}
	copy(a[:], b)
	return a, true
}

// syncSettings hands the Handler the NodeConfig-derived settings. They are rebuilt
// when the config changes and when the node's Isolated state does, because the
// isolated_synth rows of step 2 read that flag from them.
func (j *Join) syncSettings() {
	cfg, iso := j.env.Config(), j.isolated()
	j.iso.Store(iso)
	if j.setDone && cfg == j.setCfg && iso == j.setIso {
		return
	}
	var panel []names.Name
	var self netip.Addr
	var key []byte
	if cfg != nil {
		for _, p := range cfg.PanelHostnames {
			if n, err := names.ParseUser(p); err == nil {
				panel = append(panel, n)
			}
		}
		self = addr(cfg.DnsAdvertisedIp)
		key = j.env.ProofKey() // nil for the all-zero stand-in: no proof code (7.2)
	}
	j.Handler.SetSettings(dns.NewSettings(j.env.Zones(), panel, self, key, iso))
	j.setCfg, j.setIso, j.setDone = cfg, iso, true
}

// isolated is the node's Isolated state: no resolve path is healthy, which is what
// the free path refuses on and isolated_synth answers for (SC 5.2a, 8). A node with
// no Router at all is cut off in the same sense.
func (j *Join) isolated() bool {
	r := j.be.r.Load()
	if r == nil {
		return true
	}
	hs := r.Health()
	for _, h := range hs {
		if h.Healthy {
			return false
		}
	}
	return len(hs) > 0
}

// shutdown closes what the join built.
func (j *Join) shutdown() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if r := j.be.r.Swap(nil); r != nil {
		r.Close()
	}
	if j.local != nil {
		_ = j.local.Close()
	}
	j.closeFree()
}

// resolveKey fingerprints the part of a NodeConfig the Router is built from: the
// mode, the upstreams, the groups and the rules. The agent hands the NodeConfig over
// again on every dns reconnect and when it republishes a version with the real
// proof_key, as a new object each time, and a Router rebuilt for those would drop the
// whole warm cache and make every upstream "up" again with its failure counts reset.
// Only a difference in what the Router uses may do that. Marshalling is
// deterministic, so equal content gives an equal key.
func resolveKey(cfg *hubv1.NodeConfig) [32]byte {
	p := &hubv1.NodeConfig{Mode: cfg.GetMode(), Upstreams: cfg.GetUpstreams(), Groups: cfg.GetGroups(), Rules: cfg.GetRules()}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(p)
	if err != nil {
		// Cannot happen for a message the Env has already decoded; a key that never
		// matches only costs a rebuild.
		b = []byte(err.Error() + time.Now().String())
	}
	return sha256.Sum256(b)
}
