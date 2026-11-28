package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/xray"
)

// xrayNodeAddrs returns the list of addresses that the Xray manager adds to the
// finalRules of `direct` and of every freedom outbound (p4b-proxy 7.4): the panel, and
// the DNS and proxy address of every node of the applied table, the node's own
// addresses from agent.conf included. The manager adds the four addresses of the
// applied NodeConfig itself (Manager.base), so a bind address that the hub moved is
// covered there. The manager reads this list at every reconcile, so it never waits for
// a lookup and reads one small file; a change of the list is a change of the base and
// rebuilds the idle slot (7.5 step 5).
func xrayNodeAddrs(cfg *agent.Config) func() []netip.Addr {
	hub := &hubAddrs{ac: cfg.Conf, lookup: lookupHub(identifiedUnbound), alert: cfg.Alert, file: filepath.Join(cfg.Root, hubAddrsFile)}
	hub.prime()
	return func() []netip.Addr {
		var out []netip.Addr
		add := func(a netip.Addr) {
			if a.IsValid() {
				out = append(out, a.Unmap())
			}
		}
		for _, a := range []netip.Addr{cfg.Conf.DNSBindIP, cfg.Conf.DNSAdvertisedIP, cfg.Conf.ProxyBindIP, cfg.Conf.ProxyAdvertisedIP} {
			add(a)
		}
		for _, a := range hub.get() {
			add(a)
		}
		if t := store.PeekMemberAt(cfg.Root); t != nil {
			for _, n := range t.GetNodes() {
				for _, b := range [][]byte{n.GetDnsIp(), n.GetProxyIp()} {
					if a, ok := netip.AddrFromSlice(b); ok {
						add(a)
					}
				}
			}
		}
		return out
	}
}

// hubAddrs is the panel's addresses: the ones agent.conf lists, or the hub's own
// when it is an address, or what its name resolves to. A name is looked up in a
// goroutine every few minutes and the last answer kept: the list is read on the
// manager's loop, which a slow resolver must not hold.
type hubAddrs struct {
	ac     conf.Agent
	lookup func(ctx context.Context, host string) []netip.Addr
	alert  alert.Alerter

	mu       sync.Mutex
	got      []netip.Addr
	seen     map[netip.Addr]time.Time
	capped   bool
	at       time.Time
	fetching bool
	// file keeps the list across restarts of the agent (B5 r3-6); empty in tests that need none.
	file  string
	saved []netip.Addr
}

const (
	hubRefresh = 5 * time.Minute
	hubMax     = 32
	// hubRetry is the wait between two lookups while the list is still empty: at a node boot
	// Unbound may not answer for a while, and until it does the panel is not blocked (B5 r3-6).
	hubRetry     = 10 * time.Second
	hubAddrsFile = "xray-hub-addrs.json"
	// hubStale is how long an address may go unanswered before it makes room: a list that
	// only grew would freeze at the bound and miss the panel's next address (B5 r2-10).
	hubStale = 24 * time.Hour
)

// merge adds what the name answers. A name that answers with another subset each time
// must not change the list, because a change of it rebuilds the idle slot, so an
// address stays until it has not been answered for hubStale. The list is bounded, and a
// full list says so with an alert instead of dropping addresses without a word. The
// answers come from the identified Unbound only (lookupHub), never from the host's
// plain resolver, which a network attacker could fill with addresses of its choice.
func (h *hubAddrs) merge(as []netip.Addr) {
	if len(as) == 0 {
		return
	}
	now := time.Now()
	if h.seen == nil {
		h.seen = map[netip.Addr]time.Time{}
	}
	for _, a := range as {
		h.seen[a] = now
	}
	h.got = slices.DeleteFunc(h.got, func(a netip.Addr) bool { return now.Sub(h.seen[a]) > hubStale })
	for _, a := range as {
		if slices.Contains(h.got, a) {
			continue
		}
		if len(h.got) >= hubMax {
			if !h.capped && h.alert != nil {
				h.capped = true
				h.alert.Alert(alert.Alert{Code: "xray_hub_addrs_capped", Detail: "the hub name answers more addresses than the block list holds"})
			}
			return
		}
		h.got = append(h.got, a)
	}
}

// prime seeds the list from the file of the last run, then asks once, so that the first
// list is the one the running slots were rendered with and a restart of the agent
// rebuilds nothing. An empty answer (Unbound not up yet at a boot) leaves the seed.
func (h *hubAddrs) prime() {
	if len(h.ac.Panel()) > 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.load()
	h.merge(h.lookup(ctx, h.ac.HubHost()))
	h.save()
	h.at = time.Now()
}

// load reads the list of the last run. Its addresses count as just answered.
func (h *hubAddrs) load() {
	if h.file == "" {
		return
	}
	b, err := os.ReadFile(h.file)
	if err != nil {
		return
	}
	var as []netip.Addr
	if json.Unmarshal(b, &as) != nil {
		return
	}
	h.merge(as)
}

// save writes the list when it changed. It holds panel addresses only, no secret.
func (h *hubAddrs) save() {
	if h.file == "" || slices.Equal(h.got, h.saved) {
		return
	}
	b, err := json.Marshal(h.got)
	if err != nil {
		return
	}
	tmp := h.file + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, h.file) == nil {
		h.saved = slices.Clone(h.got)
	}
}

func (h *hubAddrs) get() []netip.Addr {
	if p := h.ac.Panel(); len(p) > 0 {
		return p
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	every := hubRefresh
	if len(h.got) == 0 {
		every = hubRetry
	}
	if !h.fetching && (h.at.IsZero() || time.Since(h.at) > every) {
		h.fetching = true
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			as := h.lookup(ctx, h.ac.HubHost())
			h.mu.Lock()
			h.merge(as)
			h.save()
			h.at, h.fetching = time.Now(), false
			h.mu.Unlock()
		}()
	}
	return append([]netip.Addr(nil), h.got...)
}

// lookupHub asks the identified Unbound for the hub name, IPv4 and IPv6, and then the
// host's own resolver, which is the one the agent dials and nft allows the panel through
// (internal/agent/system.go): a name that only the host knows (hosts file, internal
// zone) must be in the block list too. Both only add addresses to block, and the bound
// of hubMax keeps either from growing the list; Unbound's answers come first.
func lookupHub(unbound string) func(ctx context.Context, host string) []netip.Addr {
	v4, v6 := xray.UnboundResolver(unbound), xray.UnboundResolver6(unbound)
	return func(ctx context.Context, host string) []netip.Addr {
		var out []netip.Addr
		for _, f := range []func(context.Context, string) ([]netip.Addr, error){v4, v6} {
			if as, err := f(ctx, host); err == nil {
				out = append(out, as...)
			}
		}
		if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host); err == nil {
			for _, ip := range ips {
				out = append(out, ip.Unmap())
			}
		}
		return out
	}
}
