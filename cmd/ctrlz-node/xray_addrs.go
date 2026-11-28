package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// xrayNodeAddrs returns the list of addresses that the Xray manager adds to the
// finalRules of `direct` and of every freedom outbound (p4b-proxy 7.4): the panel, and
// the DNS and proxy address of every node of the applied table, the node's own
// addresses from agent.conf included. The manager reads it at every reconcile, so it
// never waits for a lookup and reads one small file; a change of the list is a change
// of the base and rebuilds the idle slot (7.5 step 5).
func xrayNodeAddrs(cfg *agent.Config) func() []netip.Addr {
	hub := &hubAddrs{ac: cfg.Conf, lookup: lookupHub}
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

	mu       sync.Mutex
	got      []netip.Addr
	at       time.Time
	fetching bool
}

const hubRefresh = 5 * time.Minute

// merge only adds: a name that answers with another subset each time must not change
// the list, because a change of it rebuilds the idle slot, and a stale address stays
// blocked, which costs nothing. The list is bounded.
func (h *hubAddrs) merge(as []netip.Addr) {
	for _, a := range as {
		if len(h.got) >= 32 {
			return
		}
		if !slices.Contains(h.got, a) {
			h.got = append(h.got, a)
		}
	}
}

// prime asks once, at the start, so that the first list is the one the running slots
// were rendered with and a restart of the agent rebuilds nothing.
func (h *hubAddrs) prime() {
	if len(h.ac.Panel()) > 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h.mu.Lock()
	h.merge(h.lookup(ctx, h.ac.HubHost()))
	h.at = time.Now()
	h.mu.Unlock()
}

func (h *hubAddrs) get() []netip.Addr {
	if p := h.ac.Panel(); len(p) > 0 {
		return p
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.fetching && (h.at.IsZero() || time.Since(h.at) > hubRefresh) {
		h.fetching = true
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			as := h.lookup(ctx, h.ac.HubHost())
			h.mu.Lock()
			h.merge(as)
			h.at, h.fetching = time.Now(), false
			h.mu.Unlock()
		}()
	}
	return append([]netip.Addr(nil), h.got...)
}

func lookupHub(ctx context.Context, host string) []netip.Addr {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out
}
