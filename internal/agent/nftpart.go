package agent

import (
	"context"
	"net/netip"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nft"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/unbound"
)

// The nftables guard of p4b-proxy 5.5 as a Part (B4). The table itself is applied
// by the agent's system loop through nft.Guard; this part is the timer that reads
// it back every 5 s, applies it again when it is missing or different, and raises
// the fault nft_failed while that fails. The Xray manager (B5) reads the same guard
// through Config.NftGuard: Check before it starts a slot, Changed to stop them.

// guardEvery is the read-back period (5.5).
const guardEvery = 5 * time.Second

type nftPart struct {
	g     *nft.Guard
	every time.Duration
}

// wireNftGuard is the one block B4 adds to the boot code: the guard, the fault set
// it raises its fault in, and the part that runs it.
func wireNftGuard(cfg *Config) {
	if cfg.Faults == nil {
		cfg.Faults = NewFaults()
	}
	if cfg.NftGuard == nil {
		cfg.NftGuard = nft.NewGuard(cfg.Runner)
	}
	f := cfg.Faults
	cfg.NftGuard.OnFailure(func(failed bool) { f.Set(hubv1.NodeFault_NODE_FAULT_NFT_FAILED, failed) })
	cfg.Parts = append(cfg.Parts, &nftPart{g: cfg.NftGuard, every: guardEvery})
}

func (p *nftPart) Run(ctx context.Context) {
	t := time.NewTicker(p.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.g.Heal(ctx)
		}
	}
}

// Config and Heartbeat have nothing to do: the table follows the agent's own state,
// and the fault reaches the Heartbeat through Faults.
func (p *nftPart) Config(*hubv1.NodeConfig)   {}
func (p *nftPart) Heartbeat(*hubv1.Heartbeat) {}

// proxyNft is what the proxy chains of the table need, or nil when the node cannot
// have them yet: no proxy address, or an account that does not exist. A node with
// nil here still gets the table of P4, and the guard says off for it (nft.Guard).
func (a *Agent) proxyNft() *nft.ProxyParams {
	if a.cfg.NftGuard == nil {
		return nil // no guard: this agent is not running the proxy role's table
	}
	ip := a.cfg.Conf.ProxyBindIP
	nc := a.nodeCfg.Load()
	if nc != nil {
		if v, ok := addrOf(nc.ProxyBindIp); ok {
			ip = v
		}
	}
	if !ip.IsValid() {
		return nil
	}
	lookup := a.cfg.LookupUIDs
	if lookup == nil {
		lookup = func(names ...string) ([]uint32, error) { return sock.LookupUIDs(nil, names...) }
	}
	u, err := lookup(sock.UserXray, sock.UserProxy, sock.UserBlock, sock.UserDNS, sock.UserAgent)
	if err != nil || len(u) != 5 {
		a.al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "an account of the proxy chains is unknown"})
		return nil
	}
	deny := a.nodeAddrs()
	add := func(b []byte) {
		if v, ok := addrOf(b); ok {
			deny = append(deny, v)
		}
	}
	if nc != nil {
		add(nc.ProxyAdvertisedIp)
	}
	for _, v := range []netip.Addr{a.cfg.Conf.ProxyBindIP, a.cfg.Conf.ProxyAdvertisedIP} {
		if v.IsValid() {
			deny = append(deny, v.Unmap())
		}
	}
	if m := a.member(); m != nil {
		for _, n := range m.Nodes {
			add(n.ProxyIp)
		}
	}
	return &nft.ProxyParams{
		ProxyIP:   ip,
		Uids:      nft.Uids{Xray: u[0], Proxy: u[1], Block: u[2], DNS: u[3], Agent: u[4]},
		Unbound:   unbound.DefaultParams(unbound.Identified).Listen,
		DenyAddrs: deny,
	}
}
