package agent

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
)

// pendingServes reports whether servePending will supervise anything, so boot knows
// whether a dead enrolment may end the process or must leave the supervision running.
func pendingServes(cfg Config) bool {
	return !cfg.NoSystem && cfg.Runner != nil && cfg.Files != nil
}

// servePending runs the part of the host side that needs no identity while the node
// enrols: the two Unbound processes, the nftables table and the host checks, started
// under the same checks and supervised on the same ticks as the agent does. Enrolment
// can last a day (the admin's two TOTP steps) or never end (a rejected token), and
// install removes the rendered Unbound files and stops the units so the agent writes
// them afresh (p4n-MC-r1-6). Without this the node, which the spec says keeps serving
// without the agent (7.1, 7.2), would answer every identified miss with SERVFAIL until
// an admin approves it, because the dns role forwards those to the identified Unbound,
// and after a reboot it would serve Plain DNS with no notrack rules (SC 5.2a) and
// nothing to say so (p4n-MC-r3-5). Nothing here talks to the hub. The returned function
// ends the supervision and waits for it; the units keep running (systemd owns them),
// and the agent's own start finds them active and takes them over with a reload.
func servePending(ctx context.Context, cfg Config, ac conf.Agent) (stop func()) {
	if !pendingServes(cfg) {
		return func() {}
	}
	if cfg.Alert == nil {
		cfg.Alert = alert.Discard{}
	}
	cfg.Conf = ac
	// The store is opened here, before this function returns and so before the enrolment
	// writes anything: Open removes every ".tmp-" file under the root, keys/ included, and
	// the enrolment makes such files there while it writes the pending record, the key and
	// the certificate. Run beside it, the clean-up could take a temporary file between its
	// creation and its rename, and the enrolment (whose token is already spent) would
	// be lost (p4n-MC-r3-1, p4n-MC-r3-2).
	st := pendingStateOf(cfg, ac)
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		unb := newUnbound(cfg)
		var table nftApplier
		startUnbound(ctx, cfg, cfg.Alert, unb, st.doNotQuery)
		table.apply(ctx, cfg, cfg.Alert, st.dnsIP)
		runHostChecks(ctx, cfg, cfg.Alert, st.addrs)
		every := cfg.UnboundEvery
		if every == 0 {
			every = 10 * time.Second
		}
		unbTick := time.NewTicker(every)
		defer unbTick.Stop()
		hostEvery := cfg.HostEvery
		if hostEvery == 0 {
			hostEvery = time.Minute
		}
		hostTick := time.NewTicker(hostEvery)
		defer hostTick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-unbTick.C:
				unb.Check(ctx)
			case <-hostTick.C:
				// The same retry the agent makes: a table that was not applied, a host
				// check that held back the start.
				runHostChecks(ctx, cfg, cfg.Alert, st.addrs)
				table.apply(ctx, cfg, cfg.Alert, st.dnsIP)
			}
		}
	}()
	return func() { cancel(); wg.Wait() }
}

// pendingState is what the agent would know of the node's addresses at its start: agent.conf,
// the stored NodeConfig and the table of the applied state.
type pendingState struct {
	addrs      []netip.Addr
	doNotQuery []netip.Prefix
	dnsIP      netip.Addr
}

// pendingStateOf is the agent's nodeAddrs, doNotQuery and dnsIP before the agent exists.
// An unreadable store gives the shorter list; the agent that takes over reloads the full
// one.
func pendingStateOf(cfg Config, ac conf.Agent) pendingState {
	root, err := store.Open(cfg.Root, &fsx.Writer{Hook: cfg.FSHook})
	if err != nil {
		addrs := nodeAddrList(ac, nil, nil)
		return pendingState{addrs: addrs, doNotQuery: doNotQueryOf(addrs), dnsIP: ac.DNSBindIP}
	}
	s, _ := nodecfg.New(root.Path(store.DirConfig), &fsx.Writer{Hook: cfg.FSHook}).LoadServing(cfg.ConfPath)
	addrs := nodeAddrList(ac, s.Config, root.PeekMember())
	ip := ac.DNSBindIP
	if s.Config != nil {
		if a, ok := addrOf(s.Config.DnsBindIp); ok {
			ip = a
		}
	}
	return pendingState{addrs: addrs, doNotQuery: doNotQueryOf(addrs), dnsIP: ip}
}
