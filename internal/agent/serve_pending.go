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

// servePending runs the part of the host side that needs no identity while the node
// enrols: the two Unbound processes, started under the same checks and supervised on
// the same tick as the agent does. Enrolment can last a day (the admin's two TOTP
// steps) or never end (a rejected token), and install removes the rendered Unbound
// files and stops the units so the agent writes them afresh (p4n-MC-r1-6). Without
// this the node, which the spec says keeps serving without the agent (7.1, 7.2),
// would answer every identified miss with SERVFAIL until an admin approves it,
// because the dns role forwards those to the identified Unbound. Nothing here talks
// to the hub. The returned function ends the supervision and waits for it; the units
// keep running (systemd owns them), and the agent's own start finds them active and
// takes them over with a reload.
func servePending(ctx context.Context, cfg Config, ac conf.Agent) (stop func()) {
	if cfg.NoSystem || cfg.Runner == nil || cfg.Files == nil {
		return func() {}
	}
	if cfg.Alert == nil {
		cfg.Alert = alert.Discard{}
	}
	cfg.Conf = ac
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		unb := newUnbound(cfg)
		startUnbound(ctx, cfg, cfg.Alert, unb, pendingDoNotQuery(cfg, ac))
		every := cfg.UnboundEvery
		if every == 0 {
			every = 10 * time.Second
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				unb.Check(ctx)
			}
		}
	}()
	return func() { cancel(); wg.Wait() }
}

// pendingDoNotQuery is doNotQuery before the agent exists: the node's addresses from
// agent.conf, the stored NodeConfig and the table of the applied state. An unreadable
// store gives the shorter list; the agent that takes over reloads the full one.
func pendingDoNotQuery(cfg Config, ac conf.Agent) []netip.Prefix {
	root, err := store.Open(cfg.Root, &fsx.Writer{Hook: cfg.FSHook})
	if err != nil {
		return doNotQueryOf(nodeAddrList(ac, nil, nil))
	}
	s, _ := nodecfg.New(root.Path(store.DirConfig), &fsx.Writer{Hook: cfg.FSHook}).LoadServing(cfg.ConfPath)
	return doNotQueryOf(nodeAddrList(ac, s.Config, root.PeekMember()))
}
