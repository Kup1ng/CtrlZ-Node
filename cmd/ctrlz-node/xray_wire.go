package main

import (
	"path/filepath"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nft"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
	"github.com/Kup1ng/CtrlZ-Node/internal/xray"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayctl"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// identifiedUnbound is the identified Unbound (SC 5.2a), the one resolver that the Xray
// manager and the hub name lookup trust.
const identifiedUnbound = "127.0.0.10:5300"

// wireXray is the one block of this part in the agent's boot: it builds the Xray
// manager with the Faults and DNS that every part shares and adds it to the parts.
func wireXray(cfg *agent.Config) {
	cfg.Parts = append(cfg.Parts, xray.New(xrayOptions(cfg)))
}

// xrayOptions makes the manager's options. It is apart from wireXray so that a test
// can see which Guard the manager waits on.
func xrayOptions(cfg *agent.Config) xray.Options {
	if cfg.Faults == nil {
		cfg.Faults = agent.NewFaults()
	}
	if cfg.DNS == nil {
		cfg.DNS = &agent.DNS{}
	}
	// The guard of 5.5 is made here, in the tune, because the manager reads it when it
	// is built and boot runs the tune before wireNftGuard. wireNftGuard keeps a guard
	// that is already set and runs that same one as its part, so the table the agent
	// applies and the table the manager waits on are one object. A nil *nft.Guard
	// must never be handed over: inside an agent.Guard it is not nil, and Check would
	// run on it.
	if cfg.NftGuard == nil {
		cfg.NftGuard = nft.NewGuard(cfg.Runner)
	}
	const unbound = identifiedUnbound
	return xray.Options{
		Layout:    xrayrun.DefaultLayout(),
		StateDir:  filepath.Join(cfg.Root, "xray"),
		Ctl:       &xray.SockCtl{Path: xrayctl.DefaultSock},
		Units:     xray.SystemdUnits{Runner: sysx.ExecRunner{}},
		Prober:    xray.SocksProber{},
		Guard:     cfg.NftGuard,
		Faults:    cfg.Faults,
		Publish:   cfg.DNS.Publish,
		Alert:     cfg.Alert,
		Resolve:   xray.UnboundResolver(unbound),
		NodeAddrs: xrayNodeAddrs(cfg),
		Unbound:   unbound,
		Timing:    xray.DefaultTiming(),
	}
}
