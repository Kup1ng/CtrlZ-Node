package main

import (
	"path/filepath"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
	"github.com/Kup1ng/CtrlZ-Node/internal/xray"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayctl"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// nftGuard is the guard of 5.5 that the Xray manager waits on. B4 makes it (the
// read-back of the agent's table); until it is merged and set here, the manager has
// none and fails closed: it starts no slot (xray.Manager.guard is false for a nil
// Guard). The integration step assigns it before the agent is built.
var nftGuard func(*agent.Config) agent.Guard

// wireXray is the one block of this part in the agent's boot: it builds the Xray
// manager with the Faults and DNS that every part shares and adds it to the parts.
func wireXray(cfg *agent.Config) {
	if cfg.Faults == nil {
		cfg.Faults = agent.NewFaults()
	}
	if cfg.DNS == nil {
		cfg.DNS = &agent.DNS{}
	}
	var guard agent.Guard
	if nftGuard != nil {
		guard = nftGuard(cfg)
	}
	const unbound = "127.0.0.10:5300" // the identified Unbound (SC 5.2a)
	m := xray.New(xray.Options{
		Layout:    xrayrun.DefaultLayout(),
		StateDir:  filepath.Join(cfg.Root, "xray"),
		Ctl:       &xray.SockCtl{Path: xrayctl.DefaultSock},
		Units:     xray.SystemdUnits{Runner: sysx.ExecRunner{}},
		Prober:    xray.SocksProber{},
		Guard:     guard,
		Faults:    cfg.Faults,
		Publish:   cfg.DNS.Publish,
		Alert:     cfg.Alert,
		Resolve:   xray.UnboundResolver(unbound),
		NodeAddrs: xrayNodeAddrs(cfg),
		Unbound:   unbound,
		Timing:    xray.DefaultTiming(),
	})
	cfg.Parts = append(cfg.Parts, m)
}
