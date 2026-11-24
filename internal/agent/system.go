package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/chrony"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hostcheck"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nft"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/unbound"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// afterMembership and afterConfig ask the system loop to look at the addresses
// again: the do-not-query list follows the applied PairTable and the NodeConfig,
// and nftables follows DNS_IP. They only poke: running a command is not done on
// the log worker or the table writer.
func (a *Agent) afterMembership() { a.pokeSystem() }

func (a *Agent) afterConfig(context.Context) {
	a.checkUpstreamLoops()
	a.pokeSystem()
	a.pokeTable()
}

func (a *Agent) sysWake() chan struct{} { return a.sysWakeCh }

func (a *Agent) pokeSystem() {
	select {
	case a.sysWake() <- struct{}{}:
	default:
	}
}

// checkUpstreamLoops alerts for an upstream of the NodeConfig whose address, or
// bootstrap IP, is one of the node addresses in any form (SC 5.2a, Loops): the
// free path would answer it and the query would come back. The dns role treats
// such an upstream as failed.
func (a *Agent) checkUpstreamLoops() {
	c := a.nodeCfg.Load()
	if c == nil {
		return
	}
	nodes := a.nodeAddrs()
	for _, u := range c.Upstreams {
		var ips []netip.Addr
		if ap, err := netip.ParseAddrPort(u.Address); err == nil {
			ips = append(ips, ap.Addr())
		} else if ip, err := netip.ParseAddr(u.Address); err == nil {
			ips = append(ips, ip)
		}
		if ip, ok := addrOf(u.BootstrapIp); ok {
			ips = append(ips, ip)
		}
		for _, ip := range ips {
			if nets.CoversAddr(nodes, ip) {
				a.al.Alert(alert.Alert{Code: alert.UpstreamLoop, Detail: "an upstream is a node address"})
				break
			}
		}
	}
}

// systemLoop starts and watches the host side: the two Unbound processes, the
// nftables table and chrony, and runs the periodic checks of 7.3.
func (a *Agent) systemLoop(ctx context.Context) {
	if a.cfg.NoSystem {
		return
	}

	if v := startUnbound(ctx, a.cfg, a.al, a.unb, a.doNotQuery()); v != "" {
		a.unbVersion.Store(&v)
	}
	a.applyNft(ctx)
	a.updateChrony(ctx)
	a.hostChecks(ctx)

	every := a.cfg.HostEvery
	if every == 0 {
		every = time.Minute
	}
	hostTick := time.NewTicker(every)
	defer hostTick.Stop()
	unbEvery := a.cfg.UnboundEvery
	if unbEvery == 0 {
		unbEvery = 10 * time.Second
	}
	unbTick := time.NewTicker(unbEvery)
	defer unbTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.sysWake():
			_ = a.unb.SetDoNotQuery(ctx, a.doNotQuery())
			a.applyNft(ctx)
			a.restartDNSIfDue(ctx)
		case <-unbTick.C:
			a.unb.Check(ctx)
			// A restart onto a replaced binary changes the version the hub is told.
			if v := a.unb.RunningVersion(); v != "" {
				a.unbVersion.Store(&v)
			}
		case <-hostTick.C:
			a.hostChecks(ctx)
			// A chrony restart that failed is tried again here (chrony.Update keeps
			// on disk what it still owes).
			a.updateChrony(ctx)
			// A table that was not applied (the hub's name did not resolve at boot, nft
			// failed once) is tried again here: without it the notrack rules would stay
			// missing until some PairTable or NodeConfig happened to arrive.
			a.applyNft(ctx)
			a.restartDNSIfDue(ctx)
		}
	}
}

// DNSUnit is the systemd unit of the dns process.
const DNSUnit = "ctrlz-dns.service"

// restartDNSIfDue restarts dns after a NodeConfig changed what it binds to: it
// opens its listeners once, at start, so a node that started Plain-only (no
// NodeConfig yet) would otherwise stay Plain-only. A failed restart is tried again
// on the next host tick.
func (a *Agent) restartDNSIfDue(ctx context.Context) {
	if !a.dnsRestart.Swap(false) {
		return
	}
	if _, err := a.cfg.Runner.Run(ctx, nil, "systemctl", "restart", DNSUnit); err != nil {
		a.dnsRestart.Store(true)
		a.al.Alert(alert.Alert{Code: alert.DNSRestartFailed, Detail: "ctrlz-dns could not be restarted onto the new NodeConfig"})
		return
	}
	if !a.dnsRestart.Load() { // a newer NodeConfig may have made it owed again meanwhile
		_ = os.Remove(a.dnsOwedPath())
	}
}

// dnsOwedPath is the marker of a dns restart the agent still owes. It is on disk
// because dnsKey is rebuilt at start from the stored NodeConfig on the assumption
// that dns runs on it: a restart that failed and an agent that then restarted would
// otherwise leave dns on its Plain-only fallback or an old bind address for good.
func (a *Agent) dnsOwedPath() string {
	return filepath.Join(a.root.Path(store.DirConfig), "dns-restart.owed")
}

func (a *Agent) markDNSRestartOwed() {
	if err := a.fsw.WriteFile(a.dnsOwedPath(), []byte("owed\n"), 0o640); err != nil {
		a.al.Alert(alert.Alert{Code: alert.DNSRestartFailed, Detail: "the owed restart of ctrlz-dns could not be written down"})
	}
}

func (a *Agent) hostChecks(ctx context.Context) {
	if a.cfg.SkipHostChecks {
		return
	}
	hostcheck.Alerts(a.al, hostcheck.CoreDumps(a.cfg.Files))
	hostcheck.Alerts(a.al, hostcheck.HostResolver(a.cfg.Files, a.nodeAddrs()))
	want := a.cfg.ConntrackMax
	if want == 0 {
		want = hostcheck.DefaultConntrackMax
	}
	hostcheck.Alerts(a.al, hostcheck.EnsureConntrack(ctx, a.cfg.Files, a.cfg.Runner, want))
}

// applyNft applies the agent's table when DNS_IP or the panel addresses changed.
func (a *Agent) applyNft(ctx context.Context) {
	p := nft.Params{DNSIP: a.dnsIP(), PanelAddrs: a.cfg.Conf.Panel(), FreePortLo: unbound.FreePortLo, FreePortHi: unbound.FreePortHi}
	if len(p.PanelAddrs) == 0 {
		// The hub is a name: resolve it once, here, because nftables needs addresses.
		if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", a.cfg.Conf.HubHost()); err == nil {
			for _, ip := range ips {
				p.PanelAddrs = append(p.PanelAddrs, ip.Unmap())
			}
		}
	}
	text, err := nft.Render(p)
	if err != nil {
		a.al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "the nftables table could not be rendered"})
		return
	}
	a.mu.Lock()
	same := a.lastNft == text
	a.mu.Unlock()
	if same {
		return
	}
	if err := nft.Apply(ctx, a.cfg.Runner, p); err != nil {
		a.al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "nft refused the table"})
		return
	}
	a.mu.Lock()
	a.lastNft = text
	a.mu.Unlock()
}

func (a *Agent) updateChrony(ctx context.Context) {
	ca, err := os.ReadFile(a.root.KeyPath(hubconn.NodeCAFile))
	if err != nil {
		a.al.Alert(alert.Alert{Code: alert.ChronyFailed, Detail: "no node CA to trust"})
		return
	}
	if _, err := chrony.Update(ctx, a.cfg.Files, a.cfg.Runner, a.cfg.Conf.HubHost(), ca); err != nil {
		a.al.Alert(alert.Alert{Code: alert.ChronyFailed, Detail: "the chrony drop-in could not be updated"})
	}
}

// coreGate is the host check an Unbound start depends on (SC 5.2a, No trace): no
// path left by which a crashed process could leave a core with its cache in it.
func coreGate(cfg Config) error {
	if cfg.SkipHostChecks {
		return nil
	}
	if len(hostcheck.CoreDumps(cfg.Files)) > 0 {
		return errors.New("agent: core dumps are not ruled out")
	}
	return nil
}

// startUnbound is the first start of the two processes. Core dumps come first: a
// process that can leave a core holds its cache and request list in it, so neither
// starts while a check fails (SC 5.2a, No trace). It returns the Unbound version, or
// "" when it could not be read.
func startUnbound(ctx context.Context, cfg Config, al alert.Alerter, unb *unbound.Supervisor, dnq []netip.Prefix) string {
	coresOK := true
	if !cfg.SkipHostChecks {
		fs := hostcheck.CoreDumps(cfg.Files)
		hostcheck.Alerts(al, fs)
		coresOK = len(fs) == 0
	}
	v, _ := unb.Version(ctx)
	if coresOK {
		for _, k := range []unbound.Kind{unbound.Identified, unbound.Free} {
			_ = unb.Start(ctx, k, dnq)
		}
	} else {
		al.Alert(alert.Alert{Code: alert.UnboundRefused, Detail: "core dumps are not ruled out"})
		// Not started, but meant to run: the unbound tick starts them once the host
		// check holds (an operator fixes kernel.core_pattern while the agent runs).
		unb.Want(unbound.Identified, unbound.Free)
	}
	return v
}
