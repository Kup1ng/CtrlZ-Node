package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/chrony"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hostcheck"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nft"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
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

	// The table first: it needs no Unbound, and the Xray manager waits (bounded) on its
	// first attempt, so a slow Unbound start must not eat that wait (INT2-r1-5). A hub
	// name that cannot be resolved before Unbound runs is tried again right after it.
	a.applyNft(ctx)
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
	runHostChecks(ctx, a.cfg, a.al, a.nodeAddrs())
}

// runHostChecks is the periodic host checks of 7.3 for the inputs they are made of, so
// that the node which has no identity yet (serve_pending.go) runs the same ones.
func runHostChecks(ctx context.Context, cfg Config, al alert.Alerter, nodeAddrs []netip.Addr) {
	if cfg.SkipHostChecks {
		return
	}
	hostcheck.Alerts(al, hostcheck.CoreDumps(cfg.Files))
	hostcheck.Alerts(al, hostcheck.HostResolver(cfg.Files, nodeAddrs))
	hostcheck.Alerts(al, hostcheck.Syncookies(cfg.Files))
	want := cfg.ConntrackMax
	if want == 0 {
		want = hostcheck.DefaultConntrackMax
	}
	hostcheck.Alerts(al, hostcheck.EnsureConntrack(ctx, cfg.Files, cfg.Runner, want))
	if cfg.NftGuard != nil { // the proxy role is wired (boot.go): its kernel keys matter
		hostcheck.Alerts(al, hostcheck.ProxyKernel(cfg.Files))
	}
}

// applyNft applies the agent's table when DNS_IP or the panel addresses changed.
func (a *Agent) applyNft(ctx context.Context) {
	a.nftTable.applyWith(ctx, a.cfg, a.al, a.dnsIP(), a.proxyNft())
}

// nftApplier applies the agent's nftables table and remembers the text it applied. The
// agent owns one, and so does the start before the agent exists (serve_pending.go): a
// reboot drops the kernel's table, and the notrack rules of SC 5.2a must be back before
// the first spoofed packet, identity or not.
type nftApplier struct {
	mu   sync.Mutex
	last string // the nftables script last applied
	// panel is the hub's addresses of the last lookup that answered: a lookup that
	// fails later must not render a table with no panel address, which would leave
	// the guard on over the older table.
	panel []netip.Addr
	// lookup resolves the hub name; nil takes the system resolver (a test gives its own).
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// lookupWait bounds one hub lookup; 0 means defaultLookupWait. A test shortens it.
	lookupWait time.Duration
	// g, when set, applies the table and keeps the read-back of 5.5 (nftpart.go).
	g *nft.Guard
}

func (n *nftApplier) apply(ctx context.Context, cfg Config, al alert.Alerter, dnsIP netip.Addr) {
	n.applyWith(ctx, cfg, al, dnsIP, nil)
}

// applyWith is apply with the proxy chains of p4b-proxy 5.5 (px nil: the table of P4).
func (n *nftApplier) applyWith(ctx context.Context, cfg Config, al alert.Alerter, dnsIP netip.Addr, px *nft.ProxyParams) {
	// kept says whether the older table is to be kept: the kernel holds a table of ours
	// with the proxy chains, or it could not be asked (an unknown answer is no proof that
	// the chains are gone, INT2-r2-1, INT2-r2-4). It is read
	// from the kernel and not from this process: the table outlives the agent (no
	// ExecStop), so a restarted agent has applied nothing and still faces the chains
	// that bind the uids of the slots that kept running (INT2-r1-1, INT2-r1-4). The
	// answer cannot change under us: a refused script leaves the table as it was, and
	// this loop is the only one that applies.
	var keptRead, keptVal bool
	kept := func() bool {
		if n.g == nil {
			return false
		}
		if !keptRead {
			holds, known := n.g.HoldsProxyChains(ctx)
			keptVal, keptRead = holds || !known, true
		}
		return keptVal
	}
	if px == nil && kept() {
		// The proxy part cannot be had this pass (no address, an account that did not
		// resolve). That is no reason to take the chains away from uids that still run: the
		// older table stays, the guard is off, so the manager stops the slots, and the
		// next pass that has the part puts the full table back (INT2-r1-3, INT2-r1-6).
		al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "the proxy chains cannot be built now; the older table stays"})
		n.g.Reject()
		return
	}
	p := nft.Params{DNSIP: dnsIP, PanelAddrs: cfg.Conf.Panel(), FreePortLo: unbound.FreePortLo, FreePortHi: unbound.FreePortHi, Proxy: px}
	if len(p.PanelAddrs) == 0 {
		// The hub is a name: resolve it once, here, because nftables needs addresses.
		p.PanelAddrs = n.resolvePanel(ctx, cfg)
	}
	text, err := nft.Render(p)
	fallback := false
	if err != nil && px != nil && !kept() {
		// When the proxy part is what cannot be rendered (an address equal to DNS_IP, an
		// unusable uid), the table of P4 still goes in, but only where the kernel holds no
		// proxy chains: there is no older table to stand, and the notrack and flood rules of
		// DNS_IP must not be lost with it (5.5). The guard stays off and nft_failed is
		// raised. Where the chains exist, the older table stays (B4-r2-3).
		p4 := p
		p4.Proxy = nil
		if t4, err4 := nft.Render(p4); err4 == nil {
			al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "the proxy chains could not be rendered"})
			n.mu.Lock()
			done := n.last == t4
			n.mu.Unlock()
			if done && n.g != nil {
				// Already in the kernel from an earlier pass: no reload, no clear and raise
				// of nft_failed (B4-r2-1, B4-r2-4).
				n.g.Reject()
				return
			}
			p, text, err, fallback = p4, t4, nil, true
		}
	}
	if err != nil {
		al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "the nftables table could not be rendered"})
		// A hub name with no address yet, on a guard that has not made its first attempt,
		// must not settle it as rejected: the manager would stop slots whose table is still
		// intact in the kernel, for a lookup the next pass may answer (INT2-r1-2).
		if n.g != nil && (len(p.PanelAddrs) > 0 || n.g.IsSettled()) {
			n.g.Reject()
		}
		return
	}
	n.mu.Lock()
	same := n.last == text
	n.mu.Unlock()
	// A guard that is failed (a table that could not be rendered or applied since)
	// needs the apply even for the text that is in the kernel: it is what ends the
	// failure and puts the guard on again.
	if same && (n.g == nil || !n.g.Failed()) {
		return
	}
	err = n.applyTable(ctx, cfg, p, fallback)
	if err != nil && p.Proxy != nil && n.g != nil && !kept() {
		// The script rendered but nft refused it, and no older table with chains exists:
		// the DNS_IP rules must not wait for chains that have never run on this kernel
		// (B4-r2-2). nft applies a script whole or not at all, so nothing is half
		// there; the fallback goes in with the guard off and the next pass tries the
		// full table again.
		al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "nft refused the proxy chains"})
		p4 := p
		p4.Proxy = nil
		if t4, err4 := nft.Render(p4); err4 == nil {
			if err = n.applyTable(ctx, cfg, p4, true); err == nil {
				text = t4
			} else {
				n.g.Want(p)
			}
		}
	}
	if err != nil {
		al.Alert(alert.Alert{Code: alert.NftFailed, Detail: "nft refused the table"})
		return
	}
	n.mu.Lock()
	n.last = text
	n.mu.Unlock()
}

// defaultLookupWait is the bound of one hub lookup, far below the 30 s the Xray manager
// waits for the guard's first attempt.
const defaultLookupWait = 3 * time.Second

// panelFile is where the hub's addresses of the last answered lookup are kept. The
// table is rendered from addresses, and a restarted agent whose host resolver cannot
// answer yet (it may be the Unbound that was just started) would otherwise render
// none and settle the guard as rejected, which stops slots that run on an intact
// table (INT2-r1-2, INT2-r1-5). Not a secret: the hub's addresses are in agent.conf
// or in DNS.
func panelFile(cfg Config) string {
	if cfg.Root == "" || cfg.Files == nil {
		return ""
	}
	return filepath.Join(cfg.Root, store.DirConfig, "panel-addrs")
}

// resolvePanel looks the hub name up. An answer is remembered in memory and on disk;
// when the lookup fails, the last answer stands, read from disk when this process has
// none.
func (n *nftApplier) resolvePanel(ctx context.Context, cfg Config) []netip.Addr {
	var got []netip.Addr
	// The lookup is bounded well under the guard's settle wait (Timing.GuardSettle): a
	// resolver that drops packets takes the system's retries, 30 s or more, and the
	// Xray manager would read the guard as off and stop slots whose table is intact
	// in the kernel. The addresses stored on disk stand in for a lookup that did not
	// answer in time (INT2-r2-2, INT2-r2-3).
	wait := n.lookupWait
	if wait <= 0 {
		wait = defaultLookupWait
	}
	lctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	lookup := n.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if ips, err := lookup(lctx, cfg.Conf.HubHost()); err == nil {
		for _, ip := range ips {
			got = append(got, ip.Unmap())
		}
	}
	path := panelFile(cfg)
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(got) == 0 {
		if len(n.panel) == 0 && path != "" {
			n.panel = readPanelFile(cfg.Files, path)
		}
		return n.panel
	}
	changed := !slices.Equal(got, n.panel)
	n.panel = got
	if changed && path != "" {
		var b strings.Builder
		for _, ip := range got {
			b.WriteString(ip.String() + "\n")
		}
		// A write that fails costs only the restart case above: the table still goes in.
		_ = cfg.Files.WriteFile(path, []byte(b.String()), 0o640)
	}
	return got
}

func readPanelFile(f sysx.Files, path string) []netip.Addr {
	raw, err := f.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, l := range strings.Fields(string(raw)) {
		if ip, err := netip.ParseAddr(l); err == nil && len(out) < 32 {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// applyTable applies p through the guard when there is one. rejected keeps the guard
// off and failed for a table that is only the fallback of the one wanted.
func (n *nftApplier) applyTable(ctx context.Context, cfg Config, p nft.Params, rejected bool) error {
	switch {
	case n.g == nil:
		return nft.Apply(ctx, cfg.Runner, p)
	case rejected:
		return n.g.ApplyRejected(ctx, p)
	default:
		return n.g.Apply(ctx, p)
	}
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
