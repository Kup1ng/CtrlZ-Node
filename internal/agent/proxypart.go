package agent

import (
	"context"
	"sync/atomic"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// proxyPart is the agent's end of the Grants (P4b B3): it takes the `proxy_state` that
// dns sends every 10 s and on a change, reports it in the Heartbeat (listening and
// open connections, "not listening when that is 30 s old") and sets the fault
// `grants_full` while dns says a node_cap refusal is less than 60 s old. The Grants
// themselves live in dns; the agent only carries what the hub must see.
type proxyPart struct {
	faults *Faults
	now    func() time.Time

	// at is the Unix nanosecond of the last proxy_state, 0 before the first.
	at        atomic.Int64
	listening atomic.Bool
	open      atomic.Uint32
}

// proxyStateFresh is how old a proxy_state may be and still count.
const proxyStateFresh = 30 * time.Second

// addProxyPart makes the part and adds it to cfg.Parts. It shares the Faults and the DNS
// of the other parts and makes them when the boot has made none yet.
func addProxyPart(cfg *Config) *proxyPart {
	if cfg.Faults == nil {
		cfg.Faults = NewFaults()
	}
	if cfg.DNS == nil {
		cfg.DNS = &DNS{}
	}
	p := &proxyPart{faults: cfg.Faults, now: cfg.Now}
	if p.now == nil {
		p.now = time.Now
	}
	cfg.DNS.Subscribe(p.onDNS)
	cfg.Parts = append(cfg.Parts, p)
	return p
}

// onDNS runs on the socket's reader goroutine.
func (p *proxyPart) onDNS(m *sock.Msg) {
	if m.Type != sock.TypeProxyState || m.ProxyState == nil {
		return
	}
	s := m.ProxyState
	p.listening.Store(s.Listening)
	p.open.Store(s.Open)
	p.at.Store(p.now().UnixNano())
	p.faults.Set(hubv1.NodeFault_NODE_FAULT_GRANTS_FULL, s.Full)
}

// fresh says whether dns has spoken lately. A dns that is gone says nothing, and its
// last words must not stand for a state nobody has seen.
func (p *proxyPart) fresh() bool {
	at := p.at.Load()
	return at != 0 && p.now().Sub(time.Unix(0, at)) < proxyStateFresh
}

// Run ends with the agent; a stale `full` is cleared here, since no message will.
func (p *proxyPart) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !p.fresh() {
				p.faults.Set(hubv1.NodeFault_NODE_FAULT_GRANTS_FULL, false)
			}
		}
	}
}

// Config has nothing to take: the proxy's address comes to dns from the agent's own
// config publication.
func (p *proxyPart) Config(*hubv1.NodeConfig) {}

// Heartbeat reads atomics only (L11).
func (p *proxyPart) Heartbeat(hb *hubv1.Heartbeat) {
	if !p.fresh() {
		hb.Proxy = &hubv1.ProxyState{}
		return
	}
	hb.Proxy = &hubv1.ProxyState{Listening: p.listening.Load(), OpenConnections: p.open.Load()}
}
