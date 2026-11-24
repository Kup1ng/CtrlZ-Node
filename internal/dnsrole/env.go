// Package dnsrole is the dns role's process: it reads what the agent hands it
// over the agent socket (the serving image, the zone table in use, the facts of
// SC 5.2a (c), the zone keys, the NodeConfig with its real proof_key, the
// revocations in force), runs the six listeners of internal/dns/listen with the
// step-1 limits, and gives the query path an Env to read all of it from.
//
// The query path itself (SC 5.2, the Handler) is built by the caller as a
// HandlerFactory, so this package and the query path can be built apart and
// joined by one function value. Until the query path is joined, RefuseHandler
// answers every query REFUSED (and every DoH request 404): a node that is
// built but not joined serves nothing, which is the safe state, and nothing in
// the release binary answers with made-up data.
//
// What the socket being down means is decided here (7.1, SC 5.2a Which process):
// dns keeps its last image and takes the free path as off, so the Env's FreeOK
// is false from the moment the link drops until the agent has sent the facts
// again.
package dnsrole

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// TableState is the zone table in use and the node's own view of the panel.
type TableState struct {
	// Table is nil while the node has no table in use (SC 8a.5): it answers the
	// Endpoint hostnames and name-server names with REFUSED.
	Table *zone.Table
	Local zone.Local
	// DrainSince is the Unix second the drain began, 0 when the node is not draining.
	DrainSince int64
}

// Env is what the query path reads. Every method is safe from any goroutine and
// none blocks.
type Env struct {
	image atomic.Pointer[image.Image]
	table atomic.Pointer[TableState]
	facts atomic.Pointer[sock.Facts]
	// hubOffset is the last offset of the hub's clock the agent sent, kept across a
	// reconnect (facts are cleared by it, the offset is not) and 0 until the first
	// facts of this process.
	hubOffset atomic.Int64
	// offsetKnown is set by the first facts of this process: until then dns cannot
	// judge an expiry in hub time, so it keeps what it is given and judges on read.
	offsetKnown atomic.Bool
	config      atomic.Pointer[hubv1.NodeConfig]
	revs        atomic.Pointer[[]sock.RevItem]
	keys        atomic.Pointer[[]*keyCert]
	linkUp      atomic.Bool
	// downSince is the Unix nanosecond since which the agent socket has been down, 0
	// while it is up. A dns that has never connected counts from its own start.
	downSince atomic.Int64
	now       func() time.Time // the clock, replaced by a test
	zones     atomic.Pointer[[]names.Name]
	imgName   atomic.Pointer[string]
	// onApply is the query path's way to learn that the agent changed something. It
	// is called on the socket's receive goroutine after the Env holds the new value,
	// and for an image before dns confirms it to the agent, so a confirmed image is
	// one the query path already serves from (a revocation ends on that confirmation).
	onApply atomic.Pointer[func(typ string)]
	// ctx ends with the role. The query path stops its own goroutines on it.
	ctx context.Context

	mu   sync.Mutex
	acme map[string]sock.Acme
	// acmeSeq is the arrival order of each challenge, which breaks a tie in expiry
	// when the bound is held: Go's map order is random, so without it the challenge
	// that just arrived could be the one that goes.
	acmeSeq map[string]uint64
	acmeN   uint64
}

type keyCert struct {
	sans []string
	cert *tls.Certificate
}

func newEnv() *Env {
	e := &Env{acme: map[string]sock.Acme{}, acmeSeq: map[string]uint64{}, now: time.Now, ctx: context.Background()}
	e.downSince.Store(e.now().UnixNano())
	return e
}

// Context ends when the role stops.
func (e *Env) Context() context.Context { return e.ctx }

// OnApply registers the function called with the type of each message of the agent
// (sock.TypeImage, TypeTable, TypeConfig, TypeRevocations, ...) once the Env holds
// it. The function runs on the socket's receive goroutine: it may do work but must
// not wait for the agent.
func (e *Env) OnApply(f func(typ string)) { e.onApply.Store(&f) }

func (e *Env) applied(typ string) {
	if f := e.onApply.Load(); f != nil {
		(*f)(typ)
	}
}

// HubOffset is the offset of the hub's clock that the agent last sent: add it to
// the node's clock to get hub time (HubNow is the same in whole seconds).
func (e *Env) HubOffset() time.Duration { return time.Duration(e.hubOffset.Load()) * time.Second }

// panelStaleAfter is the 30 s of SC 8a.5 after which a node with no Control stream
// counts the panel as stale. The agent applies the same rule to its own stream, but
// it cannot tell dns once it is gone, so dns applies it to the link itself.
const panelStaleAfter = 30 * time.Second

// Image is the serving image, nil before the first one. The Image value is
// never changed: the Env replaces it.
func (e *Env) Image() *image.Image { return e.image.Load() }

// Tables is the zone table in use. Serve from this, never from Image.Zone, which
// holds no flags and must not be served to clients (SC 8a.5, Table in use).
func (e *Env) Tables() TableState {
	var st TableState
	if t := e.table.Load(); t != nil {
		st = *t
	}
	// With the agent gone the node has no Control stream, and the PanelStale the agent
	// last sent is the last run's: left as it is, a node whose agent is down would
	// keep answering hostnames from a table the hub may have moved past, instead of
	// falling back to its own view of its peers (SC 8a.5).
	if ds := e.downSince.Load(); ds != 0 && e.now().Sub(time.Unix(0, ds)) >= panelStaleAfter {
		st.Local.PanelStale = true
	}
	return st
}

// FreeOK is the whole decision of SC 5.2a (a) and (c) as the agent's facts give
// it, false while the agent socket is down or no facts have arrived since it
// came up. The query path still judges (b), the hop guard, itself.
func (e *Env) FreeOK() bool {
	f := e.facts.Load()
	return e.linkUp.Load() && f != nil && f.FreeOK()
}

// FreeGate is FreeOK in its two parts, for the counters of SC 5.2a, which name the
// first of (a) and (c) that fails: on is (a) and caughtUp is (c). Both are false
// while the agent socket is down or no facts have arrived since it came up.
func (e *Env) FreeGate() (on, caughtUp bool) {
	f := e.facts.Load()
	if !e.linkUp.Load() || f == nil {
		return false, false
	}
	return f.FreeOn(), f.FreeCaughtUp()
}

// FreeQPS is the qps of the free_dns value in force, the node-wide budget, 0 when
// there is none.
func (e *Env) FreeQPS() uint32 {
	if f := e.facts.Load(); f != nil && f.FreeSet {
		return f.FreeQPS
	}
	return 0
}

// HubNow is the hub's clock in Unix seconds: this node's clock plus the offset the
// agent last sent (SC 8a.4 Clock). Every expires_at the agent hands over
// (Revocations, AcmeChallenges) is in hub time and must be judged with this, never
// with time.Now: a node clock moved by more than a lifetime would end them at once.
func (e *Env) HubNow() int64 { return e.now().Unix() + e.hubOffset.Load() }

// setFacts keeps the agent's facts and the hub offset they carry.
func (e *Env) setFacts(f sock.Facts) {
	e.hubOffset.Store(f.HubOffset)
	e.offsetKnown.Store(true)
	e.facts.Store(&f)
}

// Config is the latest NodeConfig, or nil. The key lives in this process's memory
// only. Its proof_key is the real one only after the hub has delivered a NodeConfig
// in this agent run: from start until then (the hub unreachable, say) it is the 16
// zero bytes of the stored copy, which p4-nodes 7.2 says means no code. Use ProofKey
// to read it, which returns nil for that stand-in.
func (e *Env) Config() *hubv1.NodeConfig { return e.config.Load() }

// ProofKey is the proof_key to compute UDP verify codes with, or nil when there is
// none to use: no NodeConfig yet, or the all-zero stand-in the agent publishes from
// a stored config (p4-nodes 7.2: an all-zero key means no code). A query path that
// answered with the stand-in would hand out codes anyone can compute and that the
// hub's txt_code_hash would never match.
func (e *Env) ProofKey() []byte {
	c := e.config.Load()
	if c == nil {
		return nil
	}
	for _, b := range c.ProofKey {
		if b != 0 {
			return c.ProofKey
		}
	}
	return nil
}

// Zones are the live zones of the NodeConfig, parsed.
func (e *Env) Zones() []names.Name {
	if z := e.zones.Load(); z != nil {
		return *z
	}
	return nil
}

// Revocations are the revocations in force (SC 5.2a case 1, 4b). Their ExpiresAt is
// hub time: compare it with HubNow.
func (e *Env) Revocations() []sock.RevItem {
	if r := e.revs.Load(); r != nil {
		return *r
	}
	return nil
}

// LinkUp reports whether the agent socket is connected.
func (e *Env) LinkUp() bool { return e.linkUp.Load() }

// AcmeChallenges returns the DNS-01 challenges the agent has handed over and
// that have not expired at now, which is HubNow() (their ExpiresAt is hub time).
func (e *Env) AcmeChallenges(now int64) []sock.Acme {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []sock.Acme
	for _, a := range e.acme {
		if a.ExpiresAt == 0 || a.ExpiresAt > now {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FQDN+out[i].Value < out[j].FQDN+out[j].Value })
	return out
}

// ---- updates from the agent

func (e *Env) setTable(t *sock.Table) {
	st := &TableState{DrainSince: t.DrainSince}
	var self zone.NodeID
	copy(self[:], t.Self)
	st.Local = zone.Local{Self: self, PanelStale: t.PanelStale, PeerDown: map[zone.NodeID]bool{}}
	for _, id := range t.PeerDown {
		var n zone.NodeID
		copy(n[:], id)
		st.Local.PeerDown[n] = true
	}
	if t.InUse && len(t.Member) > 0 {
		if tbl := buildTable(t); tbl != nil {
			st.Table = tbl
		} else {
			// A table that does not build keeps the previous one in use: a panic or
			// error leaves the old table (8a.4 Node apply, step 4).
			if old := e.table.Load(); old != nil {
				st.Table = old.Table
			}
		}
	}
	e.table.Store(st)
}

// buildTable builds the zone table from the agent's data under recover.
func buildTable(t *sock.Table) (out *zone.Table) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	pt := &policyv1.PairTable{}
	if err := proto.Unmarshal(t.Member, pt); err != nil {
		return nil
	}
	flags := zone.FlagMap{}
	for _, f := range t.Flags {
		var id zone.NodeID
		copy(id[:], f.Node)
		flags[id] = f.Withdrawn
	}
	tbl, err := zone.Build(zone.WithFlags(wire.ZoneInput(pt), t.Version, flags))
	if err != nil {
		return nil
	}
	return tbl
}

func (e *Env) setConfig(b []byte) {
	nc := &hubv1.NodeConfig{}
	if proto.Unmarshal(b, nc) != nil || wire.ValidateNodeConfig(nc) != nil {
		return
	}
	e.config.Store(nc)
	var zs []names.Name
	for _, z := range nc.Zones {
		if n, err := names.ParseUser(z); err == nil {
			zs = append(zs, n)
		}
	}
	e.zones.Store(&zs)
	e.pruneKeys(zs)
}

// pruneKeys drops the zone certificates that cover none of the live zones: the
// agent removes a retired zone's key from its own store, and the dns process, which
// already holds it, must stop offering it (it is also the fallback certificate for
// a name no zone covers).
func (e *Env) pruneKeys(zs []names.Name) {
	if len(zs) == 0 {
		return
	}
	for {
		old := e.keys.Load()
		if old == nil {
			return
		}
		var next []*keyCert
		for _, k := range *old {
			for _, z := range zs {
				if coversZone(k.sans, z.String()) {
					next = append(next, k)
					break
				}
			}
		}
		if len(next) == len(*old) || e.keys.CompareAndSwap(old, &next) {
			return
		}
	}
}

// setLink records the state of the agent socket. Whatever the agent said before is
// the last run's: the facts of SC 5.2a (c) are the current run's, so they are
// cleared on every change of state, and the free path stays off until the agent
// has sent them again (the first message of a connection after the hello).
func (e *Env) setLink(up bool) {
	e.linkUp.Store(up)
	e.facts.Store(nil)
	if up {
		e.downSince.Store(0)
	} else {
		e.downSince.CompareAndSwap(0, e.now().UnixNano())
	}
}

func (e *Env) setZoneKey(k *sock.ZoneKey) error {
	var chain [][]byte
	rest := k.ChainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			chain = append(chain, blk.Bytes)
		}
	}
	if len(chain) == 0 {
		return errors.New("dnsrole: zone key without a chain")
	}
	priv, err := x509.ParsePKCS8PrivateKey(k.Key)
	if err != nil {
		return errors.New("dnsrole: zone key does not parse")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return errors.New("dnsrole: zone certificate does not parse")
	}
	kc := &keyCert{sans: append([]string(nil), k.SANs...), cert: &tls.Certificate{Certificate: chain, PrivateKey: priv, Leaf: leaf}}
	sort.Strings(kc.sans)
	for {
		old := e.keys.Load()
		var next []*keyCert
		if old != nil {
			for _, x := range *old {
				if strings.Join(x.sans, ",") != strings.Join(kc.sans, ",") {
					next = append(next, x)
				}
			}
		}
		next = append(next, kc)
		if e.keys.CompareAndSwap(old, &next) {
			return nil
		}
	}
}

// maxAcme is the agent's own bound on the challenges it holds (64); dns keeps no
// more than that either, so a flood of tokens cannot grow this map.
const maxAcme = 64

// setAcme keeps a challenge. A message with ExpiresAt sock.AcmeRemoved is a removal,
// which is how the agent tells dns that it dropped a challenge to hold its bound:
// without that dns would go on answering it. Expired entries are dropped here once
// the hub offset is known, and always filtered on read.
func (e *Env) setAcme(a *sock.Acme) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := string(a.TokenID)
	if a.ExpiresAt == sock.AcmeRemoved {
		delete(e.acme, key)
		delete(e.acmeSeq, key)
		return
	}
	e.acme[key] = *a
	e.acmeN++
	e.acmeSeq[key] = e.acmeN
	// The snapshot sends the challenges before the facts that carry the hub offset, so
	// until the offset is known nothing is judged expired here: reads filter by
	// HubNow, and a challenge judged by the node clock alone would be lost for good.
	now := e.HubNow()
	for k, x := range e.acme {
		if e.offsetKnown.Load() && x.ExpiresAt != 0 && x.ExpiresAt <= now {
			delete(e.acme, k)
			delete(e.acmeSeq, k)
		}
	}
	for len(e.acme) > maxAcme {
		// The one that expires first goes, as at the agent (a challenge with no expiry
		// is the agent's to end, so it is the last to go), the oldest arrival first on
		// a tie. The challenge just given is never the victim: the agent acked it, and
		// a token that is then unanswerable fails the certificate order.
		var oldK string
		var oldExp int64
		var oldSeq uint64
		found := false
		for k, x := range e.acme {
			if k == key {
				continue
			}
			exp := x.ExpiresAt
			if exp == 0 {
				exp = 1<<62 - 1
			}
			if sq := e.acmeSeq[k]; !found || exp < oldExp || exp == oldExp && sq < oldSeq {
				oldK, oldExp, oldSeq, found = k, exp, sq, true
			}
		}
		if !found {
			break
		}
		delete(e.acme, oldK)
		delete(e.acmeSeq, oldK)
	}
}

// ---- the certificate provider

// ErrNoCertificate is returned for a handshake the node has no certificate for.
var ErrNoCertificate = errors.New("dnsrole: no zone certificate")

// GetCertificate is the certificate provider of the listeners (SC 3.3, R7). It
// is a pure function of the server name, as the listeners require, and cheap,
// because the listeners call it on every resumption too.
//
// An SNI that is a HostResolver name whose RIDHash the image does not know gets
// (nil, nil), which crypto/tls turns into the unrecognized_name alert on TCP and
// on QUIC; every other name completes the handshake. A name inside a zone gets
// that zone's certificate, anything else the first one the node holds, so apex,
// malformed and out-of-zone names still complete (R7).
func (e *Env) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := h.ServerName
	zs := e.Zones()
	host := identity.ParseHost(sni, zs)
	if host.Kind == identity.HostResolver {
		im := e.Image()
		if im == nil {
			return nil, nil
		}
		if _, ok := im.ByRIDHash(identity.RIDHash(host.RID)); !ok {
			return nil, nil
		}
	}
	keys := e.keys.Load()
	if keys == nil || len(*keys) == 0 {
		return nil, ErrNoCertificate
	}
	lower := strings.ToLower(strings.TrimSuffix(sni, "."))
	for _, k := range *keys {
		for _, z := range zs {
			zn := z.String()
			if (lower == zn || strings.HasSuffix(lower, "."+zn)) && coversZone(k.sans, zn) {
				return k.cert, nil
			}
		}
	}
	return (*keys)[0].cert, nil
}

func coversZone(sans []string, zone string) bool {
	for _, s := range sans {
		if strings.EqualFold(s, zone) {
			return true
		}
	}
	return false
}
