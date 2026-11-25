package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/zonekeys"
)

// PanelStaleAfter is the one threshold of SC 8a.5, in seconds.
const PanelStaleAfter = 30 * time.Second

// hubNow is the node's clock plus the offset from the latest ServerTime, in Unix
// seconds (8a.4 Clock); before any ServerTime it is the node's own clock. A node
// whose clock was moved still follows the hub, and anti-rollback by version keeps
// an old push from being replayed under a wrong clock.
func (a *Agent) hubNow() int64 { return a.now().Unix() + a.hubOffset.Load() }

// ---- callbacks that run on the receive loop: memory only, no waiting.

func (a *Agent) onServerTime(now int64) {
	off := now - a.now().Unix()
	a.hubOffset.Store(off)
	a.lastST.Store(a.now().UnixNano())
	a.facts.ServerTime()
	if off > 2 || off < -2 {
		a.al.Alert(alert.Alert{Code: alert.Skew, Detail: "the node clock differs from the hub's by more than 2 s"})
	}
	a.pokeTable()
}

func (a *Agent) onHeadNotice(seq uint64, _ bool) {
	a.facts.LearnHead(seq)
	for {
		cur := a.highHead.Load()
		if seq <= cur || a.highHead.CompareAndSwap(cur, seq) {
			break
		}
	}
	select {
	case a.logWake <- struct{}{}:
	default:
	}
}

func (a *Agent) onFreeOff(version uint64) {
	a.facts.FreeDNSOff(version)
	a.pokeTable()
}

func (a *Agent) onStream(up bool) {
	a.streamUp.Store(up)
	if !up {
		a.downSince.Store(a.now().UnixNano())
	}
	a.pokeTable()
}

func (a *Agent) pokeTable() {
	select {
	case a.tablePoke <- struct{}{}:
	default:
	}
}

// panelStale is SC 8a.5: no Control stream for 30 s, no valid ServerTime for 30
// s, the push in use past its expires_at by hub_now, no push accepted since the
// start (a redelivery counts), or the latest push refused for any reason but a
// lower version.
func (a *Agent) panelStale() bool {
	now := a.now()
	if !a.streamUp.Load() && now.Sub(time.Unix(0, a.downSince.Load())) >= PanelStaleAfter {
		return true
	}
	last := time.Unix(0, a.lastST.Load())
	if a.lastST.Load() == 0 {
		last = a.started
	}
	if now.Sub(last) >= PanelStaleAfter {
		return true
	}
	st := a.push.Status()
	if !st.AcceptedSinceStart {
		return true
	}
	if st.ExpiresAt != 0 && st.ExpiresAt <= a.hubNow() {
		return true
	}
	return st.LatestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED && st.LatestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION
}

// ---- the table writer: one goroutine, nothing else changes the flag map.

func (a *Agent) onPush(ctx context.Context, env *signv1.Envelope) {
	res := a.push.ApplyPush(env, a.hubNow())
	switch {
	case res.Accepted:
	case res.Refusal == hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION || res.Refusal == hubv1.PushRefusal_PUSH_REFUSAL_EXPIRED:
		// a lower version or an expired push alerts on its own (8a.4)
		a.al.Alert(alert.Alert{Code: alert.PushRefused, Detail: res.Refusal.String()})
	default:
		a.al.Alert(alert.Alert{Code: alert.PushRefused, Detail: res.Refusal.String()})
	}
	a.pokeTable()
}

// ---- work apart from the loop

const (
	// revocationTTL is what a Revocation with no expiry gets: the hub's own lifetime
	// for one (5.5). A revocation that never ends would outlive the entry that
	// replaces it.
	revocationTTL = 15 * time.Minute
	// maxRevocationIDs bounds the ids held, so the whole list stays a frame the
	// agent socket can carry (8 MiB) and a reconnecting dns never fails on it.
	maxRevocationIDs = 100_000
	// maxRevocationKeys bounds the (rev_seq, kind) keys too. A key costs about 100 bytes of
	// JSON whatever it holds, so 100,000 keys of one id each would pass the id bound and
	// still exceed the 8 MiB frame; 10,000 keys and 100,000 ids together stay near 4 MiB.
	maxRevocationKeys = 10_000
	// revocationMargin is how far past the hub's own lifetime a revocation may reach:
	// the hub renews every 5 minutes, so nothing legitimate asks for more, and an
	// expires_at far in the future would otherwise pin a revocation for good.
	revocationMargin = 5 * time.Minute
	// rearmWithin is how close to its end a revocation the hub no longer renews is
	// extended by the agent (see dropAppliedRevocations).
	rearmWithin = 60
	// maxAcmeChallenges bounds the challenges held: each is a slot of the socket's
	// snapshot, whose queue has a fixed length.
	maxAcmeChallenges = 64
	acmeTTL           = time.Hour
)

// onRevocation keeps a Revocation and acknowledges it. A revocation acts until
// the node has applied an entry at or above its rev_seq (5.5), so one for an entry
// already applied is not kept. One entry gives several, of different kinds and with
// one seq, so they are kept by (seq, kind) and the ids of two messages of one key
// are merged.
func (a *Agent) onRevocation(ctx context.Context, r *policyv1.Revocation) {
	now := a.hubNow()
	if r.ExpiresAt != 0 && r.ExpiresAt <= now {
		return // a revocation that already expired is of no use and needs no answer
	}
	if r.RevSeq > a.imageAckSeq.Load() {
		c := proto.Clone(r).(*policyv1.Revocation)
		if limit := now + int64((revocationTTL+revocationMargin)/time.Second); c.ExpiresAt == 0 {
			c.ExpiresAt = now + int64(revocationTTL/time.Second)
		} else if c.ExpiresAt > limit {
			c.ExpiresAt = limit
		}
		a.keepHubRevocation(c)
		a.publishRevocations()
	}
	a.ctl.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_RevocationAck{RevocationAck: &hubv1.RevocationAck{RevSeq: r.RevSeq}}})
}

// keepRevocation merges r into the map under a.mu and enforces the id bound by
// dropping the lowest rev_seq first: the oldest is the one this node is most likely
// to have applied the entry of already.
func (a *Agent) keepRevocation(r *policyv1.Revocation) {
	k := revKey{r.RevSeq, r.Kind}
	// The bound holds for one key too: the loop below only ever drops whole keys, so a
	// hub that keeps sending new ids under one (rev_seq, kind) would grow that entry
	// past what the agent socket's frame can carry, and dns would never keep a socket.
	// What does not fit is dropped and alerted, the oldest-first rule of the loop below
	// being impossible with one key.
	overflow := false
	if old := a.revs[k]; old != nil {
		have := make(map[string]struct{}, len(old.Ids))
		for _, id := range old.Ids {
			have[string(id)] = struct{}{}
		}
		for _, id := range r.Ids {
			if _, ok := have[string(id)]; ok {
				continue
			}
			if len(old.Ids) >= maxRevocationIDs {
				overflow = true
				break
			}
			old.Ids = append(old.Ids, id)
			a.revIDs++
			have[string(id)] = struct{}{}
		}
		old.ExpiresAt = max(old.ExpiresAt, r.ExpiresAt)
	} else {
		if len(r.Ids) > maxRevocationIDs {
			r.Ids, overflow = r.Ids[:maxRevocationIDs], true
		}
		a.revs[k] = r
		a.revIDs += len(r.Ids)
	}
	if overflow {
		a.al.Alert(alert.Alert{Code: alert.RevocationOverflow, Detail: "one revocation holds more ids than the node keeps: the rest were dropped"})
	}
	// revIDs counts the ids held, kept up as they come and go so the common message costs
	// no scan of the list; it is exact again whenever a bound is found exceeded.
	if a.revIDs <= maxRevocationIDs && len(a.revs) <= maxRevocationKeys {
		return
	}
	total := 0
	for _, x := range a.revs {
		total += len(x.Ids)
	}
	a.revIDs = total
	if total <= maxRevocationIDs && len(a.revs) <= maxRevocationKeys || len(a.revs) <= 1 {
		return
	}
	// Over a bound: drop the lowest rev_seq first, and a tenth of the key bound past it in
	// one pass, so a hub that keeps sending new keys pays a sort once every thousand
	// messages and not a scan of the whole list for each.
	keys := make([]revKey, 0, len(a.revs))
	for kk := range a.revs {
		keys = append(keys, kk)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].seq != keys[j].seq {
			return keys[i].seq < keys[j].seq
		}
		return keys[i].kind < keys[j].kind
	})
	for _, kk := range keys {
		if len(a.revs) <= 1 || total <= maxRevocationIDs-maxRevocationIDs/10 && len(a.revs) <= maxRevocationKeys-maxRevocationKeys/10 {
			break
		}
		total -= len(a.revs[kk].Ids)
		a.revIDs = total
		delete(a.revs, kk)
	}
	a.al.Alert(alert.Alert{Code: alert.RevocationOverflow, Detail: "revocations over the bound: the oldest were dropped"})
}

// dropAppliedRevocations ends every revocation whose entry's image dns has confirmed
// opening (imageAckSeq) and every expired one the hub still renews.
//
// The hub renews a revocation only while the node's Heartbeat applied_seq is below its
// rev_seq (5.5), and applied_seq is the committed seq, which moves before the image is
// swapped. A revocation whose entry is committed but whose image dns has not confirmed
// (the swap failed, or dns cannot open the image) is therefore one the hub has stopped
// renewing while the old image still serves what the entry changed. Letting it expire
// would end it at the hub's 15 minutes whatever the disk is doing, so the agent extends
// it itself, for as long as the image is missing.
func (a *Agent) dropAppliedRevocations() {
	applied, committed, now := a.imageAckSeq.Load(), a.app.AppliedSeq(), a.hubNow()
	changed := false
	a.mu.Lock()
	for k, r := range a.revs {
		switch {
		case k.seq <= applied:
			a.revIDs -= len(r.Ids)
			delete(a.revs, k)
			changed = true
		case r.ExpiresAt == 0 || r.ExpiresAt > now+rearmWithin:
		case k.seq <= committed:
			r.ExpiresAt = now + int64(revocationTTL/time.Second)
			changed = true
		case r.ExpiresAt <= now:
			a.revIDs -= len(r.Ids)
			delete(a.revs, k)
			changed = true
		}
	}
	a.mu.Unlock()
	if changed {
		a.publishRevocations()
	}
}

func (a *Agent) onAcme(ctx context.Context, c *hubv1.AcmeChallenge) {
	if n := len(c.TokenId); n == 0 || n > wire.MaxAcmeTokenID || c.Fqdn == "" || len(c.Fqdn) > 253 || len(c.Value) > 255 {
		return
	}
	now := a.hubNow()
	if c.ExpiresAt != 0 && c.ExpiresAt <= now {
		return
	}
	if c.ExpiresAt == 0 {
		c = proto.Clone(c).(*hubv1.AcmeChallenge)
		c.ExpiresAt = now + int64(acmeTTL/time.Second)
	}
	a.mu.Lock()
	key := hex.EncodeToString(c.TokenId)
	a.acmes[key] = c
	a.acmeN++
	a.acmeSeq[key] = a.acmeN
	var dropped []*hubv1.AcmeChallenge
	for len(a.acmes) > maxAcmeChallenges {
		// The one that expires first goes: it is the least likely to be still wanted.
		// A tie (every challenge sent with no expiry gets now+1h in one second) goes to
		// the oldest arrival, and the challenge just taken is never the victim: it is
		// about to be acked, and one that is then unanswerable fails the certificate
		// order. Without this the random map order picked it now and then, and it was
		// published below though no longer held, so nothing ever ended it.
		var oldK string
		var old *hubv1.AcmeChallenge
		for k, x := range a.acmes {
			if k == key {
				continue
			}
			if old == nil || x.ExpiresAt < old.ExpiresAt || x.ExpiresAt == old.ExpiresAt && a.acmeSeq[k] < a.acmeSeq[oldK] {
				oldK, old = k, x
			}
		}
		if old == nil {
			break
		}
		delete(a.acmes, oldK)
		delete(a.acmeSeq, oldK)
		dropped = append(dropped, old)
	}
	a.mu.Unlock()
	for _, d := range dropped {
		// dns has the challenge already: tell it with a removal (an expired challenge is
		// one to dns), and keep the removal out of the snapshot a new dns gets.
		_ = a.srv.Publish(&sock.Msg{Type: sock.TypeAcme, Acme: &sock.Acme{TokenID: d.TokenId, ExpiresAt: sock.AcmeRemoved}})
		a.srv.Forget(&sock.Msg{Type: sock.TypeAcme, Acme: &sock.Acme{TokenID: d.TokenId}})
	}
	_ = a.srv.Publish(&sock.Msg{Type: sock.TypeAcme, Acme: &sock.Acme{TokenID: c.TokenId, FQDN: c.Fqdn, Value: c.Value, ExpiresAt: c.ExpiresAt}})
	a.ctl.Report(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_AcmeAck{AcmeAck: &hubv1.AcmeAck{TokenId: c.TokenId}}})
}

func (a *Agent) onNodeConfig(ctx context.Context, c *hubv1.NodeConfig) {
	if err := wire.ValidateNodeConfig(c); err != nil {
		a.al.Alert(alert.Alert{Code: alert.ConfigFallback, Detail: "a NodeConfig did not validate"})
		return
	}
	// A NodeConfig is applied only above the highest version applied (L1), which is
	// persisted with the config, so a replay of an older one changes nothing.
	cur := a.cfgVersion.Load()
	if c.Version < cur {
		return
	}
	if c.Version == cur {
		// The config on disk carries a stand-in proof_key, so after a restart the hub's
		// build of that same version (it resends a cached build to a new stream, and
		// then only when the content changes) is the one message that holds the real
		// key. Take it once per run, when nothing else has been taken and the content
		// is what is stored; do not save or restart dns again.
		old := a.nodeCfg.Load()
		if a.cfgTaken.Load() || old == nil || !sameConfigButKey(old, c) {
			return
		}
		a.cfgTaken.Store(true)
		a.nodeCfg.Store(proto.Clone(c).(*hubv1.NodeConfig))
		if a.srv != nil {
			if b, err := proto.Marshal(c); err == nil {
				_ = a.srv.Publish(&sock.Msg{Type: sock.TypeConfig, Config: &sock.Config{NodeConfig: b}})
			}
		}
		return
	}
	a.cfgTaken.Store(true)
	// The restart dns is owed is written down before the config is stored: if the
	// agent dies after the store, the next run must not take the stored config for
	// the one dns was started with (that is what dnsKey is computed from at start).
	a.mu.Lock()
	owed := dnsKeyOf(c) != a.dnsKey
	a.mu.Unlock()
	if owed {
		a.markDNSRestartOwed()
	}
	if err := a.ncs.Save(c); err != nil {
		a.al.Alert(alert.Alert{Code: alert.ConfigFallback, Detail: "a NodeConfig could not be stored"})
		return
	}
	a.cfgVersion.Store(c.Version)
	a.nodeCfg.Store(proto.Clone(c).(*hubv1.NodeConfig))
	if a.srv != nil {
		if b, err := proto.Marshal(c); err == nil {
			_ = a.srv.Publish(&sock.Msg{Type: sock.TypeConfig, Config: &sock.Config{NodeConfig: b}})
		}
	}
	// dns binds its listeners once, at its start, from the NodeConfig on disk: a
	// first config ends its Plain-only fallback, and a new bind address moves it.
	a.mu.Lock()
	if key := dnsKeyOf(c); key != a.dnsKey {
		a.dnsKey = key
		a.dnsRestart.Store(true)
	}
	a.mu.Unlock()
	a.afterConfigCerts()
	a.afterConfig(ctx)
}

// sameConfigButKey reports whether two NodeConfigs are the same apart from the
// proof_key, which the stored one holds only as a stand-in.
func sameConfigButKey(a, b *hubv1.NodeConfig) bool {
	x, y := proto.Clone(a).(*hubv1.NodeConfig), proto.Clone(b).(*hubv1.NodeConfig)
	x.ProofKey, y.ProofKey = nil, nil
	return proto.Equal(x, y)
}

// onCertBundle takes a CertBundle. The names of a bundle are checked against the
// zones of the NodeConfig, which may not be stored yet when the bundle is handled
// (separate workers): a bundle refused for that reason alone is held and offered
// again after the next NodeConfig, never dropped.
func (a *Agent) onCertBundle(ctx context.Context, cb *hubv1.CertBundle) {
	a.certMu.Lock()
	defer a.certMu.Unlock()
	if a.acceptBundle(cb) {
		return
	}
	for i, h := range a.pending {
		if proto.Equal(h.cb, cb) {
			a.pending = append(a.pending[:i], a.pending[i+1:]...)
			break
		}
	}
	a.pending = append(a.pending, &heldBundle{cb: cb, at: a.now()})
	if len(a.pending) > maxHeldBundles {
		a.pending = a.pending[1:]
		a.al.Alert(alert.Alert{Code: alert.CertBundleRefused, Detail: "too many certificate bundles wait for a zone"})
	}
}

// acceptBundle reports whether the bundle is settled: accepted, or refused for good
// (and alerted). False means it should be held. certMu is held by the caller.
func (a *Agent) acceptBundle(cb *hubv1.CertBundle) bool {
	c, err := a.zk.Accept(cb)
	if err != nil {
		if errors.Is(err, zonekeys.ErrNoZones) || errors.Is(err, zonekeys.ErrNotLiveZone) {
			return false
		}
		a.al.Alert(alert.Alert{Code: alert.CertBundleRefused, Detail: "a CertBundle was refused"})
		return true
	}
	a.mu.Lock()
	kept := a.zoneKeys[:0:0]
	for _, z := range a.zoneKeys {
		if !sameSANs(z.SANs, c.SANs) {
			kept = append(kept, z)
		}
	}
	a.zoneKeys = append(kept, c)
	a.mu.Unlock()
	a.publishZoneKey(c)
	return true
}

// afterConfigCerts is what a stored NodeConfig does to the zone certificates: the
// keys of a zone that is no longer live go (the file, the probe roots, the
// snapshot dns gets), and the held bundles are offered again. It takes certMu after
// the config is stored, so a bundle that was refused against the old zones is
// already in the held list when it runs.
func (a *Agent) afterConfigCerts() {
	a.certMu.Lock()
	defer a.certMu.Unlock()
	zs := a.zones()
	var gone []*zonekeys.Cert
	a.mu.Lock()
	kept := a.zoneKeys[:0:0]
	for _, z := range a.zoneKeys {
		if len(zs) == 0 || zonekeys.Live(z.SANs, zs) {
			kept = append(kept, z)
		} else {
			gone = append(gone, z)
		}
	}
	a.zoneKeys = kept
	a.mu.Unlock()
	for _, z := range gone {
		if a.srv != nil {
			a.srv.Forget(&sock.Msg{Type: sock.TypeZoneKey, ZoneKey: &sock.ZoneKey{SANs: z.SANs}})
		}
	}
	// The file goes last: it is what a restart reads, and a dns that connects once the
	// file is gone must not be handed the snapshot slot of the retired key.
	a.zk.Prune(zs)
	rest := a.pending[:0:0]
	for _, h := range a.pending {
		if a.acceptBundle(h.cb) {
			continue
		}
		rest = append(rest, h)
	}
	a.pending = rest
}

func sameSANs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (a *Agent) publishZoneKey(c *zonekeys.Cert) {
	if a.srv == nil {
		return
	}
	_ = a.srv.Publish(&sock.Msg{Type: sock.TypeZoneKey, ZoneKey: &sock.ZoneKey{SANs: c.SANs, ChainPEM: c.ChainPEM, Key: c.KeyDER, NotAfter: c.NotAfter}})
}

// ---- the Heartbeat

// heartbeat builds the Heartbeat that is due. It reads atomics and the push
// writer's copy of its report state, and takes no lock that Apply, a fetch or the
// table writer's disk write holds (L11).
func (a *Agent) heartbeat() *hubv1.Heartbeat {
	st := a.push.Status()
	pv := &hubv1.PeerView{PairTableVersion: st.Version, Peers: a.probe.PeerView(), LastRefusal: st.LastRefusal, Refusals: st.Refusals}
	pvb, err := proto.Marshal(pv)
	if err != nil {
		pvb = nil
	}
	hb := &hubv1.Heartbeat{
		NodeTime:          a.now().Unix(),
		AppliedSeq:        a.app.AppliedSeq(),
		NodeVersion:       a.cfg.Version,
		BlobMajorMax:      uint32(blob.Major),
		Quarantined:       a.quarantined.Load(),
		PeerView:          pvb,
		NodeConfigVersion: a.cfgVersion.Load(),
	}
	if v := a.unbVersion.Load(); v != nil {
		hb.UnboundVersion = *v
	}
	if s := a.dnsStats.Load(); s != nil && a.now().Sub(s.at) < 30*time.Second {
		hb.Qps = min(s.s.QPS, wire.MaxHeartbeatQPS)
		hb.CacheHitPermille = min(s.s.CacheHitPermille, 1000)
		hb.Isolated = s.s.Isolated
		hb.Upstreams = upstreamHealth(s.s.Upstreams)
		// What dns reports is not trusted to be well formed: the hub refuses a
		// Heartbeat that fails its door and then judges this node silent. If the
		// dns-supplied part is the reason, the Heartbeat goes out without it.
		if wire.ValidateHeartbeat(hb) != nil {
			hb.Upstreams, hb.Qps, hb.CacheHitPermille, hb.Isolated = nil, 0, 0, false
		}
	}
	return hb
}

// upstreamHealth turns dns's list into what a Heartbeat may carry: ids of 16
// bytes, no id twice (the local Unbound's reserved id above all), at most
// MaxHeartbeatItems of them.
func upstreamHealth(in []sock.Health) []*hubv1.UpstreamHealth {
	var out []*hubv1.UpstreamHealth
	seen := make(map[string]struct{}, len(in))
	for _, u := range in {
		if len(u.ID) != 16 || len(out) >= wire.MaxHeartbeatItems {
			continue
		}
		if _, dup := seen[string(u.ID)]; dup {
			continue
		}
		seen[string(u.ID)] = struct{}{}
		out = append(out, &hubv1.UpstreamHealth{Id: u.ID, Healthy: u.Healthy, LatencyMs: u.LatencyMS})
	}
	return out
}

// alertStaleBundles says once, for each CertBundle that has waited longer than the
// grace for a NodeConfig that names its zone, that it names no live zone. A bundle
// that only overtook its NodeConfig is settled within moments and never reaches this.
func (a *Agent) alertStaleBundles() {
	grace := a.cfg.HeldBundleGrace
	if grace == 0 {
		grace = 30 * time.Second
	}
	a.certMu.Lock()
	defer a.certMu.Unlock()
	for _, h := range a.pending {
		if !h.alerted && a.now().Sub(h.at) >= grace {
			h.alerted = true
			a.al.Alert(alert.Alert{Code: alert.CertBundleRefused, Detail: "a CertBundle names no live zone"})
		}
	}
}

// keepHubRevocation merges a revocation dated in hub time into the held ones.
//
// A key still waiting for its rebase holds a node-dated expiry (see
// rebaseLoadedRevocations). Merging a hub-dated one into it would take the max of two
// clocks and then be shifted by the offset a second time, so the renewal is put into
// the node's clock first: the rebase that follows moves the merged value back to hub
// time, and nothing reaches dns in a new order.
func (a *Agent) keepHubRevocation(c *policyv1.Revocation) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, loaded := a.revUnsynced[revKey{c.RevSeq, c.Kind}]; loaded {
		c.ExpiresAt -= a.hubOffset.Load()
	}
	a.keepRevocation(c)
}
