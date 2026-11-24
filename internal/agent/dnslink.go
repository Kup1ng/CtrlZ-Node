package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/telem"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// publish sends a message to dns when it differs from the last one sent for its
// slot. The agent's snapshot keeps the latest of each slot for a dns that
// reconnects, so a message that did not change need not be sent again.
func (a *Agent) publish(slot string, m *sock.Msg) {
	a.pubMu.Lock()
	defer a.pubMu.Unlock()
	a.publishLocked(slot, m)
}

// publishLocked is publish with pubMu held. Server.Publish never blocks, so the lock is
// held across the send: that is what keeps the order of lastPub and the order dns sees
// the same.
func (a *Agent) publishLocked(slot string, m *sock.Msg) {
	if a.srv == nil {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	a.mu.Lock()
	same := a.lastPub[slot] == string(b)
	if !same {
		a.lastPub[slot] = string(b)
	}
	a.mu.Unlock()
	if !same {
		_ = a.srv.Publish(m)
	}
}

// publishAll gives dns everything the agent holds, at start. A dns that connects
// later gets the same from the server's snapshot.
func (a *Agent) publishAll() {
	if c := a.nodeCfg.Load(); c != nil {
		if b, err := proto.Marshal(c); err == nil {
			a.publish("config", &sock.Msg{Type: sock.TypeConfig, Config: &sock.Config{NodeConfig: b}})
		}
	}
	a.mu.Lock()
	keys := append(a.zoneKeys[:0:0], a.zoneKeys...)
	a.mu.Unlock()
	for _, k := range keys {
		a.publishZoneKey(k)
	}
	if n := a.currentImage(); n != "" {
		a.publishImage(n)
	}
	a.publishRevocations()
	a.publishTableAndFacts()
}

// publishImage tells dns that image name is the one to serve from.
func (a *Agent) publishImage(name string) {
	a.publish("image", &sock.Msg{Type: sock.TypeImage, Image: &sock.Image{Name: name}})
}

// publishRevocations sends the list the agent holds. The snapshot of the list and the
// send are one step under pubMu: the revocation worker, the log worker and the sweep
// all call it, and a snapshot taken earlier must never be sent after a later one.
func (a *Agent) publishRevocations() {
	a.pubMu.Lock()
	items := a.revItems()
	a.publishLocked("revocations", &sock.Msg{Type: sock.TypeRevocations, Revocations: &sock.Revocations{Items: items}})
	a.pubMu.Unlock()
	select {
	case a.revSave <- struct{}{}:
	default:
	}
}

// revItems is the list of revocations in force, in a fixed order.
func (a *Agent) revItems() []sock.RevItem {
	a.mu.Lock()
	items := make([]sock.RevItem, 0, len(a.revs))
	for _, r := range a.revs {
		items = append(items, sock.RevItem{Seq: r.RevSeq, Kind: int32(r.Kind), IDs: r.Ids, ExpiresAt: r.ExpiresAt})
	}
	a.mu.Unlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].Seq != items[j].Seq {
			return items[i].Seq < items[j].Seq
		}
		return items[i].Kind < items[j].Kind
	})
	return items
}

// revocationsPath is the file that holds the revocations in force across an agent restart. They are
// otherwise memory only, and an agent that restarts (a crash, an OOM kill, an upgrade)
// hands dns an empty list on its first snapshot, which lifts a revocation dns still
// needs until the hub sends it again: after the first ServerTime on the new stream, and
// never while the hub cannot be reached. Nothing in it is secret (resource ids the hub
// already revoked), and it is kept with the node's other state.
func (a *Agent) revocationsPath() string {
	return filepath.Join(a.root.Path(store.DirConfig), "revocations.json")
}

// maxRevocationFile bounds what a restart reads back: the bounds of keepRevocation
// keep what the agent writes near 4 MiB.
const maxRevocationFile = 16 << 20

// loadRevocations reads the file back at start. Every item goes through the same
// checks and bounds as one from the hub, and an expired one is dropped: a file that
// is damaged or edited can only give fewer revocations or revocations the hub may
// itself send, never more than the bounds allow.
func (a *Agent) loadRevocations() {
	p := a.revocationsPath()
	if st, err := os.Stat(p); err != nil || st.Size() > maxRevocationFile {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var list sock.Revocations
	if json.Unmarshal(b, &list) != nil {
		return
	}
	// The node clock is not trusted until the first ServerTime (8a.4 Clock), and a
	// node whose clock was moved is exactly the case that matters, so an expiry is
	// not compared with the clock here: the file says when it was written (in hub
	// time) and what is left of each lifetime is counted from the start. Down time is
	// not subtracted, which keeps a revocation a little longer and never past the
	// TTL and margin, and the hub renews or the applied image ends it. The items are
	// then in the node-clock domain, and the first ServerTime moves them into the
	// hub's (rebaseLoadedRevocations).
	now := a.hubNow()
	limit := int64((revocationTTL + revocationMargin) / time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, it := range list.Items {
		kind := policyv1.RevocationKind(it.Kind)
		left := it.ExpiresAt - list.Saved
		if list.Saved == 0 {
			left = it.ExpiresAt - now // a file from before Saved: the old reading
		}
		if it.Seq == 0 || kind < policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT || kind > policyv1.RevocationKind_REVOCATION_KIND_GRANTS_BY_ENDPOINT ||
			left <= 0 || len(it.IDs) == 0 {
			continue
		}
		ok := true
		for _, id := range it.IDs {
			ok = ok && len(id) == 16
		}
		if !ok {
			continue
		}
		a.keepRevocation(&policyv1.Revocation{RevSeq: it.Seq, Kind: kind, Ids: it.IDs, ExpiresAt: now + min(left, limit)})
		a.revUnsynced[revKey{it.Seq, kind}] = struct{}{}
	}
}

// rebaseLoadedRevocations moves the revocations read from disk into hub time once
// the first ServerTime has given the offset: they were dated with the node clock as
// it stood at start. It runs once per start, from publishTableAndFacts, which passes
// the offset it is about to tell dns so that the two reach dns in the order that
// never judges a revocation earlier than its lifetime (see there).
//
// seen is whether the ServerTime had arrived when off was read, decided by the caller
// BEFORE it read off: hubOffset is stored before lastST, so an offset read after a
// non-zero lastST is that ServerTime's or a newer one. Checking lastST here, after the
// caller had read off, could rebase by a stale 0 and clear revUnsynced for good.
func (a *Agent) rebaseLoadedRevocations(off int64, seen bool) {
	if !seen {
		return
	}
	a.mu.Lock()
	for k := range a.revUnsynced {
		if r := a.revs[k]; r != nil && r.ExpiresAt != 0 {
			r.ExpiresAt += off
		}
	}
	changed := len(a.revUnsynced) > 0
	a.revUnsynced = map[revKey]struct{}{}
	a.mu.Unlock()
	if changed {
		a.publishRevocations()
	}
}

// revSaveLoop writes the revocation file after a change. Writes are at least a second
// apart, so a hub that sends revocations in a flood costs one write a second and not
// one each; the last write at shutdown covers whatever the pause held back.
func (a *Agent) revSaveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			a.saveRevocations()
			return
		case <-a.revSave:
		}
		a.saveRevocations()
		select {
		case <-ctx.Done():
			a.saveRevocations()
			return
		case <-time.After(time.Second):
		}
	}
}

func (a *Agent) saveRevocations() {
	b, err := json.Marshal(&sock.Revocations{Items: a.revItems(), Saved: a.hubNow()})
	if err == nil {
		err = a.fsw.WriteFile(a.revocationsPath(), b, 0o640)
	}
	if err != nil {
		a.al.Alert(alert.Alert{Code: alert.RevocationsNotSaved, Detail: "the revocations could not be written down; a restart now starts with none"})
	}
}

// tableLoop keeps dns's view of the zone table and of the free-path facts
// current. Both change with events (a push, an Apply, a ServerTime) and with
// time (PanelStale, the 30 s before a persisted table is put in use, the
// lag rule), so it also runs on a tick.
func (a *Agent) tableLoop(ctx context.Context) {
	every := a.cfg.TableEvery
	if every == 0 {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		a.publishTableAndFacts()
		select {
		case <-ctx.Done():
			return
		case <-a.tablePoke:
		case <-t.C:
		}
	}
}

func (a *Agent) publishTableAndFacts() {
	now := a.now()
	st := a.push.Status()
	tb := a.push.TableInUse(now.Unix())
	built := a.push.Table()

	// The drain rule watches every table the node applies, in use or not.
	a.mu.Lock()
	if built != nil && built != a.drainFor {
		a.drainFor = built
		wasDraining := a.drain.Draining()
		a.drain.Applied(now, built, nil, a.self)
		if a.drain.Draining() && !wasDraining {
			a.drainSince = now.Unix()
		} else if !a.drain.Draining() {
			a.drainSince = 0
		}
	}
	drainSince := a.drainSince
	a.mu.Unlock()

	m := &sock.Table{Self: a.self[:], Version: st.Version, InUse: tb != nil, PanelStale: a.panelStale(), DrainSince: drainSince}
	if mem := a.push.Member(); mem != nil {
		if b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(mem); err == nil {
			m.Member = b
		}
	}
	for id, w := range a.push.Flags() {
		id := id
		m.Flags = append(m.Flags, sock.Flag{Node: id[:], Withdrawn: w})
	}
	sort.Slice(m.Flags, func(i, j int) bool { return bytes.Compare(m.Flags[i].Node, m.Flags[j].Node) < 0 })
	for id, down := range a.probe.PeerDown() {
		if down {
			id := id
			m.PeerDown = append(m.PeerDown, id[:])
		}
	}
	sort.Slice(m.PeerDown, func(i, j int) bool { return bytes.Compare(m.PeerDown[i], m.PeerDown[j]) < 0 })
	a.publish("table", &sock.Msg{Type: sock.TypeTable, Table: m})

	fs := a.facts.State()
	// lastST first, then the offset (see rebaseLoadedRevocations). Before the first
	// ServerTime the offset dns is told is 0, which is also what it already holds.
	seen := a.lastST.Load() != 0
	var off int64
	if seen {
		off = a.hubOffset.Load()
	}
	f := &sock.Facts{ServerTimeSeen: fs.ServerTimeSeen, CaughtUpOnce: fs.CaughtUpOnce, LagOK: fs.LagOK, OffFloor: fs.OffFloor, HubOffset: off}
	if v := a.freeValue.Load(); v != nil {
		f.FreeSet, f.FreeEnabled, f.FreeQPS, f.FreeVersion = true, v.Enabled, v.Qps, v.Version
	}
	// Revocations loaded at start are dated with the node clock until the first
	// ServerTime, and dns judges them against its clock plus the offset. The two
	// messages cannot reach dns at one instant, so the order errs on holding a
	// revocation longer: with the node behind the hub (offset >= 0) the rebased
	// expiry goes first (a later expiry under the old clock), with the node ahead
	// (offset < 0) the offset goes first (an earlier clock against the old expiry).
	// The other order lets a revoked resolver id lapse for the gap between them.
	if off >= 0 {
		a.rebaseLoadedRevocations(off, seen)
	}
	a.publish("facts", &sock.Msg{Type: sock.TypeFacts, Facts: f})
	if off < 0 {
		a.rebaseLoadedRevocations(off, seen)
	}
}

// sweepLoop drops revocations and ACME challenges that expired.
func (a *Agent) sweepLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.revPoke:
		}
		a.dropAppliedRevocations()
		a.alertStaleBundles()
		now := a.hubNow()
		a.mu.Lock()
		for k, c := range a.acmes {
			if c.ExpiresAt != 0 && c.ExpiresAt <= now {
				delete(a.acmes, k)
				delete(a.acmeSeq, k)
				if a.srv != nil {
					a.srv.Forget(&sock.Msg{Type: sock.TypeAcme, Acme: &sock.Acme{TokenID: c.TokenId}})
				}
			}
		}
		a.mu.Unlock()
	}
}

// sockHandlers are what dns may send the agent. Each is a few instructions on
// memory: the socket's reader must not wait.
func (a *Agent) sockHandlers() sock.Handlers {
	return sock.Handlers{
		ImageAck: func(name string) {
			a.imageAcked.Store(&name)
			if seq, _, ok := image.ParseDirName(name); ok {
				a.imageAckSeq.Store(seq)
				select {
				case a.revPoke <- struct{}{}:
				default:
				}
			}
		},
		FreeCounts: func(items []sock.FreeCount) {
			for _, it := range items {
				a.free.Add(telem.FreeKey{Proto: commonv1.Protocol(it.Proto), Outcome: telemetryv1.FreeOutcome(it.Outcome), Rcode: it.Rcode}, it.Count)
			}
		},
		Activity: func(items []sock.ActivityItem) {
			// dns stamps an item with hub time (its clock is the node's plus the
			// offset), so it is checked against hub time: against the node clock a
			// node more than the window off the hub would have every bucket
			// replaced with its own wrong time.
			now := time.Unix(a.hubNow(), 0)
			for _, it := range items {
				if len(it.Endpoint) != 16 {
					continue
				}
				at := time.Unix(it.At, 0)
				if it.At == 0 || at.After(now.Add(5*time.Minute)) || at.Before(now.Add(-time.Hour)) {
					at = now
				}
				var ep [16]byte
				copy(ep[:], it.Endpoint)
				a.act.Add(telem.Report{EndpointID: ep, ClientLabel: it.Label, ClaimID: it.Claim, SourceIPHash: it.SourceIPHash,
					Protocol: commonv1.Protocol(it.Proto), At: at})
			}
		},
		Stats: func(s sock.Stats) {
			a.dnsStats.Store(&statsAt{s: s, at: a.now()})
		},
		Outbound: func(b []byte) {
			if len(b) == 0 || len(b) > 64<<10 {
				return
			}
			m := &hubv1.NodeMessage{}
			if proto.Unmarshal(b, m) != nil {
				return
			}
			// Only the three kinds an outside party can cause come this way; the
			// agent's own messages are built here, never taken from dns. The message
			// is checked again at the door the hub uses.
			switch m.Body.(type) {
			case *hubv1.NodeMessage_ProofObservation, *hubv1.NodeMessage_LearnedIp, *hubv1.NodeMessage_BlockUnblockRequest:
			default:
				return
			}
			if wire.ValidateNodeMessage(m, a.hubNow()) != nil {
				return
			}
			a.ctl.Outside(m)
		},
		Connected: func(bool) { a.pokeTable() },
	}
}
