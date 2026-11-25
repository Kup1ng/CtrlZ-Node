package push_test

// The cases of the pair-table-apply vector group of SC 8a.10 and 15 that the other
// tests of this package do not name, run through the real writer. The group has no
// canonical file yet (p4-nodes 13, W8): each case here carries the wording of its
// SC 8a.10 item, and the list goes to Plan.md so the canonical group can be written
// from it. Every case checks what the node would ANSWER (zone.Target), not only what
// the writer holds.

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/push"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// globalPair is the pair storetest.Table makes the global one.
var globalPair = zone.PairID(bytes.Repeat([]byte{0xb0}, 16))

// answered is the node that SC 8a.2 picks for the global pair with no local view.
func answered(t *testing.T, tb *zone.Table) int {
	t.Helper()
	if tb == nil {
		t.Fatal("no table")
	}
	n, ok := zone.Target(tb, globalPair, zone.Local{})
	if !ok {
		t.Fatal("no target")
	}
	for i := 0; i < 4; i++ {
		if n.ID == zone.NodeID(storetest.NodeID(i)) {
			return i
		}
	}
	t.Fatal("an answer outside the table")
	return -1
}

func TestSC15PairTableApply(t *testing.T) {
	t.Run("a higher version is taken by node_id onto the node's own membership", func(t *testing.T) {
		f := newFixture(t, nil)
		f.w.Load(storetest.Table(3, 0), now)
		f.apply(f.signed(100, 0))
		if got := answered(t, f.w.Table()); got != 1 {
			t.Fatalf("primary withdrawn: answered node %d", got)
		}
		// A push that names only a node the membership holds keeps the other flags.
		pt := storetest.Table(3, 101)
		pt.ExpiresAt = expiry
		pt.Nodes = pt.Nodes[2:]
		pt.Pairs, pt.GlobalPairId = nil, nil
		if r := f.apply(f.keys.Sign(t, pt)); !r.Accepted {
			t.Fatalf("%+v", r)
		}
		if got := answered(t, f.w.Table()); got != 1 {
			t.Fatalf("a push that did not name node 0 changed the answer to %d", got)
		}
	})

	t.Run("behind and ahead of a membership rollout", func(t *testing.T) {
		// Behind: the push names node 2, which the node's membership does not hold yet.
		f := newFixture(t, nil)
		f.w.Load(storetest.Table(2, 0), now)
		f.apply(f.signed(100, 0, 2))
		if got := len(f.w.Table().Nodes); got != 2 {
			t.Fatalf("the push changed the membership: %d nodes", got)
		}
		if got := answered(t, f.w.Table()); got != 1 {
			t.Fatalf("answered node %d", got)
		}
		// The entry that adds node 2 comes next: its flag, taken from the push, holds.
		if _, err := f.w.SetMembership(storetest.Table(3, 0)); err != nil {
			t.Fatal(err)
		}
		if !f.w.Table().Nodes[zone.NodeID(storetest.NodeID(2))].Withdrawn {
			t.Fatal("the flag of a node the log added later was lost")
		}
		// Ahead: the node's membership holds node 2 and a push of an older shape does not
		// name it; it keeps the flag it had, and a node no push named is not withdrawn.
		g := newFixture(t, nil)
		g.w.Load(storetest.Table(3, 0), now)
		pt := storetest.Table(3, 100)
		pt.ExpiresAt = expiry
		pt.Nodes = pt.Nodes[:2]
		if r := g.apply(g.keys.Sign(t, pt)); !r.Accepted {
			t.Fatalf("%+v", r)
		}
		if g.w.Table().Nodes[zone.NodeID(storetest.NodeID(2))].Withdrawn {
			t.Fatal("a node no push named is withdrawn")
		}
	})

	t.Run("a lagging node keeps a removed node withdrawn, after a restart too", func(t *testing.T) {
		f := newFixture(t, nil)
		f.w.Load(storetest.Table(3, 0), now)
		f.apply(f.signed(100, 0)) // the hub withdraws A (node 0)
		// The next push holds a membership without A. This node is still on the old
		// membership, so A stays withdrawn and the fallback is answered, not A.
		pt := storetest.Table(3, 101)
		pt.ExpiresAt = expiry
		pt.Nodes = pt.Nodes[1:]
		pt.Pairs, pt.GlobalPairId = nil, nil
		if r := f.apply(f.keys.Sign(t, pt)); !r.Accepted {
			t.Fatalf("%+v", r)
		}
		if got := answered(t, f.w.Table()); got != 1 {
			t.Fatalf("answered node %d, the removed node is advertised again", got)
		}
		g := f.writer(nil)
		if res := g.Load(storetest.Table(3, 0), now+3600); res.Dropped != nil {
			t.Fatalf("%+v", res)
		}
		if got := answered(t, g.Table()); got != 1 {
			t.Fatalf("after a restart answered node %d", got)
		}
	})

	t.Run("a flag is dropped only for a node in neither the membership nor the push", func(t *testing.T) {
		f := newFixture(t, nil)
		f.w.Load(storetest.Table(2, 0), now)
		f.apply(f.signed(100, 2)) // node 2 is in the push only
		if _, ok := f.w.Flags()[zone.NodeID(storetest.NodeID(2))]; !ok {
			t.Fatal("the flag of a node named by the push was dropped")
		}
		// A later push that does not name node 2, while the membership still lacks it: the
		// node is now in neither, and its flag goes.
		pt := storetest.Table(2, 101)
		pt.ExpiresAt = expiry
		if r := f.apply(f.keys.Sign(t, pt)); !r.Accepted {
			t.Fatalf("%+v", r)
		}
		if _, ok := f.w.Flags()[zone.NodeID(storetest.NodeID(2))]; ok {
			t.Fatal("the flag of a node in neither was kept")
		}
		if _, err := f.w.SetMembership(storetest.Table(3, 0)); err != nil {
			t.Fatal(err)
		}
		if f.w.Table().Nodes[zone.NodeID(storetest.NodeID(2))].Withdrawn {
			t.Fatal("a node whose flag was dropped came back withdrawn")
		}
	})

	t.Run("a log table applied after a push takes the membership and keeps the flags", func(t *testing.T) {
		f := newFixture(t, nil)
		f.w.Load(storetest.Table(3, 0), now)
		f.apply(f.signed(100, 0))
		m := storetest.Table(3, 0)
		m.Nodes[2].DnsIp = []byte{9, 9, 9, 8} // an address edit in the log
		if _, err := f.w.SetMembership(m); err != nil {
			t.Fatal(err)
		}
		tb := f.w.Table()
		if got := tb.Nodes[zone.NodeID(storetest.NodeID(2))].DNSIP.String(); got != "9.9.9.8" {
			t.Fatalf("membership not taken: %s", got)
		}
		if !tb.Nodes[zone.NodeID(storetest.NodeID(0))].Withdrawn || answered(t, tb) != 1 {
			t.Fatal("the flags were lost")
		}
	})

	t.Run("a push's SPKI, slot and address are not taken: only its flags", func(t *testing.T) {
		member := storetest.Table(3, 0)
		member.Nodes[2].SpkiSha256 = nil // node 2 is revoked in the node's own log entry
		f := newFixture(t, nil)
		f.w.Load(member, now)
		pt := storetest.Table(3, 100, 0)
		pt.ExpiresAt = expiry
		pt.Nodes[2].SpkiSha256 = bytes.Repeat([]byte{7}, 32) // the push says node 2 is not revoked
		pt.Nodes[1].DnsIp, pt.Nodes[1].ProxyIp = []byte{5, 5, 5, 5}, []byte{5, 5, 5, 5}
		if r := f.apply(f.keys.Sign(t, pt)); !r.Accepted {
			t.Fatalf("%+v", r)
		}
		tb := f.w.Table()
		if !tb.Nodes[zone.NodeID(storetest.NodeID(2))].Revoked {
			t.Fatal("a push un-revoked a node")
		}
		if got := tb.Nodes[zone.NodeID(storetest.NodeID(1))].DNSIP.String(); got != "8.8.4.4" {
			t.Fatalf("a push changed an address: %s", got)
		}
		for _, n := range zone.NameServers(tb) {
			if n.ID == zone.NodeID(storetest.NodeID(2)) {
				t.Fatal("the revoked node is a name server")
			}
		}
		if answered(t, tb) != 1 {
			t.Fatal("the flags of the push were not taken")
		}
	})

	t.Run("an equal version with the same flags after a reboot is a redelivery", func(t *testing.T) {
		f := newFixture(t, nil)
		f.w.Load(storetest.Table(3, 0), now)
		f.apply(f.signed(100, 0))
		g := f.writer(nil)
		g.Load(storetest.Table(3, 0), now+10)
		if g.Status().AcceptedSinceStart {
			t.Fatal("a load counts as an accepted push")
		}
		late := storetest.Table(3, 100, 0)
		late.ExpiresAt = expiry + 900
		r := g.ApplyPush(f.keys.Sign(t, late), now+10)
		if !r.Accepted || !r.Redelivery || r.Refusal != hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED {
			t.Fatalf("%+v", r)
		}
		st := g.Status()
		if !st.AcceptedSinceStart || st.Refusals != 0 || st.LatestRefusal != 0 || st.ExpiresAt != expiry+900 {
			t.Fatalf("%+v", st)
		}
		// With a flag that differs at the same version: refused, FLAG_CONFLICT.
		if r := g.ApplyPush(f.signed(100, 1), now+10); r.Refusal != hubv1.PushRefusal_PUSH_REFUSAL_FLAG_CONFLICT {
			t.Fatalf("%+v", r)
		}
	})

	t.Run("an expired persisted push is kept at restart whatever the clock says", func(t *testing.T) {
		for _, later := range []int64{31 * 60, 24 * 3600} {
			f := newFixture(t, nil)
			f.w.Load(storetest.Table(3, 0), now)
			f.apply(f.signed(100, 0))
			g := f.writer(nil)
			res := g.Load(storetest.Table(3, 0), now+later)
			if res.Dropped != nil || res.Version != 100 {
				t.Fatalf("clock +%d s: %+v", later, res)
			}
			// The flags are unchanged, a withdrawn primary is still withdrawn, and the push
			// in use is past its expiry, which is what makes the node PanelStale.
			if answered(t, g.Table()) != 1 || g.Status().ExpiresAt >= now+later {
				t.Fatalf("clock +%d s: answered %d, expires_at %d", later, answered(t, g.Table()), g.Status().ExpiresAt)
			}
		}
	})

	t.Run("every refusal is reported and counted, a lower version included", func(t *testing.T) {
		f := newFixture(t, nil)
		f.w.Load(storetest.Table(3, 0), now)
		f.apply(f.signed(100, 0))
		other := storetest.NewKeys(t)
		bad := storetest.Table(3, 300)
		bad.ExpiresAt = expiry
		bad.Nodes[1].Slot = bad.Nodes[0].Slot
		badPayload, _ := proto.Marshal(bad)
		exp := storetest.Table(3, 400)
		exp.ExpiresAt = now
		pt := storetest.Table(3, 200)
		pt.ExpiresAt = expiry
		cases := []struct {
			name string
			do   func() push.Result
			want hubv1.PushRefusal
		}{
			{"signature", func() push.Result { return f.apply(other.Sign(t, pt)) }, hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE},
			{"invalid", func() push.Result { return f.apply(f.keys.SignPayload(manifest.TypePairTable, badPayload)) }, hubv1.PushRefusal_PUSH_REFUSAL_INVALID},
			{"expired", func() push.Result { return f.apply(f.keys.Sign(t, exp)) }, hubv1.PushRefusal_PUSH_REFUSAL_EXPIRED},
			{"lower version", func() push.Result { return f.apply(f.signed(99)) }, hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION},
			{"flag conflict", func() push.Result { return f.apply(f.signed(100, 1)) }, hubv1.PushRefusal_PUSH_REFUSAL_FLAG_CONFLICT},
		}
		for i, c := range cases {
			r := c.do()
			st := f.w.Status()
			if r.Accepted || r.Refusal != c.want || st.Refusals != uint64(i+1) || st.LastRefusal != c.want || st.LatestRefusal != c.want {
				t.Errorf("%s: %+v %+v", c.name, r, st)
			}
			// What PanelStale reads (SC 8a.5): every refusal but a lower version.
			stale := st.LatestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED && st.LatestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION
			if stale != (c.want != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION) {
				t.Errorf("%s: panel-stale input %v", c.name, stale)
			}
		}
		// The next accepted push clears the latest refusal and keeps the count.
		if r := f.apply(f.signed(101, 0)); !r.Accepted {
			t.Fatalf("%+v", r)
		}
		if st := f.w.Status(); st.LatestRefusal != 0 || st.Refusals != uint64(len(cases)) || st.LastRefusal != hubv1.PushRefusal_PUSH_REFUSAL_FLAG_CONFLICT {
			t.Fatalf("%+v", st)
		}
	})
}
