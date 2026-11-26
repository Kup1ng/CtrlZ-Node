package push_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/push"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const (
	now    = int64(1_000_000)
	expiry = now + 1800
)

type fixture struct {
	t    *testing.T
	dir  string
	keys *storetest.Keys
	w    *push.Writer
}

func newFixture(t *testing.T, hook *fsx.Writer) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), keys: storetest.NewKeys(t)}
	f.w = f.writer(hook)
	return f
}

func (f *fixture) writer(wr *fsx.Writer) *push.Writer {
	return push.New(push.Config{Dir: f.dir, W: wr, Root: func() (*signv1.Root, error) { return f.keys.Root, nil }})
}

// signed signs a push of the 3-node table at a version, withdrawing the nodes named.
func (f *fixture) signed(version uint64, withdrawn ...int) *signv1.Envelope {
	pt := storetest.Table(3, version, withdrawn...)
	pt.ExpiresAt = expiry
	return f.keys.Sign(f.t, pt)
}

func (f *fixture) apply(env *signv1.Envelope) push.Result {
	f.t.Helper()
	return f.w.ApplyPush(env, now)
}

func withdrawn(w *push.Writer, n int) bool {
	t := w.Table()
	if t == nil {
		return false
	}
	return t.Nodes[zone.NodeID(storetest.NodeID(n))].Withdrawn
}

func TestAcceptsAPushAndPutsItsFlagsInTheTable(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	if f.w.Table() == nil || f.w.Table().Version != 0 {
		t.Fatal("no table from the membership")
	}
	res := f.apply(f.signed(100, 0))
	if !res.Accepted || res.Redelivery || res.PersistErr != nil {
		t.Fatalf("%+v", res)
	}
	if !withdrawn(f.w, 0) || withdrawn(f.w, 1) || f.w.Table().Version != 100 {
		t.Fatal("flags not in the table")
	}
	st := f.w.Status()
	if st.Version != 100 || st.Highest != 100 || st.ExpiresAt != expiry || !st.AcceptedSinceStart || st.Refusals != 0 {
		t.Fatalf("%+v", st)
	}
}

// Step 1 of SC 8a.4 Node apply, each refusal in turn. The node keeps its table.
func TestRefusals(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	if r := f.apply(f.signed(100, 0)); !r.Accepted {
		t.Fatalf("%+v", r)
	}
	other := storetest.NewKeys(t)
	pt := storetest.Table(3, 200, 1)
	pt.ExpiresAt = expiry
	payload, _ := proto.Marshal(pt)
	bad := storetest.Table(3, 300)
	bad.ExpiresAt = expiry
	bad.Nodes[1].Slot = bad.Nodes[0].Slot // two nodes with one slot
	badPayload, _ := proto.Marshal(bad)
	v0 := storetest.Table(3, 0)
	v0.ExpiresAt = expiry
	exp := storetest.Table(3, 400)
	exp.ExpiresAt = now
	cases := []struct {
		name string
		env  *signv1.Envelope
		want hubv1.PushRefusal
	}{
		{"nil envelope", nil, hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE},
		{"empty payload", &signv1.Envelope{PayloadType: manifest.TypePairTable}, hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE},
		{"signed by another key", other.Sign(t, pt), hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE},
		{"wrong payload type", f.keys.SignPayload(manifest.TypeHead, payload), hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE},
		{"payload changed after signing", func() *signv1.Envelope {
			e := f.keys.Sign(t, pt)
			e.Payload = append(append([]byte(nil), e.Payload...), 0)
			return e
		}(), hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE},
		{"signed garbage", f.keys.SignPayload(manifest.TypePairTable, []byte{0xff, 0xff, 0xff}), hubv1.PushRefusal_PUSH_REFUSAL_INVALID},
		{"invalid table", f.keys.SignPayload(manifest.TypePairTable, badPayload), hubv1.PushRefusal_PUSH_REFUSAL_INVALID},
		{"version 0", f.keys.Sign(t, v0), hubv1.PushRefusal_PUSH_REFUSAL_INVALID},
		{"expired", f.keys.Sign(t, exp), hubv1.PushRefusal_PUSH_REFUSAL_EXPIRED},
		{"lower version", f.signed(99, 2), hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION},
		{"equal version with another flag", f.signed(100, 0, 1), hubv1.PushRefusal_PUSH_REFUSAL_FLAG_CONFLICT},
	}
	// SC 8a.5: a refused LOWER_VERSION is counted and is the last refusal, but it never
	// replaces latest_refusal, so the previous case's refusal stays in force.
	var wantLatest hubv1.PushRefusal
	for i, c := range cases {
		if c.want != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION {
			wantLatest = c.want
		}
		res := f.apply(c.env)
		if res.Accepted || res.Refusal != c.want || res.Err == nil {
			t.Errorf("%s: %+v", c.name, res)
		}
		// The table and the flag map stay as they were.
		if !withdrawn(f.w, 0) || withdrawn(f.w, 1) || withdrawn(f.w, 2) || f.w.Status().Version != 100 {
			t.Errorf("%s changed the table in use", c.name)
		}
		st := f.w.Status()
		if st.Refusals != uint64(i+1) || st.LastRefusal != c.want || st.LatestRefusal != wantLatest {
			t.Errorf("%s: %+v", c.name, st)
		}
	}
	// An accepted push clears the latest refusal; the count and the last one stay.
	if r := f.apply(f.signed(101, 0)); !r.Accepted {
		t.Fatalf("%+v", r)
	}
	if st := f.w.Status(); st.LatestRefusal != 0 || st.Refusals != uint64(len(cases)) {
		t.Fatalf("%+v", st)
	}
	// An error text never carries payload bytes.
	for _, c := range cases {
		if res := f.apply(c.env); res.Err != nil && bytes.Contains([]byte(res.Err.Error()), []byte{0xff, 0xff, 0xff}) {
			t.Errorf("%s: error holds payload bytes", c.name)
		}
	}
}

func TestExpiryIsJudgedByHubNowNotTheNodesClock(t *testing.T) {
	f := newFixture(t, nil)
	env := f.signed(100, 0)
	if r := f.w.ApplyPush(env, expiry); r.Refusal != hubv1.PushRefusal_PUSH_REFUSAL_EXPIRED {
		t.Fatalf("%+v", r)
	}
	if r := f.w.ApplyPush(env, expiry-1); !r.Accepted {
		t.Fatalf("%+v", r)
	}
}

// Step 2: the same version with the same flags is a redelivery that takes the
// later expiry; an older expiry changes nothing.
func TestRedelivery(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	f.apply(f.signed(100, 0))
	late := storetest.Table(3, 100, 0)
	late.ExpiresAt = expiry + 600
	res := f.apply(f.keys.Sign(t, late))
	if !res.Accepted || !res.Redelivery {
		t.Fatalf("%+v", res)
	}
	if f.w.Status().ExpiresAt != expiry+600 {
		t.Fatal("later expiry not taken")
	}
	if r := f.apply(f.signed(100, 0)); !r.Accepted || !r.Redelivery || f.w.Status().ExpiresAt != expiry+600 {
		t.Fatalf("%+v", r)
	}
	// A redelivery counts as accepted even if it is the first of this run.
	g := newFixture(t, nil)
	g.w.Load(nil, now)
	g.apply(g.signed(100))
	if st := g.w.Status(); !st.AcceptedSinceStart {
		t.Fatal("not counted")
	}
}

// Step 3: a node the push names takes its flag; a node it does not name keeps the
// flag it had; the map drops a node in neither the membership nor the push.
func TestFlagMapKeepsWhatAPushDoesNotName(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	f.apply(f.signed(100, 0, 1)) // withdraws nodes 0 and 1
	if !withdrawn(f.w, 0) || !withdrawn(f.w, 1) {
		t.Fatal("setup")
	}
	// A higher push that names only node 2 (a two-node table drops 0 and 1 from the push).
	pt := storetest.Table(3, 101)
	pt.ExpiresAt = expiry
	pt.Nodes = pt.Nodes[2:]
	pt.Pairs = nil
	pt.GlobalPairId = nil
	pt.Nodes[0].DnsWithdrawn = true
	if r := f.apply(f.keys.Sign(t, pt)); !r.Accepted {
		t.Fatalf("%+v", r)
	}
	if !withdrawn(f.w, 0) || !withdrawn(f.w, 1) || !withdrawn(f.w, 2) {
		t.Fatal("flags of nodes the push did not name were lost")
	}
	flags := f.w.Flags()
	if len(flags) != 3 {
		t.Fatalf("%v", flags)
	}
	// A node no push ever named is not withdrawn.
	g := newFixture(t, nil)
	g.w.Load(storetest.Table(3, 0), now)
	g.apply(g.signed(5))
	for i := 0; i < 3; i++ {
		if withdrawn(g.w, i) {
			t.Fatal("a node that no push named is withdrawn")
		}
	}
}

// The membership is the node's own, from the log: a push that names a node the
// log has not added yet keeps its flag until the entry that adds it is applied.
func TestAPushForANodeTheLogHasNotAddedYet(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(2, 0), now)
	f.apply(f.signed(100, 2)) // names node 2, withdrawn
	if len(f.w.Table().Nodes) != 2 {
		t.Fatal("the push changed the membership")
	}
	if _, err := f.w.SetMembership(storetest.Table(3, 0)); err != nil {
		t.Fatal(err)
	}
	if !withdrawn(f.w, 2) {
		t.Fatal("the flag held for node 2 was not laid on the new membership")
	}
	// And the other way: an entry's membership is kept after a later push.
	f.apply(f.signed(101, 1))
	if len(f.w.Table().Nodes) != 3 || !withdrawn(f.w, 1) || withdrawn(f.w, 2) {
		t.Fatalf("%+v", f.w.Flags())
	}
}

func TestAPushBeforeAnyMembershipIsKeptForLater(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(nil, now)
	if r := f.apply(f.signed(100, 0)); !r.Accepted {
		t.Fatalf("%+v", r)
	}
	if f.w.Table() != nil {
		t.Fatal("a table without a membership")
	}
	if _, err := f.w.SetMembership(storetest.Table(3, 0)); err != nil {
		t.Fatal(err)
	}
	if !withdrawn(f.w, 0) || f.w.Table().Version != 100 {
		t.Fatal("the flag of the earlier push was lost")
	}
}

// Step 4: a build that fails leaves the old table, the old flags, and the old
// version in use, and nothing is written.
func TestAFailedBuildKeepsTheOldTable(t *testing.T) {
	f := newFixture(t, nil)
	good := storetest.Table(3, 0)
	f.w.Load(good, now)
	f.apply(f.signed(100, 0))
	before := f.w.Table()
	usedBefore, _ := os.ReadFile(filepath.Join(f.dir, "used"))
	// Break the membership under the writer: a table whose build fails with any
	// flags (a node entry the validator would refuse). SetMembership refuses it.
	bad := storetest.Table(3, 0)
	bad.Nodes[0].Slot = 9
	if _, err := f.w.SetMembership(bad); err == nil {
		t.Fatal("a table that does not build was put in use")
	}
	if err := f.w.CheckMembership(bad); err == nil {
		t.Fatal("check accepted it")
	}
	if f.w.Table() != before || len(f.w.Member().Nodes) != 3 {
		t.Fatal("a failed build changed the table")
	}
	// A push on a membership that cannot build (loaded from a damaged state):
	// refused with BUILD, flags and version unchanged.
	g := newFixture(t, nil)
	g.w.Load(bad, now)
	if g.w.Table() != nil {
		t.Fatal("a table from a bad membership")
	}
	res := g.apply(g.signed(100, 0))
	if res.Accepted || res.Refusal != hubv1.PushRefusal_PUSH_REFUSAL_BUILD {
		t.Fatalf("%+v", res)
	}
	if g.w.Status().Version != 0 || g.w.Status().Highest != 0 {
		t.Fatal("a refused push moved the version")
	}
	usedAfter, _ := os.ReadFile(filepath.Join(f.dir, "used"))
	if !bytes.Equal(usedBefore, usedAfter) {
		t.Fatal("a refusal wrote to disk")
	}
}

func TestSetMembershipUndo(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(2, 0), now)
	f.apply(f.signed(100, 1))
	undo, err := f.w.SetMembership(storetest.Table(3, 0))
	if err != nil || len(f.w.Table().Nodes) != 3 {
		t.Fatal(err)
	}
	// A push lands between the swap and the undo: the undo keeps its flags.
	f.apply(f.signed(101, 0))
	undo()
	if len(f.w.Table().Nodes) != 2 || !withdrawn(f.w, 0) || f.w.Table().Version != 101 {
		t.Fatalf("%+v", f.w.Table())
	}
	// With no previous membership the undo leaves no table.
	g := newFixture(t, nil)
	g.w.Load(nil, now)
	u, _ := g.w.SetMembership(storetest.Table(2, 0))
	u()
	if g.w.Table() != nil || g.w.Member() != nil {
		t.Fatal("undo left a table")
	}
}

func TestPersistedStateIsLoadedAtStart(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	f.apply(f.signed(100, 0, 2))
	f.apply(f.signed(101, 2)) // names all three: node 0 is cleared, node 2 stays withdrawn
	g := f.writer(nil)
	// Load is by the node's clock a day later and past the push's expiry: it judges neither.
	res := g.Load(storetest.Table(3, 0), expiry+86400)
	if res.Dropped != nil || res.Version != 101 {
		t.Fatalf("%+v", res)
	}
	if withdrawn(g, 0) || withdrawn(g, 1) || !withdrawn(g, 2) {
		t.Fatal("flags after a restart")
	}
	if st := g.Status(); st.Highest != 101 || st.AcceptedSinceStart || st.Refusals != 0 || st.ExpiresAt != expiry {
		t.Fatalf("%+v", st)
	}
	// The node keeps refusing what it refused before the restart.
	if r := g.ApplyPush(f.signed(100, 1), now); r.Refusal != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION {
		t.Fatalf("%+v", r)
	}
	// And the hub's resend of the persisted version is a redelivery, accepted.
	if r := g.ApplyPush(f.signed(101, 2), now); !r.Accepted || !r.Redelivery {
		t.Fatalf("%+v", r)
	}
}

// If the persisted push fails its check at start, the flags and the push are
// deleted and the node runs with no flags, but it still refuses an older push.
func TestAPersistedPushThatFailsItsCheckIsDropped(t *testing.T) {
	for _, damage := range []string{"push rotted", "push signed by another key", "used rotted", "push absent and used rotted"} {
		t.Run(damage, func(t *testing.T) {
			f := newFixture(t, nil)
			f.w.Load(storetest.Table(3, 0), now)
			f.apply(f.signed(100, 0))
			switch damage {
			case "push rotted":
				p := filepath.Join(f.dir, "push")
				b, _ := os.ReadFile(p)
				b[len(b)-2] ^= 1
				_ = os.WriteFile(p, b, 0o600)
			case "push signed by another key":
				other := storetest.NewKeys(t)
				pt := storetest.Table(3, 100, 0)
				pt.ExpiresAt = expiry
				env := other.Sign(t, pt)
				b, _ := proto.Marshal(env)
				_ = os.WriteFile(filepath.Join(f.dir, "push"), fsx.Seal("CZPE", b), 0o600)
			case "used rotted":
				p := filepath.Join(f.dir, "used")
				b, _ := os.ReadFile(p)
				b[len(b)-2] ^= 1
				_ = os.WriteFile(p, b, 0o600)
			case "push absent and used rotted":
				_ = os.Remove(filepath.Join(f.dir, "push"))
				_ = os.WriteFile(filepath.Join(f.dir, "used"), []byte("junk"), 0o600)
			}
			g := f.writer(nil)
			res := g.Load(storetest.Table(3, 0), now)
			if res.Dropped == nil || res.Version != 0 {
				t.Fatalf("%+v", res)
			}
			if withdrawn(g, 0) || g.Table() == nil || g.Table().Version != 0 {
				t.Fatal("the node did not run with no flags")
			}
			// The push is deleted; the used file is rewritten with the highest version
			// when it was readable, and gone when it was not.
			if _, err := os.Stat(filepath.Join(f.dir, "push")); err == nil {
				t.Fatal("the push is still on disk")
			}
			// A rotted used file counts too: the push beside it is signed and carries
			// the version of the last accepted push, which becomes the floor (review
			// round 1, r1-10). Only when both are gone is there nothing to keep.
			usedReadable := damage != "push absent and used rotted"
			if usedReadable {
				// Anti-rollback outlives the flags.
				if g.Status().Highest != 100 {
					t.Fatalf("highest %d", g.Status().Highest)
				}
				if r := g.ApplyPush(f.signed(99), now); r.Refusal != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION {
					t.Fatalf("%+v", r)
				}
				// The same version again applies its flags: the flags were dropped, so it
				// is not a redelivery of anything.
				r := g.ApplyPush(f.signed(100, 0), now)
				if !r.Accepted || r.Redelivery || !withdrawn(g, 0) {
					t.Fatalf("%+v", r)
				}
			}
			// The next start finds a directory that loads without dropping anything.
			if res := f.writer(nil).Load(storetest.Table(3, 0), now); res.Dropped != nil {
				t.Fatalf("second start: %+v", res)
			}
		})
	}
}

// A deleted used file beside a verified push must not lower the floor: the push
// carries the version of the last one accepted (review round 3, r3-3).
func TestAMissingUsedFileKeepsTheVersionFloor(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	f.apply(f.signed(100, 0))
	if err := os.Remove(filepath.Join(f.dir, "used")); err != nil {
		t.Fatal(err)
	}
	g := f.writer(nil)
	if res := g.Load(storetest.Table(3, 0), now); res.Dropped != nil {
		t.Fatalf("%+v", res)
	}
	if g.Status().Highest != 100 {
		t.Fatalf("highest %d", g.Status().Highest)
	}
	if r := g.ApplyPush(f.signed(99), now); r.Refusal != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION {
		t.Fatalf("a lower push was taken: %+v", r)
	}
	// The floor was written back, so another start keeps it.
	h := f.writer(nil)
	h.Load(storetest.Table(3, 0), now)
	if h.Status().Highest != 100 {
		t.Fatalf("highest after another start %d", h.Status().Highest)
	}
}

// A persisted push whose table does not build with the membership drops the
// flags too: a push that crashes the build cannot crash the node on every start.
func TestAFlagSetThatPanicsTheBuildIsDroppedAtStart(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	f.apply(f.signed(100, 0))
	g := f.writer(nil)
	bad := storetest.Table(3, 0)
	bad.Nodes[1].DnsIp = bad.Nodes[0].DnsIp // a membership the build refuses
	res := g.Load(bad, now)
	if res.Dropped == nil || g.Table() != nil {
		t.Fatalf("%+v", res)
	}
}

// A cut at every step of persisting a push leaves a directory that loads, with
// either the old flags or the new ones, and never both halves.
func TestPersistenceInterruptedAtEveryStep(t *testing.T) {
	for _, step := range fsx.Steps() {
		for _, file := range []string{"used", "push"} {
			f := newFixture(t, nil)
			f.w.Load(storetest.Table(3, 0), now)
			f.apply(f.signed(100, 0))
			w := &fsx.Writer{Hook: func(p string, s fsx.Step) error {
				if s == step && filepath.Base(p) == file {
					return fsx.ErrInjected
				}
				return nil
			}}
			g := f.writer(w)
			g.Load(storetest.Table(3, 0), now)
			res := g.ApplyPush(f.signed(200, 1), now)
			if !res.Accepted || !errors.Is(res.PersistErr, fsx.ErrInjected) {
				t.Fatalf("%v/%s: %+v", step, file, res)
			}
			// The node in memory serves the new flags whatever the disk write did.
			if !withdrawn(g, 1) || g.Status().Version != 200 {
				t.Fatalf("%v/%s: memory", step, file)
			}
			// A restart: leftovers are cleaned, the directory loads.
			_, _ = fsx.CleanTemps(f.dir, false)
			h := f.writer(nil)
			lr := h.Load(storetest.Table(3, 0), now)
			if lr.Dropped != nil {
				t.Fatalf("%v/%s: dropped: %v", step, file, lr.Dropped)
			}
			v := h.Status().Version
			if v != 100 && v != 200 {
				t.Fatalf("%v/%s: version %d", step, file, v)
			}
			if (v == 100) != (withdrawn(h, 0) && !withdrawn(h, 1)) && (v == 200) != withdrawn(h, 1) {
				t.Fatalf("%v/%s: flags do not belong to version %d", step, file, v)
			}
		}
	}
}

// One writer: a push applied while entries swap their membership, and the reverse,
// always leaves a table that has the latest flags and the latest membership.
func TestPushAndMembershipNeverLoseEachOther(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(2, 0), now)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = f.w.SetMembership(storetest.Table(3, 0))
		}()
		go func(v uint64) {
			defer wg.Done()
			f.apply(f.signed(100+v, 1))
		}(uint64(i))
	}
	wg.Wait()
	tbl := f.w.Table()
	if len(tbl.Nodes) != 3 || !withdrawn(f.w, 1) || tbl.Version != f.w.Status().Version || tbl.Version < 100 {
		t.Fatalf("%d nodes, version %d (status %d)", len(tbl.Nodes), tbl.Version, f.w.Status().Version)
	}
}

// Hostile bytes: signed or not, any envelope is refused without a panic.
func TestHostileEnvelopesNeverPanic(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	junk := [][]byte{nil, {0}, bytes.Repeat([]byte{0xff}, 1000), []byte("\x0a\x02\x08\x01"), {0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}}
	for _, j := range junk {
		for _, typ := range []string{manifest.TypePairTable, "x", ""} {
			f.apply(&signv1.Envelope{PayloadType: typ, Payload: j})
			f.apply(f.keys.SignPayload(typ, j))
		}
	}
	if r := f.apply(f.signed(5, 0)); !r.Accepted {
		t.Fatalf("a valid push was refused after hostile ones: %+v", r)
	}
	_ = policyv1.PairTable{}
}
