package apply_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"
	"github.com/Kup1ng/CtrlZ-Shared/vectors"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/blobfetch"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/push"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// The pair-table-apply vector group (SC 15, 8a.4, 8a.5, 8a.10; T-541, T-545) run
// through the node's real code: a signed push goes to push.Writer.ApplyPush, a log
// entry to apply.Applier.ApplyEntry (which checks and swaps the membership through
// the same Writer), a restart opens both again over the same directory, and what the
// node reports is read from the Writer's Status, push.Status.PanelStale and the
// table in use. The reference model of the shared module runs the same cases, so a
// node that drifts from 8a.4 fails here.
//
// What the harness does itself is the part of the agent that is plain clock keeping:
// the hub offset of the latest ServerTime and the time since it (8a.4, Clock). The
// Control stream is taken as up, as the group says.

// glueApply is the node's ApplyHarness.
type glueApply struct{ t *testing.T }

func TestPairTableApplyVectorsThroughTheTableWriter(t *testing.T) {
	vectors.RunPairTableApply(t, glueApply{t: t})
}

func (h glueApply) Start(c *vectors.ApplyCase) (vectors.ApplyNode, error) {
	n := &applyNode{
		t: h.t, c: c, dir: h.t.TempDir(), keys: storetest.NewKeys(h.t), hub: storetest.NewHub(),
		self: zone.NodeID(vectors.PairVectorID(c.Node.Self)), now: c.Node.Clock,
		nodeName: map[zone.NodeID]string{}, pairName: map[zone.PairID]string{},
	}
	nodes, pairs := c.Names()
	for _, name := range nodes {
		n.nodeName[zone.NodeID(vectors.PairVectorID(name))] = name
	}
	for _, name := range pairs {
		n.pairName[zone.PairID(vectors.PairVectorID(name))] = name
	}
	if err := n.seedLog(); err != nil {
		return nil, err
	}
	if err := n.seedPush(); err != nil {
		return nil, err
	}
	if err := n.start(c.Node.Clock); err != nil {
		return nil, err
	}
	return n, nil
}

type applyNode struct {
	t        *testing.T
	c        *vectors.ApplyCase
	dir      string
	keys     *storetest.Keys
	hub      *storetest.Hub
	self     zone.NodeID
	nodeName map[zone.NodeID]string
	pairName map[zone.PairID]string

	chain storetest.Chain
	root  *store.Root
	w     *push.Writer
	a     *apply.Applier

	// now is the node's own clock, set by each step before it acts. started, offset
	// and lastST are the agent's per-process clock state (8a.4, Clock), reset at start.
	now     int64
	started int64
	offset  int64
	lastST  int64
	hasST   bool
}

// open starts the node's store, table writer and applier over the directory, the
// way the agent does at process start.
func (n *applyNode) open(now int64) error {
	n.now = now
	fw := &fsx.Writer{}
	root, err := store.Open(n.dir, fw)
	if err != nil {
		return err
	}
	n.root = root
	n.w = push.New(push.Config{Dir: root.Path(store.DirPush), W: fw, Root: func() (*signv1.Root, error) { return n.keys.Root, nil }})
	a, _, err := apply.Open(apply.Config{
		Root: root, Fetcher: blobfetch.New(n.hub, blobfetch.WithTimeout(5*time.Second)), Tables: n.w,
		Snapshots: n.hub, Now: func() int64 { return n.now },
	})
	if err != nil {
		return err
	}
	n.a = a
	return nil
}

// start is a process start at now: everything is read back from disk and the
// per-process counters begin again.
func (n *applyNode) start(now int64) error {
	if err := n.open(now); err != nil {
		return err
	}
	n.started, n.offset, n.lastST, n.hasST = now, 0, 0, false
	return nil
}

// seedLog brings the node's applied log to the case's applied_seq with the case's
// membership in the last entry, through the real applier. The earlier entries carry
// nothing: the group asks only what the table says. A case with no membership starts
// on an empty node, so there is nothing to seed and the first open is start's.
func (n *applyNode) seedLog() error {
	s := &n.c.Node
	if s.Membership == nil {
		if s.AppliedSeq != 0 {
			return fmt.Errorf("applied_seq %d with no membership", s.AppliedSeq)
		}
		return n.open(s.Clock)
	}
	if s.AppliedSeq == 0 {
		return fmt.Errorf("a membership with applied_seq 0")
	}
	pt, err := s.Membership.Table()
	if err != nil {
		return err
	}
	if err := n.open(s.Clock); err != nil {
		return err
	}
	for seq := uint64(1); seq <= s.AppliedSeq; seq++ {
		ent := &policyv1.ConfigEntry{}
		if seq == s.AppliedSeq {
			ent.PairTable = pt
		}
		if res := n.applyEntry(ent); !res.Report.Advanced || res.ImageErr != nil {
			return fmt.Errorf("seed entry %d was not applied: %+v", seq, res)
		}
	}
	return nil
}

func (n *applyNode) applyEntry(ent *policyv1.ConfigEntry) apply.Result {
	b := n.chain.Marshal(n.t, ent)
	res := n.a.ApplyEntry(context.Background(), b)
	if res.Report.Advanced {
		n.chain.Advance(b)
	}
	return res
}

// seedPush writes the persisted push state of the case (8a.4, At start) in the
// two files the table writer keeps: the sealed used file, and, when the case has an
// expires_at, the signed push it came from. The files are read back by Load, which
// checks the push by its signature, so a format that drifts fails the start.
func (n *applyNode) seedPush() error {
	s := &n.c.Node
	if len(s.Flags) == 0 && s.VersionUsed == 0 && s.Highest == 0 && s.ExpiresAt == 0 {
		return nil
	}
	high := s.Highest
	if high < s.VersionUsed {
		high = s.VersionUsed
	}
	flags := map[string]bool{}
	for name, w := range s.Flags {
		flags[hex.EncodeToString(vectors.PairVectorID(name))] = w
	}
	used, err := json.Marshal(struct {
		Highest uint64          `json:"highest"`
		Version uint64          `json:"version"`
		Flags   map[string]bool `json:"flags"`
	}{high, s.VersionUsed, flags})
	if err != nil {
		return err
	}
	dir := n.root.Path(store.DirPush)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "used"), fsx.Seal("CZPU", used), 0o600); err != nil {
		return err
	}
	if s.ExpiresAt == 0 {
		return nil
	}
	if s.Membership == nil {
		return fmt.Errorf("a persisted push with no membership")
	}
	pt, err := s.Membership.Table()
	if err != nil {
		return err
	}
	pt.Version, pt.ExpiresAt = s.VersionUsed, s.ExpiresAt
	for _, ne := range pt.Nodes {
		ne.DnsWithdrawn = s.Flags[n.nodeName[zone.NodeID(ne.NodeId)]]
	}
	env, err := proto.MarshalOptions{Deterministic: true}.Marshal(n.keys.Sign(n.t, pt))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "push"), fsx.Seal("CZPE", env), 0o600)
}

func (n *applyNode) Step(_ int, s *vectors.ApplyStep, now int64) (vectors.ApplyObserved, error) {
	n.now = now
	res, reason, scope := "none", hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED, ""
	switch s.Kind {
	case "push":
		var err error
		if res, reason, err = n.push(s); err != nil {
			return vectors.ApplyObserved{}, err
		}
	case "log":
		var err error
		if res, scope, err = n.log(s); err != nil {
			return vectors.ApplyObserved{}, err
		}
	case "restart":
		if s.CorruptPush {
			// A persisted push that fails its check at start (8a.4, At start).
			p := filepath.Join(n.root.Path(store.DirPush), "push")
			b, err := os.ReadFile(p)
			if err != nil {
				return vectors.ApplyObserved{}, fmt.Errorf("corrupt_push with no persisted push: %w", err)
			}
			b[len(b)-1] ^= 0xff
			if err := os.WriteFile(p, b, 0o600); err != nil {
				return vectors.ApplyObserved{}, err
			}
		}
		if err := n.start(now); err != nil {
			return vectors.ApplyObserved{}, err
		}
	case "server_time":
		n.offset, n.lastST, n.hasST = s.Offset, now, true
	case "tick":
	default:
		return vectors.ApplyObserved{}, fmt.Errorf("unknown step kind %q", s.Kind)
	}
	return n.observe(now, res, reason, scope), nil
}

// push signs the step's table with the hub's policy key and gives it to the writer
// at the hub's clock. A defect is the damage the group names.
func (n *applyNode) push(s *vectors.ApplyStep) (string, hubv1.PushRefusal, error) {
	var env *signv1.Envelope
	switch s.Defect {
	case "empty":
		env = &signv1.Envelope{PayloadType: manifest.TypePairTable}
	case "signature":
		// The case may give no table: the payload is then any bytes under a signature
		// that does not verify, which is what the step says.
		var payload []byte
		if s.Table != nil && !s.Table.Nil {
			pt, err := s.Table.Table()
			if err != nil {
				return "", 0, err
			}
			if payload, err = proto.Marshal(pt); err != nil {
				return "", 0, err
			}
		} else {
			payload = []byte{0x08, 0x01}
		}
		env = n.keys.SignPayload(manifest.TypePairTable, payload)
		env.Signatures[0].Sig[0] ^= 0xff
	case "":
		pt, err := n.pushTable(s)
		if err != nil {
			return "", 0, err
		}
		env = n.keys.Sign(n.t, pt)
	default:
		return "", 0, fmt.Errorf("unknown defect %q", s.Defect)
	}
	r := n.w.ApplyPush(env, n.now+n.offset)
	switch {
	case !r.Accepted:
		return "refused", r.Refusal, nil
	case r.Redelivery:
		return "redelivered", 0, nil
	}
	return "applied", 0, nil
}

func (n *applyNode) pushTable(s *vectors.ApplyStep) (*policyv1.PairTable, error) {
	if s.Table == nil || s.Table.Nil {
		return nil, fmt.Errorf("a push step needs a table")
	}
	return s.Table.Table()
}

// log applies a log entry that carries the step's table, with the seq the case
// names, which must be the next one.
func (n *applyNode) log(s *vectors.ApplyStep) (result, scope string, err error) {
	if s.Table == nil {
		return "", "", fmt.Errorf("a log step needs a table")
	}
	if s.ConfigSeq != n.chain.Seq+1 {
		return "", "", fmt.Errorf("config_seq %d, the node's next is %d", s.ConfigSeq, n.chain.Seq+1)
	}
	pt, err := s.Table.Table()
	if err != nil {
		return "", "", err
	}
	res := n.applyEntry(&policyv1.ConfigEntry{PairTable: pt})
	switch {
	case res.Err != nil:
		return "", "", res.Err
	case res.Report.Advanced:
		return "applied", "", nil
	case res.Report.Entry != nil && res.Report.Entry.Scope == quarantine.ScopeEntry:
		return "refused", "entry", nil
	}
	return "", "", fmt.Errorf("entry neither applied nor refused as an entry: %+v", res)
}

func refusalName(r hubv1.PushRefusal) string {
	if r == hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(r.String(), "PUSH_REFUSAL_")
}

func (n *applyNode) observe(now int64, res string, reason hubv1.PushRefusal, scope string) vectors.ApplyObserved {
	st := n.w.Status()
	last := n.started
	if n.hasST {
		last = n.lastST
	}
	o := vectors.ApplyObserved{
		Result: res, Reason: refusalName(reason), Flags: map[string]bool{}, VersionUsed: st.Version, ExpiresAt: st.ExpiresAt,
		LastRefusal: refusalName(st.LastRefusal), Refusals: st.Refusals, AppliedSeq: n.a.AppliedSeq(), Quarantine: scope,
		PanelStale: st.PanelStale(push.StaleClocks{SinceServerTime: time.Duration(now-last) * time.Second, HubNow: now + n.offset}),
		Answers:    map[string]string{},
	}
	for id, f := range n.w.Flags() {
		o.Flags[n.nodeName[id]] = f
	}
	tb := n.w.TableInUse(now)
	o.InUse = tb != nil
	if tb != nil {
		for _, ns := range zone.NameServers(tb) {
			o.NSSet = append(o.NSSet, fmt.Sprintf("ns%d", ns.Slot))
		}
		for id, name := range n.pairName {
			if nd, ok := zone.Target(tb, id, zone.Local{Self: n.self}); ok && tb.Pairs[id].ID == id {
				o.Answers[name] = nd.DNSIP.String()
			}
		}
	}
	return o
}
