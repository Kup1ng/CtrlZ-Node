package peer

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// A forward goes over a connection only while the applied table still trusts it. The loop
// of Run never ticks here (an hour), so only the use of the connection can notice the new
// table: the old code sent over the open stream to the old peer or the old key until the
// next tick (B6p-r1-1, r1-4).
func TestForwardNeverUsesAConnectionTheTableNoLongerTrusts(t *testing.T) {
	for _, tc := range []string{"the peer is re-keyed", "the pair moves to another node"} {
		t.Run(tc, func(t *testing.T) {
			p := newPKI(t)
			nodes := mkNodes(t, p, 3)
			dir := newDir()
			a := startRig(t, p, dir, nodes[0], mkTable(5, nodes, nil, [2]int{0, 1}), func(c *Config) { c.Tick = time.Hour })
			b := startRig(t, p, dir, nodes[1], mkTable(5, nodes, nil, [2]int{0, 1}))
			c := startRig(t, p, dir, nodes[2], mkTable(6, nodes, nil, [2]int{0, 2}))
			for _, r := range []*rig{a, b, c} {
				r.env.endpoint(gidOf(1), nil)
			}
			// The connection to B is open and has carried a forward.
			g := fwd(1, 1)
			a.dns.deliver(out(t, g))
			b.dns.next(t, sock.TypeGrantIn)
			b.dns.deliver(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: g.GrantId, Accepted: true}})
			if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantAccepted {
				t.Fatalf("first forward: %s", r)
			}

			if tc == "the peer is re-keyed" {
				pt := mkTable(6, nodes, nil, [2]int{0, 1})
				pt.Nodes[1].SpkiSha256 = make([]byte, 32)
				pt.Nodes[1].SpkiSha256[0] = 0x11
				a.env.table.Store(pt)
			} else {
				a.env.table.Store(mkTable(6, nodes, nil, [2]int{0, 2}))
			}
			a.dns.deliver(out(t, fwd(2, 1)))
			if tc == "the pair moves to another node" {
				c.dns.next(t, sock.TypeGrantIn) // the new peer gets it
			} else if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantUnsent {
				t.Fatalf("a forward to a key the table does not hold was %s", r)
			}
			b.dns.none(t, sock.TypeGrantIn, 200*time.Millisecond) // and the old one gets nothing
		})
	}
}

// Only the pair peer may forward: another live node finishes its handshake (the address
// check admits every live node) and its stream ends before a message is read (B6p-r1-6).
func TestStreamOfALiveNodeThatIsNotThePairPeerEnds(t *testing.T) {
	p, nodes, dir, _, b := pairOfTwo(t)
	c := startRig(t, p, dir, nodes[2], b.env.table.Load())
	_, err := dialRaw(t, c, b, c.n.cert, b.n.id)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the stream of a node outside the pair: %v", err)
	}
	b.dns.none(t, sock.TypeGrantIn, 100*time.Millisecond)
}

// ackOf reads the next ack of a raw stream.
func ackOf(t *testing.T, r *raw) *peerv1.GrantAck {
	t.Helper()
	a, err := r.st.Recv()
	if err != nil {
		t.Fatalf("no ack: %v", err)
	}
	return a
}

func fwdID(i int) *peerv1.GrantForward {
	g := fwd(1, 1)
	g.GrantId = append([]byte{byte(i), byte(i >> 8), 0x77}, make([]byte, 13)...)
	return g
}

// A grant_id that is already waiting is refused at once and reaches dns once; the answer
// of dns then goes to the first (B6p-r1-2).
func TestReceiverRefusesAGrantIDThatIsAlreadyWaiting(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t)
	cl := rawClient(t, a, b)
	g := fwdID(1)
	if err := cl.st.Send(g); err != nil {
		t.Fatal(err)
	}
	b.dns.next(t, sock.TypeGrantIn)
	if err := cl.st.Send(g); err != nil {
		t.Fatal(err)
	}
	if ak := ackOf(t, cl); ak.Accepted {
		t.Fatal("the second forward under one grant_id was taken")
	}
	b.dns.none(t, sock.TypeGrantIn, 100*time.Millisecond)
	b.dns.deliver(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: g.GrantId, Accepted: true}})
	if ak := ackOf(t, cl); !ak.Accepted || string(ak.GrantId) != string(g.GrantId) {
		t.Fatal("dns's answer did not reach the first forward")
	}
}

// 256 forwards of one stream may wait for dns; the 257th is refused at once.
func TestReceiverRefusesTheForwardPast256Unanswered(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t, func(c *Config) { c.AckWait = 30 * time.Second })
	cl := rawClient(t, a, b)
	for i := 1; i <= MaxUnanswered; i++ {
		if err := cl.st.Send(fwdID(i)); err != nil {
			t.Fatal(err)
		}
	}
	over := fwdID(MaxUnanswered + 1)
	if err := cl.st.Send(over); err != nil {
		t.Fatal(err)
	}
	if ak := ackOf(t, cl); ak.Accepted || string(ak.GrantId) != string(over.GrantId) {
		t.Fatalf("the first answer is not the refusal of forward 257: %x", ak.GrantId)
	}
	ins := 0
	deadline := time.After(300 * time.Millisecond)
count:
	for {
		select {
		case m := <-b.dns.got:
			if m.Type == sock.TypeGrantIn {
				ins++
			}
		case <-deadline:
			break count
		}
	}
	if ins != MaxUnanswered {
		t.Fatalf("dns got %d forwards, want %d", ins, MaxUnanswered)
	}
}

// The receiver admits 500 forwards a second for each sender and refuses the rest. The
// clock is frozen so no token comes back during the test, and dns answers each forward at
// once so that the cap of unanswered ones is never the reason for a refusal.
func TestReceiverRateOf500ForwardsAPerSecond(t *testing.T) {
	t0 := time.Now()
	_, _, _, a, b := pairOfTwo(t, func(c *Config) { c.Now = func() time.Time { return t0 } })
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			case m := <-b.dns.got:
				if m.Type == sock.TypeGrantIn {
					var g peerv1.GrantForward
					_ = proto.Unmarshal(m.GrantIn.Forward, &g)
					b.dns.deliver(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: g.GrantId, Accepted: true}})
				}
			}
		}
	}()
	cl := rawClient(t, a, b)
	const batch = 100
	next := 1
	for round := 1; round <= Rate/batch+1; round++ {
		for i := 0; i < batch; i++ {
			if err := cl.st.Send(fwdID(next)); err != nil {
				t.Fatal(err)
			}
			next++
		}
		accepted := 0
		for i := 0; i < batch; i++ {
			if ackOf(t, cl).Accepted {
				accepted++
			}
		}
		want := batch
		if round > Rate/batch {
			want = 0
		}
		if accepted != want {
			t.Fatalf("round %d: %d accepted, want %d", round, accepted, want)
		}
	}
}

// sender_config_seq is the sender's own claim, so the receiver puts no bound on it: a
// bound would be empty for a liar and would refuse an honest peer whose receiver has not
// heard the hub's latest head (B6p-r2-2). A forward that claims to be ahead goes to dns,
// whose hold-and-judge is the gate for its pair; one that is not ahead is judged here.
func TestReceiverPassesAnyAheadSenderConfigSeqToDNS(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t) // B is applied at 100
	cl := rawClient(t, a, b)
	other := func(seq uint64, i int) *peerv1.GrantForward {
		g := fwdID(i)
		g.EndpointId = gidOf(9) // an Endpoint of the other pair
		g.SenderConfigSeq = seq
		return g
	}
	// An honest peer 30 entries ahead of a receiver that missed the hub's notices.
	for i, seq := range []uint64{130, math.MaxUint64} {
		g := other(seq, i+1)
		if err := cl.st.Send(g); err != nil {
			t.Fatal(err)
		}
		b.dns.next(t, sock.TypeGrantIn)
		b.dns.deliver(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: g.GrantId, Accepted: false}})
		ackOf(t, cl)
	}
	// Not ahead: the Endpoint of another pair is refused here, before dns.
	if err := cl.st.Send(other(100, 10)); err != nil {
		t.Fatal(err)
	}
	if ackOf(t, cl).Accepted {
		t.Fatal("an Endpoint of another pair was taken at the receiver's own seq")
	}
	b.dns.none(t, sock.TypeGrantIn, 50*time.Millisecond)
}

// A stream is judged against the key its connection showed at every forward, not once a
// tick: the loop of Run never ticks here (an hour), and a table that replaces the peer's
// key must stop the open stream at its next message (B6p-r2-1, r2-3).
func TestReceiverEndsAStreamWhoseKeyTheTableHasReplaced(t *testing.T) {
	_, nodes, _, a, b := pairOfTwo(t, func(c *Config) { c.Tick = time.Hour })
	cl := rawClient(t, a, b)
	g := fwdID(1)
	if err := cl.st.Send(g); err != nil {
		t.Fatal(err)
	}
	b.dns.next(t, sock.TypeGrantIn) // the stream works under the old table
	b.dns.deliver(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: g.GrantId, Accepted: true}})
	ackOf(t, cl)

	pt := mkTable(6, nodes, nil, [2]int{0, 1}, [2]int{2, 3})
	pt.Nodes[0].SpkiSha256 = make([]byte, 32) // A re-enrolled: the key it holds is no longer the table's
	pt.Nodes[0].SpkiSha256[0] = 0x22
	b.env.table.Store(pt)

	if err := cl.st.Send(fwdID(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.st.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the stream of a replaced key: %v", err)
	}
	b.dns.none(t, sock.TypeGrantIn, 100*time.Millisecond)
}

// A connection whose key the table replaced between the TLS check and the record of the
// key is refused when it is recorded (B6p-r2-1).
func TestBindLeafJudgesTheKeyUnderTheCurrentTable(t *testing.T) {
	_, nodes, _, _, b := pairOfTwo(t, func(c *Config) { c.Tick = time.Hour })
	pc := &peerConn{node: nodes[0].id, p: b.p}
	old := nodes[0].spki()
	if err := b.p.bindLeaf(pc, old); err != nil {
		t.Fatalf("the key of the table: %v", err)
	}
	pt := mkTable(6, nodes, nil, [2]int{0, 1}, [2]int{2, 3})
	pt.Nodes[0].SpkiSha256 = make([]byte, 32)
	b.env.table.Store(pt)
	if err := b.p.bindLeaf(pc, old); err != errTrust {
		t.Fatalf("a key the table replaced: %v", err)
	}
	if _, has := pc.leaf(); !has {
		t.Fatal("the key was not recorded before it was judged, so recheck would skip the connection")
	}
}

// A bind that fails leaves the old listener open and is tried again no sooner than 5 s
// later, not on every tick.
func TestFailedBindKeepsTheOldListenerAndRetriesEvery5s(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int32
	var skew atomic.Int64 // seconds added to the part's clock
	p := newPKI(t)
	nodes := mkNodes(t, p, 2)
	r := startRig(t, p, newDir(), nodes[0], mkTable(5, nodes, nil, [2]int{0, 1}), func(c *Config) {
		orig := c.Listen
		c.Listen = func(ip netip.Addr, port int) (net.Listener, error) {
			if fail.Load() {
				calls.Add(1)
				return nil, errors.New("bind failed")
			}
			return orig(ip, port)
		}
		c.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load()) * time.Second) }
	})
	old := r.addr.Load()
	fail.Store(true)
	ip := netip.MustParseAddr("127.0.0.7")
	r.env.bind.Store(&ip)
	r.p.poke()
	time.Sleep(300 * time.Millisecond) // 15 ticks
	if n := calls.Load(); n != 1 {
		t.Fatalf("the bind was tried %d times in 300 ms", n)
	}
	c, err := net.DialTimeout("tcp", old.String(), time.Second)
	if err != nil {
		t.Fatalf("the old listener is gone after a failed bind: %v", err)
	}
	c.Close()
	if r.lis.Load() != 1 {
		t.Fatal("a listener was opened by a failed bind")
	}
	// 5 s later it is tried again, and then it works.
	skew.Store(6)
	fail.Store(false)
	for deadline := time.Now().Add(3 * time.Second); r.lis.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("the bind was not retried")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
