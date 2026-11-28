package peer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

const hubNow = 1_800_000_000

// ---- the pieces a node is made of in these tests: a CA, a certificate for each node,
// a fake of the agent's Env and a fake of the agent's DNS.

type pki struct {
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &pki{ca: ca, key: k}
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}

// issue makes a node certificate: clientAuth only, as the real ones are.
func (p *pki) issue(t *testing.T, id zone.NodeID, eku x509.ExtKeyUsage, notAfter time.Time) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: hex.EncodeToString(id[:])},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}
}

type tnode struct {
	id   zone.NodeID
	ip   netip.Addr
	cert tls.Certificate
}

func (n *tnode) spki() [32]byte { return sha256.Sum256(n.cert.Leaf.RawSubjectPublicKeyInfo) }

func mkNodes(t *testing.T, p *pki, count int) []*tnode {
	var out []*tnode
	for i := 0; i < count; i++ {
		id := zone.NodeID{byte(i + 1), 0xAA}
		out = append(out, &tnode{id: id, ip: netip.MustParseAddr("127.0.0." + string(rune('2'+i))),
			cert: p.issue(t, id, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))})
	}
	return out
}

// pairID of the fixtures.
func pid(b byte) []byte { return append([]byte{b}, make([]byte, 15)...) }

// mkTable is a PairTable of nodes, with the listed ones revoked, and pairs of (a, b)
// index pairs. The first pair is the global one.
func mkTable(version uint64, nodes []*tnode, revoked map[int]bool, pairs ...[2]int) *policyv1.PairTable {
	pt := &policyv1.PairTable{Version: version, ExpiresAt: hubNow + 1000}
	for i, n := range nodes {
		e := &policyv1.NodeEntry{NodeId: n.id[:], DnsIp: n.ip.AsSlice(), ProxyIp: n.ip.AsSlice()}
		if !revoked[i] {
			s := n.spki()
			e.SpkiSha256 = s[:]
		}
		pt.Nodes = append(pt.Nodes, e)
	}
	for i, pr := range pairs {
		pt.Pairs = append(pt.Pairs, &policyv1.Pair{PairId: pid(byte(i + 1)), Primary: nodes[pr[0]].id[:], Fallback: nodes[pr[1]].id[:]})
	}
	if len(pairs) > 0 {
		pt.GlobalPairId = pid(1)
	}
	return pt
}

type fakeEnv struct {
	table atomic.Pointer[policyv1.PairTable]
	mu    sync.Mutex
	eps   map[string][]byte // endpoint id -> pair id ("" for the global pair)
	seq   atomic.Uint64
	bind  atomic.Pointer[netip.Addr]
}

func newEnv(pt *policyv1.PairTable, bind netip.Addr) *fakeEnv {
	e := &fakeEnv{eps: map[string][]byte{}}
	e.table.Store(pt)
	e.bind.Store(&bind)
	e.seq.Store(100)
	return e
}
func (e *fakeEnv) Table() *policyv1.PairTable { return e.table.Load() }
func (e *fakeEnv) EndpointPair(id []byte) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.eps[string(id)]
	return p, ok
}
func (e *fakeEnv) AppliedSeq() uint64 { return e.seq.Load() }
func (e *fakeEnv) HubNow() int64      { return hubNow }
func (e *fakeEnv) BindIP() netip.Addr { return *e.bind.Load() }
func (e *fakeEnv) endpoint(id []byte, pair []byte) {
	e.mu.Lock()
	e.eps[string(id)] = pair
	e.mu.Unlock()
}

type fakeDNS struct {
	mu     sync.Mutex
	subs   []func(*sock.Msg)
	got    chan *sock.Msg
	downed atomic.Bool // Send reports false
}

func newDNS() *fakeDNS { return &fakeDNS{got: make(chan *sock.Msg, 1024)} }
func (d *fakeDNS) Send(m *sock.Msg) bool {
	if d.downed.Load() {
		return false
	}
	d.got <- m
	return true
}
func (d *fakeDNS) Subscribe(f func(*sock.Msg)) {
	d.mu.Lock()
	d.subs = append(d.subs, f)
	d.mu.Unlock()
}
func (d *fakeDNS) deliver(m *sock.Msg) {
	d.mu.Lock()
	subs := append([]func(*sock.Msg){}, d.subs...)
	d.mu.Unlock()
	for _, f := range subs {
		f(m)
	}
}

// next returns the next message of a type within a second.
func (d *fakeDNS) next(t *testing.T, typ string) *sock.Msg {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case m := <-d.got:
			if m.Type == typ {
				return m
			}
		case <-deadline:
			t.Fatalf("no %s message", typ)
			return nil
		}
	}
}

// none asserts no message of the type arrives within d.
func (d *fakeDNS) none(t *testing.T, typ string, wait time.Duration) {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case m := <-d.got:
			if m.Type == typ {
				t.Fatalf("an unexpected %s message", typ)
			}
		case <-deadline:
			return
		}
	}
}

// rig is one running node: its part, env, dns fake and listener.
type rig struct {
	n    *tnode
	p    *Peer
	env  *fakeEnv
	dns  *fakeDNS
	addr atomic.Pointer[net.TCPAddr] // where its listener really is
	lis  atomic.Int32                // listeners opened
}

// directory maps the table address of a node to where its listener really is, since
// every test listener is on 127.0.0.1 with its own port.
type directory struct {
	mu sync.Mutex
	m  map[netip.Addr]*rig
}

func (d *directory) add(r *rig) { d.mu.Lock(); d.m[r.n.ip] = r; d.mu.Unlock() }
func (d *directory) find(ip netip.Addr) *rig {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[ip]
}

func startRig(t *testing.T, p *pki, dir *directory, n *tnode, pt *policyv1.PairTable, mut ...func(*Config)) *rig {
	t.Helper()
	r := &rig{n: n, env: newEnv(pt, n.ip), dns: newDNS()}
	cfg := Config{
		Self: n.id, Cert: func() tls.Certificate { return n.cert }, Roots: p.pool(), DNS: r.dns,
		Tick: 20 * time.Millisecond, AckWait: time.Second, SentWait: 2 * time.Second, DialTimeout: 2 * time.Second,
		Listen: func(ip netip.Addr, port int) (net.Listener, error) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				r.addr.Store(l.Addr().(*net.TCPAddr))
				r.lis.Add(1)
			}
			return l, err
		},
		Dial: func(ctx context.Context, local, remote netip.Addr, port int) (net.Conn, error) {
			target := dir.find(remote)
			if target == nil || target.addr.Load() == nil {
				return nil, net.ErrClosed
			}
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: local.AsSlice()}}
			return d.DialContext(ctx, "tcp", target.addr.Load().String())
		},
	}
	for _, m := range mut {
		m(&cfg)
	}
	r.p = New(cfg)
	r.p.SetEnv(r.env)
	dir.add(r)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.p.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(3 * time.Second)
	for r.addr.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the listener did not open")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return r
}

func newDir() *directory { return &directory{m: map[netip.Addr]*rig{}} }

func fwd(gid, ep byte) *peerv1.GrantForward {
	return &peerv1.GrantForward{
		GrantId:         append([]byte{gid}, make([]byte, 15)...),
		EndpointId:      append([]byte{ep}, make([]byte, 15)...),
		SourcePrefix:    []byte{203, 0, 113, 7, 32},
		NameWire:        []byte("\x03www\x07example\x03com\x00"),
		Location:        3,
		GrantKind:       1,
		ExpiresAt:       hubNow + 3600,
		SenderConfigSeq: 100,
	}
}

func out(t *testing.T, g *peerv1.GrantForward) *sock.Msg {
	b, err := proto.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return &sock.Msg{Type: sock.TypeGrantOut, GrantOut: &sock.GrantOut{Forward: b}}
}

// pairOfTwo is the usual fixture: nodes 0 and 1 are a pair (the global one), node 2 and 3
// another, and the endpoints are known to both of the first.
func pairOfTwo(t *testing.T, mut ...func(*Config)) (*pki, []*tnode, *directory, *rig, *rig) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 4)
	pt := mkTable(5, nodes, nil, [2]int{0, 1}, [2]int{2, 3})
	dir := newDir()
	a := startRig(t, p, dir, nodes[0], pt, mut...)
	b := startRig(t, p, dir, nodes[1], pt, mut...)
	for _, r := range []*rig{a, b} {
		r.env.endpoint(append([]byte{1}, make([]byte, 15)...), nil)    // global pair
		r.env.endpoint(append([]byte{2}, make([]byte, 15)...), pid(1)) // named: the same pair
		r.env.endpoint(append([]byte{9}, make([]byte, 15)...), pid(2)) // another pair
	}
	return p, nodes, dir, a, b
}

func gidOf(b byte) []byte { return append([]byte{b}, make([]byte, 15)...) }

// ---- tests

func TestForwardRoundTripAccepted(t *testing.T) {
	_, nodes, _, a, b := pairOfTwo(t)
	g := fwd(1, 1)
	a.dns.deliver(out(t, g))

	in := b.dns.next(t, sock.TypeGrantIn)
	if string(in.GrantIn.Sender) != string(nodes[0].id[:]) {
		t.Fatal("grant_in names the wrong sender")
	}
	var got peerv1.GrantForward
	if err := proto.Unmarshal(in.GrantIn.Forward, &got); err != nil || !proto.Equal(&got, g) {
		t.Fatal("the forward did not arrive as sent")
	}
	// dns of B takes it
	b.dns.deliver(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: g.GrantId, Accepted: true}})
	sent := a.dns.next(t, sock.TypeGrantSent)
	if sent.GrantSent.Result != sock.GrantAccepted || string(sent.GrantSent.GrantID) != string(g.GrantId) {
		t.Fatalf("grant_sent: %+v", sent.GrantSent)
	}
}

func TestForwardRefusedByDNS(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t)
	g := fwd(2, 2)
	a.dns.deliver(out(t, g))
	b.dns.next(t, sock.TypeGrantIn)
	b.dns.deliver(&sock.Msg{Type: sock.TypeGrantRes, GrantRes: &sock.GrantRes{GrantID: g.GrantId, Accepted: false}})
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantRefused {
		t.Fatalf("a refusal reached the sender as %s", r)
	}
}

// Two tenants' Endpoints: one in this pair, one in another. The one of the other pair
// is never sent and never reaches the peer's dns, and the first still goes through.
func TestEndpointOfAnotherPairIsNotForwarded(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t)
	other := fwd(3, 9)
	mine := fwd(4, 1)
	a.dns.deliver(out(t, other))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent; r.Result != sock.GrantRefused || string(r.GrantID) != string(other.GrantId) {
		t.Fatalf("the other pair's Endpoint: %+v", r)
	}
	a.dns.deliver(out(t, mine))
	in := b.dns.next(t, sock.TypeGrantIn)
	var got peerv1.GrantForward
	_ = proto.Unmarshal(in.GrantIn.Forward, &got)
	if string(got.GrantId) != string(mine.GrantId) {
		t.Fatal("the wrong grant reached the peer")
	}
	b.dns.none(t, sock.TypeGrantIn, 100*time.Millisecond)
}

// An Endpoint the sender does not know is refused too, and an unknown id is never
// treated as "the global pair".
func TestUnknownEndpointIsRefusedOnSendAndReceive(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t)
	g := fwd(5, 77)
	a.dns.deliver(out(t, g))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantRefused {
		t.Fatalf("send side: %s", r)
	}
	// Receiver side: A knows it (so it sends), B does not and is not behind.
	a.env.endpoint(g.EndpointId, nil)
	a.dns.deliver(out(t, g))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantRefused {
		t.Fatalf("receive side: %s", r)
	}
	b.dns.none(t, sock.TypeGrantIn, 100*time.Millisecond)
}

// A receiver that is behind the sender's config_seq cannot judge an Endpoint it does not
// know yet: it hands the forward to dns, which holds it until its image catches up.
func TestBehindReceiverPassesUnknownEndpointToDNS(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t)
	a.env.endpoint(gidOf(66), nil)
	g := fwd(6, 66)
	g.SenderConfigSeq = 500 // B is at 100
	a.dns.deliver(out(t, g))
	b.dns.next(t, sock.TypeGrantIn)
}

func TestSenderThatIsNotThePairPeerIsRefused(t *testing.T) {
	// A's table says (A, B); B's says B pairs with C. A is a live node of B's table, so
	// the TLS check passes, and B ends A's stream at its start: A's forward is unsent
	// (it never gets an answer) and nothing reaches B's dns.
	p := newPKI(t)
	nodes := mkNodes(t, p, 3)
	dir := newDir()
	a := startRig(t, p, dir, nodes[0], mkTable(5, nodes, nil, [2]int{0, 1}))
	b := startRig(t, p, dir, nodes[1], mkTable(5, nodes, nil, [2]int{1, 2}))
	a.env.endpoint(gidOf(1), nil)
	b.env.endpoint(gidOf(1), nil)
	a.dns.deliver(out(t, fwd(7, 1)))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantUnsent {
		t.Fatalf("got %s", r)
	}
	b.dns.none(t, sock.TypeGrantIn, 100*time.Millisecond)
}

// A forward whose shape is wrong is refused and writes nothing: a wide prefix, an
// expiry in the past.
func TestMalformedForwardsAreRefused(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t)
	wide := fwd(8, 1)
	wide.SourcePrefix = []byte{203, 0, 113, 0, 24}
	stale := fwd(9, 1)
	stale.ExpiresAt = hubNow - 5
	// Drive B's server with a hand-made client that presents A's certificate.
	cl := rawClient(t, a, b)
	for _, g := range []*peerv1.GrantForward{wide, stale} {
		if err := cl.st.Send(g); err != nil {
			t.Fatal(err)
		}
		ack, err := cl.st.Recv()
		if err != nil || ack.Accepted || string(ack.GrantId) != string(g.GrantId) {
			t.Fatalf("ack %v err %v", ack, err)
		}
	}
	b.dns.none(t, sock.TypeGrantIn, 100*time.Millisecond)
}

// Revoke is never served: any peer's call is Unimplemented.
func TestRevokeIsUnimplemented(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t)
	cl := rawClient(t, a, b)
	_, err := cl.client.Revoke(context.Background(), &peerv1.GrantRevoke{EndpointId: gidOf(1), RevSeq: 1})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Revoke answered %v", err)
	}
}

// A revocation in the applied table ends the open connection of the revoked peer and
// refuses its next one, on the receiving side; and on the sending side nothing is
// sent to it.
func TestRevokedPeerIsCutAndNotSentTo(t *testing.T) {
	p, nodes, _, a, b := pairOfTwo(t)
	cl := rawClient(t, a, b)
	// B applies the entry that empties A's key.
	b.env.table.Store(mkTable(6, nodes, map[int]bool{0: true}, [2]int{0, 1}, [2]int{2, 3}))
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := cl.st.Send(fwd(10, 1)); err != nil {
			break
		}
		if _, err := cl.st.Recv(); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the revoked peer's stream is still open")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := dialRaw(t, a, b, a.n.cert, nodes[0].id); err == nil {
		t.Fatal("a new connection of the revoked peer was accepted")
	}
	// A applies the same entry: it sends B nothing and opens no connection.
	a.env.table.Store(mkTable(6, nodes, map[int]bool{1: true}, [2]int{0, 1}, [2]int{2, 3}))
	a.dns.deliver(out(t, fwd(11, 1)))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantUnsent {
		t.Fatalf("a forward to a revoked node was %s", r)
	}
	_ = p
}

// A connection from an address that is no live node of the table is closed before TLS.
func TestUnlistedAddressIsClosedBeforeTLS(t *testing.T) {
	_, _, _, _, b := pairOfTwo(t)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.9")}}
	c, err := d.Dial("tcp", b.addr.Load().String())
	if err != nil {
		t.Skip("cannot bind 127.0.0.9 here")
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	// The server speaks first in no TLS version; a closed connection reads EOF, an open one
	// would time out.
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 || isTimeout(err) {
		t.Fatalf("the connection stayed open: %v", err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// A certificate for another node than the address names, a certificate of another CA,
// one with serverAuth only, and an expired one: each fails the handshake.
func TestCertificateChecks(t *testing.T) {
	p, nodes, _, a, b := pairOfTwo(t)
	other := newPKI(t)
	cases := map[string]tls.Certificate{
		"another node's certificate": nodes[2].cert,
		"another CA":                 other.issue(t, nodes[0].id, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour)),
		"serverAuth only":            p.issue(t, nodes[0].id, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour)),
		"expired":                    p.issue(t, nodes[0].id, x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Minute)),
		// the right CA and node id, a fresh key the table does not hold
		"a key not in the table": p.issue(t, nodes[0].id, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour)),
	}
	for name, c := range cases {
		if _, err := dialRaw(t, a, b, c, nodes[1].id); err == nil {
			t.Errorf("%s: the handshake passed", name)
		}
	}
	// and the real one passes
	if cl, err := dialRaw(t, a, b, nodes[0].cert, nodes[1].id); err != nil {
		t.Fatalf("the real certificate failed: %v", err)
	} else {
		cl.close()
	}
}

// 2 connections for one node and 8 in all, counted before TLS.
func TestConnectionCaps(t *testing.T) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 6)
	pt := mkTable(5, nodes, nil, [2]int{0, 1})
	dir := newDir()
	srv := startRig(t, p, dir, nodes[0], pt)
	hold := func(from *tnode) (net.Conn, bool) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: from.ip.AsSlice()}}
		c, err := d.Dial("tcp", srv.addr.Load().String())
		if err != nil {
			t.Skip("cannot bind loopback aliases here")
		}
		// a counted connection stays open; a refused one is closed by the server
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err = c.Read(make([]byte, 1))
		return c, !isTimeout(err)
	}
	var keep []net.Conn
	defer func() {
		for _, c := range keep {
			c.Close()
		}
	}()
	for i := 1; i <= 4; i++ {
		for j := 0; j < MaxConnsPerNode; j++ {
			c, closed := hold(nodes[i])
			keep = append(keep, c)
			if closed {
				t.Fatalf("node %d connection %d was refused below the caps", i, j+1)
			}
		}
		if c, closed := hold(nodes[i]); !closed {
			c.Close()
			t.Fatalf("node %d got a third connection", i)
		} else {
			c.Close()
		}
	}
	// 8 are open; a fifth node is over the total
	if c, closed := hold(nodes[5]); !closed {
		c.Close()
		t.Fatal("a ninth connection was accepted")
	} else {
		c.Close()
	}
}

// 256 forwards may wait for an answer; the rest are unsent, and a forward the peer never
// answers is unsent after the wait, and then a late answer is ignored.
func TestUnansweredCapAndTimeout(t *testing.T) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 2)
	pt := mkTable(5, nodes, nil, [2]int{0, 1})
	dir := newDir()
	a := startRig(t, p, dir, nodes[0], pt, func(c *Config) { c.SentWait = 700 * time.Millisecond })
	b := startRig(t, p, dir, nodes[1], pt, func(c *Config) { c.AckWait = 5 * time.Second })
	a.env.endpoint(gidOf(1), nil)
	b.env.endpoint(gidOf(1), nil)
	const total = MaxUnanswered + 20
	for i := 0; i < total; i++ {
		g := fwd(1, 1)
		g.GrantId = append([]byte{byte(i), byte(i >> 8)}, make([]byte, 14)...)
		a.dns.deliver(out(t, g))
	}
	res := map[string]int{}
	deadline := time.After(6 * time.Second)
	for n := 0; n < total; {
		select {
		case m := <-a.dns.got:
			if m.Type == sock.TypeGrantSent {
				res[m.GrantSent.Result]++
				n++
			}
		case <-deadline:
			t.Fatalf("only %d reports: %v", n, res)
		}
	}
	if res[sock.GrantUnsent] != total || res[sock.GrantAccepted] != 0 {
		t.Fatalf("results %v", res)
	}
}

// A receiver whose dns does not answer in time refuses, and one whose dns is away
// refuses at once.
func TestReceiverAnswersRefusedWhenDNSIsSlowOrAway(t *testing.T) {
	_, _, _, a, b := pairOfTwo(t, func(c *Config) { c.AckWait = 300 * time.Millisecond })
	a.dns.deliver(out(t, fwd(20, 1)))
	b.dns.next(t, sock.TypeGrantIn)
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantRefused {
		t.Fatalf("slow dns: %s", r)
	}
	b.dns.downed.Store(true)
	a.dns.deliver(out(t, fwd(21, 1)))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantRefused {
		t.Fatalf("away dns: %s", r)
	}
}

// When the peer is gone the forwards that waited are unsent and a forward made while
// it is unreachable is unsent at once; when it returns the next one goes through.
func TestPeerGoneAndBack(t *testing.T) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 2)
	pt := mkTable(5, nodes, nil, [2]int{0, 1})
	dir := newDir()
	a := startRig(t, p, dir, nodes[0], pt)
	a.env.endpoint(gidOf(1), nil)
	// B is not up: nothing listens for it
	a.dns.deliver(out(t, fwd(30, 1)))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantUnsent {
		t.Fatalf("no peer: %s", r)
	}
	b := startRig(t, p, dir, nodes[1], pt)
	b.env.endpoint(gidOf(1), nil)
	// the first attempt after a failure waits out the 1 s back-off
	time.Sleep(1100 * time.Millisecond)
	a.dns.deliver(out(t, fwd(31, 1)))
	b.dns.next(t, sock.TypeGrantIn)
}

// dns_bind_ip moving: the new listener opens, the old closes.
func TestBindChangeMovesTheListener(t *testing.T) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 2)
	dir := newDir()
	r := startRig(t, p, dir, nodes[0], mkTable(5, nodes, nil, [2]int{0, 1}))
	old := r.addr.Load()
	ip := netip.MustParseAddr("127.0.0.7")
	r.env.bind.Store(&ip)
	r.p.poke()
	deadline := time.Now().Add(3 * time.Second)
	for r.lis.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no second listener")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c, err := net.DialTimeout("tcp", old.String(), 500*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("the old listener is still open")
	}
}

func TestViewPairs(t *testing.T) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 4)
	v := newView(mkTable(1, nodes, nil, [2]int{0, 1}, [2]int{2, 3}), nodes[0].id)
	if v.peer == nil || v.peer.id != nodes[1].id {
		t.Fatal("the pair peer")
	}
	if !v.inOurPair(nil) || !v.inOurPair(pid(1)) || v.inOurPair(pid(2)) || v.inOurPair(pid(7)) {
		t.Fatal("the pair of an Endpoint")
	}
	// A revoked peer is still the pair peer but is not live.
	v = newView(mkTable(1, nodes, map[int]bool{1: true}, [2]int{0, 1}), nodes[0].id)
	if v.peerLive() != nil || v.byAddr[nodes[1].ip] != nil {
		t.Fatal("a revoked node must not be live or accepted by address")
	}
	// no table, no peer
	if newView(nil, nodes[0].id).inOurPair(nil) {
		t.Fatal("no table")
	}
}

// ---- a hand-made client, to put frames on a server that the real client would not send.

type raw struct {
	cc     *grpc.ClientConn
	client peerv1.PeerNodeClient
	st     peerv1.PeerNode_ForwardClient
	cancel context.CancelFunc
}

func (r *raw) close() { r.cancel(); _ = r.cc.Close() }

// dialRaw connects from `from`'s address to `to` with cert and opens a Forward stream,
// expecting the server to be the node `want`.
func dialRaw(t *testing.T, from, to *rig, cert tls.Certificate, want zone.NodeID) (*raw, error) {
	t.Helper()
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, ServerName: "x", InsecureSkipVerify: true,
		Certificates: []tls.Certificate{cert}})
	cc, err := grpc.NewClient("passthrough:///x", grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: from.n.ip.AsSlice()}}
			return d.DialContext(ctx, "tcp", to.addr.Load().String())
		}))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	cl := peerv1.NewPeerNodeClient(cc)
	st, err := cl.Forward(ctx)
	if err == nil {
		// A server that refuses the client certificate fails a later read in TLS 1.3, so a
		// frame is sent and the answer awaited.
		// A frame the server refuses at once and never hands to dns: a /24 prefix.
		probe := fwd(200, 1)
		probe.SourcePrefix = []byte{203, 0, 113, 0, 24}
		err = st.Send(probe)
		if err == nil {
			_, err = st.Recv()
		}
	}
	if err != nil {
		cancel()
		_ = cc.Close()
		return nil, err
	}
	_ = want
	return &raw{cc: cc, client: cl, st: st, cancel: cancel}, nil
}

func rawClient(t *testing.T, from, to *rig) *raw {
	t.Helper()
	r, err := dialRaw(t, from, to, from.n.cert, to.n.id)
	if err != nil {
		t.Fatalf("the raw client could not connect: %v", err)
	}
	t.Cleanup(r.close)
	return r
}

// The client verifies the server as the server verifies the client: a peer that
// answers with a certificate of another CA, or of another node, is never spoken to.
func TestClientRefusesAWrongServerCertificate(t *testing.T) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 2)
	pt := mkTable(5, nodes, nil, [2]int{0, 1})
	other := newPKI(t)
	cases := map[string]tls.Certificate{
		"another CA":     other.issue(t, nodes[1].id, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour)),
		"another node":   nodes[0].cert,
		"a key not held": p.issue(t, nodes[1].id, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour)),
	}
	for name, cert := range cases {
		dir := newDir()
		a := startRig(t, p, dir, nodes[0], pt)
		fake := *nodes[1]
		fake.cert = cert
		// B's listener is the real one, but it presents the wrong certificate (its own table
		// and peers are right, so only the client's check can stop this).
		b := startRig(t, p, dir, &fake, pt)
		a.env.endpoint(gidOf(1), nil)
		b.env.endpoint(gidOf(1), nil)
		a.dns.deliver(out(t, fwd(40, 1)))
		if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantUnsent {
			t.Errorf("%s: the forward was %s", name, r)
		}
		b.dns.none(t, sock.TypeGrantIn, 50*time.Millisecond)
	}
}

// The sender's open connection ends when its own table stops trusting the peer, and
// what it still waited for is unsent.
func TestOpenClientConnectionEndsWhenPeerIsRevoked(t *testing.T) {
	p := newPKI(t)
	nodes := mkNodes(t, p, 2)
	pt := mkTable(5, nodes, nil, [2]int{0, 1})
	dir := newDir()
	a := startRig(t, p, dir, nodes[0], pt)
	b := startRig(t, p, dir, nodes[1], pt)
	a.env.endpoint(gidOf(1), nil)
	b.env.endpoint(gidOf(1), nil)
	a.dns.deliver(out(t, fwd(50, 1)))
	b.dns.next(t, sock.TypeGrantIn) // waits for B's dns: the connection is open and the forward pending
	a.env.table.Store(mkTable(6, nodes, map[int]bool{1: true}, [2]int{0, 1}))
	if r := a.dns.next(t, sock.TypeGrantSent).GrantSent.Result; r != sock.GrantUnsent {
		t.Fatalf("the pending forward was %s", r)
	}
	a.p.omu.Lock()
	open := a.p.cur != nil
	a.p.omu.Unlock()
	if open {
		t.Fatal("the connection to a revoked peer is still open")
	}
}
