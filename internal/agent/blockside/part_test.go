package blockside

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/zonekeys"
)

var epoch1 = []byte("EPOCH001")

func id16(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

// issue is the hub's side: one account's root and a fresh intermediate sealed to
// the node's key, with the constraints of 10.3. A mutator changes the template to
// make a bundle the node must refuse.
type issuer struct {
	root *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newIssuer(t *testing.T, name string) *issuer {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tm := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ctrl Z Block Page " + name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(1000 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tm, tm, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &issuer{root: c, key: k}
}

func (is *issuer) bundle(t *testing.T, node *ecdsa.PrivateKey, account, ep []byte, mut func(*x509.Certificate)) *hubv1.CertBundle {
	t.Helper()
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tm := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: true, ExcludedDNSDomains: []string{"ctrl-z.org", "panel.example"},
		ExcludedIPRanges: []*net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}}}
	if mut != nil {
		mut(tm)
	}
	der, err := x509.CreateCertificate(rand.Reader, tm, is.root, &ik.PublicKey, is.key)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(ik)
	wrapped, err := zonekeys.Seal(&node.PublicKey, p8)
	if err != nil {
		t.Fatal(err)
	}
	pemb := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: is.root.Raw})...)
	return &hubv1.CertBundle{Kind: signv1.Kind_KIND_CERTS, WrappedKey: wrapped, ChainPem: pemb, NotAfter: tm.NotAfter.Unix(),
		Use: hubv1.CertUse_CERT_USE_BLOCK_INTERMEDIATE, AccountHash: account, BlockRootEpoch: ep}
}

type fakeFaults struct {
	mu sync.Mutex
	on map[hubv1.NodeFault]bool
}

func (f *fakeFaults) Set(k hubv1.NodeFault, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.on == nil {
		f.on = map[hubv1.NodeFault]bool{}
	}
	f.on[k] = on
}
func (f *fakeFaults) has(k hubv1.NodeFault) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.on[k] }

type rig struct {
	t       *testing.T
	p       *Part
	node    *ecdsa.PrivateKey
	faults  *fakeFaults
	now     time.Time
	nowMu   sync.Mutex
	mu      sync.Mutex
	sent    []*hubv1.NodeMessage
	up      bool
	blobs   map[[32]byte][]byte
	block   *sockfake.Endpoint[sock.BlockMsg]
	ended   chan struct{}
	cancel  context.CancelFunc
	connect bool
}

func newRig(t *testing.T) *rig {
	t.Helper()
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &rig{t: t, node: nk, faults: &fakeFaults{}, now: time.Now(), up: true, blobs: map[[32]byte][]byte{}}
	r.p = New(Config{Faults: r.faults, Now: func() time.Time { r.nowMu.Lock(); defer r.nowMu.Unlock(); return r.now }})
	r.p.Attach(Host{
		Unseal: func(w []byte) ([]byte, error) { return zonekeys.Unseal(nk, w) },
		PageBlob: func(h [32]byte) []byte {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.blobs[h]
		},
		Outside:   func(m *hubv1.NodeMessage) bool { r.mu.Lock(); r.sent = append(r.sent, m); r.mu.Unlock(); return true },
		ControlUp: func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.up },
		HubNow:    func() int64 { return time.Now().Unix() },
	})
	r.p.Config(&hubv1.NodeConfig{BlockRootEpoch: epoch1, Zones: []string{"ctrl-z.org"}, PanelHostnames: []string{"panel.example"}})
	return r
}

// connect starts a session: the part is the agent end, the test the block end.
func (r *rig) connectBlock() {
	block, agent := sockfake.BlockPair()
	r.block = block
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.ended = make(chan struct{})
	go func() { r.p.Serve(ctx, agent.Conn); close(r.ended) }()
	r.t.Cleanup(func() { cancel(); block.Close() })
}

func (r *rig) advance(d time.Duration) { r.nowMu.Lock(); r.now = r.now.Add(d); r.nowMu.Unlock() }

func (r *rig) sentMsgs() []*hubv1.NodeMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*hubv1.NodeMessage(nil), r.sent...)
}

func (r *rig) recv() *sock.BlockMsg {
	r.t.Helper()
	m, err := r.block.Recv()
	if err != nil {
		r.t.Fatalf("recv: %v", err)
	}
	return m
}

func (r *rig) needKey(endpoint, account []byte) {
	r.t.Helper()
	if err := r.block.Send(&sock.BlockMsg{Type: sock.BlockNeedKey, NeedKey: &sock.NeedKey{Endpoint: endpoint, Account: account}}); err != nil {
		r.t.Fatal(err)
	}
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestEpochComesFirstAndFollowsTheConfig(t *testing.T) {
	r := newRig(t)
	r.connectBlock()
	if m := r.recv(); m.Type != sock.BlockEpoch || string(m.Epoch.Epoch) != string(epoch1) {
		t.Fatalf("first frame %+v", m)
	}
	r.p.Config(&hubv1.NodeConfig{BlockRootEpoch: []byte("EPOCH002")})
	if m := r.recv(); m.Type != sock.BlockEpoch || string(m.Epoch.Epoch) != "EPOCH002" {
		t.Fatalf("after the change: %+v", m)
	}
	// The same config again changes nothing (Config is idempotent).
	r.p.Config(&hubv1.NodeConfig{BlockRootEpoch: []byte("EPOCH002")})
	_ = r.block.Send(&sock.BlockMsg{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: make([]byte, 32)}})
	if m := r.recv(); m.Type != sock.BlockPage {
		t.Fatalf("a repeated config sent %+v", m)
	}
}

func TestNeedPageAnswersFromTheStoredBlobOnly(t *testing.T) {
	r := newRig(t)
	h := [32]byte{7}
	r.blobs[h] = []byte("a stored page")
	r.connectBlock()
	r.recv() // epoch
	_ = r.block.Send(&sock.BlockMsg{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: h[:]}})
	if m := r.recv(); m.Type != sock.BlockPage || string(m.Page.Blob) != "a stored page" || !bytes.Equal(m.Page.Hash, h[:]) {
		t.Fatalf("%+v", m)
	}
	other := bytes.Repeat([]byte{8}, 32)
	_ = r.block.Send(&sock.BlockMsg{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: other}})
	if m := r.recv(); m.Type != sock.BlockPage || len(m.Page.Blob) != 0 {
		t.Fatalf("a hash with no page got %+v", m)
	}
	// A page over what a frame carries is answered as no page: ours is served.
	r.mu.Lock()
	r.blobs[[32]byte{9}] = bytes.Repeat([]byte{1}, sock.MaxPageBlob+1)
	r.mu.Unlock()
	_ = r.block.Send(&sock.BlockMsg{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: bytes.Repeat([]byte{9}, 32)}})
	if m := r.recv(); m.Type != sock.BlockPage || len(m.Page.Blob) != 0 {
		t.Fatalf("an oversize blob got %d bytes", len(m.Page.Blob))
	}
}

func TestKeyAskRateAndAnswerFromMemory(t *testing.T) {
	r := newRig(t)
	r.connectBlock()
	r.recv() // epoch
	is := newIssuer(t, "A")
	r.needKey(id16(1), id16(2))
	eventually(t, func() bool { return len(r.sentMsgs()) == 1 })
	m := r.sentMsgs()[0].GetBlockKeyRequest()
	if m == nil || !bytes.Equal(m.EndpointId, id16(1)) {
		t.Fatalf("the request: %+v", r.sentMsgs()[0])
	}
	// A second ask inside the minute is not sent again.
	r.needKey(id16(1), id16(2))
	time.Sleep(100 * time.Millisecond)
	if n := len(r.sentMsgs()); n != 1 {
		t.Fatalf("%d requests inside a minute", n)
	}
	r.advance(61 * time.Second)
	r.needKey(id16(1), id16(2))
	eventually(t, func() bool { return len(r.sentMsgs()) == 2 })

	// The hub's answer is held and pushed at once.
	if err := r.p.Bundle(is.bundle(t, r.node, id16(2), epoch1, nil)); err != nil {
		t.Fatal(err)
	}
	if m := r.recv(); m.Type != sock.BlockIntermediate || !bytes.Equal(m.Intermediate.Account, id16(2)) {
		t.Fatalf("%+v", m)
	}
	// Later asks are answered from memory with no hub traffic.
	r.needKey(id16(1), id16(2))
	if m := r.recv(); m.Type != sock.BlockIntermediate {
		t.Fatalf("%+v", m)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(r.sentMsgs()); n != 2 {
		t.Fatalf("%d requests after the key arrived", n)
	}
}

func TestAKeyReachesTheBlockProcessThatRestarted(t *testing.T) {
	r := newRig(t)
	if err := r.p.Bundle(newIssuer(t, "A").bundle(t, r.node, id16(2), epoch1, nil)); err != nil {
		t.Fatal(err)
	}
	r.connectBlock()
	if m := r.recv(); m.Type != sock.BlockEpoch {
		t.Fatalf("%+v", m)
	}
	if m := r.recv(); m.Type != sock.BlockIntermediate {
		t.Fatalf("%+v", m)
	}
}

func TestTwoAccountsKeepTheirOwnKeys(t *testing.T) {
	r := newRig(t)
	a, b := newIssuer(t, "A"), newIssuer(t, "B")
	if err := r.p.Bundle(a.bundle(t, r.node, id16(2), epoch1, nil)); err != nil {
		t.Fatal(err)
	}
	if err := r.p.Bundle(b.bundle(t, r.node, id16(3), epoch1, nil)); err != nil {
		t.Fatal(err)
	}
	r.connectBlock()
	r.recv()
	r.recv()
	r.recv() // epoch and both keys
	// B's Endpoint with A's account: the answer is A's key, filed under A, and the
	// hub is not asked in B's name.
	r.needKey(id16(7), id16(2))
	m := r.recv()
	if !bytes.Equal(m.Intermediate.Account, id16(2)) {
		t.Fatal("the key came back under another account")
	}
	c, _ := x509.ParseCertificate(m.Intermediate.Chain[0])
	if c.CheckSignatureFrom(a.root) != nil || c.CheckSignatureFrom(b.root) == nil {
		t.Fatal("account A's key is not signed by A's root alone")
	}
	if len(r.sentMsgs()) != 0 {
		t.Fatal("the hub was asked although the key was held")
	}
}

func TestBundlesTheNodeRefuses(t *testing.T) {
	is := newIssuer(t, "A")
	tests := []struct {
		name string
		mut  func(*x509.Certificate)
		ep   []byte
		want error // nil: any other error
	}{
		{"another epoch", nil, []byte("EPOCH999"), ErrOtherEpoch},
		{"path length 1", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 1, false }, epoch1, nil},
		{"not critical", func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }, epoch1, nil},
		{"zone not excluded", func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"panel.example"} }, epoch1, nil},
		{"panel host not excluded", func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"ctrl-z.org"} }, epoch1, nil},
		{"IPv6 left open", func(c *x509.Certificate) { c.ExcludedIPRanges = c.ExcludedIPRanges[:1] }, epoch1, nil},
		{"two usages", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}, epoch1, nil},
		{"lives 30 days", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(30 * 24 * time.Hour) }, epoch1, nil},
		{"expired", func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
		}, epoch1, nil},
		{"not a CA", func(c *x509.Certificate) { c.IsCA, c.MaxPathLen, c.MaxPathLenZero = false, 0, false }, epoch1, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			err := r.p.Bundle(is.bundle(t, r.node, id16(2), tc.ep, tc.mut))
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
			if tc.want == nil && errors.Is(err, ErrOtherEpoch) {
				t.Fatalf("refused as another epoch: %v", err)
			}
			if len(r.p.keys) != 0 {
				t.Fatal("a refused bundle was held")
			}
		})
	}
	t.Run("sealed to another node", func(t *testing.T) {
		r := newRig(t)
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err := r.p.Bundle(is.bundle(t, other, id16(2), epoch1, nil)); err == nil {
			t.Fatal("a bundle sealed to another key opened")
		}
	})
	t.Run("a zone bundle", func(t *testing.T) {
		r := newRig(t)
		cb := is.bundle(t, r.node, id16(2), epoch1, nil)
		cb.Use, cb.AccountHash, cb.BlockRootEpoch = hubv1.CertUse_CERT_USE_UNSPECIFIED, nil, nil
		if err := r.p.Bundle(cb); err == nil {
			t.Fatal("a zone bundle was taken as an intermediate")
		}
	})
}

func TestEpochChangeDropsHeldKeys(t *testing.T) {
	r := newRig(t)
	if err := r.p.Bundle(newIssuer(t, "A").bundle(t, r.node, id16(2), epoch1, nil)); err != nil {
		t.Fatal(err)
	}
	r.p.Config(&hubv1.NodeConfig{BlockRootEpoch: []byte("EPOCH002"), Zones: []string{"ctrl-z.org"}, PanelHostnames: []string{"panel.example"}})
	if len(r.p.keys) != 0 {
		t.Fatal("a key of the old epoch was kept")
	}
	// A late bundle of the old epoch is dropped, and the key asked for again.
	if err := r.p.Bundle(newIssuer(t, "A").bundle(t, r.node, id16(2), epoch1, nil)); !errors.Is(err, ErrOtherEpoch) {
		t.Fatalf("got %v", err)
	}
}

func TestBlockKeyMissingFault(t *testing.T) {
	r := newRig(t)
	r.connectBlock()
	r.recv()
	r.needKey(id16(1), id16(2))
	eventually(t, func() bool { return len(r.sentMsgs()) == 1 })
	r.p.check()
	if r.faults.has(hubv1.NodeFault_NODE_FAULT_BLOCK_KEY_MISSING) {
		t.Fatal("the fault is set at once")
	}
	r.advance(11 * time.Minute)
	r.p.check()
	if !r.faults.has(hubv1.NodeFault_NODE_FAULT_BLOCK_KEY_MISSING) {
		t.Fatal("no fault after ten minutes with Control up")
	}
	// The key arrives: the fault ends.
	if err := r.p.Bundle(newIssuer(t, "A").bundle(t, r.node, id16(2), epoch1, nil)); err != nil {
		t.Fatal(err)
	}
	r.p.check()
	if r.faults.has(hubv1.NodeFault_NODE_FAULT_BLOCK_KEY_MISSING) {
		t.Fatal("the fault stays after the key arrived")
	}
}

func TestTimeWithControlDownDoesNotCount(t *testing.T) {
	r := newRig(t)
	r.connectBlock()
	r.recv()
	r.mu.Lock()
	r.up = false
	r.mu.Unlock()
	r.needKey(id16(1), id16(2))
	eventually(t, func() bool { return len(r.sentMsgs()) == 1 })
	r.advance(30 * time.Minute)
	r.p.check()
	if r.faults.has(hubv1.NodeFault_NODE_FAULT_BLOCK_KEY_MISSING) {
		t.Fatal("a node cut off from the hub was blamed")
	}
	r.mu.Lock()
	r.up = true
	r.mu.Unlock()
	r.p.check()
	r.advance(5 * time.Minute)
	r.p.check()
	if r.faults.has(hubv1.NodeFault_NODE_FAULT_BLOCK_KEY_MISSING) {
		t.Fatal("the clock did not start when Control came back")
	}
	r.advance(6 * time.Minute)
	r.p.check()
	if !r.faults.has(hubv1.NodeFault_NODE_FAULT_BLOCK_KEY_MISSING) {
		t.Fatal("no fault ten minutes after Control came back")
	}
}

func TestUnblockIsRelayedAsARequest(t *testing.T) {
	r := newRig(t)
	r.connectBlock()
	r.recv()
	_ = r.block.Send(&sock.BlockMsg{Type: sock.BlockUnblock, Unblock: &sock.UnblockMsg{
		Endpoint: id16(1), Profile: id16(9), Name: "Bank.Example", Message: "please", At: 5}})
	eventually(t, func() bool { return len(r.sentMsgs()) == 1 })
	u := r.sentMsgs()[0].GetBlockUnblockRequest()
	if u == nil || !bytes.Equal(u.EndpointId, id16(1)) || !bytes.Equal(u.ProfileId, id16(9)) || u.Message != "please" {
		t.Fatalf("%+v", u)
	}
	if want := "\x04bank\x07example\x00"; string(u.QnameWire) != want {
		t.Errorf("wire name %q", u.QnameWire)
	}
	if u.At < time.Now().Unix()-5 {
		t.Error("the time is the visitor's, not the node's")
	}
}

func TestAFrameOnlyTheAgentMaySendEndsTheSession(t *testing.T) {
	r := newRig(t)
	r.connectBlock()
	r.recv()
	_ = r.block.Send(&sock.BlockMsg{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: epoch1}})
	select {
	case <-r.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the session went on")
	}
}

func TestNoHostDropsEverything(t *testing.T) {
	p := New(Config{})
	p.Config(&hubv1.NodeConfig{BlockRootEpoch: epoch1})
	if err := p.Bundle(&hubv1.CertBundle{}); err == nil {
		t.Fatal("a bundle was taken with no host")
	}
	p.needKey(id16(1), id16(2))
	p.needPage(make([]byte, 32))
	p.check()
}
