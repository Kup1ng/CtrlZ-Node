package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// skipWindows: Apply swaps the serving image with a symlink rename, which is
// Linux. The agent's integration tests run in the Linux container.
func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the image swap is a symlink rename, which is Linux")
	}
}

// lab is one node against a fake hub, with a dns process on the agent socket.
type lab struct {
	t      *testing.T
	dir    string
	hub    *fakehub.Hub
	keys   *storetest.Keys
	chain  storetest.Chain
	runner *fake.Runner
	files  *fake.Files
	alerts *alert.Memory
	cfg    agent.Config
	ag     *agent.Agent
	cancel context.CancelFunc
	done   chan struct{}

	// clock offset in seconds, so a test can move the node's time forward.
	skew atomic.Int64

	// units says which systemd units are up: none until the agent starts them.
	units fake.Units

	dnsMu   sync.Mutex
	dnsMsgs []*sock.Msg
	dnsUp   *atomic.Bool // one flag per attached client: a stale client's late State(false) must not clear the new one's
	dnsCl   *sock.Client
	dnsStop context.CancelFunc
	// dnsNoAck makes the attached dns stay silent about images, as a dns that cannot open one.
	dnsNoAck atomic.Bool
	sockPath string
	id       *hubconn.Identity
	idp      idParts
}

func (l *lab) now() time.Time { return time.Now().Add(time.Duration(l.skew.Load()) * time.Second) }

type idParts struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	node  *ecdsa.PrivateKey
}

// newIdentity makes the node's credentials. A short certificate is one a third
// of whose life is already gone, which is when the agent renews.
func newIdentity(t *testing.T, short bool) (*hubconn.Identity, idParts) {
	return newIdentityCN(t, short, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
}

// newIdentityCN is newIdentity with the subject CN given.
func newIdentityCN(t *testing.T, short bool, cn string) (*hubconn.Identity, idParts) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cder, _ := x509.CreateCertificate(rand.Reader, ctmpl, ctmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(cder)
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ntmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-3 * time.Hour),
		NotAfter: lifeEnd(short), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	nder, _ := x509.CreateCertificate(rand.Reader, ntmpl, ca, &nk.PublicKey, caKey)
	kder, _ := x509.MarshalPKCS8PrivateKey(nk)
	id, err := hubconn.NewIdentity(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nder}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder}), [32]byte{1}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return id, idParts{ca: ca, caKey: caKey, node: nk}
}

type labOpt func(*lab)

// newLab builds a lab. Nothing runs until start.
func newLab(t *testing.T, opts ...labOpt) *lab {
	t.Helper()
	skipWindows(t)
	l := &lab{t: t, dir: t.TempDir(), hub: fakehub.New(), keys: storetest.NewKeys(t), runner: &fake.Runner{}, alerts: &alert.Memory{}}
	l.files = fake.NewFiles(map[string]string{
		"/proc/sys/net/ipv4/ip_local_port_range":   "32768 39999\n",
		"/proc/sys/net/ipv4/tcp_syncookies":        "1\n",
		"/proc/self/limits":                        "Max core file size 0 0 bytes\n",
		"/proc/sys/kernel/core_pattern":            "|/lib/systemd/systemd-coredump %P\n",
		"/etc/systemd/coredump.conf.d/ctrlz.conf":  "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
		"/proc/sys/net/netfilter/nf_conntrack_max": "999999\n",
		"/etc/resolv.conf":                         "nameserver 9.9.9.9\n",
	})
	l.runner.Reply = func(c fake.Call) ([]byte, error) {
		if out, err, ok := l.units.Handle(c); ok {
			return out, err
		}
		if c.Name == "unbound" {
			return []byte("Version 1.20.0\n"), nil
		}
		return nil, nil
	}
	l.hub.Start()
	t.Cleanup(l.hub.Stop)
	l.id, l.idp = newIdentity(t, false)
	l.sockPath = filepath.Join(t.TempDir(), "a.sock")
	if err := os.WriteFile(filepath.Join(l.dir, "agent.conf"), []byte("hub=127.0.0.1\ndns_bind_ip=10.0.0.5\ndns_advertised_ip=8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l.cfg = agent.Config{
		Root: filepath.Join(l.dir, "ctrlz"), ConfPath: filepath.Join(l.dir, "agent.conf"),
		Conf:     conf.Agent{Hub: "127.0.0.1", DNSBindIP: netip.MustParseAddr("10.0.0.5"), DNSAdvertisedIP: netip.MustParseAddr("8.8.8.8")},
		SockPath: l.sockPath, PeerCheck: func(net.Conn) error { return nil }, Version: "vtest",
		Identity:  l.id,
		Dial:      func(hubconn.Role) (*grpc.ClientConn, error) { return l.hub.Dial() },
		TrustRoot: func() (*signv1.Root, error) { return l.keys.Root, nil },
		Runner:    l.runner, Files: l.files, Alert: l.alerts, Now: l.now,
		NoSystem: true, SkipHostChecks: true,
		HeartbeatEvery: 100 * time.Millisecond, ServerTimeTimeout: time.Hour, TableEvery: 50 * time.Millisecond,
		CountersPoll: 20 * time.Millisecond, ActivityEvery: 200 * time.Millisecond, TransferIdle: 5 * time.Second,
		RetryEvery: time.Hour, LogPoll: time.Hour, ProbeEvery: time.Hour,
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// start creates the agent and runs it.
func (l *lab) start() {
	l.t.Helper()
	ag, err := agent.New(l.cfg)
	if err != nil {
		l.t.Fatal(err)
	}
	l.ag = ag
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.done = make(chan struct{})
	go func() {
		defer close(l.done)
		if err := ag.Run(ctx); err != nil {
			l.t.Errorf("agent.Run: %v", err)
		}
	}()
	l.t.Cleanup(l.stop)
}

func (l *lab) stop() {
	if l.cancel != nil {
		l.cancel()
		<-l.done
		l.cancel = nil
	}
	if l.dnsStop != nil {
		l.dnsStop()
		l.dnsStop = nil
	}
}

// restart stops the agent and starts a new one over the same directory.
func (l *lab) restart() {
	l.t.Helper()
	l.stop()
	l.start()
}

// attachDNS connects a dns client to the agent socket and records what it gets.
func (l *lab) attachDNS() {
	l.t.Helper()
	if l.dnsStop != nil {
		l.dnsStop()
	}
	l.dnsMu.Lock()
	l.dnsMsgs = nil
	l.dnsMu.Unlock()
	up := new(atomic.Bool)
	l.dnsUp = up
	var cl *sock.Client
	cl = sock.NewClient(l.sockPath, sock.ClientHandlers{
		Message: func(m *sock.Msg) {
			l.dnsMu.Lock()
			l.dnsMsgs = append(l.dnsMsgs, m)
			l.dnsMu.Unlock()
			// dns confirms an image it opened, as dnsrole does (the agent ends revocations on it)
			if m.Type == sock.TypeImage && m.Image != nil && !l.dnsNoAck.Load() {
				cl.Send(&sock.Msg{Type: sock.TypeImageAck, ImageAck: &sock.ImageAck{Name: m.Image.Name}})
			}
		},
		State: func(b bool) { up.Store(b) },
	})
	l.dnsCl = cl
	ctx, cancel := context.WithCancel(context.Background())
	l.dnsStop = cancel
	go l.dnsCl.Run(ctx)
	eventually(l.t, "dns connected", up.Load)
}

// lastDNS returns the latest message of a type, or nil.
func (l *lab) lastDNS(typ string) *sock.Msg {
	l.dnsMu.Lock()
	defer l.dnsMu.Unlock()
	for i := len(l.dnsMsgs) - 1; i >= 0; i-- {
		if l.dnsMsgs[i].Type == typ {
			return l.dnsMsgs[i]
		}
	}
	return nil
}

func (l *lab) waitDNS(what string, f func() bool) { eventually(l.t, what, f) }

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	eventuallyWithin(t, 15*time.Second, what, f)
}

// eventuallyWithin is eventually for a step that is I/O bound by design: every
// entry the Applier commits writes and syncs the state and builds an image, which
// takes about a second on this machine under load (the apply package's own tests
// run for minutes), so a test that applies a dozen entries one by one needs more
// than 15 s.
func eventuallyWithin(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- hub side helpers

func (l *lab) session() *fakehub.Session {
	l.t.Helper()
	s, err := l.hub.NextSession(10 * time.Second)
	if err != nil {
		l.t.Fatal(err)
	}
	return s
}

func serverTime() *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: time.Now().Unix()}}}
}

func headNotice(seq uint64) *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_HeadNotice{HeadNotice: &hubv1.HeadNotice{Seq: seq, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY}}}
}

func nodeConfigMsg(version uint64, proofKey []byte) *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: testNodeConfig(version, proofKey)}}
}

func testNodeConfig(version uint64, proofKey []byte) *hubv1.NodeConfig {
	return &hubv1.NodeConfig{
		Version: version, DnsBindIp: []byte{10, 0, 0, 5}, DnsAdvertisedIp: []byte{8, 8, 8, 8}, ProxyBindIp: []byte{10, 0, 0, 5}, ProxyAdvertisedIp: []byte{8, 8, 8, 8},
		Zones: []string{"dns.example.net"}, PanelHostnames: []string{"panel.example.net"},
		Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, ProofKey: proofKey,
	}
}

// addEntry appends an entry to the hub's log (and its blobs to the hub), and
// returns its seq.
func (l *lab) addEntry(blobs [][]byte, ent *policyv1.ConfigEntry) uint64 {
	l.t.Helper()
	for _, b := range blobs {
		l.hub.SetBlob(storetest.Hash(b), b)
		ent.PutBlobs = append(ent.PutBlobs, storetest.Ref(b))
	}
	stored := l.chain.Next(l.t, ent)
	l.hub.Script(func(h *fakehub.Hub) {
		h.Entries = append(h.Entries, &hubv1.StoredEntry{Seq: l.chain.Seq, EntryHash: l.chain.Head[:], EntryBytes: stored})
	})
	l.setHead()
	return l.chain.Seq
}

// setHead makes GetHead answer for the newest entry.
func (l *lab) setHead() {
	head := signHead(l.t, l.keys, l.chain.Seq, l.chain.Head)
	l.hub.Script(func(h *fakehub.Hub) { h.Head = head })
}

func signHead(t *testing.T, k *storetest.Keys, seq uint64, hash [32]byte) *signv1.Envelope {
	t.Helper()
	payload, err := proto.Marshal(&signv1.SignedHead{Seq: seq, EntryHash: hash[:], CreatedAt: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return k.SignPayload("ctrlz/head", payload)
}

func countHB(s *fakehub.Session) int {
	n := 0
	for _, m := range s.Messages() {
		if m.GetHeartbeat() != nil {
			n++
		}
	}
	return n
}

func lastHB(s *fakehub.Session) *hubv1.Heartbeat {
	msgs := s.Messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if hb := msgs[i].GetHeartbeat(); hb != nil {
			return hb
		}
	}
	return &hubv1.Heartbeat{} // none yet: a test that waits for something polls again
}

func bytesEq(a, b []byte) bool { return bytes.Equal(a, b) }

func newIdentityKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
