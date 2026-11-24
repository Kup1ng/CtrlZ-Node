package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
	"github.com/Kup1ng/CtrlZ-Node/internal/enroll"
	"github.com/Kup1ng/CtrlZ-Node/internal/labroot"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const bootToken = "tkn_BootTestTokenValue_0123456789abcdef"

// enrollHub is the hub's two services as the node meets them at install: the
// enrolment service behind TLS under a pin, which approves only when the test says
// so, and the Control service of the fake hub.
type enrollHub struct {
	enrollv1.UnimplementedEnrollmentServer
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caPEM  []byte
	pin    [32]byte
	lis    *bufconn.Listener
	srv    *grpc.Server

	approve atomic.Bool
	enrolls atomic.Int32
	// busy is how many Enroll calls the hub still answers with its limiter's code.
	busy   atomic.Int32
	mu     sync.Mutex
	id     []byte
	pub    *ecdsa.PublicKey
	issued []byte
}

func newEnrollHub(t *testing.T) *enrollHub {
	t.Helper()
	h := &enrollHub{}
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100)); return n }
	h.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "node CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cder, err := x509.CreateCertificate(rand.Reader, ctpl, ctpl, &h.caKey.PublicKey, h.caKey)
	if err != nil {
		t.Fatal(err)
	}
	h.caCert, _ = x509.ParseCertificate(cder)
	h.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder})
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	htpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "hub"}, DNSNames: []string{"hub.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	hder, err := x509.CreateCertificate(rand.Reader, htpl, h.caCert, &hk.PublicKey, h.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(hder)
	h.pin = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	h.lis = bufconn.Listen(1 << 20)
	h.srv = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{hder}, PrivateKey: hk}}, MinVersion: tls.VersionTLS13})))
	enrollv1.RegisterEnrollmentServer(h.srv, h)
	go func() { _ = h.srv.Serve(h.lis) }()
	t.Cleanup(h.srv.Stop)
	return h
}

func (h *enrollHub) Enroll(_ context.Context, r *enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
	h.enrolls.Add(1)
	if h.busy.Add(-1) >= 0 {
		return nil, status.Error(codes.ResourceExhausted, "limiter")
	}
	if r.Token != bootToken {
		return nil, status.Error(codes.PermissionDenied, "token")
	}
	csr, err := x509.ParseCertificateRequest(r.CsrDer)
	if err != nil || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "csr")
	}
	pub := csr.PublicKey.(*ecdsa.PublicKey)
	spki, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(spki)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.id = make([]byte, 16)
	_, _ = rand.Read(h.id)
	h.pub = pub
	return &enrollv1.EnrollResponse{EnrollmentId: h.id, KeyFingerprint: hex.EncodeToString(sum[:])}, nil
}

func (h *enrollHub) Poll(_ context.Context, r *enrollv1.PollRequest) (*enrollv1.PollResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	digest := sha256.Sum256(enroll.ProofInput(h.id))
	if string(r.EnrollmentId) != string(h.id) || !ecdsa.VerifyASN1(h.pub, digest[:], r.ProofSig) {
		return nil, status.Error(codes.PermissionDenied, "proof")
	}
	if !h.approve.Load() {
		return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}, nil
	}
	if h.issued == nil {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tpl, h.caCert, h.pub, h.caKey)
		if err != nil {
			return nil, err
		}
		h.issued = der
	}
	return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_APPROVED, NodeId: bytes.Repeat([]byte{0xa0}, 16),
		ClientCertDer: h.issued, CaChainDer: [][]byte{h.caCert.Raw}}, nil
}

// bootRig is a node directory as the install leaves it before the first start: the
// config, the hub's pin and CA, root.json and the enrolment token, and no identity.
type bootRig struct {
	env  bootEnv
	keys string
	out  *bytes.Buffer
}

func newBootRig(t *testing.T, caPEM []byte, pin [32]byte, rootJSON []byte) *bootRig {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the image swap is a symlink rename, which is Linux")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "ctrlz")
	keys := filepath.Join(root, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	confPath := filepath.Join(dir, "agent.conf")
	write(confPath, "hub=hub.test\ndns_bind_ip=10.0.0.5\ndns_advertised_ip=203.0.113.5\nproxy_bind_ip=10.0.0.6\nproxy_advertised_ip=203.0.113.6\n")
	write(filepath.Join(keys, hubconn.HubPinFile), "sha256//"+base64.StdEncoding.EncodeToString(pin[:])+"\n")
	write(filepath.Join(keys, hubconn.NodeCAFile), string(caPEM))
	write(filepath.Join(keys, hubconn.RootFile), string(rootJSON))
	write(filepath.Join(keys, enroll.TokenFile), bootToken+"\n")
	osrel := filepath.Join(dir, "os-release")
	write(osrel, "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\n")
	out := &bytes.Buffer{}
	return &bootRig{keys: keys, out: out, env: bootEnv{
		Version: "vtest", Root: root, ConfPath: confPath, SockPath: filepath.Join(dir, "a.sock"),
		OSReleasePath: osrel, Out: out,
		Hostname:  func() (string, error) { return "node-1.example", nil },
		LookupUID: func(string) (uint32, error) { return 0, nil },
	}}
}

// The first start of a node that holds no certificate: the agent enrols, waits for the
// admin's approval without opening Control (nothing but the enrolment service is
// spoken to, R19), stores the certificate, and then opens Control.
func TestBootEnrolsThenOpensControl(t *testing.T) {
	eh := newEnrollHub(t)
	keysFix := storetest.NewKeys(t)
	rootJSON, err := protojson.Marshal(keysFix.Root)
	if err != nil {
		t.Fatal(err)
	}
	rig := newBootRig(t, eh.caPEM, eh.pin, rootJSON)
	hub := fakehub.New()
	hub.Start()
	t.Cleanup(hub.Stop)

	rig.env.TuneEnroll = func(c *enroll.Config) {
		c.PollEvery = 20 * time.Millisecond
		c.CallTimeout = 5 * time.Second
		c.Dial = func(ctx context.Context, _ string) (net.Conn, error) { return eh.lis.DialContext(ctx) }
	}
	rig.env.Tune = func(c *Config) {
		c.SockGroup = ""
		c.PeerCheck = func(net.Conn) error { return nil }
		c.Dial = func(hubconn.Role) (*grpc.ClientConn, error) { return hub.Dial() }
		c.Runner, c.Files = &fake.Runner{}, fake.NewFiles(nil)
		c.NoSystem, c.SkipHostChecks = true, true
		c.HeartbeatEvery = 50 * time.Millisecond
		c.RetryEvery, c.LogPoll, c.ProbeEvery = time.Hour, time.Hour, time.Hour
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- boot(ctx, rig.env) }()
	t.Cleanup(func() { cancel(); <-done })

	// While the admin has not approved, the node has enrolled once and opened no Control.
	deadline := time.Now().Add(10 * time.Second)
	for eh.enrolls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if eh.enrolls.Load() != 1 {
		t.Fatalf("Enroll called %d times", eh.enrolls.Load())
	}
	if s, err := hub.NextSession(400 * time.Millisecond); err == nil {
		t.Fatalf("Control opened before approval: %v", s)
	}
	if _, err := os.Stat(filepath.Join(rig.keys, hubconn.NodeCertFile)); err == nil {
		t.Fatal("a certificate before approval")
	}
	if _, err := os.Stat(filepath.Join(rig.keys, enroll.TokenFile)); err == nil {
		t.Error("the token is still on disk after the hub answered")
	}
	if !strings.Contains(rig.out.String(), "key fingerprint") || strings.Contains(rig.out.String(), bootToken) {
		t.Errorf("console: %q", rig.out.String())
	}

	eh.approve.Store(true)
	s, err := hub.NextSession(10 * time.Second)
	if err != nil {
		t.Fatalf("no Control stream after approval: %v", err)
	}
	m, err := s.Wait(5*time.Second, func(m *hubv1.NodeMessage) bool { return m.GetHeartbeat() != nil })
	if err != nil {
		t.Fatal(err)
	}
	if m.GetHeartbeat().NodeVersion != "vtest" {
		t.Errorf("heartbeat version %q", m.GetHeartbeat().NodeVersion)
	}
	// The files are what the hub issued, and the pending record is gone.
	crt, err := os.ReadFile(filepath.Join(rig.keys, hubconn.NodeCertFile))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(crt)
	if blk == nil || !bytes.Equal(blk.Bytes, eh.issued) {
		t.Error("node.crt is not the certificate the hub issued")
	}
	if fi, err := os.Stat(filepath.Join(rig.keys, hubconn.NodeKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("node.key: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(rig.keys, enroll.PendingFile)); err == nil {
		t.Error("the pending record outlived the enrolment")
	}
}

// A node that already holds its identity does not enrol: the hub's enrolment service
// is never called, even with a token file lying around.
func TestBootWithAnIdentityDoesNotEnrol(t *testing.T) {
	eh := newEnrollHub(t)
	rootJSON, _ := protojson.Marshal(storetest.NewKeys(t).Root)
	rig := newBootRig(t, eh.caPEM, eh.pin, rootJSON)
	// enrol once to get a real identity on disk, then start again
	eh.approve.Store(true)
	hub := fakehub.New()
	hub.Start()
	t.Cleanup(hub.Stop)
	rig.env.TuneEnroll = func(c *enroll.Config) {
		c.PollEvery = 10 * time.Millisecond
		c.Dial = func(ctx context.Context, _ string) (net.Conn, error) { return eh.lis.DialContext(ctx) }
	}
	rig.env.Tune = func(c *Config) {
		c.SockGroup = ""
		c.PeerCheck = func(net.Conn) error { return nil }
		c.Dial = func(hubconn.Role) (*grpc.ClientConn, error) { return hub.Dial() }
		c.Runner, c.Files = &fake.Runner{}, fake.NewFiles(nil)
		c.NoSystem, c.SkipHostChecks = true, true
		c.RetryEvery, c.LogPoll, c.ProbeEvery = time.Hour, time.Hour, time.Hour
	}
	run := func() (context.CancelFunc, chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- boot(ctx, rig.env) }()
		return cancel, done
	}
	cancel, done := run()
	if _, err := hub.NextSession(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if eh.enrolls.Load() != 1 {
		t.Fatalf("first start: %d Enroll calls", eh.enrolls.Load())
	}
	if err := os.WriteFile(filepath.Join(rig.keys, enroll.TokenFile), []byte(bootToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancel, done = run()
	defer func() { cancel(); <-done }()
	if _, err := hub.NextSession(10 * time.Second); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if eh.enrolls.Load() != 1 {
		t.Errorf("a node with an identity enrolled again (%d calls)", eh.enrolls.Load())
	}
}

// A release build refuses the lab test root at load: before it has made a key or
// spent the token, and the root cache never serves it later either.
func TestBootRefusesTheLabRootInAReleaseBuild(t *testing.T) {
	if labroot.Lab {
		t.Skip("a lab build accepts the lab root")
	}
	labJSON, err := os.ReadFile(filepath.Join("..", "labroot", "testdata", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	eh := newEnrollHub(t)
	rig := newBootRig(t, eh.caPEM, eh.pin, labJSON)
	rig.env.TuneEnroll = func(c *enroll.Config) {
		c.Dial = func(ctx context.Context, _ string) (net.Conn, error) { return eh.lis.DialContext(ctx) }
	}
	err = boot(context.Background(), rig.env)
	if !errors.Is(err, labroot.ErrLabRoot) {
		t.Fatalf("boot with the lab root: %v", err)
	}
	if eh.enrolls.Load() != 0 {
		t.Error("the node spoke to a hub whose root is the lab root")
	}
	if _, err := os.Stat(filepath.Join(rig.keys, enroll.TokenFile)); err != nil {
		t.Errorf("the token was spent or removed: %v", err)
	}
	for _, f := range []string{hubconn.NodeKeyFile, hubconn.NodeCertFile, enroll.PendingFile} {
		if _, err := os.Stat(filepath.Join(rig.keys, f)); err == nil {
			t.Errorf("%s exists", f)
		}
	}

	// Later: a good root is in force, then the file becomes the lab root. The cache keeps the good one.
	good, _ := protojson.Marshal(storetest.NewKeys(t).Root)
	p := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(p, good, 0o600); err != nil {
		t.Fatal(err)
	}
	c := &rootCache{path: p}
	r1, err := c.get()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, labJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	c.at = time.Time{} // the minute is over
	r2, err := c.get()
	if err != nil || r2 != r1 {
		t.Errorf("a lab root replaced the good one: %v", err)
	}
	// With no good root yet, the lab root is an error, not a root.
	c2 := &rootCache{path: p}
	if r, err := c2.get(); err == nil || r != nil || !errors.Is(err, labroot.ErrLabRoot) {
		t.Errorf("the cache served the lab root: %v %v", r, err)
	}
}

// sleeps records the waits boot asks for and makes them instant.
type sleeps struct {
	mu sync.Mutex
	ds []time.Duration
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	s.ds = append(s.ds, d)
	s.mu.Unlock()
	return nil
}

func (s *sleeps) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.ds...)
}

// p4n-MC-r1-4: a hub that is busy (the limiter's ResourceExhausted), down or garbled
// is waited out inside boot with a back-off. Leaving it to systemd's two-second restart
// would call Enroll thirty times a minute, the whole limit of the node's /24.
func TestBootRetriesATransientEnrolmentFailureWithABackoff(t *testing.T) {
	eh := newEnrollHub(t)
	eh.busy.Store(3) // the first three Enroll calls are refused by the limiter
	rootJSON, _ := protojson.Marshal(storetest.NewKeys(t).Root)
	rig := newBootRig(t, eh.caPEM, eh.pin, rootJSON)
	hub := fakehub.New()
	hub.Start()
	t.Cleanup(hub.Stop)
	sl := &sleeps{}
	rig.env.Sleep = sl.sleep
	rig.env.TuneEnroll = func(c *enroll.Config) {
		c.PollEvery = 10 * time.Millisecond
		c.Dial = func(ctx context.Context, _ string) (net.Conn, error) { return eh.lis.DialContext(ctx) }
	}
	rig.env.Tune = func(c *Config) {
		c.SockGroup = ""
		c.PeerCheck = func(net.Conn) error { return nil }
		c.Dial = func(hubconn.Role) (*grpc.ClientConn, error) { return hub.Dial() }
		c.Runner, c.Files = &fake.Runner{}, fake.NewFiles(nil)
		c.NoSystem, c.SkipHostChecks = true, true
		c.RetryEvery, c.LogPoll, c.ProbeEvery = time.Hour, time.Hour, time.Hour
	}
	eh.approve.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- boot(ctx, rig.env) }()
	t.Cleanup(func() { cancel(); <-done })
	if _, err := hub.NextSession(10 * time.Second); err != nil {
		t.Fatalf("the node did not get past a busy hub: %v", err)
	}
	if got := eh.enrolls.Load(); got != 4 {
		t.Errorf("Enroll calls = %d, want 4 (three refused by the limiter, one accepted)", got)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	got := sl.all()
	if len(got) != len(want) {
		t.Fatalf("waits %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("wait %d = %v, want %v", i, got[i], want[i])
		}
	}
	if strings.Contains(rig.out.String(), bootToken) {
		t.Error("the token reached the console")
	}
}

func TestEnrolBackoffGrowsAndStops(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if got := enrolBackoff(i); got != w*time.Second {
			t.Errorf("enrolBackoff(%d) = %v, want %v", i, got, w*time.Second)
		}
	}
	if enrolBackoff(1000) != 30*time.Second {
		t.Error("the back-off grows without a bound")
	}
}

// A dead enrolment (no token, no pending record) ends the process, and systemd starts
// it again two seconds later: boot holds a minute first, so it is one line a minute.
func TestBootHoldsADeadEnrolmentBeforeItExits(t *testing.T) {
	eh := newEnrollHub(t)
	rootJSON, _ := protojson.Marshal(storetest.NewKeys(t).Root)
	rig := newBootRig(t, eh.caPEM, eh.pin, rootJSON)
	if err := os.Remove(filepath.Join(rig.keys, enroll.TokenFile)); err != nil {
		t.Fatal(err)
	}
	sl := &sleeps{}
	rig.env.Sleep = sl.sleep
	rig.env.TuneEnroll = func(c *enroll.Config) {
		c.Dial = func(ctx context.Context, _ string) (net.Conn, error) { return eh.lis.DialContext(ctx) }
	}
	err := boot(context.Background(), rig.env)
	if !errors.Is(err, enroll.ErrNoToken) {
		t.Fatalf("boot with no token: %v", err)
	}
	if got := sl.all(); len(got) != 1 || got[0] != deadEnrolmentHold {
		t.Errorf("waits %v, want one of %v", got, deadEnrolmentHold)
	}
	if eh.enrolls.Load() != 0 {
		t.Error("a node with no token spoke to the hub")
	}
}
