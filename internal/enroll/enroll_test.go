package enroll

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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"
)

const testToken = "tkn_Q3f9Z0-TestTokenValue_8c2e41aa77"

// pki is a node CA and the hub's leaf under it.
type pki struct {
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	caPEM   []byte
	hubCert tls.Certificate
	pin     [32]byte
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func newCA(t *testing.T, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "node CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return k, c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newPKI(t *testing.T, now time.Time) *pki {
	t.Helper()
	p := &pki{}
	p.caKey, p.caCert, p.caPEM = newCA(t, now)
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "hub"}, DNSNames: []string{"hub.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.caCert, &hk.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	p.hubCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: hk, Leaf: leaf}
	p.pin = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return p
}

// issue makes a node client certificate for pub, as the hub's template of 4.2 step 6.
func (p *pki) issue(t *testing.T, pub any, now time.Time, mut func(*x509.Certificate)) []byte {
	t.Helper()
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: hex.EncodeToString(id)},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if mut != nil {
		mut(tpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.caCert, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeHub is the in-process hub: the real proto, the real TLS pin, a scripted answer.
type fakeHub struct {
	enrollv1.UnimplementedEnrollmentServer
	t   *testing.T
	pki *pki
	now func() time.Time

	mu       sync.Mutex
	enrolls  []*enrollv1.EnrollRequest
	polls    int
	pollSigs int // proof signatures that verified
	records  map[string]*record

	// onPoll decides the n-th Poll (1-based) after the proof was checked.
	onPoll func(n int, rec *record) (*enrollv1.PollResponse, error)
	// onEnroll, when set, replaces the default.
	onEnroll func(r *enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error)
	block    chan struct{} // when set, Poll and Enroll never answer until it is closed
}

type record struct {
	id   []byte
	pub  *ecdsa.PublicKey
	spki []byte
	csr  []byte
}

func (h *fakeHub) Enroll(ctx context.Context, r *enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
	if h.block != nil {
		<-h.block
	}
	h.mu.Lock()
	h.enrolls = append(h.enrolls, proto.Clone(r).(*enrollv1.EnrollRequest))
	h.mu.Unlock()
	if h.onEnroll != nil {
		return h.onEnroll(r)
	}
	csr, err := x509.ParseCertificateRequest(r.CsrDer)
	if err != nil || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "csr")
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, status.Error(codes.InvalidArgument, "key")
	}
	if r.Token != testToken {
		return nil, status.Error(codes.PermissionDenied, "token")
	}
	spki, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(spki)
	rec := &record{id: make([]byte, 16), pub: pub, spki: spki, csr: r.CsrDer}
	_, _ = rand.Read(rec.id)
	h.mu.Lock()
	h.records[string(rec.id)] = rec
	h.mu.Unlock()
	return &enrollv1.EnrollResponse{EnrollmentId: rec.id, KeyFingerprint: hex.EncodeToString(sum[:])}, nil
}

func (h *fakeHub) Poll(ctx context.Context, r *enrollv1.PollRequest) (*enrollv1.PollResponse, error) {
	if h.block != nil {
		select {
		case <-h.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	h.mu.Lock()
	h.polls++
	n := h.polls
	rec := h.records[string(r.EnrollmentId)]
	h.mu.Unlock()
	if rec == nil {
		return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_REJECTED}, nil
	}
	digest := sha256.Sum256(ProofInput(rec.id))
	if !ecdsa.VerifyASN1(rec.pub, digest[:], r.ProofSig) {
		return nil, status.Error(codes.PermissionDenied, "proof")
	}
	h.mu.Lock()
	h.pollSigs++
	h.mu.Unlock()
	if h.onPoll == nil {
		return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}, nil
	}
	return h.onPoll(n, rec)
}

func (h *fakeHub) approved(t *testing.T, rec *record) *enrollv1.PollResponse {
	t.Helper()
	der := h.pki.issue(t, rec.pub, h.now(), nil)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &enrollv1.PollResponse{
		State: enrollv1.EnrollState_ENROLL_STATE_APPROVED, NodeId: id, ClientCertDer: der,
		CaChainDer: [][]byte{h.pki.caCert.Raw},
	}
}

// clock is a fake clock: Sleep advances it and returns at once.
type clock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.sleeps = append(c.sleeps, d)
	c.mu.Unlock()
	return nil
}

type rig struct {
	t    *testing.T
	hub  *fakeHub
	pki  *pki
	clk  *clock
	cfg  Config
	out  *bytes.Buffer
	dir  string
	stop func()
}

func newRig(t *testing.T) *rig {
	t.Helper()
	clk := &clock{t: time.Now()}
	p := newPKI(t, clk.Now())
	h := &fakeHub{t: t, pki: p, now: clk.Now, records: map[string]*record{}}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{p.hubCert}, MinVersion: tls.VersionTLS13})), grpc.MaxSendMsgSize(4<<20))
	enrollv1.RegisterEnrollmentServer(srv, h)
	go func() { _ = srv.Serve(lis) }()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, TokenFile), []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	r := &rig{t: t, hub: h, pki: p, clk: clk, out: out, dir: dir, stop: func() { srv.Stop(); lis.Close() }}
	r.cfg = Config{
		KeysDir: dir, Hub: "hub.test:9443", HubHost: "hub.test", Pin: p.pin, NodeCAPEM: p.caPEM,
		DNSBind: netip.MustParseAddr("10.0.0.5"), DNSAdvertised: netip.MustParseAddr("203.0.113.5"),
		ProxyBind: netip.MustParseAddr("10.0.0.6"), ProxyAdvertised: netip.MustParseAddr("203.0.113.6"),
		Hostname: "node-1.example", OSRelease: "Ubuntu 24.04 LTS", NodeVersion: "1.0.0",
		Out: out, Now: clk.Now, Sleep: clk.Sleep, CallTimeout: 2 * time.Second,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) { return lis.DialContext(ctx) },
	}
	t.Cleanup(r.stop)
	return r
}

func (r *rig) run(t *testing.T) (*Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Run(ctx, r.cfg)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestEnrolsAfterAWhilePending(t *testing.T) {
	r := newRig(t)
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) {
		if n <= 4 {
			return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}, nil
		}
		return r.hub.approved(t, rec), nil
	}
	// A key and certificate from an earlier install: never reused.
	if err := os.WriteFile(filepath.Join(r.dir, NodeKeyFile), []byte("OLD KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := r.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.NodeID) != 16 || res.Fingerprint == "" {
		t.Fatalf("result %+v", res)
	}
	// Polls came every 5 s, five of them, each with a proof that verified.
	if len(r.clk.sleeps) != 4 {
		t.Fatalf("slept %d times", len(r.clk.sleeps))
	}
	for _, d := range r.clk.sleeps {
		if d != 5*time.Second {
			t.Fatalf("poll cadence %v", d)
		}
	}
	if r.hub.pollSigs != 5 {
		t.Fatalf("%d proofs verified", r.hub.pollSigs)
	}
	// One Enroll, with the four addresses and a CSR of a P-256 key; the token was sent
	// and is gone from disk.
	if len(r.hub.enrolls) != 1 {
		t.Fatalf("%d Enroll calls", len(r.hub.enrolls))
	}
	e := r.hub.enrolls[0]
	for _, c := range []struct {
		got  []byte
		want string
	}{{e.DnsBindIp, "10.0.0.5"}, {e.DnsAdvertisedIp, "203.0.113.5"}, {e.ProxyBindIp, "10.0.0.6"}, {e.ProxyAdvertisedIp, "203.0.113.6"}} {
		a, _ := netip.AddrFromSlice(c.got)
		if a.String() != c.want {
			t.Errorf("address %s, want %s", a, c.want)
		}
	}
	if e.Hostname != "node-1.example" || e.OsRelease != "Ubuntu 24.04 LTS" || e.NodeVersion != "1.0.0" {
		t.Errorf("request %+v", e)
	}
	if exists(filepath.Join(r.dir, TokenFile)) || exists(filepath.Join(r.dir, PendingFile)) {
		t.Error("the token or the pending record is still on disk")
	}
	// node.key is the key the CSR carried (not the old file), and the certificate is for it.
	keyPEM, _ := os.ReadFile(filepath.Join(r.dir, NodeKeyFile))
	if bytes.Contains(keyPEM, []byte("OLD KEY")) {
		t.Fatal("the old key file was kept")
	}
	certPEM, _ := os.ReadFile(filepath.Join(r.dir, NodeCertFile))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(e.CsrDer)
	want, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	got, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if !bytes.Equal(got, want) {
		t.Fatal("the stored certificate is not for the key of the CSR")
	}
	if runtime.GOOS != "windows" {
		for name, mode := range map[string]os.FileMode{NodeKeyFile: 0o600, NodeCertFile: 0o644} {
			fi, _ := os.Stat(filepath.Join(r.dir, name))
			if fi.Mode().Perm() != mode {
				t.Errorf("%s has mode %v, want %v", name, fi.Mode().Perm(), mode)
			}
		}
	}
	// The console shows the fingerprint (of the key sent) and the four addresses; the
	// token is nowhere in it.
	sum := sha256.Sum256(want)
	console := r.out.String()
	for _, s := range []string{res.Fingerprint, "10.0.0.5", "203.0.113.5", "10.0.0.6", "203.0.113.6", "confirm and approve"} {
		if !strings.Contains(console, s) {
			t.Errorf("console lacks %q:\n%s", s, console)
		}
	}
	_ = sum
	if strings.Contains(console, testToken) {
		t.Error("the token is on the console")
	}
}

func TestEveryEnrolmentMakesAFreshKey(t *testing.T) {
	var csrKeys [][]byte
	for i := 0; i < 2; i++ {
		r := newRig(t)
		r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) { return r.hub.approved(t, rec), nil }
		if _, err := r.run(t); err != nil {
			t.Fatal(err)
		}
		csr, _ := x509.ParseCertificateRequest(r.hub.enrolls[0].CsrDer)
		k, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
		csrKeys = append(csrKeys, k)
	}
	if bytes.Equal(csrKeys[0], csrKeys[1]) {
		t.Fatal("two enrolments used one key")
	}
	// A stale key on disk is never the one sent: the first test shows the file is
	// overwritten; here the key in the CSR is shown not to derive from any file.
	r := newRig(t)
	stale, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(stale)
	if err := os.WriteFile(filepath.Join(r.dir, NodeKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) { return r.hub.approved(t, rec), nil }
	if _, err := r.run(t); err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(r.hub.enrolls[0].CsrDer)
	sent, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	old, _ := x509.MarshalPKIXPublicKey(&stale.PublicKey)
	if bytes.Equal(sent, old) {
		t.Fatal("the key on disk was reused")
	}
}

func TestRejectedAndExpiredEnrolments(t *testing.T) {
	r := newRig(t)
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) {
		if n < 3 {
			return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}, nil
		}
		return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_REJECTED}, nil
	}
	if _, err := r.run(t); !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v", err)
	}
	for _, n := range []string{NodeKeyFile, NodeCertFile, PendingFile} {
		if exists(filepath.Join(r.dir, n)) {
			t.Errorf("%s exists after a rejection", n)
		}
	}

	// The panel never decides: the wait is bounded on the node's side too.
	r = newRig(t)
	r.cfg.MaxWait = time.Minute
	_, err := r.run(t)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
	if exists(filepath.Join(r.dir, PendingFile)) {
		t.Error("the pending record outlived the wait")
	}
	if len(r.clk.sleeps) < 10 || len(r.clk.sleeps) > 13 {
		t.Errorf("%d polls in a minute", len(r.clk.sleeps))
	}
}

func TestRefusedAndUnreachableEnroll(t *testing.T) {
	r := newRig(t)
	r.hub.onEnroll = func(*enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "token used SECRET-TEXT-FROM-THE-HUB")
	}
	_, err := r.run(t)
	if !errors.Is(err, ErrEnrollRefused) || strings.Contains(err.Error(), "SECRET-TEXT") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("got %v", err)
	}
	if exists(filepath.Join(r.dir, TokenFile)) {
		t.Error("a token the hub answered about stays on disk")
	}

	r = newRig(t)
	r.hub.onEnroll = func(*enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
		return nil, status.Error(codes.Unavailable, "down")
	}
	_, err = r.run(t)
	if !errors.Is(err, ErrHubUnreachable) {
		t.Fatalf("got %v", err)
	}
	if !exists(filepath.Join(r.dir, TokenFile)) {
		t.Error("a token the hub never answered about was deleted")
	}
	if exists(filepath.Join(r.dir, PendingFile)) {
		t.Error("a pending record without an enrolment")
	}
}

// The token is deleted only when the hub read it and refused it. A rate limit
// (answered before any database read, spec 5.7), a hub fault and an unknown error
// say nothing about the token, so it stays and the next try can use it.
func TestTokenSurvivesAnswersThatDoNotSpendIt(t *testing.T) {
	for _, tc := range []struct {
		code  codes.Code
		spent bool
	}{
		{codes.ResourceExhausted, false}, {codes.Internal, false}, {codes.Unknown, false},
		{codes.Unavailable, false}, {codes.DeadlineExceeded, false}, {codes.Aborted, false},
		{codes.Unimplemented, false}, {codes.DataLoss, false},
		{codes.InvalidArgument, true}, {codes.PermissionDenied, true}, {codes.NotFound, true},
		{codes.FailedPrecondition, true}, {codes.AlreadyExists, true}, {codes.Unauthenticated, true},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			r := newRig(t)
			r.hub.onEnroll = func(*enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
				return nil, status.Error(tc.code, "no")
			}
			_, err := r.run(t)
			if err == nil {
				t.Fatal("enrolled")
			}
			if got := !exists(filepath.Join(r.dir, TokenFile)); got != tc.spent {
				t.Errorf("code %s: token deleted = %v, want %v (%v)", tc.code, got, tc.spent, err)
			}
			if tc.spent != errors.Is(err, ErrEnrollRefused) {
				t.Errorf("code %s: error %v", tc.code, err)
			}
		})
	}
}

func TestHubThatNeverAnswers(t *testing.T) {
	r := newRig(t)
	r.hub.block = make(chan struct{})
	defer close(r.hub.block)
	r.cfg.CallTimeout = 150 * time.Millisecond
	start := time.Now()
	_, err := r.run(t)
	if !errors.Is(err, ErrHubUnreachable) {
		t.Fatalf("Enroll: got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("did not time out")
	}
	if !exists(filepath.Join(r.dir, TokenFile)) {
		t.Error("the token was deleted although the hub never answered")
	}

	// Poll that never answers: each call times out, polling goes on until the wait ends.
	r = newRig(t)
	// Only Poll is slow. The rig's CallTimeout (2 s) stays, so the Enroll call, whose
	// TLS handshake and chain check take well over 100 ms under -race on a loaded
	// machine, is never what times out (p4n-W5c-r6-1). The fake clock steps PollEvery
	// per sleep, so a 6 s wait is two real polls.
	r.cfg.MaxWait = 6 * time.Second
	started := make(chan struct{})
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		time.Sleep(r.cfg.CallTimeout + 300*time.Millisecond) // longer than the call timeout
		return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}, nil
	}
	_, err = r.run(t)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Poll: got %v", err)
	}
	<-started
}

func TestAnswersThatAreNotValid(t *testing.T) {
	cases := map[string]func(r *rig, rec *record) *enrollv1.PollResponse{
		"unknown state": func(r *rig, rec *record) *enrollv1.PollResponse {
			return &enrollv1.PollResponse{State: enrollv1.EnrollState(99)}
		},
		"unspecified state": func(r *rig, rec *record) *enrollv1.PollResponse { return &enrollv1.PollResponse{} },
		"approved with no certificate": func(r *rig, rec *record) *enrollv1.PollResponse {
			return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_APPROVED}
		},
		"pending that carries a certificate": func(r *rig, rec *record) *enrollv1.PollResponse {
			return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING, ClientCertDer: []byte{1}}
		},
		"certificate that is not DER": func(r *rig, rec *record) *enrollv1.PollResponse {
			return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_APPROVED, NodeId: make([]byte, 16), ClientCertDer: []byte("not a certificate"), CaChainDer: [][]byte{r.pki.caCert.Raw}}
		},
		"node id of the wrong length": func(r *rig, rec *record) *enrollv1.PollResponse {
			p := r.hub.approved(t, rec)
			p.NodeId = []byte{1, 2, 3}
			return p
		},
		"a replayed certificate of another key": func(r *rig, rec *record) *enrollv1.PollResponse {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			p := r.hub.approved(t, rec)
			p.ClientCertDer = r.pki.issue(t, &other.PublicKey, r.clk.Now(), nil)
			return p
		},
		"a certificate of another CA": func(r *rig, rec *record) *enrollv1.PollResponse {
			foreign := newPKI(t, r.clk.Now())
			p := r.hub.approved(t, rec)
			p.ClientCertDer = foreign.issue(t, rec.pub, r.clk.Now(), nil)
			p.CaChainDer = [][]byte{foreign.caCert.Raw}
			return p
		},
		"an expired certificate": func(r *rig, rec *record) *enrollv1.PollResponse {
			p := r.hub.approved(t, rec)
			p.ClientCertDer = r.pki.issue(t, rec.pub, r.clk.Now(), func(c *x509.Certificate) {
				c.NotBefore = r.clk.Now().Add(-48 * time.Hour)
				c.NotAfter = r.clk.Now().Add(-time.Hour)
			})
			return p
		},
		"a server certificate": func(r *rig, rec *record) *enrollv1.PollResponse {
			p := r.hub.approved(t, rec)
			p.ClientCertDer = r.pki.issue(t, rec.pub, r.clk.Now(), func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			})
			return p
		},
		"a CA certificate": func(r *rig, rec *record) *enrollv1.PollResponse {
			p := r.hub.approved(t, rec)
			p.ClientCertDer = r.pki.issue(t, rec.pub, r.clk.Now(), func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true })
			return p
		},
		"a certificate good for years": func(r *rig, rec *record) *enrollv1.PollResponse {
			p := r.hub.approved(t, rec)
			p.ClientCertDer = r.pki.issue(t, rec.pub, r.clk.Now(), func(c *x509.Certificate) { c.NotAfter = r.clk.Now().Add(5 * 365 * 24 * time.Hour) })
			return p
		},
		"an oversized chain": func(r *rig, rec *record) *enrollv1.PollResponse {
			p := r.hub.approved(t, rec)
			p.CaChainDer = [][]byte{r.pki.caCert.Raw, r.pki.caCert.Raw, r.pki.caCert.Raw, r.pki.caCert.Raw, r.pki.caCert.Raw}
			return p
		},
	}
	for name, mk := range cases {
		r := newRig(t)
		r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) { return mk(r, rec), nil }
		_, err := r.run(t)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, ErrBadHub) && !errors.Is(err, ErrBadCertificate) {
			t.Errorf("%s: %v", name, err)
		}
		// The loop gave up after a few bad answers, not at the first and not never.
		if r.hub.polls != badLimit {
			t.Errorf("%s: %d polls before giving up, want %d", name, r.hub.polls, badLimit)
		}
		for _, n := range []string{NodeKeyFile, NodeCertFile} {
			if exists(filepath.Join(r.dir, n)) {
				t.Errorf("%s: %s was written", name, n)
			}
		}
	}
}

func TestPendingAnswersResetTheBadCount(t *testing.T) {
	r := newRig(t)
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) {
		switch {
		case n%2 == 1 && n < 8:
			return &enrollv1.PollResponse{State: enrollv1.EnrollState(99)}, nil
		case n < 8:
			return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}, nil
		}
		return r.hub.approved(t, rec), nil
	}
	if _, err := r.run(t); err != nil {
		t.Fatalf("a hub that is odd now and then was given up on: %v", err)
	}
}

func TestPollRefusedByTheHub(t *testing.T) {
	r := newRig(t)
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "x")
	}
	if _, err := r.run(t); !errors.Is(err, ErrBadHub) {
		t.Fatalf("got %v", err)
	}
	if r.hub.polls != 1 {
		t.Errorf("%d polls after a refusal", r.hub.polls)
	}
}

// garbage makes the server write bytes that are not a protobuf message.
type garbageCodec struct{}

func (garbageCodec) Marshal(v any) ([]byte, error) { return []byte("\xff\xff not protobuf \xff"), nil }
func (garbageCodec) Unmarshal(data []byte, v any) error {
	return proto.Unmarshal(data, v.(proto.Message))
}
func (garbageCodec) Name() string { return "proto" }

var _ encoding.Codec = garbageCodec{}

func TestHubThatAnswersGarbageOrTooMuch(t *testing.T) {
	clk := &clock{t: time.Now()}
	p := newPKI(t, clk.Now())

	serve := func(h *fakeHub, opts ...grpc.ServerOption) *bufconn.Listener {
		lis := bufconn.Listen(1 << 20)
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{p.hubCert}, MinVersion: tls.VersionTLS13})))
		srv := grpc.NewServer(opts...)
		enrollv1.RegisterEnrollmentServer(srv, h)
		go func() { _ = srv.Serve(lis) }()
		t.Cleanup(func() { srv.Stop(); lis.Close() })
		return lis
	}

	// Garbage bytes in the PollResponse. Enroll is answered normally first, through a
	// hub with the real codec, then the Poll goes to a hub whose codec writes garbage:
	// both are one fake hub, so the garbage codec is used for the whole connection and
	// the Enroll reply is made valid by a scripted onEnroll that the codec cannot spoil.
	h := &fakeHub{t: t, pki: p, now: clk.Now, records: map[string]*record{}}
	lis := serve(h, grpc.ForceServerCodec(garbageCodec{}))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, TokenFile), []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		KeysDir: dir, Hub: "hub.test:9443", HubHost: "hub.test", Pin: p.pin, NodeCAPEM: p.caPEM,
		DNSBind: netip.MustParseAddr("10.0.0.5"), DNSAdvertised: netip.MustParseAddr("10.0.0.5"),
		ProxyBind: netip.MustParseAddr("10.0.0.6"), ProxyAdvertised: netip.MustParseAddr("10.0.0.6"),
		Hostname: "node-1", OSRelease: "Ubuntu", NodeVersion: "1", Now: clk.Now, Sleep: clk.Sleep, CallTimeout: 2 * time.Second,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) { return lis.DialContext(ctx) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Even the Enroll answer is garbage here: the run ends with an error and no file.
	if _, err := Run(ctx, cfg); err == nil {
		t.Fatal("garbage was accepted")
	}
	for _, n := range []string{NodeKeyFile, NodeCertFile} {
		if exists(filepath.Join(dir, n)) {
			t.Errorf("%s written after garbage", n)
		}
	}

	// An answer bigger than the node accepts (64 KiB): ends the run after a few tries.
	h2 := &fakeHub{t: t, pki: p, now: clk.Now, records: map[string]*record{}}
	h2.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) {
		return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_APPROVED, NodeId: make([]byte, 16), ClientCertDer: bytes.Repeat([]byte{1}, 200<<10), CaChainDer: [][]byte{{1}}}, nil
	}
	lis2 := serve(h2, grpc.MaxSendMsgSize(4<<20))
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, TokenFile), []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KeysDir = dir2
	cfg.Dial = func(ctx context.Context, addr string) (net.Conn, error) { return lis2.DialContext(ctx) }
	_, err := Run(ctx, cfg)
	if !errors.Is(err, ErrBadHub) {
		t.Fatalf("an oversized answer: got %v", err)
	}
	if h2.polls != badLimit {
		t.Errorf("%d polls before giving up on oversized answers", h2.polls)
	}
}

func TestOnlyTheHubUnderItsPinIsTalkedTo(t *testing.T) {
	// A wrong pin: the handshake fails, so no Enroll is sent and the token is kept.
	r := newRig(t)
	r.cfg.Pin = [32]byte{1}
	r.cfg.CallTimeout = 500 * time.Millisecond
	if _, err := r.run(t); err == nil {
		t.Fatal("a hub with the wrong pin was talked to")
	}
	if len(r.hub.enrolls) != 0 {
		t.Fatal("Enroll reached a hub with the wrong pin")
	}
	if !exists(filepath.Join(r.dir, TokenFile)) {
		t.Error("the token was deleted although it was never sent")
	}

	// The right key but a certificate that does not chain to the node CA.
	r = newRig(t)
	foreignCA, _, foreignPEM := newCA(t, r.clk.Now())
	_ = foreignCA
	r.cfg.NodeCAPEM = foreignPEM
	r.cfg.CallTimeout = 500 * time.Millisecond
	if _, err := r.run(t); err == nil {
		t.Fatal("a hub that does not chain to the node CA was talked to")
	}
	if len(r.hub.enrolls) != 0 {
		t.Fatal("Enroll reached a hub that does not chain to the node CA")
	}

	// The wrong name.
	r = newRig(t)
	r.cfg.HubHost = "other.test"
	r.cfg.CallTimeout = 500 * time.Millisecond
	if _, err := r.run(t); err == nil || len(r.hub.enrolls) != 0 {
		t.Fatal("a hub under the wrong name was talked to")
	}
}

func TestFingerprintMismatchIsRefused(t *testing.T) {
	r := newRig(t)
	r.hub.onEnroll = func(*enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
		return &enrollv1.EnrollResponse{EnrollmentId: make([]byte, 16), KeyFingerprint: strings.Repeat("ab", 32)}, nil
	}
	if _, err := r.run(t); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("got %v", err)
	}
	if exists(filepath.Join(r.dir, PendingFile)) {
		t.Error("pending record written for a refused enrolment")
	}
	r = newRig(t)
	r.hub.onEnroll = func(*enrollv1.EnrollRequest) (*enrollv1.EnrollResponse, error) {
		return &enrollv1.EnrollResponse{EnrollmentId: []byte{1}, KeyFingerprint: "x"}, nil
	}
	if _, err := r.run(t); !errors.Is(err, ErrBadHub) {
		t.Fatalf("a short enrollment id: got %v", err)
	}
}

// An agent that restarts while the admin has not yet approved resumes the same
// enrolment with the same key; it does not Enroll again and uses no token.
func TestResumeAfterRestart(t *testing.T) {
	r := newRig(t)
	calls := 0
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) {
		calls++
		if calls == 1 {
			return &enrollv1.PollResponse{State: enrollv1.EnrollState_ENROLL_STATE_PENDING}, nil
		}
		return r.hub.approved(t, rec), nil
	}
	// First run: cancelled after the first pending answer, as a restart would.
	ctx, cancel := context.WithCancel(context.Background())
	r.cfg.Sleep = func(c context.Context, d time.Duration) error { cancel(); return c.Err() }
	if _, err := Run(ctx, r.cfg); err == nil {
		t.Fatal("expected the cancelled run to fail")
	}
	if !exists(filepath.Join(r.dir, PendingFile)) {
		t.Fatal("no pending record after the first poll")
	}
	if exists(filepath.Join(r.dir, TokenFile)) {
		t.Fatal("the token stayed after Enroll succeeded")
	}
	// Second run: no token, the pending record carries on.
	r.cfg.Sleep = r.clk.Sleep
	if _, err := r.run(t); err != nil {
		t.Fatal(err)
	}
	if len(r.hub.enrolls) != 1 {
		t.Fatalf("%d Enroll calls; a restart must not Enroll again", len(r.hub.enrolls))
	}
	if exists(filepath.Join(r.dir, PendingFile)) || !exists(filepath.Join(r.dir, NodeKeyFile)) {
		t.Error("files after the resumed enrolment")
	}
}

func TestStaleOrBrokenPendingRecordIsNotUsed(t *testing.T) {
	// Too old: dropped, and with no token there is nothing to start from.
	r := newRig(t)
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) { return r.hub.approved(t, rec), nil }
	if _, err := r.run(t); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"not json", `{"v":1,"enrollment_id":"zz","key_pkcs8":"AAAA","started":1}`, `{"v":2}`} {
		r2 := newRig(t)
		if err := os.Remove(filepath.Join(r2.dir, TokenFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r2.dir, PendingFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := r2.run(t); !errors.Is(err, ErrNoToken) {
			t.Errorf("%q: got %v", content, err)
		}
		if exists(filepath.Join(r2.dir, PendingFile)) {
			t.Errorf("%q: the broken record stayed", content)
		}
		if len(r2.hub.enrolls) != 0 {
			t.Errorf("%q: Enroll was called", content)
		}
	}
	// A record older than the wait is dropped, and the token (when there is one) starts a new enrolment.
	r3 := newRig(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	old := &pending{key: k, id: make([]byte, 16), started: r3.clk.Now().Add(-48 * time.Hour)}
	if err := savePending(r3.dir, old); err != nil {
		t.Fatal(err)
	}
	r3.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) { return r3.hub.approved(t, rec), nil }
	if _, err := r3.run(t); err != nil {
		t.Fatal(err)
	}
	if len(r3.hub.enrolls) != 1 {
		t.Fatalf("%d Enroll calls; a stale record must give way to a new enrolment", len(r3.hub.enrolls))
	}
}

func TestNoTokenNoEnrolment(t *testing.T) {
	r := newRig(t)
	if err := os.Remove(filepath.Join(r.dir, TokenFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.run(t); !errors.Is(err, ErrNoToken) {
		t.Fatalf("got %v", err)
	}
	r = newRig(t)
	if err := os.WriteFile(filepath.Join(r.dir, TokenFile), []byte("two words"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.run(t); !errors.Is(err, ErrNoToken) {
		t.Fatalf("a token with a space: got %v", err)
	}
}

func TestBadLocalInputIsRefusedBeforeAnything(t *testing.T) {
	for name, mut := range map[string]func(c *Config){
		"host name with an underscore": func(c *Config) { c.Hostname = "my_node" },
		"empty host name":              func(c *Config) { c.Hostname = "" },
		"host name with a dot dot":     func(c *Config) { c.Hostname = "a..b" },
		"os release with a newline":    func(c *Config) { c.OSRelease = "Ubuntu\n24.04" },
		"unspecified address":          func(c *Config) { c.DNSBind = netip.MustParseAddr("0.0.0.0") },
		"missing address":              func(c *Config) { c.ProxyAdvertised = netip.Addr{} },
		"multicast address":            func(c *Config) { c.DNSAdvertised = netip.MustParseAddr("224.0.0.1") },
	} {
		r := newRig(t)
		mut(&r.cfg)
		if _, err := r.run(t); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(r.hub.enrolls) != 0 || !exists(filepath.Join(r.dir, TokenFile)) {
			t.Errorf("%s: something was sent or deleted", name)
		}
	}
	// An embedded-IPv4 form is sent as the IPv4 address.
	r := newRig(t)
	r.cfg.DNSBind = netip.MustParseAddr("::ffff:10.0.0.5")
	r.hub.onPoll = func(n int, rec *record) (*enrollv1.PollResponse, error) { return r.hub.approved(t, rec), nil }
	if _, err := r.run(t); err != nil {
		t.Fatal(err)
	}
	if len(r.hub.enrolls[0].DnsBindIp) != 4 {
		t.Errorf("an IPv4-mapped address was sent as %d bytes", len(r.hub.enrolls[0].DnsBindIp))
	}
}

func TestProofSigIsOverTheDomainSeparatedInput(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := bytes.Repeat([]byte{9}, 16)
	sig, err := ProofSig(k, id, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := sha256.Sum256(append([]byte("ctrlz-poll-v1\x00"), id...))
	if !ecdsa.VerifyASN1(&k.PublicKey, good[:], sig) {
		t.Fatal("the signature is not over \"ctrlz-poll-v1\\0\" || id")
	}
	bare := sha256.Sum256(id)
	if ecdsa.VerifyASN1(&k.PublicKey, bare[:], sig) {
		t.Fatal("the signature also verifies over the bare id")
	}
}

// A golden vector for the hub side (W3, Panel): the same bytes and digest must come
// out of its implementation. Computed outside Go, with printf and sha256sum.
func TestProofInputGoldenVector(t *testing.T) {
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if got, want := hex.EncodeToString(ProofInput(id)), "6374726c7a2d706f6c6c2d7631000102030405060708090a0b0c0d0e0f10"; got != want {
		t.Fatalf("ProofInput = %s, want %s", got, want)
	}
	sum := sha256.Sum256(ProofInput(id))
	if got, want := hex.EncodeToString(sum[:]), "ed213f81920fcc9792708e93b04efd440a1feacebf0e3d7dd39ee334074208c8"; got != want {
		t.Fatalf("SHA-256 of ProofInput = %s, want %s", got, want)
	}
}
