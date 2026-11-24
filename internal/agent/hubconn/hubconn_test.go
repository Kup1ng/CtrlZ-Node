package hubconn

import (
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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	n    int64
}

func newCA(t *testing.T) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour * 24), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return &ca{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (c *ca) issue(t *testing.T, key *ecdsa.PrivateKey, cn string, ips []net.IP, eku x509.ExtKeyUsage, notAfter time.Time) (der []byte) {
	t.Helper()
	c.n++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(10 + c.n), Subject: pkix.Name{CommonName: cn}, IPAddresses: ips,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemKey(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type hubUnderTest struct {
	addr   string
	nodeCN chan string
}

type ctlServer struct {
	hubv1.UnimplementedNodeHubServer
	cn chan string
}

func (s *ctlServer) Control(srv grpc.BidiStreamingServer[hubv1.NodeMessage, hubv1.HubMessage]) error {
	if _, err := srv.Recv(); err != nil {
		return err
	}
	return srv.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: time.Now().Unix()}}})
}

// startHub serves NodeHub over real TLS with the given server certificate on a
// port of the lane's range. Client certificates are required and checked against
// the node CA.
func startHub(t *testing.T, serverCert tls.Certificate, nodeCA *ca) *hubUnderTest {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(nodeCA.cert)
	var l net.Listener
	var port int
	for port = 5600; port < 5610; port++ {
		var err error
		if l, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			break
		}
	}
	if l == nil || port == 5610 {
		t.Skip("no free port in the lane's range")
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
	h := &hubUnderTest{addr: "127.0.0.1:" + strconv.Itoa(port), nodeCN: make(chan string, 4)}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	hubv1.RegisterNodeHubServer(srv, &ctlServer{cn: h.nodeCN})
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return h
}

func control(t *testing.T, id *Identity, addr string) error {
	t.Helper()
	cc, err := id.Dial(addr, RoleControl)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	st, err := hubv1.NewNodeHubClient(cc).Control(ctx)
	if err != nil {
		return err
	}
	if err := st.Send(&hubv1.NodeMessage{}); err != nil {
		return err
	}
	_, err = st.Recv()
	return err
}

type world struct {
	nodeCA *ca
	hubKey *ecdsa.PrivateKey
	pin    [32]byte
	node   *Identity
	hubTLS tls.Certificate
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{nodeCA: newCA(t)}
	w.hubKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, _ := x509.ParseCertificate(w.nodeCA.issue(t, w.hubKey, "hub", []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour)))
	w.pin = SPKIHash(leaf)
	w.hubTLS = tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: w.hubKey}
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nodeDER := w.nodeCA.issue(t, nk, "0123456789abcdef0123456789abcdef", nil, x509.ExtKeyUsageClientAuth, time.Now().Add(30*24*time.Hour))
	id, err := NewIdentity(pemCert(nodeDER), pemKey(nk), w.nodeCA.pem, w.pin, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	w.node = id
	return w
}

func TestMutualTLSWithThePin(t *testing.T) {
	w := newWorld(t)
	h := startHub(t, w.hubTLS, w.nodeCA)
	if err := control(t, w.node, h.addr); err != nil {
		t.Fatalf("a correct node cannot reach the hub: %v", err)
	}
	if w.node.NodeID() != "0123456789abcdef0123456789abcdef" {
		t.Errorf("NodeID = %q", w.node.NodeID())
	}
}

func TestHubTrustFailures(t *testing.T) {
	w := newWorld(t)
	other := newCA(t)
	mkHub := func(t *testing.T, c *ca, key *ecdsa.PrivateKey, ips []net.IP, notAfter time.Time) *hubUnderTest {
		leaf := c.issue(t, key, "hub", ips, x509.ExtKeyUsageServerAuth, notAfter)
		return startHub(t, tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: key}, w.nodeCA)
	}
	loop := []net.IP{net.ParseIP("127.0.0.1")}
	t.Run("another key, right CA", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		h := mkHub(t, w.nodeCA, k, loop, time.Now().Add(time.Hour))
		if control(t, w.node, h.addr) == nil {
			t.Error("a hub with another key passed the pin")
		}
	})
	t.Run("pinned key, another CA", func(t *testing.T) {
		h := mkHub(t, other, w.hubKey, loop, time.Now().Add(time.Hour))
		if control(t, w.node, h.addr) == nil {
			t.Error("a chain to another CA was accepted because the pin matched")
		}
	})
	t.Run("pinned key, no name for the host", func(t *testing.T) {
		h := mkHub(t, w.nodeCA, w.hubKey, []net.IP{net.ParseIP("10.9.9.9")}, time.Now().Add(time.Hour))
		if control(t, w.node, h.addr) == nil {
			t.Error("a leaf without the host in its SANs was accepted")
		}
	})
	t.Run("pinned key, expired", func(t *testing.T) {
		h := mkHub(t, w.nodeCA, w.hubKey, loop, time.Now().Add(-time.Minute))
		if control(t, w.node, h.addr) == nil {
			t.Error("an expired leaf was accepted")
		}
	})
	t.Run("a node that was handed a different pin", func(t *testing.T) {
		h := startHub(t, w.hubTLS, w.nodeCA)
		nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der := w.nodeCA.issue(t, nk, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
		id, _ := NewIdentity(pemCert(der), pemKey(nk), w.nodeCA.pem, [32]byte{1}, "127.0.0.1")
		if control(t, id, h.addr) == nil {
			t.Error("a wrong pin passed")
		}
	})
}

func TestHubWithoutOurClientCertificateIsRefused(t *testing.T) {
	// The server insists on a client certificate from the node CA; a node holding
	// one from another CA cannot connect.
	w := newWorld(t)
	h := startHub(t, w.hubTLS, w.nodeCA)
	evil := newCA(t)
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := evil.issue(t, nk, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	id, _ := NewIdentity(pemCert(der), pemKey(nk), w.nodeCA.pem, w.pin, "127.0.0.1")
	if control(t, id, h.addr) == nil {
		t.Error("a certificate from another CA was accepted by the hub")
	}
}

func TestPinForms(t *testing.T) {
	sum := sha256.Sum256([]byte("spki"))
	for _, s := range []string{hex.EncodeToString(sum[:]), "sha256//" + base64.StdEncoding.EncodeToString(sum[:]), "  " + hex.EncodeToString(sum[:]) + "\n"} {
		got, err := ParsePin(s)
		if err != nil || got != sum {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "zz", hex.EncodeToString(sum[:16]), "sha256//AAAA", "sha1//" + base64.StdEncoding.EncodeToString(sum[:])} {
		if _, err := ParsePin(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestLoadIdentityAndRoot(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := w.nodeCA.issue(t, nk, "cccccccccccccccccccccccccccccccc", nil, x509.ExtKeyUsageClientAuth, time.Now().Add(time.Hour))
	write := func(n string, b []byte) { _ = os.WriteFile(filepath.Join(dir, n), b, 0o600) }
	if _, err := LoadIdentity(dir, "127.0.0.1"); err == nil {
		t.Fatal("loaded from an empty directory")
	}
	write(NodeKeyFile, pemKey(nk))
	write(NodeCertFile, pemCert(der))
	write(NodeCAFile, w.nodeCA.pem)
	write(HubPinFile, []byte("sha256//"+base64.StdEncoding.EncodeToString(w.pin[:])+"\n"))
	id, err := LoadIdentity(dir, "127.0.0.1")
	if err != nil || id.NodeID() != "cccccccccccccccccccccccccccccccc" {
		t.Fatalf("%v", err)
	}
	// a certificate for another key is refused
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	write(NodeKeyFile, pemKey(other))
	if _, err := LoadIdentity(dir, "127.0.0.1"); err == nil {
		t.Error("a key that does not match its certificate was loaded")
	}
	// renewal: same key, new certificate
	write(NodeKeyFile, pemKey(nk))
	id, _ = LoadIdentity(dir, "127.0.0.1")
	renewed := w.nodeCA.issue(t, nk, "cccccccccccccccccccccccccccccccc", nil, x509.ExtKeyUsageClientAuth, time.Now().Add(48*time.Hour))
	if err := id.SetCertificate(pemCert(renewed)); err != nil {
		t.Fatal(err)
	}
	if !id.Leaf().NotAfter.After(time.Now().Add(40 * time.Hour)) {
		t.Error("the renewed certificate is not in use")
	}
	foreign := w.nodeCA.issue(t, other, "cccccccccccccccccccccccccccccccc", nil, x509.ExtKeyUsageClientAuth, time.Now().Add(48*time.Hour))
	if err := id.SetCertificate(pemCert(foreign)); err == nil {
		t.Error("a certificate for another key was swapped in")
	}

	root := &signv1.Root{Version: 3, ExpiresAt: 99}
	b, _ := protojson.Marshal(root)
	write(RootFile, b)
	got, err := LoadRoot(filepath.Join(dir, RootFile))
	if err != nil || got.Version != 3 {
		t.Fatalf("root: %v", err)
	}
	write(RootFile, []byte("{nope"))
	if _, err := LoadRoot(filepath.Join(dir, RootFile)); err == nil {
		t.Error("garbage root accepted")
	}
}

func TestPoolReplacesTheConnection(t *testing.T) {
	var dials int
	p := NewPool(func() (*grpc.ClientConn, error) {
		dials++
		return grpc.NewClient("passthrough:///x", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed }),
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	})
	p.Client()
	p.Client()
	if dials != 1 {
		t.Errorf("dials = %d", dials)
	}
	p.Reset()
	p.Client()
	if dials != 2 {
		t.Errorf("dials after Reset = %d", dials)
	}
	p.Close()
	bad := NewPool(func() (*grpc.ClientConn, error) { return nil, net.ErrClosed })
	if _, err := bad.Client().GetHead(context.Background(), &hubv1.GetHeadRequest{}); err == nil {
		t.Error("a failed dial gave a working client")
	}
}
