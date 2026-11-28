// Package hubconn builds the agent's gRPC connections to the hub: mutual TLS
// with the node certificate, the hub's key pinned, and a replaceable connection
// for each of the three roles (Control, transfers, uploads) so that no role ever
// shares an HTTP/2 connection with another (SC 8a.11 L6 and L10).
//
// Trust (p4-nodes 4.1): the node trusts the SPKI of the hub's TLS key, pinned at
// install, and the hub's leaf must also chain to the node CA (`node_ca.pem`,
// fetched at install under the pin) for the name it dials. A chain without the
// pin, or the pin without the chain, is refused. Enrolment is not here: this
// package takes an existing key and certificate from keys/.
package hubconn

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/encoding/protojson"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
)

// File names under keys/.
const (
	NodeKeyFile  = "node.key"
	NodeCertFile = "node.crt"
	NodeCAFile   = "node_ca.pem"
	HubPinFile   = "hub.pin"
	RootFile     = "root.json"
)

// Role of a connection.
type Role uint8

const (
	// RoleControl carries the Control stream and nothing else.
	RoleControl Role = iota + 1
	// RoleTransfer carries FetchEntries, GetHead, FetchBlob, GetSnapshot, FetchBundle, RenewCert.
	RoleTransfer
	// RoleUpload carries UploadCounters and ReportActivity (and UploadLogs from P5).
	RoleUpload
)

func (r Role) String() string {
	switch r {
	case RoleControl:
		return "control"
	case RoleTransfer:
		return "transfer"
	case RoleUpload:
		return "upload"
	}
	return "role?"
}

// Identity is the node's credentials: its key and certificate, replaceable when
// the certificate is renewed, and the trust it holds in the hub.
type Identity struct {
	mu    sync.RWMutex
	cert  tls.Certificate
	leaf  *x509.Certificate
	ca    *x509.CertPool
	pin   [32]byte
	host  string
	nowFn func() time.Time
}

// ParsePin reads a pin as the install writes it: `sha256//<base64>` (the form of
// curl's --pinnedpubkey) or 64 hex characters.
func ParsePin(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	if b64, ok := strings.CutPrefix(s, "sha256//"); ok {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(b) != 32 {
			return out, errors.New("hubconn: bad pin")
		}
		copy(out[:], b)
		return out, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errors.New("hubconn: bad pin")
	}
	copy(out[:], b)
	return out, nil
}

// LoadIdentity reads the node's key, certificate and CA and the hub pin from the
// keys directory. host is the name or address the hub is dialled by, which its
// leaf must carry.
func LoadIdentity(keysDir, host string) (*Identity, error) {
	read := func(name string) ([]byte, error) {
		b, err := os.ReadFile(keysDir + "/" + name)
		if err != nil {
			return nil, fmt.Errorf("hubconn: %s: %w", name, err)
		}
		return b, nil
	}
	keyPEM, err := read(NodeKeyFile)
	if err != nil {
		return nil, err
	}
	certPEM, err := read(NodeCertFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := read(NodeCAFile)
	if err != nil {
		return nil, err
	}
	pinTxt, err := read(HubPinFile)
	if err != nil {
		return nil, err
	}
	pin, err := ParsePin(string(pinTxt))
	if err != nil {
		return nil, err
	}
	return NewIdentity(certPEM, keyPEM, caPEM, pin, host)
}

// NewIdentity builds an Identity from PEM bytes.
func NewIdentity(certPEM, keyPEM, caPEM []byte, pin [32]byte, host string) (*Identity, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("hubconn: the node certificate and key do not form a pair")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("hubconn: no certificate in the node CA file")
	}
	if host == "" {
		return nil, errors.New("hubconn: no hub host")
	}
	return &Identity{cert: cert, leaf: leaf, ca: pool, pin: pin, host: host, nowFn: time.Now}, nil
}

// NodeID is the node's id: the subject CN of its certificate (4.2 step 6).
func (id *Identity) NodeID() string {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.leaf.Subject.CommonName
}

// Leaf is the current certificate.
func (id *Identity) Leaf() *x509.Certificate {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.leaf
}

// Key is the node's private key, for the CSR of a renewal and for opening a
// CertBundle. It never leaves the agent process.
func (id *Identity) Key() tls.Certificate {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.cert
}

// CA is the node CA pool.
func (id *Identity) CA() *x509.CertPool { return id.ca }

// SetCertificate swaps in a renewed certificate. The key must be the same.
func (id *Identity) SetCertificate(certPEM []byte) error {
	id.mu.Lock()
	defer id.mu.Unlock()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return errors.New("hubconn: no certificate")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}
	// The new leaf must carry the key already held, or the next handshake fails.
	if _, err := tls.X509KeyPair(certPEM, mustKeyPEM(id.cert)); err != nil {
		return errors.New("hubconn: the renewed certificate is not for the node's key")
	}
	id.cert.Certificate = [][]byte{blk.Bytes}
	id.cert.Leaf = leaf
	id.leaf = leaf
	return nil
}

// SPKIHash is the SHA-256 of a certificate's SubjectPublicKeyInfo, the form of
// the pin.
func SPKIHash(c *x509.Certificate) [32]byte { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// TLSConfig is the client configuration: the node certificate is presented when
// the hub asks, and the hub's leaf must chain to the node CA for the host and
// carry the pinned key. InsecureSkipVerify is set only so that crypto/tls does
// not run its own, weaker verification first: VerifyConnection below runs the
// whole check, the chain and the name included, and fails the handshake on any
// difference.
func (id *Identity) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
		ServerName:         id.host,
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection does the verification, with the pin
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			id.mu.RLock()
			defer id.mu.RUnlock()
			c := id.cert
			return &c, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("hubconn: the hub sent no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if SPKIHash(leaf) != id.pin {
				return errors.New("hubconn: the hub's key is not the pinned one")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := leaf.Verify(x509.VerifyOptions{
				DNSName: id.host, Roots: id.ca, Intermediates: inter, CurrentTime: id.nowFn(),
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return errors.New("hubconn: the hub's certificate does not verify against the node CA")
			}
			return nil
		},
	}
}

// Options are the dial options of a role. Keepalive is the node's end of 5.8: a
// ping every 10 s and the connection dropped after 10 s without an ack.
func Options(role Role, creds credentials.TransportCredentials) []grpc.DialOption {
	recv := 4 << 20
	switch role {
	case RoleTransfer:
		recv = 20 << 20 // an entry is at most 16 MiB (wire.MaxEntrySize)
	case RoleUpload:
		recv = 1 << 20 // the hub answers with Acks
	}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		// The hub is named in agent.conf and resolved through the host's plain DNS. gRPC would
		// also read a TXT service config from that answer (timeouts, size limits, retry and
		// balancing), which lets whoever can forge a plain DNS answer steer the client; the
		// node has no use for it, and the pin and chain checks do not cover it.
		grpc.WithDisableServiceConfig(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(recv)),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoffCfg(),
			MinConnectTimeout: 5 * time.Second,
		}),
	}
}

// Pool is the connection of one role. Client dials on first use and Reset drops
// the connection, so the next Client call is a new HTTP/2 connection. It
// implements the Conn interfaces of transfer and upload.
type Pool struct {
	dial func() (*grpc.ClientConn, error)

	mu sync.Mutex
	cc *grpc.ClientConn
}

// NewPool returns a Pool that connects with dial.
func NewPool(dial func() (*grpc.ClientConn, error)) *Pool { return &Pool{dial: dial} }

// Client returns a client on the current connection, dialling if there is none.
// The gRPC client is lazy: a dial does not wait for the network.
func (p *Pool) Client() hubv1.NodeHubClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cc == nil {
		cc, err := p.dial()
		if err != nil {
			return failed{err}
		}
		p.cc = cc
	}
	return hubv1.NewNodeHubClient(p.cc)
}

// Reset closes the connection.
func (p *Pool) Reset() {
	p.mu.Lock()
	cc := p.cc
	p.cc = nil
	p.mu.Unlock()
	if cc != nil {
		go cc.Close() // closing may wait for streams to end; never on the caller
	}
}

// Close closes the connection for good.
func (p *Pool) Close() { p.Reset() }

// failed is a client whose every call returns the dial error.
type failed struct{ err error }

func (f failed) Control(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[hubv1.NodeMessage, hubv1.HubMessage], error) {
	return nil, f.err
}
func (f failed) FetchEntries(context.Context, *hubv1.FetchEntriesRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[hubv1.StoredEntry], error) {
	return nil, f.err
}
func (f failed) GetHead(context.Context, *hubv1.GetHeadRequest, ...grpc.CallOption) (*signv1.Envelope, error) {
	return nil, f.err
}
func (f failed) FetchBlob(context.Context, *hubv1.FetchBlobRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[hubv1.BlobChunk], error) {
	return nil, f.err
}
func (f failed) GetSnapshot(context.Context, *hubv1.GetSnapshotRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[hubv1.BlobChunk], error) {
	return nil, f.err
}
func (f failed) FetchBundle(context.Context, *hubv1.FetchBundleRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[hubv1.BlobChunk], error) {
	return nil, f.err
}
func (f failed) RenewCert(context.Context, *hubv1.RenewCertRequest, ...grpc.CallOption) (*hubv1.RenewCertResponse, error) {
	return nil, f.err
}

// LoadRoot reads keys/root.json: the trusted Root as protojson, written by the
// install after its hash was checked against the install command (4.2). The
// agent trusts nothing else for the signatures of heads and pushes.
func LoadRoot(path string) (*signv1.Root, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hubconn: root: %w", err)
	}
	if len(b) > 1<<20 {
		return nil, errors.New("hubconn: root over the cap")
	}
	r := &signv1.Root{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(b, r); err != nil {
		return nil, errors.New("hubconn: root.json does not decode")
	}
	return r, nil
}

func mustKeyPEM(c tls.Certificate) []byte {
	// Re-encoding the key to compare it with a new certificate: PKCS#8 PEM of the
	// private key already held. Errors cannot occur for a key tls.X509KeyPair accepted.
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func backoffCfg() backoff.Config {
	return backoff.Config{BaseDelay: time.Second, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 30 * time.Second}
}

// Dial makes a new connection for a role to the hub at addr (host:port). Each
// call is a new HTTP/2 connection.
func (id *Identity) Dial(addr string, role Role) (*grpc.ClientConn, error) {
	return grpc.NewClient(addr, Options(role, credentials.NewTLS(id.TLSConfig()))...)
}

func (f failed) UploadLogs(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[telemetryv1.LogBatch, telemetryv1.Ack], error) {
	return nil, f.err
}
func (f failed) UploadCounters(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[telemetryv1.CountersBatch, telemetryv1.Ack], error) {
	return nil, f.err
}
func (f failed) ReportActivity(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[telemetryv1.ActivityBatch, telemetryv1.Ack], error) {
	return nil, f.err
}
