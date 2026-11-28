// Package enroll is the node's side of enrolment (p4-nodes 4.2 steps 3, 6 and 7,
// Plan T-078, SC 12).
//
// The agent makes a fresh ECDSA P-256 key, sends the CSR and its four addresses with
// the one-time token, prints the key's fingerprint and the addresses to the console
// for the admin to compare (R19), polls every 5 s with a signature that proves it holds
// the key, and stores the certificate the hub issues once the admin has approved.
//
// Three rules shape the code:
//
//   - A key is never taken from a file. Every Enroll makes a new one (T-078), so a
//     key that leaked from an old install, or one a clone of the disk still holds,
//     never becomes a node's identity. The one file with a key before approval is the
//     pending record, written only after Enroll succeeded, used only to resume the
//     Poll of that same enrolment after an agent restart, and deleted at the end.
//   - The hub is reached only under its pin, with its certificate chained to the node
//     CA fetched at install under that same pin. The hub is not trusted past that:
//     every answer is checked as hostile input (size, shape, the certificate's key,
//     its chain and its life), and a hub that keeps answering badly ends the run.
//   - The token is read once, sent once, deleted once the hub has answered, and is in
//     no error text, no console line and no log.
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/Kup1ng/CtrlZ-Shared/enrollproof"
	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"
)

// File names under keys/ (p4-nodes 7.2).
const (
	NodeKeyFile  = "node.key"
	NodeCertFile = "node.crt"
	TokenFile    = "enroll.token"
	// PendingFile holds the key and id of an enrolment that has been sent and not
	// yet answered; see the package comment.
	PendingFile = "enroll.pending"
)

// Limits. The hub's answers are tiny (an ECDSA leaf and a chain of one or two
// certificates), so anything near these is a fault, not data.
const (
	maxMessage   = 64 << 10
	maxCertDER   = 8 << 10
	maxChainLen  = 4
	idLen        = 16
	maxHostname  = 253
	maxFreeText  = 128
	badLimit     = 5
	maxLifetime  = 90 * 24 * time.Hour
	notBeforeTol = 24 * time.Hour
)

// Errors a caller can tell apart.
var (
	ErrNoToken         = errors.New("enroll: there is no enrolment token and no enrolment in progress; run the install command again")
	ErrRejected        = errors.New("enroll: the hub rejected or expired this enrolment; create a new one in the admin page and install again")
	ErrTimeout         = errors.New("enroll: no approval within the waiting time; create a new enrolment and install again")
	ErrBadHub          = errors.New("enroll: the hub keeps answering with something that is not a valid answer")
	ErrFingerprint     = errors.New("enroll: the hub's fingerprint of the key is not the key's fingerprint")
	ErrEnrollRefused   = errors.New("enroll: the hub refused the enrolment (the token is used, expired or unknown)")
	ErrBadCertificate  = errors.New("enroll: the certificate the hub sent is not for this key, this CA or this time")
	ErrHubUnreachable  = errors.New("enroll: the hub did not answer Enroll")
	errBadHostname     = errors.New("enroll: the host name is not a valid DNS host name; set it with hostnamectl and install again")
	errBadAddress      = errors.New("enroll: an address is not valid")
	errUnexpectedState = errors.New("enroll: unexpected state")
)

// Config is everything Run needs.
type Config struct {
	// KeysDir is /var/lib/ctrlz/keys (0700, the agent's).
	KeysDir string
	// Hub is host:port as dialled and HubHost the name its certificate must carry.
	Hub, HubHost string
	// Pin is the SHA-256 of the hub leaf's SubjectPublicKeyInfo (hub.pin).
	Pin [32]byte
	// NodeCAPEM is node_ca.pem.
	NodeCAPEM []byte
	// The four addresses of agent.conf.
	DNSBind, DNSAdvertised, ProxyBind, ProxyAdvertised netip.Addr
	// Hostname, OSRelease and NodeVersion go to the hub as given (printable ASCII).
	Hostname, OSRelease, NodeVersion string

	// Out is the console: the fingerprint and the addresses go here. nil is io.Discard.
	Out io.Writer

	// PollEvery is 5 s, CallTimeout 15 s per RPC, MaxWait 24 h of waiting for approval
	// in all; zero values take those.
	PollEvery, CallTimeout, MaxWait time.Duration

	// The rest is for tests.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	Dial  func(ctx context.Context, addr string) (net.Conn, error)
	Rand  io.Reader
}

func (c *Config) defaults() {
	if c.Out == nil {
		c.Out = io.Discard
	}
	if c.PollEvery == 0 {
		c.PollEvery = 5 * time.Second
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = 15 * time.Second
	}
	if c.MaxWait == 0 {
		c.MaxWait = 24 * time.Hour
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
}

// Result is a finished enrolment. The files are already written.
type Result struct {
	NodeID      []byte
	Fingerprint string
	NotAfter    time.Time
}

// Run enrols, or resumes an enrolment in progress, and returns when the certificate
// is stored, the hub has refused, or the time is up.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	cfg.defaults()
	req, err := cfg.baseRequest()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.NodeCAPEM) {
		return nil, errors.New("enroll: no certificate in the node CA file")
	}
	cc, err := cfg.dial(pool)
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	client := enrollv1.NewEnrollmentClient(cc)

	pend, err := loadPending(cfg.KeysDir, cfg.Now(), cfg.MaxWait)
	if err != nil {
		return nil, err
	}
	if pend == nil {
		if pend, err = cfg.start(ctx, client, req); err != nil {
			return nil, err
		}
	} else {
		cfg.announce(pend.fingerprint)
	}
	return cfg.poll(ctx, client, pool, pend)
}

// baseRequest checks the fixed parts of the request before anything is sent.
func (c *Config) baseRequest() (*enrollv1.EnrollRequest, error) {
	if !hostnameRE.MatchString(c.Hostname) || len(c.Hostname) > maxHostname || strings.Contains(c.Hostname, "..") {
		return nil, errBadHostname
	}
	if !printable(c.OSRelease, maxFreeText) || !printable(c.NodeVersion, maxFreeText) {
		return nil, errors.New("enroll: os_release and node_version are printable ASCII")
	}
	r := &enrollv1.EnrollRequest{Hostname: c.Hostname, OsRelease: c.OSRelease, NodeVersion: c.NodeVersion}
	for _, a := range []struct {
		dst  *[]byte
		addr netip.Addr
	}{{&r.DnsBindIp, c.DNSBind}, {&r.DnsAdvertisedIp, c.DNSAdvertised}, {&r.ProxyBindIp, c.ProxyBind}, {&r.ProxyAdvertisedIp, c.ProxyAdvertised}} {
		ip := a.addr.Unmap()
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errBadAddress
		}
		*a.dst = ip.AsSlice()
	}
	return r, nil
}

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// pending is an enrolment sent and not yet answered.
type pending struct {
	key         *ecdsa.PrivateKey
	id          []byte
	fingerprint string
	started     time.Time
}

type pendingFile struct {
	Version int    `json:"v"`
	ID      string `json:"enrollment_id"`
	Key     string `json:"key_pkcs8"`
	Started int64  `json:"started"`
}

// start makes the key, sends Enroll and records the pending enrolment.
func (c *Config) start(ctx context.Context, client enrollv1.EnrollmentClient, req *enrollv1.EnrollRequest) (*pending, error) {
	tokenPath := filepath.Join(c.KeysDir, TokenFile)
	tok, err := readSmall(tokenPath, 512)
	if err != nil {
		return nil, ErrNoToken
	}
	token := strings.TrimSpace(string(tok))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, ErrNoToken
	}

	// A fresh key, every time; nothing on disk is consulted.
	key, err := ecdsa.GenerateKey(elliptic.P256(), c.Rand)
	if err != nil {
		return nil, fmt.Errorf("enroll: key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(c.Rand, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ctrlz-node"}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("enroll: csr: %w", err)
	}
	fp, err := fingerprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	r := &enrollv1.EnrollRequest{
		Token: token, CsrDer: csr, Hostname: req.Hostname, OsRelease: req.OsRelease, NodeVersion: req.NodeVersion,
		DnsBindIp: req.DnsBindIp, DnsAdvertisedIp: req.DnsAdvertisedIp, ProxyBindIp: req.ProxyBindIp, ProxyAdvertisedIp: req.ProxyAdvertisedIp,
	}
	cctx, cancel := context.WithTimeout(ctx, c.CallTimeout)
	resp, err := client.Enroll(cctx, r)
	cancel()
	token = ""
	r.Token = ""
	if err != nil {
		if !tokenSpent(err) {
			// Not answered, or answered before the hub read the token (the limiter's
			// ResourceExhausted comes before any database read, spec 5.7; Internal and
			// Unknown say nothing about the token): the token stays for the next try.
			return nil, fmt.Errorf("%w (%s)", ErrHubUnreachable, code(err))
		}
		// The hub read the token and refused it: it is spent.
		_ = os.Remove(tokenPath)
		return nil, fmt.Errorf("%w (%s)", ErrEnrollRefused, code(err))
	}
	_ = os.Remove(tokenPath)
	if len(resp.GetEnrollmentId()) != idLen {
		return nil, fmt.Errorf("%w: the enrollment id is not %d bytes", ErrBadHub, idLen)
	}
	if !strings.EqualFold(resp.GetKeyFingerprint(), fp) {
		return nil, ErrFingerprint
	}
	p := &pending{key: key, id: resp.GetEnrollmentId(), fingerprint: fp, started: c.Now()}
	if err := savePending(c.KeysDir, p); err != nil {
		return nil, err
	}
	c.announce(fp)
	return p, nil
}

// announce prints what the admin compares with the admin page (R19, T-340). The
// fingerprint is the key's own, computed here; the hub's copy was compared with it.
func (c *Config) announce(fp string) {
	fmt.Fprintf(c.Out, "ctrlz-enroll: key fingerprint (SHA-256 of the public key) %s\n", fp)
	fmt.Fprintf(c.Out, "ctrlz-enroll: dns_bind_ip=%s dns_advertised_ip=%s proxy_bind_ip=%s proxy_advertised_ip=%s\n",
		c.DNSBind.Unmap(), c.DNSAdvertised.Unmap(), c.ProxyBind.Unmap(), c.ProxyAdvertised.Unmap())
	fmt.Fprintln(c.Out, "ctrlz-enroll: compare them with the admin page, then confirm and approve this node there")
}

// ProofSig signs a Poll with the enrolled key: ECDSA over enrollproof.Digest(id), ASN.1
// DER. The signed input is defined once, in shared/enrollproof, which the hub calls to
// check it, so the node and the hub cannot hash different bytes. The hub checks the
// signature against the record's key before it reads further, so a leaked enrolment id
// gives nothing.
func ProofSig(key *ecdsa.PrivateKey, id []byte, rnd io.Reader) ([]byte, error) {
	return ecdsa.SignASN1(rnd, key, enrollproof.Digest(id))
}

func (c *Config) poll(ctx context.Context, client enrollv1.EnrollmentClient, roots *x509.CertPool, p *pending) (*Result, error) {
	deadline := p.started.Add(c.MaxWait)
	bad := 0
	for {
		if c.Now().After(deadline) {
			_ = os.Remove(filepath.Join(c.KeysDir, PendingFile))
			return nil, ErrTimeout
		}
		sig, err := ProofSig(p.key, p.id, c.Rand)
		if err != nil {
			return nil, fmt.Errorf("enroll: sign: %w", err)
		}
		cctx, cancel := context.WithTimeout(ctx, c.CallTimeout)
		resp, err := client.Poll(cctx, &enrollv1.PollRequest{EnrollmentId: p.id, ProofSig: sig})
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		switch {
		case err != nil && fatalCode(err):
			return nil, fmt.Errorf("%w (%s)", ErrBadHub, code(err))
		case err != nil && malformed(err):
			// A message that does not decode, or is over the size the node accepts.
			if bad++; bad >= badLimit {
				return nil, fmt.Errorf("%w (%s)", ErrBadHub, code(err))
			}
		case err != nil:
			// The hub is unreachable or busy: keep polling until the time is up.
		default:
			res, st, verr := c.judge(resp, roots, p)
			switch {
			case verr != nil:
				if bad++; bad >= badLimit {
					return nil, verr
				}
			case st == stRejected:
				return nil, ErrRejected
			case st == stApproved:
				return res, nil
			default:
				bad = 0
			}
		}
		if err := c.Sleep(ctx, c.PollEvery); err != nil {
			return nil, err
		}
	}
}

type pollState int

const (
	stPending pollState = iota
	stRejected
	stApproved
)

// judge decides what a PollResponse is. An error is an answer that is not valid.
func (c *Config) judge(r *enrollv1.PollResponse, roots *x509.CertPool, p *pending) (*Result, pollState, error) {
	switch r.GetState() {
	case enrollv1.EnrollState_ENROLL_STATE_PENDING:
		if len(r.GetClientCertDer()) != 0 || len(r.GetCaChainDer()) != 0 || len(r.GetNodeId()) != 0 {
			return nil, stPending, fmt.Errorf("%w: a pending answer carries a certificate", ErrBadHub)
		}
		return nil, stPending, nil
	case enrollv1.EnrollState_ENROLL_STATE_REJECTED:
		// Rejected, expired, used or unknown: the hub says one thing for all four (4.2
		// step 6). The key is of no use any more.
		_ = os.Remove(filepath.Join(c.KeysDir, PendingFile))
		return nil, stRejected, nil
	case enrollv1.EnrollState_ENROLL_STATE_APPROVED:
		res, err := c.accept(r, roots, p)
		if err != nil {
			return nil, stPending, err
		}
		return res, stApproved, nil
	}
	return nil, stPending, fmt.Errorf("%w: %v", ErrBadHub, errUnexpectedState)
}

// accept checks an approved answer as hostile input and stores the certificate.
func (c *Config) accept(r *enrollv1.PollResponse, roots *x509.CertPool, p *pending) (*Result, error) {
	if len(r.GetNodeId()) != idLen || len(r.GetClientCertDer()) == 0 || len(r.GetClientCertDer()) > maxCertDER ||
		len(r.GetCaChainDer()) == 0 || len(r.GetCaChainDer()) > maxChainLen {
		return nil, fmt.Errorf("%w: the shape of an approved answer", ErrBadHub)
	}
	leaf, err := x509.ParseCertificate(r.GetClientCertDer())
	if err != nil {
		return nil, fmt.Errorf("%w: the certificate does not parse", ErrBadHub)
	}
	// It must be for the key made here: a certificate for another key (an answer
	// replayed from another enrolment) is of no use and is refused.
	got, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	want, _ := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil || string(got) != string(want) {
		return nil, fmt.Errorf("%w: not the enrolled key", ErrBadCertificate)
	}
	inter := x509.NewCertPool()
	var chain []*x509.Certificate
	for _, der := range r.GetCaChainDer() {
		if len(der) == 0 || len(der) > maxCertDER {
			return nil, fmt.Errorf("%w: a chain certificate is empty or over its size", ErrBadHub)
		}
		ca, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: a chain certificate does not parse", ErrBadHub)
		}
		inter.AddCert(ca)
		chain = append(chain, ca)
	}
	now := c.Now()
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasEKU(leaf, x509.ExtKeyUsageClientAuth) || hasEKU(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, fmt.Errorf("%w: wrong kind of certificate", ErrBadCertificate)
	}
	// The id the hub put in the answer and the id the certificate names are one node:
	// a certificate issued for another id (a hub fault) is not accepted, and neither
	// is a CN that is no node id, which would leave the agent with no identity.
	cn := leaf.Subject.CommonName
	if cn == "" || !printable(cn, 64) {
		return nil, fmt.Errorf("%w: no node id in the subject", ErrBadCertificate)
	}
	if id, ok := ParseNodeID(cn); !ok || !bytes.Equal(id, r.GetNodeId()) {
		return nil, fmt.Errorf("%w: the subject is not the node id of the answer", ErrBadCertificate)
	}
	if !leaf.NotAfter.After(now) || leaf.NotAfter.Sub(leaf.NotBefore) > maxLifetime {
		return nil, fmt.Errorf("%w: expired or too long-lived", ErrBadCertificate)
	}
	at := now
	if at.Before(leaf.NotBefore) && leaf.NotBefore.Sub(at) <= notBeforeTol {
		at = leaf.NotBefore // a slow clock at install; the node's clock is set from the panel next
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("%w: it does not chain to the node CA", ErrBadCertificate)
	}

	if err := storeIdentity(c.KeysDir, p.key, leaf, chain); err != nil {
		return nil, err
	}
	_ = os.Remove(filepath.Join(c.KeysDir, PendingFile))
	return &Result{NodeID: r.GetNodeId(), Fingerprint: p.fingerprint, NotAfter: leaf.NotAfter}, nil
}

func hasEKU(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, e := range c.ExtKeyUsage {
		if e == u {
			return true
		}
	}
	return false
}

// storeIdentity writes node.key and node.crt: the leaf, then the chain certificates
// that are not self-signed (the node CA itself is node_ca.pem). The key first: a crash
// between the two leaves a key with no certificate, which the pending file's resume
// answers with the same certificate again.
func storeIdentity(dir string, key *ecdsa.PrivateKey, leaf *x509.Certificate, chain []*x509.Certificate) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, NodeKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return fmt.Errorf("enroll: write the key: %w", err)
	}
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	for _, c := range chain {
		if c.CheckSignatureFrom(c) == nil && string(c.RawSubject) == string(c.RawIssuer) {
			continue
		}
		crt = append(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := writeAtomic(filepath.Join(dir, NodeCertFile), crt, 0o644); err != nil {
		return fmt.Errorf("enroll: write the certificate: %w", err)
	}
	return nil
}

func fingerprint(pub *ecdsa.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(spki)
	return hex.EncodeToString(h[:]), nil
}

// --- the pending record ------------------------------------------------------------

func savePending(dir string, p *pending) error {
	der, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		return err
	}
	b, err := json.Marshal(pendingFile{Version: 1, ID: hex.EncodeToString(p.id), Key: base64.StdEncoding.EncodeToString(der), Started: p.started.Unix()})
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, PendingFile), b, 0o600); err != nil {
		return fmt.Errorf("enroll: write the pending record: %w", err)
	}
	return nil
}

// loadPending reads an enrolment in progress. A record that does not parse, or is
// older than the waiting time, is deleted and treated as none: the key in it is never
// used for a new Enroll.
func loadPending(dir string, now time.Time, maxWait time.Duration) (*pending, error) {
	path := filepath.Join(dir, PendingFile)
	b, err := readSmall(path, 4096)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("enroll: read the pending record: %w", err)
	}
	var f pendingFile
	if json.Unmarshal(b, &f) != nil || f.Version != 1 {
		_ = os.Remove(path)
		return nil, nil
	}
	id, err1 := hex.DecodeString(f.ID)
	der, err2 := base64.StdEncoding.DecodeString(f.Key)
	started := time.Unix(f.Started, 0)
	if err1 != nil || err2 != nil || len(id) != idLen || now.Sub(started) > maxWait {
		_ = os.Remove(path)
		return nil, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	key, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		_ = os.Remove(path)
		return nil, nil
	}
	// The curve check above also holds the key's own consistency (ParsePKCS8 checks
	// the point); ECDH refuses a key that is not on the curve.
	if _, err := key.ECDH(); err != nil {
		_ = os.Remove(path)
		return nil, nil
	}
	fp, err := fingerprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &pending{key: key, id: id, fingerprint: fp, started: started}, nil
}

// --- files ----------------------------------------------------------------------------

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("file too large")
	}
	return b, nil
}

// writeAtomic writes through a temporary file in the same directory and renames it,
// so a reader never sees half a file.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-enroll-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(err error) error {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// --- the connection ---------------------------------------------------------------------

func (c *Config) dial(roots *x509.CertPool) (*grpc.ClientConn, error) {
	host := c.HubHost
	if host == "" {
		return nil, errors.New("enroll: no hub host")
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, ServerName: host,
		// InsecureSkipVerify only stops crypto/tls from running its own, weaker check
		// first: VerifyConnection runs the whole one, pin and chain and name, and
		// fails the handshake on any difference.
		InsecureSkipVerify: true, //nolint:gosec
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("enroll: the hub sent no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if sha256.Sum256(leaf.RawSubjectPublicKeyInfo) != c.Pin {
				return errors.New("enroll: the hub's key is not the pinned one")
			}
			inter := x509.NewCertPool()
			for _, x := range cs.PeerCertificates[1:] {
				inter.AddCert(x)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter, CurrentTime: c.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return errors.New("enroll: the hub's certificate does not verify against the node CA")
			}
			return nil
		},
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		// The hub is named in agent.conf and resolved through the host's plain DNS;
		// a TXT service config in that answer must not steer the client.
		grpc.WithDisableServiceConfig(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessage), grpc.MaxCallSendMsgSize(16<<10)),
	}
	target := c.Hub
	if c.Dial != nil {
		dial := c.Dial
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) { return dial(ctx, addr) }))
		target = "passthrough:///" + c.Hub
	}
	return grpc.NewClient(target, opts...)
}

// --- classifying errors ------------------------------------------------------------------

func code(err error) string { return status.Code(err).String() }

// tokenSpent is true only for the codes that mean the hub processed the token and
// refused it. Every other code (a limiter, a hub fault, a lost connection) proves
// nothing about the token, and deleting it would send the admin back to make a new
// enrolment for nothing.
func tokenSpent(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.PermissionDenied, codes.NotFound, codes.FailedPrecondition,
		codes.AlreadyExists, codes.Unauthenticated:
		return true
	}
	return false
}

// malformed is an answer that arrived and is not a valid message: undecodable, or over
// the size the node accepts (the client side of the cap reports ResourceExhausted with
// "larger than max").
func malformed(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch s.Code() {
	case codes.Internal, codes.Unknown, codes.DataLoss, codes.Unimplemented:
		return true
	case codes.ResourceExhausted:
		return strings.Contains(s.Message(), "larger than max")
	}
	return false
}

// fatalCode is the hub refusing the Poll itself rather than answering it: the proof
// was refused or the call is not allowed. The spec answers an unknown or finished
// enrolment with state rejected, so these are not part of a working hub.
func fatalCode(err error) bool {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition, codes.AlreadyExists:
		return true
	}
	return false
}
