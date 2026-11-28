package peer

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"

	"google.golang.org/grpc/credentials"

	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/enroll"
)

// Errors carry fixed text only: a certificate's subject or key is the peer's input and
// is never quoted back into a log.
var (
	errNoCert  = errors.New("peer: the peer sent no certificate")
	errChain   = errors.New("peer: the peer's certificate does not verify against the node CA")
	errSubject = errors.New("peer: the peer's certificate is not for the expected node")
	errTrust   = errors.New("peer: the peer's key is not the one in the applied table")
	errConn    = errors.New("peer: connection refused")
)

func spkiOf(c *x509.Certificate) [32]byte { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// verifyPeer is the check both ends make in VerifyConnection (4.5): the chain to the
// node CA, validity now, EKU clientAuth, the CN equal to the expected node id, and the
// SPKI equal to the non-empty spki_sha256 of that node in the applied table.
//
// The node certificate carries clientAuth alone and no serverAuth is ever added to it
// (4.5), so the usual server verification, which asks for serverAuth, cannot be used
// and the client side sets InsecureSkipVerify only so that this runs instead of it.
func (p *Peer) verifyPeer(cs tls.ConnectionState, want zone.NodeID) (*x509.Certificate, error) {
	if len(cs.PeerCertificates) == 0 {
		return nil, errNoCert
	}
	leaf := cs.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.cfg.Roots, Intermediates: inter, CurrentTime: p.cfg.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, errChain
	}
	raw, ok := enroll.ParseNodeID(leaf.Subject.CommonName)
	if !ok || len(raw) != 16 || zone.NodeID(raw) != want {
		return nil, errSubject
	}
	if !p.view().trusts(want, spkiOf(leaf)) {
		return nil, errTrust
	}
	return leaf, nil
}

// peerConn is an accepted connection that passed the address check. It is counted
// from Accept to Close, and remembers whose key it was verified with so that a later
// table can end it.
type peerConn struct {
	net.Conn
	node zone.NodeID
	p    *Peer
	once sync.Once

	mu   sync.Mutex
	spki [32]byte
	has  bool
}

func (c *peerConn) setLeaf(spki [32]byte) {
	c.mu.Lock()
	c.spki, c.has = spki, true
	c.mu.Unlock()
}

func (c *peerConn) leaf() ([32]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spki, c.has
}

func (c *peerConn) Close() error {
	c.once.Do(func() { c.p.release(c) })
	return c.Conn.Close()
}

// acceptCheck is the listener the server uses: the address check of 4.5 and the
// caps, both before TLS. gRPC's own accept loop never sees a connection that fails
// them, and none of them costs a handshake.
//
// It is our own check because the agent's nftables table holds no per-source rule for
// DNS_IP (SC 8a.11 L13).
type acceptCheck struct {
	net.Listener
	p *Peer
}

func (l *acceptCheck) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if pc := l.p.admit(c); pc != nil {
			return pc, nil
		}
		_ = c.Close()
	}
}

// admit returns the counted connection, or nil when the address is no live node of the
// table or a cap is full.
func (p *Peer) admit(c net.Conn) *peerConn {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return nil
	}
	n := p.view().byAddr[ip.Unmap()]
	if n == nil {
		return nil
	}
	p.cmu.Lock()
	defer p.cmu.Unlock()
	if len(p.conns) >= MaxConns || p.perNod[n.id] >= MaxConnsPerNode {
		return nil
	}
	pc := &peerConn{Conn: c, node: n.id, p: p}
	p.conns[pc] = struct{}{}
	p.perNod[n.id]++
	return pc
}

func (p *Peer) release(c *peerConn) {
	p.cmu.Lock()
	defer p.cmu.Unlock()
	if _, ok := p.conns[c]; !ok {
		return
	}
	delete(p.conns, c)
	if p.perNod[c.node]--; p.perNod[c.node] <= 0 {
		delete(p.perNod, c.node)
	}
}

// serverCreds is gRPC's TLS server credentials with a verification that knows which
// node the connection claimed to be by its address. TLS 1.3 only.
type serverCreds struct {
	credentials.TransportCredentials
	p *Peer
}

func newServerCreds(p *Peer) serverCreds {
	return serverCreds{TransportCredentials: credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13}), p: p}
}

func (c serverCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	pc, ok := raw.(*peerConn)
	if !ok {
		_ = raw.Close()
		return nil, nil, errConn
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := c.p.cfg.Cert()
			return &cert, nil
		},
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			leaf, err := c.p.verifyPeer(cs, pc.node)
			if err != nil {
				return err
			}
			pc.setLeaf(spkiOf(leaf))
			return nil
		},
	}
	conn, info, err := credentials.NewTLS(cfg).ServerHandshake(raw)
	if err != nil {
		_ = pc.Close()
		return nil, nil, errConn
	}
	return conn, info, nil
}

// recheck ends every connection whose key the table v no longer trusts: a revoked
// peer's calls stop at the entry that empties its key, not at the next reconnect.
func (p *Peer) recheck(v *view) {
	p.cmu.Lock()
	var drop []*peerConn
	for c := range p.conns {
		if spki, has := c.leaf(); has && !v.trusts(c.node, spki) {
			drop = append(drop, c)
		}
	}
	p.cmu.Unlock()
	for _, c := range drop {
		p.stat.Revoked.Add(1)
		_ = c.Conn.Close()
	}
	p.recheckOut(v)
}
