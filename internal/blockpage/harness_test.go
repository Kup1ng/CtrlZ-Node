package blockpage

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"image"
	"image/png"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

// authority is one account's root and intermediate, as the hub would make them.
type authority struct {
	root     *x509.Certificate
	interDER []byte
	interKey *ecdsa.PrivateKey
	pkcs8    []byte
}

func newAuthority(t *testing.T, name string) *authority {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ctrl Z Block Page " + name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 365),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	rder, err := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rder)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate " + name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	ider, err := x509.CreateCertificate(rand.Reader, it, root, &ik.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(ik)
	return &authority{root: root, interDER: ider, interKey: ik, pkcs8: p8}
}

func (a *authority) bundle(account, epoch []byte) *sock.Intermediate {
	return &sock.Intermediate{Account: account, Epoch: epoch, Chain: [][]byte{a.interDER, a.root.Raw}, Key: a.pkcs8,
		NotAfter: time.Now().Add(7 * 24 * time.Hour).Unix()}
}

func (a *authority) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.root)
	return p
}

func ids(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

// harness is a Server with the agent played by the test.
type harness struct {
	t      *testing.T
	s      *Server
	agent  *sockfake.Endpoint[sock.BlockMsg]
	epoch  []byte
	mu     sync.Mutex
	pages  map[[32]byte][]byte
	auth   map[string]*authority // by account (string of 16 bytes)
	noKeys bool

	pageAsks, keyAsks atomic.Int64
	unblocks          chan *sock.UnblockMsg
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, s: s, epoch: []byte("EPOCH001"), pages: map[[32]byte][]byte{}, auth: map[string]*authority{},
		unblocks: make(chan *sock.UnblockMsg, 256)}
	block, agent := sockfake.BlockPair()
	h.agent = agent
	s.ServeAgent(block.Conn)
	t.Cleanup(func() { agent.Close(); s.link.close() })
	go h.agentLoop()
	if err := agent.Send(&sock.BlockMsg{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: h.epoch}}); err != nil {
		t.Fatal(err)
	}
	// The server reads the epoch frame on its own goroutine, and until it is applied
	// no key is used (10.2). A test that connects at once would be refused by the
	// rule under test on a loaded runner, and pass on a quiet machine.
	waitFor(t, func() bool {
		s.keys.mu.Lock()
		defer s.keys.mu.Unlock()
		return s.keys.haveEpoch
	})
	return h
}

func (h *harness) agentLoop() {
	for {
		m, err := h.agent.Recv()
		if err != nil {
			return
		}
		switch m.Type {
		case sock.BlockNeedPage:
			h.pageAsks.Add(1)
			var k [32]byte
			copy(k[:], m.NeedPage.Hash)
			h.mu.Lock()
			blob := h.pages[k]
			h.mu.Unlock()
			_ = h.agent.Send(&sock.BlockMsg{Type: sock.BlockPage, Page: &sock.PageMsg{Hash: m.NeedPage.Hash, Blob: blob}})
		case sock.BlockNeedKey:
			h.keyAsks.Add(1)
			h.mu.Lock()
			a := h.auth[string(m.NeedKey.Account)]
			no, ep := h.noKeys, h.epoch
			h.mu.Unlock()
			if a != nil && !no {
				_ = h.agent.Send(&sock.BlockMsg{Type: sock.BlockIntermediate, Intermediate: a.bundle(m.NeedKey.Account, ep)})
			}
		case sock.BlockUnblock:
			h.unblocks <- m.Unblock
		}
	}
}

func (h *harness) setAccount(acct []byte, a *authority) {
	h.mu.Lock()
	h.auth[string(acct)] = a
	h.mu.Unlock()
}

// addPage stores a page record under its hash and returns the hash.
func (h *harness) addPage(p *policyv1.BlockPage) []byte {
	b, err := proto.Marshal(p)
	if err != nil {
		h.t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	h.mu.Lock()
	h.pages[sum] = b
	h.mu.Unlock()
	return sum[:]
}

func testLogo(t *testing.T) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 8, 8))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func frame(name string, port uint16, hash []byte) *sock.ServeFrame {
	return &sock.ServeFrame{Name: name, Port: port, Endpoint: ids(1), Account: ids(2), Source: []byte{192, 0, 2, 7}, PageHash: hash}
}

// plain sends the frame and a raw request over a pipe and reads the answer.
func (h *harness) plain(f *sock.ServeFrame, req string) (*http.Response, []byte) {
	h.t.Helper()
	srv, cli := net.Pipe()
	go h.s.ServeConn(srv)
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	if err := sock.ServeCodec.Write(cli, f); err != nil {
		h.t.Fatal(err)
	}
	go func() { _, _ = io.WriteString(cli, req) }()
	resp, err := http.ReadResponse(bufio.NewReader(cli), nil)
	if err != nil {
		h.t.Fatalf("no response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.ContentLength >= 0 && int64(len(body)) != resp.ContentLength {
		h.t.Fatalf("body is %d bytes, Content-Length says %d", len(body), resp.ContentLength)
	}
	return resp, body
}

func get(host string) string {
	return "GET / HTTP/1.1\r\nHost: " + host + "\r\nAccept-Language: en\r\n\r\n"
}

// tlsConnect dials the frame's name over a pipe and returns the connection state
// or the handshake error.
func (h *harness) tlsConnect(f *sock.ServeFrame, sni string, roots *x509.CertPool) (*tls.ConnectionState, error) {
	srv, cli := net.Pipe()
	go h.s.ServeConn(srv)
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	if err := sock.ServeCodec.Write(cli, f); err != nil {
		return nil, err
	}
	tc := tls.Client(cli, &tls.Config{ServerName: sni, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		InsecureSkipVerify: sni == "" /* the test of a missing SNI: the server must refuse, not the client */})
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	st := tc.ConnectionState()
	return &st, nil
}
