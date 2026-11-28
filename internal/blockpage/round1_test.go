package blockpage

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

// A body the client drips is part of the request: it gets the 5 s of 10.2, not the
// 30 s of the whole connection (round 1, B6-r1-4). Takes about five seconds.
func TestSlowFormBodyEndsAtTheRequestBudget(t *testing.T) {
	h := newHarness(t)
	hash := h.addPage(formPage(policyv1.UnblockMode_UNBLOCK_MODE_REQUEST))
	f := frame("bank.example", 80, hash)
	tok := h.formToken(f)

	srv, cli := net.Pipe()
	go h.s.ServeConn(srv)
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(15 * time.Second))
	if err := sock.ServeCodec.Write(cli, f); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	go func() {
		// A valid token, a length of 100 bytes, and ten of them sent: then silence.
		_, _ = io.WriteString(cli, "POST /.ctrlz/unblock HTTP/1.1\r\nHost: bank.example\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\nt="+tok[:8])
	}()
	resp, err := http.ReadResponse(bufio.NewReader(cli), nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if took := time.Since(began); took > 8*time.Second {
		t.Fatalf("the body was waited for %v, over the 5 s request budget", took)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d", resp.StatusCode)
	}
	select {
	case <-h.unblocks:
		t.Fatal("a half form was relayed")
	default:
	}
}

// A title that holds the logo marker's letters must not move the logo (B6-r1-14).
func TestTitleWithTheLogoMarkerKeepsThePageWhole(t *testing.T) {
	h := newHarness(t)
	logo := testLogo(t)
	p := formPage(policyv1.UnblockMode_UNBLOCK_MODE_NONE)
	p.Title, p.Message = "x "+logoSentinel+" y", "m "+logoSentinel
	p.Logo, p.LogoHash = logo, sha(logo)
	hash := h.addPage(p)
	_, body := h.plain(frame("a.example", 80, hash), get("a.example"))
	s := string(body)
	if i := strings.Index(s, "<title>"); i < 0 || strings.Contains(s[i:strings.Index(s, "</title>")], "data:") {
		t.Fatal("the logo's data URI landed in the title")
	}
	if strings.Count(s, "data:image/png;base64,") != 1 {
		t.Fatal("the logo is not written once")
	}
	if !strings.Contains(s, `<img class="logo" alt="" src="data:image/png;base64,`) {
		t.Fatal("the logo is not in the img tag")
	}
	if strings.Count(s, logoSentinel) != 3 { // the title, the h1 and the message: the tenant's own text
		t.Fatalf("tenant text altered: %d markers", strings.Count(s, logoSentinel))
	}
}

// When the agent link ends, the keys and leaves go with it (B6-r1-9, r1-10).
func TestLinkLossForgetsKeysAndLeaves(t *testing.T) {
	h := newHarness(t)
	a := newAuthority(t, "A")
	h.setAccount(ids(2), a)
	f := frame("bank.example", 443, nil)
	if _, err := h.tlsConnect(f, "bank.example", a.pool()); err != nil {
		t.Fatal(err)
	}
	h.agent.Close()
	waitFor(t, func() bool {
		h.s.keys.mu.Lock()
		defer h.s.keys.mu.Unlock()
		return h.s.keys.keys.Len() == 0
	})
	if h.s.leafs.cache.ll.Len() != 0 {
		t.Fatal("a leaf outlived the link")
	}
	// A new connection that sends the same epoch again does not bring the key back
	// by itself: the agent sends the keys it holds, and nothing else does.
	block, agent := sockfake.BlockPair()
	h.s.ServeAgent(block.Conn)
	defer agent.Close()
	_ = agent.Send(&sock.BlockMsg{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: h.epoch}})
	waitFor(t, func() bool {
		h.s.keys.mu.Lock()
		defer h.s.keys.mu.Unlock()
		return h.s.keys.haveEpoch
	})
	if h.s.keys.keys.Len() != 0 {
		t.Fatal("a key of the lost connection was kept")
	}
}

// A connection that replaces another starts with no epoch and no key, whether or
// not the old reader noticed its end (B6-r1-5, r1-13).
func TestReplacingConnectionStartsWithNoKeys(t *testing.T) {
	h := newHarness(t)
	a := newAuthority(t, "A")
	h.setAccount(ids(2), a)
	f := frame("bank.example", 443, nil)
	if _, err := h.tlsConnect(f, "bank.example", a.pool()); err != nil {
		t.Fatal(err)
	}
	block, agent := sockfake.BlockPair()
	h.s.ServeAgent(block.Conn) // the first connection is still open
	defer agent.Close()
	h.s.keys.mu.Lock()
	have, n := h.s.keys.haveEpoch, h.s.keys.keys.Len()
	h.s.keys.mu.Unlock()
	if have || n != 0 {
		t.Fatalf("the replacement inherited the epoch (%v) or keys (%d)", have, n)
	}
	if _, err := h.tlsConnect(f, "bank.example", a.pool()); err == nil {
		t.Fatal("a key was used before the new connection's epoch frame")
	}
}

// A leaf that was minted under an old key and landed in the cache after the purge
// is not handed out for the new key (B6-r1-6, r1-12).
func TestCachedLeafOfAnotherIssuerIsNotServed(t *testing.T) {
	c := newLeafCache()
	var acct [16]byte
	k := leafKey{acct, "n.example"}
	cert := &tls.Certificate{}
	now := time.Now()
	c.add(k, cert, now.Add(23*time.Hour), []byte("old issuer"))
	if c.get(k, now, []byte("new issuer")) != nil {
		t.Fatal("a leaf of the old issuer was served")
	}
	c.add(k, cert, now.Add(23*time.Hour), []byte("new issuer"))
	if c.get(k, now, []byte("new issuer")) == nil {
		t.Fatal("a leaf of the present issuer was missed")
	}
}

func TestMintedLeafChainsToTheKeyInHand(t *testing.T) {
	h := newHarness(t)
	a, b := newAuthority(t, "A"), newAuthority(t, "B")
	ha, err := parseHeld(a.bundle(ids(2), h.epoch))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := parseHeld(b.bundle(ids(2), h.epoch))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	first, err := h.s.leafs.certificate(ctx, ids(2), "n.example", ha)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.s.leafs.certificate(ctx, ids(2), "n.example", hb)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Certificate[1]) != string(ha.interDER) || string(second.Certificate[1]) != string(hb.interDER) {
		t.Fatal("a leaf was served under an intermediate that is not the key in hand")
	}
}

// listener fails the first n Accepts with a plain error, then hands out one
// connection, then reports a closed listener.
type flakyListener struct {
	mu    sync.Mutex
	fails int
	conn  net.Conn
	done  bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.fails > 0:
		l.fails--
		return nil, errors.New("accept: too many open files")
	case l.conn != nil:
		c := l.conn
		l.conn = nil
		return c, nil
	}
	l.done = true
	return nil, net.ErrClosed
}
func (l *flakyListener) Close() error   { return nil }
func (l *flakyListener) Addr() net.Addr { return &net.UnixAddr{Name: "x", Net: "unix"} }

// An Accept error that is not a closed listener is waited out (B6-r1-8).
func TestAcceptErrorIsRetriedNotFatal(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	ln := &flakyListener{fails: 3, conn: srv}
	got := make(chan struct{}, 1)
	acceptLoop("test", ln, func(net.Conn) error { return nil }, func(c net.Conn) { c.Close(); got <- struct{}{} })
	select {
	case <-got:
	default:
		t.Fatal("the loop gave up on an Accept error before the connection came")
	}
	if !ln.done {
		t.Fatal("the loop did not run to the closed listener")
	}
}

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
