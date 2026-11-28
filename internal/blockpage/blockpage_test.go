package blockpage

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

func formPage(mode policyv1.UnblockMode) *policyv1.BlockPage {
	return &policyv1.BlockPage{Title: "Blocked by ACME", Message: "Ask the office.", UnblockMode: mode, ProfileId: ids(9)}
}

func TestDefaultPageHasNoTenantTextAndNoForm(t *testing.T) {
	h := newHarness(t)
	resp, body := h.plain(frame("bad.example", 80, nil), get("bad.example"))
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for k, want := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
		if resp.Header.Get(k) != want {
			t.Errorf("%s = %q", k, resp.Header.Get(k))
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, w := range []string{"default-src 'none'", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'", "img-src data:"} {
		if !strings.Contains(csp, w) {
			t.Errorf("CSP lacks %q: %s", w, csp)
		}
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("a cookie or HSTS was set")
	}
	s := string(body)
	if strings.Contains(s, "<form") || strings.Contains(s, "<script") || !strings.Contains(s, "bad.example") || !strings.Contains(s, "Ctrl Z") {
		t.Errorf("unexpected default page: %s", s)
	}
	if h.pageAsks.Load() != 0 {
		t.Error("an empty hash asked the agent for a page")
	}
}

func TestLanguageByAcceptLanguage(t *testing.T) {
	h := newHarness(t)
	_, fa := h.plain(frame("a.example", 80, nil), "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if !strings.Contains(string(fa), `dir="rtl"`) || !strings.Contains(string(fa), `lang="fa"`) {
		t.Error("the default is not Persian and right to left")
	}
	_, en := h.plain(frame("a.example", 80, nil), get("a.example"))
	if !strings.Contains(string(en), `lang="en"`) {
		t.Error("Accept-Language en did not give English")
	}
}

func TestNotADocumentGetsAnEmpty403(t *testing.T) {
	h := newHarness(t)
	resp, body := h.plain(frame("a.example", 80, nil), "GET /x.js HTTP/1.1\r\nHost: a.example\r\nSec-Fetch-Dest: script\r\n\r\n")
	if resp.StatusCode != 403 || len(body) != 0 {
		t.Fatalf("status %d, %d bytes", resp.StatusCode, len(body))
	}
	resp, body = h.plain(frame("a.example", 80, nil), "GET / HTTP/1.1\r\nHost: a.example\r\nSec-Fetch-Dest: document\r\n\r\n")
	if resp.StatusCode != 403 || len(body) == 0 {
		t.Fatalf("a document got status %d, %d bytes", resp.StatusCode, len(body))
	}
}

func TestOversizeHeadersAreRefused(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.plain(frame("a.example", 80, nil), "GET / HTTP/1.1\r\nHost: a.example\r\nX-Pad: "+strings.Repeat("a", MaxHeaderBytes)+"\r\n\r\n")
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestLogoIsWrittenOnceFromTheCache(t *testing.T) {
	h := newHarness(t)
	logo := testLogo(t)
	sum := sha256.Sum256(logo)
	p := formPage(policyv1.UnblockMode_UNBLOCK_MODE_NONE)
	p.Logo, p.LogoHash = logo, sum[:]
	hash := h.addPage(p)
	resp, body := h.plain(frame("a.example", 80, hash), get("a.example"))
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	s := string(body)
	if strings.Count(s, "data:image/png;base64,") != 1 || strings.Contains(s, logoSentinel) {
		t.Fatalf("logo placement wrong")
	}
	if !strings.Contains(s, "Blocked by ACME") || strings.Contains(s, ">Ctrl Z<") {
		t.Error("tenant title missing or the brand shown beside the user's logo")
	}
	// The second connection comes from the cache: the agent is asked once.
	h.plain(frame("a.example", 80, hash), get("a.example"))
	if n := h.pageAsks.Load(); n != 1 {
		t.Errorf("page asks %d", n)
	}
}

func TestUnknownPageHashServesOursAndIsAskedOnce(t *testing.T) {
	h := newHarness(t)
	hash := sha256.Sum256([]byte("nobody has this"))
	for i := 0; i < 3; i++ {
		_, body := h.plain(frame("a.example", 80, hash[:]), get("a.example"))
		if strings.Contains(string(body), "<form") || strings.Contains(string(body), "ACME") {
			t.Fatal("a tenant page was served for an unknown hash")
		}
	}
	if n := h.pageAsks.Load(); n != 1 {
		t.Errorf("page asks %d, want 1 for the whole NoPageTTL", n)
	}
}

func TestConcurrentConnectionsShareOnePageAsk(t *testing.T) {
	h := newHarness(t)
	hash := h.addPage(formPage(policyv1.UnblockMode_UNBLOCK_MODE_NONE))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.plain(frame("a.example", 80, hash), get("a.example"))
		}()
	}
	wg.Wait()
	if n := h.pageAsks.Load(); n != 1 {
		t.Errorf("page asks %d", n)
	}
}

var tokenRE = regexp.MustCompile(`name="t" value="([^"]+)"`)

func (h *harness) post(f *sock.ServeFrame, token, msg string, extra string) *http.Response {
	form := url.Values{"t": {token}, "m": {msg}}.Encode()
	req := "POST /.ctrlz/unblock HTTP/1.1\r\nHost: " + f.Name + "\r\n" + extra +
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + itoa(len(form)) + "\r\n\r\n" + form
	resp, _ := h.plain(f, req)
	return resp
}

func itoa(n int) string { return strconv.Itoa(n) }

func (h *harness) formToken(f *sock.ServeFrame) string {
	_, body := h.plain(f, get(f.Name))
	m := tokenRE.FindStringSubmatch(string(body))
	if m == nil {
		h.t.Fatalf("no form on the page: %s", body)
	}
	return m[1]
}

func TestUnblockFormRelaysOnceWithItsGuards(t *testing.T) {
	h := newHarness(t)
	hash := h.addPage(formPage(policyv1.UnblockMode_UNBLOCK_MODE_REQUEST))
	f := frame("bank.example", 80, hash)
	tok := h.formToken(f)

	// A wrong token, a foreign origin and a cross-site fetch relay nothing.
	if r := h.post(f, "bogus", "hi", ""); r.StatusCode != 403 {
		t.Errorf("wrong token: %d", r.StatusCode)
	}
	if r := h.post(f, tok, "hi", "Origin: http://evil.example\r\n"); r.StatusCode != 403 {
		t.Errorf("foreign origin: %d", r.StatusCode)
	}
	if r := h.post(f, tok, "hi", "Origin: null\r\nSec-Fetch-Site: cross-site\r\n"); r.StatusCode != 403 {
		t.Errorf("cross-site: %d", r.StatusCode)
	}
	// A token of another source is refused.
	other := *f
	other.Source = []byte{192, 0, 2, 8}
	if r := h.post(&other, tok, "hi", ""); r.StatusCode != 403 {
		t.Errorf("token of another source: %d", r.StatusCode)
	}
	select {
	case <-h.unblocks:
		t.Fatal("a refused form was relayed")
	case <-time.After(100 * time.Millisecond):
	}

	// Origin: null is what a browser sends under no-referrer; it is accepted.
	if r := h.post(f, tok, "please\r\nunblock \x01it", "Origin: null\r\nSec-Fetch-Site: same-origin\r\n"); r.StatusCode != 200 {
		t.Fatalf("good form: %d", r.StatusCode)
	}
	select {
	case u := <-h.unblocks:
		if string(u.Endpoint) != string(ids(1)) || string(u.Profile) != string(ids(9)) || u.Name != "bank.example" || u.Message != "please\nunblock it" {
			t.Errorf("relayed %+v", u)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing relayed")
	}

	// Five an hour per (Endpoint, source): the sixth says received but is not relayed.
	for i := 0; i < 4; i++ {
		h.post(f, tok, "again", "")
	}
	if r := h.post(f, tok, "sixth", ""); r.StatusCode != 200 {
		t.Fatalf("over the limit the page still says received, got %d", r.StatusCode)
	}
	n := 0
	for {
		select {
		case <-h.unblocks:
			n++
			continue
		case <-time.After(200 * time.Millisecond):
		}
		break
	}
	if n != 4 {
		t.Errorf("relayed %d more, want 4 (5 in all)", n)
	}
}

func TestUnblockBodyOverLimitAndPerEndpointCap(t *testing.T) {
	h := newHarness(t)
	hash := h.addPage(formPage(policyv1.UnblockMode_UNBLOCK_MODE_REQUEST))
	f := frame("bank.example", 80, hash)
	tok := h.formToken(f)
	if r := h.post(f, tok, strings.Repeat("a", MaxFormBody), ""); r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over 4 KiB: %d", r.StatusCode)
	}
	// 60 an hour per Endpoint across sources.
	relayed := 0
	for i := 0; i < 70; i++ {
		g := *f
		g.Source = []byte{198, 51, 100, byte(i)}
		tk := h.s.unb.token(g.Name, g.Endpoint, g.Source)
		h.post(&g, tk, "m", "")
	}
	for {
		select {
		case <-h.unblocks:
			relayed++
			continue
		case <-time.After(200 * time.Millisecond):
		}
		break
	}
	if relayed != UnblockPerEndpoint {
		t.Errorf("relayed %d, want %d", relayed, UnblockPerEndpoint)
	}
}

func TestNoFormForModeNoneOrURL(t *testing.T) {
	h := newHarness(t)
	none := h.addPage(formPage(policyv1.UnblockMode_UNBLOCK_MODE_NONE))
	_, body := h.plain(frame("a.example", 80, none), get("a.example"))
	if strings.Contains(string(body), "<form") || strings.Contains(string(body), "<a ") {
		t.Error("mode none shows an action")
	}
	p := formPage(policyv1.UnblockMode_UNBLOCK_MODE_URL)
	p.UnblockUrl = "https://help.example/unblock"
	_, body = h.plain(frame("a.example", 80, h.addPage(p)), get("a.example"))
	if !strings.Contains(string(body), `href="https://help.example/unblock" rel="noopener noreferrer"`) {
		t.Errorf("the custom link is missing: %s", body)
	}
	// A post to a page that has no form relays nothing.
	if r := h.post(frame("a.example", 80, none), "x", "m", ""); r.StatusCode != 403 {
		t.Errorf("post to a page with no form: %d", r.StatusCode)
	}
}

// ---- HTTPS

func TestHTTPSLeafVerifiesUnderTheAccountsRootOnly(t *testing.T) {
	h := newHarness(t)
	a, b := newAuthority(t, "A"), newAuthority(t, "B")
	h.setAccount(ids(2), a)
	h.setAccount(ids(3), b)

	fa := frame("bank.example", 443, nil)
	st, err := h.tlsConnect(fa, "bank.example", a.pool())
	if err != nil {
		t.Fatalf("handshake under A's root: %v", err)
	}
	if st.NegotiatedProtocol != "http/1.1" || len(st.PeerCertificates) != 2 {
		t.Errorf("alpn %q, %d certificates", st.NegotiatedProtocol, len(st.PeerCertificates))
	}
	// The same name, A's account: B's root does not verify it, at any depth.
	if _, err := h.tlsConnect(fa, "bank.example", b.pool()); err == nil {
		t.Fatal("A's leaf verified under B's root")
	}
	// B's account gets B's chain, which A's root does not verify.
	fb := frame("bank.example", 443, nil)
	fb.Account = ids(3)
	if _, err := h.tlsConnect(fb, "bank.example", b.pool()); err != nil {
		t.Fatalf("B under B: %v", err)
	}
	if _, err := h.tlsConnect(fb, "bank.example", a.pool()); err == nil {
		t.Fatal("B's leaf verified under A's root")
	}
}

func TestHTTPSServesThePageAndChecksTheName(t *testing.T) {
	h := newHarness(t)
	a := newAuthority(t, "A")
	h.setAccount(ids(2), a)
	hash := h.addPage(formPage(policyv1.UnblockMode_UNBLOCK_MODE_NONE))
	f := frame("bank.example", 443, hash)

	srv, cli := net.Pipe()
	go h.s.ServeConn(srv)
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	_ = sock.ServeCodec.Write(cli, f)
	tc := tls.Client(cli, &tls.Config{ServerName: "bank.example", RootCAs: a.pool(), MinVersion: tls.VersionTLS12})
	go func() { _, _ = io.WriteString(tc, get("bank.example")) }()
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(body), "Blocked by ACME") {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// An SNI that is not the frame's name gets no certificate.
	if _, err := h.tlsConnect(f, "other.example", a.pool()); err == nil {
		t.Error("a handshake for another name succeeded")
	}
	// No SNI at all.
	if _, err := h.tlsConnect(f, "", a.pool()); err == nil {
		t.Error("a handshake without SNI succeeded")
	}
}

func TestHTTPSWithNoKeyClosesTLSAndPort80Serves(t *testing.T) {
	h := newHarness(t)
	h.noKeys = true
	h.setAccount(ids(2), newAuthority(t, "A"))
	t0 := time.Now()
	if _, err := h.tlsConnect(frame("bank.example", 443, nil), "bank.example", nil); err == nil {
		t.Fatal("handshake without a key")
	} else if !strings.Contains(err.Error(), "internal error") {
		t.Errorf("not internal_error: %v", err)
	}
	if d := time.Since(t0); d > KeyWait+2*time.Second {
		t.Errorf("waited %s for a key", d)
	}
	if resp, _ := h.plain(frame("bank.example", 80, nil), get("bank.example")); resp.StatusCode != 403 {
		t.Error("port 80 did not serve")
	}
}

func TestEpochChangeDropsKeysAndLeaves(t *testing.T) {
	h := newHarness(t)
	a := newAuthority(t, "A")
	h.setAccount(ids(2), a)
	f := frame("bank.example", 443, nil)
	if _, err := h.tlsConnect(f, "bank.example", a.pool()); err != nil {
		t.Fatal(err)
	}
	if h.s.leafs.cache.ll.Len() != 1 {
		t.Fatal("no leaf cached")
	}
	// The agent's epoch moves; its next intermediate is of the old epoch (the
	// harness answers with h.epoch, which it has not changed).
	_ = h.agent.Send(&sock.BlockMsg{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: []byte("EPOCH002")}})
	waitFor(t, func() bool { return h.s.leafs.cache.ll.Len() == 0 })
	if _, err := h.tlsConnect(f, "bank.example", a.pool()); err == nil {
		t.Fatal("a key of the old epoch was used")
	}
	// With the harness following to the new epoch, the key is asked again and works.
	h.mu.Lock()
	h.epoch = []byte("EPOCH002")
	h.mu.Unlock()
	h.s.keys.mu.Lock()
	h.s.keys.lastAsk = map[[16]byte]time.Time{}
	h.s.keys.mu.Unlock()
	if _, err := h.tlsConnect(f, "bank.example", a.pool()); err != nil {
		t.Fatalf("after the new epoch: %v", err)
	}
}

func TestNoKeyIsUsedWhileTheAgentIsGone(t *testing.T) {
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
		return !h.s.keys.haveEpoch
	})
	if _, err := h.tlsConnect(f, "bank.example", a.pool()); err == nil {
		t.Fatal("a held key was used with no epoch from the agent")
	}
}

func TestMintRateIsBounded(t *testing.T) {
	h := newHarness(t)
	a := newAuthority(t, "A")
	h.setAccount(ids(2), a)
	failed := 0
	for i := 0; i < mintAccountBurst+10; i++ {
		name := "n" + itoa(i) + ".example"
		if _, err := h.tlsConnect(frame(name, 443, nil), name, a.pool()); err != nil {
			failed++
		}
	}
	if failed < 1 || failed > 12 {
		t.Errorf("%d handshakes failed over a burst of %d", failed, mintAccountBurst)
	}
}

func TestAgentFrameOfTheWrongKindEndsTheLink(t *testing.T) {
	h := newHarness(t)
	_ = h.agent.Send(&sock.BlockMsg{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: make([]byte, 32)}})
	waitFor(t, func() bool {
		h.s.link.mu.Lock()
		defer h.s.link.mu.Unlock()
		return h.s.link.conn == nil
	})
}

func TestLeafCacheBoundsPerAccount(t *testing.T) {
	c := newLeafCache()
	var acct [16]byte
	acct[0] = 1
	cert := &tls.Certificate{}
	na := time.Now().Add(24 * time.Hour)
	for i := 0; i < MaxLeavesPerAccount+50; i++ {
		c.add(leafKey{acct, "n" + itoa(i)}, cert, na, nil)
	}
	if c.perAcct[acct] != MaxLeavesPerAccount {
		t.Fatalf("%d leaves of one account", c.perAcct[acct])
	}
	var other [16]byte
	other[0] = 2
	for i := 0; i < MaxLeaves; i++ {
		c.add(leafKey{other, "m" + itoa(i)}, cert, na, nil)
	}
	if c.ll.Len() > MaxLeaves {
		t.Fatalf("%d leaves", c.ll.Len())
	}
}

func TestMessageAndTokenHelpers(t *testing.T) {
	if m, ok := cleanMessage("  a\r\nb\x00c\x7f  "); !ok || m != "a\nbc" {
		t.Errorf("clean: %q %v", m, ok)
	}
	if _, ok := cleanMessage("\xff"); ok {
		t.Error("invalid UTF-8 accepted")
	}
	long, _ := cleanMessage(strings.Repeat("ب", 600))
	if n := len([]rune(long)); n != MaxMessageChars {
		t.Errorf("%d characters kept", n)
	}
	now := time.Unix(1_000_000, 0)
	u, _ := newUnblocker(func() time.Time { return now })
	tok := u.token("n", ids(1), []byte{1, 2, 3, 4})
	if !u.valid(tok, "n", ids(1), []byte{1, 2, 3, 4}) || u.valid(tok, "m", ids(1), []byte{1, 2, 3, 4}) || u.valid(tok, "n", ids(2), []byte{1, 2, 3, 4}) {
		t.Error("token binding is wrong")
	}
	now = now.Add(time.Hour)
	if !u.valid(tok, "n", ids(1), []byte{1, 2, 3, 4}) {
		t.Error("the token of the hour before is refused")
	}
	now = now.Add(time.Hour)
	if u.valid(tok, "n", ids(1), []byte{1, 2, 3, 4}) {
		t.Error("a token two hours old is accepted")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}
