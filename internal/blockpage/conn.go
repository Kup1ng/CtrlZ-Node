package blockpage

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

const unblockPath = "/.ctrlz/unblock"

// ServeConn serves one connection of serve.sock: the proxy's frame, then the
// client's bytes. It owns c and closes it. One request a connection, 5 s to read
// it (the TLS handshake included), 30 s for the whole connection (10.2).
func (s *Server) ServeConn(c net.Conn) {
	start := time.Now()
	defer c.Close()
	_ = c.SetDeadline(start.Add(ReadTimeout))
	// The frame is read byte-exact, with nothing buffered past it, so what follows
	// on the connection is the client's.
	f, err := sock.ServeCodec.Read(c)
	if err != nil {
		return
	}
	var rw io.ReadWriteCloser = c
	https := f.Port == 443
	if https {
		tc := tls.Server(c, s.tlsConfig(f))
		ctx, cancel := context.WithTimeout(context.Background(), ReadTimeout)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			return
		}
		rw = tc
	}
	defer func() { _ = rw.Close() }()
	s.request(c, rw, f, https, start)
}

// tlsConfig is the config of one connection: the name must be the frame's, and the
// leaf is minted under the key of the frame's account. A failure of any kind comes
// out as a handshake error, which Go sends as internal_error (10.2).
func (s *Server) tlsConfig(f *sock.ServeFrame) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !strings.EqualFold(strings.TrimSuffix(h.ServerName, "."), f.Name) {
				return nil, errors.New("blockpage: the name is not the frame's")
			}
			ctx := h.Context()
			k, err := s.keys.get(ctx, f.Endpoint, f.Account)
			if err != nil {
				return nil, err
			}
			return s.leafs.certificate(ctx, f.Account, f.Name, k)
		},
	}
}

// request reads one request and answers it. raw is the unix connection, whose
// deadlines are the ones that count; rw is the TLS side or the same connection.
func (s *Server) request(raw net.Conn, rw io.ReadWriter, f *sock.ServeFrame, https bool, start time.Time) {
	lr := &io.LimitedReader{R: rw, N: MaxHeaderBytes}
	br := bufio.NewReaderSize(lr, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		status := http.StatusBadRequest
		if lr.N <= 0 {
			status = http.StatusRequestHeaderFieldsTooLarge
		}
		writeEmpty(rw, status)
		return
	}
	// The body is allowed after the headers were read under their own cap.
	lr.N += MaxFormBody + 1
	_ = raw.SetDeadline(start.Add(ConnTimeout))

	// Anything but a page load gets an empty 403: a script, an image or a frame of
	// a blocked site must not receive markup (10.4).
	if d := req.Header.Get("Sec-Fetch-Dest"); d != "" && d != "document" {
		writeEmpty(rw, http.StatusForbidden)
		return
	}
	lang := pickLang(req.Header.Get("Accept-Language"))
	switch {
	case req.Method == http.MethodPost && req.URL.Path == unblockPath:
		s.unblock(rw, req, f, https, lang)
	case req.Method == http.MethodGet || req.Method == http.MethodHead:
		s.page(rw, req, f, lang)
	default:
		writeEmpty(rw, http.StatusMethodNotAllowed)
	}
}

// page answers a page load: status 403 with the page of the frame's hash.
func (s *Server) page(w io.Writer, req *http.Request, f *sock.ServeFrame, lang *texts) {
	p := s.pages.get(req.Context(), f.Account, f.PageHash)
	token := ""
	if p.Custom && p.Mode == policyv1.UnblockMode_UNBLOCK_MODE_REQUEST && len(p.Profile) == 16 {
		token = s.unb.token(f.Name, f.Endpoint, f.Source)
	}
	nonce := newNonce()
	r, err := p.render(lang, f.Name, nonce, token)
	if err != nil {
		writeEmpty(w, http.StatusInternalServerError)
		return
	}
	writePage(w, http.StatusForbidden, nonce, r, req.Method == http.MethodHead)
}

// unblock takes the form (10.4). The order is cheapest check first, and nothing is
// relayed that the token, the origin and the sizes have not passed.
func (s *Server) unblock(w io.Writer, req *http.Request, f *sock.ServeFrame, https bool, lang *texts) {
	p := s.pages.get(req.Context(), f.Account, f.PageHash)
	if !p.Custom || p.Mode != policyv1.UnblockMode_UNBLOCK_MODE_REQUEST || len(p.Profile) != 16 {
		writeEmpty(w, http.StatusForbidden)
		return
	}
	if !sameOrigin(req, f.Name, https) {
		writeEmpty(w, http.StatusForbidden)
		return
	}
	if req.ContentLength < 0 || req.ContentLength > MaxFormBody {
		writeEmpty(w, http.StatusRequestEntityTooLarge)
		return
	}
	if ct := req.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		writeEmpty(w, http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, MaxFormBody+1))
	if err != nil || len(raw) > MaxFormBody {
		writeEmpty(w, http.StatusRequestEntityTooLarge)
		return
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil || !s.unb.valid(form.Get("t"), f.Name, f.Endpoint, f.Source) {
		writeEmpty(w, http.StatusForbidden)
		return
	}
	msg, ok := cleanMessage(form.Get("m"))
	if !ok {
		writeEmpty(w, http.StatusBadRequest)
		return
	}
	if s.unb.admit(f.Endpoint, f.Source) {
		wn, err := names.FromString(f.Name)
		if err != nil || wn.IsRoot() {
			writeEmpty(w, http.StatusBadRequest)
			return
		}
		sent := s.link.send(&sock.BlockMsg{Type: sock.BlockUnblock, Unblock: &sock.UnblockMsg{
			Endpoint: f.Endpoint, Profile: p.Profile, Name: f.Name, Message: msg, At: s.now().Unix()}})
		if !sent {
			// The agent is not there to take it: say so, the visitor may try again.
			writeEmpty(w, http.StatusServiceUnavailable)
			return
		}
	}
	nonce := newNonce()
	r, err := p.renderReceived(lang, f.Name, nonce)
	if err != nil {
		writeEmpty(w, http.StatusInternalServerError)
		return
	}
	writePage(w, http.StatusOK, nonce, r, false)
}

// sameOrigin judges the form's origin. A page with Referrer-Policy no-referrer
// makes the browser send "Origin: null" on its own same-origin form post, so null
// is accepted; it is the token that stops a cross-site post, because the other
// site cannot read a token from this one. A named origin must be this one, and a
// Sec-Fetch-Site that says cross-site is refused whatever the origin says.
func sameOrigin(req *http.Request, name string, https bool) bool {
	scheme := "http"
	if https {
		scheme = "https"
	}
	if o := req.Header.Get("Origin"); o != "" && o != "null" && o != scheme+"://"+name {
		return false
	}
	if site := req.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	return true
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func csp(nonce string) string {
	return "default-src 'none'; style-src 'nonce-" + nonce + "'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
}

// writeHeaders writes a status line and the headers every answer has: no cache, no
// sniffing, no referrer, no cookie and no HSTS (10.4).
func writeHeaders(w io.Writer, status int, length int, extra string) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status) + "\r\n")
	b.WriteString("Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n")
	b.WriteString(extra)
	b.WriteString("Content-Length: " + strconv.Itoa(length) + "\r\n\r\n")
	_, _ = io.WriteString(w, b.String())
}

func writeEmpty(w io.Writer, status int) {
	extra := ""
	if status == http.StatusMethodNotAllowed {
		extra = "Allow: GET, HEAD, POST\r\n"
	}
	writeHeaders(w, status, 0, extra)
}

// writePage writes the head, the logo from the cache and the tail. Nothing is
// joined into one buffer, so the logo is not copied per connection.
func writePage(w io.Writer, status int, nonce string, r *rendered, headOnly bool) {
	writeHeaders(w, status, r.size(),
		"Content-Type: text/html; charset=utf-8\r\nContent-Security-Policy: "+csp(nonce)+"\r\n")
	if headOnly {
		return
	}
	bw := bufio.NewWriterSize(w, 4096)
	_, _ = bw.Write(r.head)
	if r.logo != "" {
		_, _ = bw.WriteString(r.logo)
		_, _ = bw.Write(r.tail)
	}
	_ = bw.Flush()
}
