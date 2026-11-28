package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/textproto"
	"time"
)

// What the proxy reads before it knows where a connection goes: the ClientHello on
// 443 or the first request on 80 (5.2 step 2). Both are bounded by 16 KiB and by
// the pool's time, and both keep every byte they read so the target can be sent
// the same bytes again.

// MaxSniff is the most a connection may send before its destination is known.
const MaxSniff = 16 << 10

var (
	errSniffLimit = errors.New("proxy: the first bytes are over the sniff limit")
	errSniffStop  = errors.New("proxy: hello parsed")
	errBadRequest = errors.New("proxy: refused request")
)

// recorder is a connection that remembers what it reads and writes nothing: crypto/tls
// answers a bad hello with an alert, and the client must get no byte from us before
// the verdict. It fails once more than MaxSniff has been read.
type recorder struct {
	net.Conn
	buf []byte
}

func (r *recorder) Read(p []byte) (int, error) {
	room := MaxSniff - len(r.buf)
	if room <= 0 {
		return 0, errSniffLimit
	}
	if len(p) > room {
		p = p[:room]
	}
	n, err := r.Conn.Read(p)
	r.buf = append(r.buf, p[:n]...)
	return n, err
}

// Write pretends: nothing may reach the client from the TLS layer.
func (r *recorder) Write(p []byte) (int, error) { return len(p), nil }

// sniffTLS reads a ClientHello from c and returns its server name and every byte it
// read. The standard library parses it, so record splits and large hellos (post
// quantum key shares) are its business and not ours.
func sniffTLS(c net.Conn, deadline time.Time) (name string, recorded []byte, err error) {
	_ = c.SetReadDeadline(deadline)
	defer c.SetReadDeadline(time.Time{})
	rec := &recorder{Conn: c}
	cfg := &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errSniffStop
		},
	}
	herr := tls.Server(rec, cfg).Handshake()
	if herr == nil || !errors.Is(herr, errSniffStop) {
		// A hello that did not parse, a read that failed or the limit.
		return "", rec.buf, errBadRequest
	}
	return name, rec.buf, nil
}

// httpFirst is what the first request of a port 80 connection says.
type httpFirst struct {
	Host     string // the host to look up, from Host or the absolute-form target
	Movable  bool   // GET or HEAD with no body: the request may be sent to a later target
	Recorded []byte
}

// sniffHTTP reads the first request. A CONNECT, and an absolute-form target whose
// host differs from the Host header, are refused (5.2 step 2): the second is how a
// proxy-aware client names one host and asks for another, and the node dials the
// name that dns judged, which must be the one that is asked for. Later requests of
// the connection are not parsed, the destination is fixed.
func sniffHTTP(c net.Conn, deadline time.Time) (*httpFirst, error) {
	_ = c.SetReadDeadline(deadline)
	defer c.SetReadDeadline(time.Time{})
	rec := &recorder{Conn: c}
	req, err := http.ReadRequest(bufio.NewReaderSize(rec, MaxSniff))
	if err != nil {
		return nil, errBadRequest
	}
	if req.Method == http.MethodConnect {
		return nil, errBadRequest
	}
	hdr := rawHost(rec.buf)
	host := req.Host
	if req.URL != nil && req.URL.Host != "" {
		if hdr != "" && !sameHost(hdr, req.URL.Host) {
			return nil, errBadRequest
		}
		host = req.URL.Host
	} else if host == "" {
		host = hdr
	}
	if host == "" {
		return nil, errBadRequest
	}
	movable := (req.Method == http.MethodGet || req.Method == http.MethodHead) &&
		req.ContentLength <= 0 && len(req.TransferEncoding) == 0
	return &httpFirst{Host: hostOnly(host), Movable: movable, Recorded: rec.buf}, nil
}

// rawHost is the Host header as the client wrote it. net/http folds an absolute-form
// target into req.Host and drops the header, so the comparison of 5.2 step 2 reads
// the recorded bytes again.
func rawHost(b []byte) string {
	tr := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
	if _, err := tr.ReadLine(); err != nil {
		return ""
	}
	h, _ := tr.ReadMIMEHeader()
	return h.Get("Host")
}

func sameHost(a, b string) bool {
	_, ta, ea := normalize(hostOnly(a))
	_, tb, eb := normalize(hostOnly(b))
	return ea == nil && eb == nil && ta == tb
}
