package resolve

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The DoH upstream client is our own, on net/http (Plan.md D66).
//
// Why not dnsproxy's: its DoH upstream resets its HTTP client on every error,
// and the old transport keeps its in-flight connections for five minutes, so
// the bound of two connections belongs to one transport and not to one
// upstream. A tenant, or a free-DNS user whose misses reach the same upstream,
// could make it slow on purpose and take descriptors and conntrack entries
// without limit (docs/research/p4-t551.md section 6, point 5). Here the
// Transport is created once and never replaced, so MaxConnsPerHost is a bound on
// the upstream whatever errors happen.

// dohMaxConns bounds the connections to one DoH upstream. HTTP/2 multiplexes
// about 100 streams on each, so eight carry some 800 queries in flight, which at
// a far upstream's 60 ms is about 13,000 a second: sized by p4-t551.md (peak
// queries a second times the round trip, over streams per connection). A server
// that speaks only HTTP/1.1 gets one query per connection, so eight in flight;
// such an upstream is a poor choice and the cap is what keeps it harmless.
const dohMaxConns = 8

// An HTTP/2 connection that has been idle for dohSendPing gets a PING, and one
// that does not answer within dohPingTimeout is closed. The Transport is never
// replaced (D66), which was dnsproxy's only way out of a connection that a
// firewall or NAT had silently dropped: without a liveness check such a
// connection would sit in the pool and time out every query sent on it until the
// kernel gave up, and the health probe would use the same dead connection.
const (
	dohSendPing    = 5 * time.Second
	dohPingTimeout = 5 * time.Second
)

// dohHandshakeSlack is how much longer than the call deadline a TLS handshake
// may take before the transport gives up on it.
const dohHandshakeSlack = time.Second

// maxDoHReply is the largest DNS message there is.
const maxDoHReply = 65535

type dohClient struct {
	addr    string // human readable, for Address(): host and path, no query
	url     string
	tr      *http.Transport
	client  *http.Client
	timeout time.Duration

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	// peak and total are the most connections open at once and the number ever
	// dialled, as this client saw them: a test reads them, because a server sees
	// a closed connection later than the client lets go of its slot.
	peak, total int
	closed      bool
}

// newDoHClient builds the client for rawURL (https://name:port/path, the name
// being the TLS server name) that dials only dial.
func newDoHClient(rawURL string, dial netip.Addr, roots *x509.CertPool, timeout time.Duration) (*dohClient, error) {
	return newDoHClientPing(rawURL, dial, roots, timeout, dohSendPing, dohPingTimeout)
}

// newDoHClientPing is newDoHClient with the liveness ping times of the HTTP/2
// connections given, so a test can run them in milliseconds.
func newDoHClientPing(rawURL string, dial netip.Addr, roots *x509.CertPool, timeout, sendPing, pingTimeout time.Duration) (*dohClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: doh url", ErrBadAddress)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, fmt.Errorf("%w: port", ErrBadAddress)
	}
	target := net.JoinHostPort(dial.String(), port)
	c := &dohClient{timeout: timeout, conns: map[net.Conn]struct{}{}}
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// The only address this client may dial is the bootstrap address. The
		// address in the URL, a name, is never looked up (T-550, rule 9).
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := d.DialContext(ctx, network, target)
			if err != nil {
				return nil, err
			}
			return c.track(conn), nil
		},
		TLSClientConfig: &tls.Config{
			ServerName: u.Hostname(), // the tls_name, or the host when there is none
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:   true,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: sendPing, PingTimeout: pingTimeout},
		MaxConnsPerHost:     dohMaxConns,
		MaxIdleConnsPerHost: dohMaxConns,
		MaxIdleConns:        dohMaxConns,
		// net/http dials on a context cut off from the request's (it uses
		// context.WithoutCancel), so a request whose deadline has passed leaves
		// its dial and TLS handshake running, and that dial keeps one of the
		// MaxConnsPerHost slots. Only this timer ends a handshake that the peer
		// never answers; without it eight such stalls lock the upstream until the
		// Router is closed (p4n-W7-r5-1). It is longer than the call deadline by
		// dohHandshakeSlack so the call context always fires first and Exchange
		// reports a deadline, not "TLS handshake timeout" (p4n-W7-r4-1).
		TLSHandshakeTimeout:   timeout + dohHandshakeSlack,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 0,
		Proxy:                 nil, // an environment proxy must never carry upstream traffic
		DisableCompression:    true,
	}
	c.addr, c.url, c.tr = u.Host+u.Path, u.String(), tr
	c.client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}

// track remembers a connection so Close can end the busy ones too: closing the
// idle connections of an http.Transport leaves any that still carry a stream.
func (c *dohClient) track(conn net.Conn) net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = conn.Close()
		return conn
	}
	t := &trackedConn{Conn: conn, owner: c}
	c.conns[t] = struct{}{}
	c.total++
	if len(c.conns) > c.peak {
		c.peak = len(c.conns)
	}
	return t
}

type trackedConn struct {
	net.Conn
	owner *dohClient
}

func (t *trackedConn) Close() error {
	t.owner.mu.Lock()
	delete(t.owner.conns, t)
	t.owner.mu.Unlock()
	return t.Conn.Close()
}

// Exchange sends req as an RFC 8484 POST. A POST keeps the packed query out of
// the URL, so no client or proxy error can quote it. The query goes with ID 0, as
// the RFC asks, and the reply keeps the ID the caller's Exchange puts back.
func (c *dohClient) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Copy()
	q.Id = 0
	wire, err := q.Pack()
	if err != nil {
		return nil, errors.New("doh: cannot pack the query")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(wire))
	if err != nil {
		return nil, errors.New("doh: cannot build the request")
	}
	hr.Header.Set("Content-Type", "application/dns-message")
	hr.Header.Set("Accept", "application/dns-message")
	resp, err := c.client.Do(hr)
	if err != nil {
		// A url.Error quotes the URL, whose path may be a secret of the upstream
		// account. Keep the cause (a deadline stays a deadline) and drop the URL.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("doh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("doh: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHReply+1))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("doh: reading the reply: %w", err)
	}
	if len(body) > maxDoHReply {
		return nil, errors.New("doh: reply too large")
	}
	out := new(dns.Msg)
	if out.Unpack(body) != nil {
		// Never quote the body: it echoes the qname and is whatever the
		// upstream sent (SC 5.2a, No trace).
		return nil, errors.New("doh: the reply is not a DNS message")
	}
	return out, nil
}

// Address is the host and path, no query and no scheme.
func (c *dohClient) Address() string { return c.addr }

// Close ends every connection of the pool, the busy ones too. The upstream is
// not used after it.
func (c *dohClient) Close() error {
	c.mu.Lock()
	c.closed = true
	open := make([]net.Conn, 0, len(c.conns))
	for k := range c.conns {
		open = append(open, k)
	}
	c.mu.Unlock()
	c.tr.CloseIdleConnections()
	for _, k := range open {
		_ = k.Close()
	}
	return nil
}
