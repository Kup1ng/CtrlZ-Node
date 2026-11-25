package resolve

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// maxUpstreamTimeout mirrors shared/wire ValidateNodeConfig (timeout_ms is at
// most 60 s), so a Config that passes there always passes here.
const maxUpstreamTimeout = 60 * time.Second

// defaultDoHPath is the RFC 8484 conventional path, used when the address of a
// DoH upstream carries none.
const defaultDoHPath = "/dns-query"

// Refusals. They are sentinel values so a test (N6 of the P4 spec) and the
// agent can tell "the config is wrong" from "the server did not answer".
var (
	ErrNoBootstrap     = errors.New("resolve: upstream has no bootstrap IP and no numeric address")
	ErrNoTimeout       = errors.New("resolve: upstream timeout must be above zero")
	ErrBadKind         = errors.New("resolve: unsupported upstream kind")
	ErrBadAddress      = errors.New("resolve: bad upstream address")
	ErrBootstrapAddr   = errors.New("resolve: bad bootstrap address")
	ErrBootstrapDiffer = errors.New("resolve: bootstrap IP differs from the numeric address")
	// ErrViaLocation: 7.7 of the P4 spec refuses an upstream that asks to be
	// reached through another location until P4b. Dialling it directly would
	// send the query from this node's own address, which is the opposite of
	// what the hub asked for.
	ErrViaLocation = errors.New("resolve: via_location upstreams are not supported")
	// ErrBadQuery: the query to forward has no single question.
	ErrBadQuery = errors.New("resolve: query must carry exactly one question")
	// ErrBadReply: the reply does not answer the question that was asked.
	ErrBadReply = errors.New("resolve: reply does not match the question")
)

// Config describes one upstream, field for field the hub's Upstream message
// (SC 8a.11) without the fields that are not about connecting.
type Config struct {
	Kind commonv1.UpstreamKind
	// Address is "ip:port" for udp (as netip.AddrPort prints it), and
	// "host[:port]" for dot and doq. For doh it may carry a path
	// ("host[:port]/path", default /dns-query). The host may be a name or an
	// IP literal.
	Address string
	// BootstrapIP is where a named host is dialled. It is the only address
	// source for a name: nothing is ever looked up.
	BootstrapIP netip.Addr
	// TLSName is the name the server certificate is checked against. Empty
	// means the host of Address.
	TLSName string
	Timeout time.Duration
	// RootCAs replaces the system roots for the TLS kinds. Production leaves
	// it nil; it exists for private-CA upstreams and for tests.
	RootCAs *x509.CertPool
	// There is deliberately no logger field. dnsproxy logs the query name, type
	// and ID of every exchange (debug) and of every timeout (error), so
	// handing it a logger would put the name a user asked for into the journal
	// (SC 5.2a "No trace"). Its lines are always discarded; the node logs from
	// its own code, and a caller that logs an Exchange error gets text with
	// the query already cut out of it.
}

// ConfigFromWire converts a hub Upstream message into a Config. It checks only
// what a Config cannot carry (via_location, the shape of the bootstrap bytes);
// NewUpstream does the rest, so the address rules live in one place.
func ConfigFromWire(u *hubv1.Upstream) (Config, error) {
	if u.GetViaLocation() != 0 {
		return Config{}, ErrViaLocation
	}
	cfg := Config{
		Kind:    u.GetKind(),
		Address: u.GetAddress(),
		TLSName: u.GetTlsName(),
		Timeout: time.Duration(u.GetTimeoutMs()) * time.Millisecond,
	}
	if b := u.GetBootstrapIp(); len(b) != 0 {
		ip, ok := netip.AddrFromSlice(b)
		if !ok {
			return Config{}, fmt.Errorf("%w: %d bytes", ErrBootstrapAddr, len(b))
		}
		cfg.BootstrapIP = ip
	}
	return cfg, nil
}

// Upstream is one built upstream client. NewUpstream is the only way to get
// one, so every Upstream in the process has an explicit bootstrap address and
// a timeout above zero (T-550, rule 9).
type Upstream struct {
	u         upstream.Upstream
	kind      commonv1.UpstreamKind
	bootstrap netip.Addr
	timeout   time.Duration
}

// NewUpstream builds an upstream client from cfg. For udp, DoT and DoQ it wraps
// dnsproxy's upstream.AddressToUpstream, never the other constructors; DoH is
// our own client (D66). It refuses a
// config that would make dnsproxy fall back to the host resolver (nil
// Bootstrap) or run with no deadline (zero Timeout), both of which dnsproxy
// accepts silently.
func NewUpstream(cfg Config) (*Upstream, error) {
	if cfg.Timeout <= 0 {
		return nil, ErrNoTimeout
	}
	if cfg.Timeout > maxUpstreamTimeout {
		return nil, fmt.Errorf("%w: timeout above %s", ErrBadAddress, maxUpstreamTimeout)
	}

	rawURL, bootstrap, err := upstreamURL(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Kind == commonv1.UpstreamKind_UPSTREAM_KIND_DOH {
		// D66: DoH is our own client, never dnsproxy's (see doh.go).
		c, err := newDoHClient(rawURL, bootstrap, cfg.RootCAs, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		return &Upstream{u: c, kind: cfg.Kind, bootstrap: bootstrap, timeout: cfg.Timeout}, nil
	}

	opts := &upstream.Options{
		Logger:    slog.New(slog.DiscardHandler),
		RootCAs:   cfg.RootCAs,
		Timeout:   cfg.Timeout,
		Bootstrap: upstream.StaticResolver{bootstrap},
		// No h3: DoH3 upstreams are not a node_upstreams kind (D51).
		HTTPVersions: []upstream.HTTPVersion{upstream.HTTPVersion2, upstream.HTTPVersion11},
	}
	u, err := upstream.AddressToUpstream(rawURL, opts)
	if err != nil {
		// dnsproxy's error text can quote the URL, which holds the address; the
		// address is configuration, not a secret, but keep the cause out of
		// the sentinel so callers match on ErrBadAddress only.
		return nil, fmt.Errorf("%w: %v", ErrBadAddress, err)
	}
	return &Upstream{u: u, kind: cfg.Kind, bootstrap: bootstrap, timeout: cfg.Timeout}, nil
}

// upstreamURL turns cfg into the URL dnsproxy parses, and returns the one
// address the upstream may dial. It never accepts a scheme of its own, so
// "sdns://" stamps (which overwrite Bootstrap inside dnsproxy), DNSCrypt and
// h3 cannot reach dnsproxy.
func upstreamURL(cfg Config) (string, netip.Addr, error) {
	var scheme string
	switch cfg.Kind {
	case commonv1.UpstreamKind_UPSTREAM_KIND_UDP:
		scheme = "udp"
	case commonv1.UpstreamKind_UPSTREAM_KIND_DOT:
		scheme = "tls"
	case commonv1.UpstreamKind_UPSTREAM_KIND_DOH:
		scheme = "https"
	case commonv1.UpstreamKind_UPSTREAM_KIND_DOQ:
		scheme = "quic"
	default:
		return "", netip.Addr{}, fmt.Errorf("%w: %d", ErrBadKind, cfg.Kind)
	}
	if strings.Contains(cfg.Address, "://") || strings.ContainsAny(cfg.Address, " \t\r\n@?#") {
		return "", netip.Addr{}, fmt.Errorf("%w: not a bare host", ErrBadAddress)
	}

	if cfg.Kind == commonv1.UpstreamKind_UPSTREAM_KIND_UDP {
		ap, err := netip.ParseAddrPort(cfg.Address)
		if err != nil || ap.Port() == 0 {
			return "", netip.Addr{}, fmt.Errorf("%w: udp needs ip:port", ErrBadAddress)
		}
		if err := checkBootstrap(ap.Addr()); err != nil {
			return "", netip.Addr{}, err
		}
		if cfg.BootstrapIP.IsValid() && cfg.BootstrapIP != ap.Addr() {
			return "", netip.Addr{}, ErrBootstrapDiffer
		}
		return scheme + "://" + ap.String(), ap.Addr(), nil
	}

	hostport, path, _ := strings.Cut(cfg.Address, "/")
	if path != "" && cfg.Kind != commonv1.UpstreamKind_UPSTREAM_KIND_DOH {
		return "", netip.Addr{}, fmt.Errorf("%w: a path is only for doh", ErrBadAddress)
	}
	host, port := hostport, ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return "", netip.Addr{}, fmt.Errorf("%w: port", ErrBadAddress)
		}
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
	}
	if host == "" {
		return "", netip.Addr{}, fmt.Errorf("%w: empty host", ErrBadAddress)
	}

	// The bootstrap address: an explicit one, or the numeric host itself.
	bootstrap := cfg.BootstrapIP
	numeric, numErr := netip.ParseAddr(host)
	if numErr == nil {
		if bootstrap.IsValid() && bootstrap != numeric {
			return "", netip.Addr{}, ErrBootstrapDiffer
		}
		bootstrap = numeric
	}
	if !bootstrap.IsValid() {
		return "", netip.Addr{}, ErrNoBootstrap
	}
	if err := checkBootstrap(bootstrap); err != nil {
		return "", netip.Addr{}, err
	}

	// The name in the URL is the TLS server name. A TLSName replaces the
	// host, while the dial still goes to the bootstrap address. It must be a
	// name, never an IP literal: dnsproxy dials an IP host directly and skips
	// Options.Bootstrap, so an IP tls_name would move the dial away from the
	// address that BootstrapIP() reports and the SC 5.2a checks looked at.
	name := host
	if cfg.TLSName != "" {
		if strings.ContainsAny(cfg.TLSName, "/:@?# ") {
			return "", netip.Addr{}, fmt.Errorf("%w: tls_name", ErrBadAddress)
		}
		if _, err := netip.ParseAddr(cfg.TLSName); err == nil {
			return "", netip.Addr{}, fmt.Errorf("%w: tls_name is an IP address", ErrBadAddress)
		}
		name = cfg.TLSName
	}
	if numErr == nil && cfg.TLSName == "" {
		// A numeric host with no tls_name: the certificate must carry the IP.
		name = numeric.String()
	}
	if port == "" {
		switch cfg.Kind {
		case commonv1.UpstreamKind_UPSTREAM_KIND_DOH:
			port = "443"
		default:
			port = "853"
		}
	}
	u := url.URL{Scheme: scheme, Host: hostPort(name, port)}
	if cfg.Kind == commonv1.UpstreamKind_UPSTREAM_KIND_DOH {
		u.Path = "/" + path
		if path == "" {
			u.Path = defaultDoHPath
		}
	}
	return u.String(), bootstrap, nil
}

// hostPort brackets an IPv6 literal.
func hostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// embeddedV4Prefixes are the IPv6 ranges that stand for an IPv4 address (SC 11:
// NAT64, IPv4-compatible, 6to4, Teredo). The same host would compare unequal
// to the IPv4 it reaches, and the loop checks of SC 5.2a compare by equality.
// shared/netclass keeps its own copy unexported; it is canonical in the Panel
// repository, so the list is repeated here rather than changed in the sync.
func embeddedV4Prefixes() []netip.Prefix {
	m := netip.MustParsePrefix
	return []netip.Prefix{m("64:ff9b::/96"), m("::/96"), m("2002::/16"), m("2001::/32")}
}

// checkBootstrap refuses the forms that are not one canonical address: the
// IPv4-mapped form and every IPv6 range that embeds an IPv4 address. ::1 stays
// valid, as in netclass, where the loopback row matches before the embedded
// forms.
func checkBootstrap(a netip.Addr) error {
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" || a.Is4In6() {
		return fmt.Errorf("%w: %s", ErrBootstrapAddr, a)
	}
	if a.Is6() && a != netip.IPv6Loopback() {
		for _, p := range embeddedV4Prefixes() {
			if p.Contains(a) {
				return fmt.Errorf("%w: %s embeds an IPv4 address", ErrBootstrapAddr, a)
			}
		}
	}
	return nil
}

// Exchange sends req and returns the reply. It returns within one Timeout, and
// at once when ctx ends, whatever the transport does: dnsproxy's DoT dial has
// a fixed 10 s handshake limit that ignores Options.Timeout and ctx, and its
// plain UDP/TCP and DoH paths retry once with a fresh timeout, so the bound is
// enforced here. A call abandoned that way finishes inside dnsproxy on its own
// deadline and its result is dropped.
//
// req must carry exactly one question (dnsproxy indexes it unchecked and
// panics on none). The reply must carry the same question (name compared
// without case, type and class): dnsproxy checks that only for plain and DoH,
// so a DoT or DoQ server could otherwise answer for another name. A reply and
// an error are never returned together.
//
// The query that leaves the node always carries a fresh random ID, never the
// caller's: dnsproxy keeps a non-zero ID as it is, and a client that knows the
// ID of the node's plain UDP query only has the source port left to guess when
// it sprays forged replies. The reply gets the caller's ID back, and req is
// not modified.
//
// The error text never contains the query or the reply body: a DoH client
// error quotes the request URL, whose dns= parameter is the packed query, and
// one for a reply that does not unpack quotes the body (SC 5.2a). The text is
// printable ASCII and at most maxErrorText bytes.
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) != 1 {
		return nil, ErrBadQuery
	}
	out := req.Copy()
	out.Id = dns.Id()

	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()

	type result struct {
		resp *dns.Msg
		err  error
	}
	// Buffered, so an abandoned call can still deliver and exit.
	done := make(chan result, 1)
	go func() {
		resp, err := u.u.Exchange(ctx, out)
		done <- result{resp, err}
	}()

	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		return nil, fmt.Errorf("resolve: exchange: %w", ctx.Err())
	}
	if r.err != nil {
		return nil, redactedError{r.err}
	}
	if r.resp == nil || len(r.resp.Question) != 1 || !sameQuestion(r.resp.Question[0], req.Question[0]) {
		return nil, ErrBadReply
	}
	r.resp.Id = req.Id
	return r.resp, nil
}

func sameQuestion(a, b dns.Question) bool {
	return a.Qtype == b.Qtype && a.Qclass == b.Qclass && strings.EqualFold(a.Name, b.Name)
}

// queryParam matches the packed query in a DoH request URL.
var queryParam = regexp.MustCompile(`dns=[A-Za-z0-9_=-]*`)

// bodyMarker precedes the raw reply body in dnsproxy's "unpacking response"
// error for DoH. The body is whatever the upstream sent (up to 64 KiB), and a
// DNS reply echoes the question, so it can hold the qname and any bytes a
// hostile record put there, newlines included. The address before the marker
// is configuration and has no spaces, so the first marker is the real one.
const bodyMarker = "body is "

// maxErrorText caps what Error returns; the cause stays whole behind Unwrap.
const maxErrorText = 512

// redactedError keeps the cause for errors.Is and errors.As (a deadline stays
// a deadline) and cuts what must not reach a log from the text: the DoH query,
// the DoH reply body with everything after it, and any byte that is not
// printable ASCII (so an upstream cannot forge a log line).
type redactedError struct{ err error }

func (e redactedError) Error() string {
	s := e.err.Error()
	if i := strings.Index(s, bodyMarker); i >= 0 {
		s = s[:i+len(bodyMarker)] + "<cut>"
	}
	s = queryParam.ReplaceAllString(s, "dns=<cut>")
	b := make([]byte, 0, min(len(s), maxErrorText))
	for i := 0; i < len(s) && len(b) < maxErrorText; i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b = append(b, c)
	}
	return string(b)
}

func (e redactedError) Unwrap() error { return e.err }

// Kind returns the configured kind.
func (u *Upstream) Kind() commonv1.UpstreamKind { return u.kind }

// BootstrapIP returns the only address this upstream dials. N6 walks it.
func (u *Upstream) BootstrapIP() netip.Addr { return u.bootstrap }

// Timeout returns the per-exchange timeout, always above zero.
func (u *Upstream) Timeout() time.Duration { return u.timeout }

// Close releases the pooled connections.
func (u *Upstream) Close() error {
	var c io.Closer = u.u
	return c.Close()
}
