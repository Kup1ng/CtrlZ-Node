// Package listen holds the six listeners of the DNS role (p4-nodes.md 7.4):
// Plain UDP and TCP 53, DoT, DoH on TCP, DoH3 and DoQ. They are our own loops
// on the DNS library for messages, quic-go for QUIC and the standard library
// for TLS and HTTP (D52), because the loops of a ready-made DNS server do not
// meet L13 of the shared contract without patches.
//
// What a listener does: read a query, parse it, ask the name-form exemption,
// ask the limits (package limits) when the name is not exempt, and give the
// query to a Handler. What it never does: look at what the query means. The
// query path of SC 5.2 (identity, zone answers, policy, resolve) is the
// Handler, built in W7; this package is step 1 and the transports.
//
// Rules that hold on every listener, each tested:
//   - the source of a query is the address of its connection, never a header;
//   - a handler error or panic answers SERVFAIL for that query and never
//     closes the connection (T-549);
//   - no limit closes an accepted connection (L13 (2)); the only closes are
//     the idle deadline (armed only while nothing is unread or unanswered),
//     the write-stall deadline (the same), a protocol error, and a refusal
//     before the connection is accepted;
//   - nothing is logged: a listener has an Observer of counters and no
//     logger, so no name, address or request line reaches a sink (R21).
package listen

import (
	"context"
	"net/http"
	"net/netip"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// Transport is the listener a query came on.
type Transport = limits.Transport

// Transport names, re-exported so a handler needs one import.
const (
	UDP  = limits.UDP
	TCP  = limits.TCP
	DoT  = limits.DoT
	DoH  = limits.DoH
	DoH3 = limits.DoH3
	DoQ  = limits.DoQ
)

// HTTPInfo is what the query path needs of a DoH or DoH3 request (SC 3.4,
// P4 7.6). Header values are not passed on, only what the decisions read:
// the proof rule needs to know whether Origin, Referer and Sec-Fetch-Site
// are present, and nothing else about them.
type HTTPInfo struct {
	Path        string // URL path, as sent (the token is in it: never log it)
	Authority   string // :authority, or Host on HTTP/1.1
	Method      string // GET or POST
	ContentType string // as sent; empty for GET

	HasOrigin       bool
	HasReferer      bool
	HasSecFetchSite bool
}

// Request is one query as the query path sees it.
type Request struct {
	Msg       *dns.Msg
	Transport Transport

	// Source is the address of the connection or datagram, never taken from a
	// header (D52). A UDP source can be spoofed unless Validated says
	// otherwise.
	Source netip.AddrPort

	// Validated is true for TCP (a finished handshake), for DoT, DoH, DoH3 and
	// DoQ (a finished TLS or QUIC handshake), and for UDP only when the query
	// carried a server cookie this node made (RFC 9018) so the source address
	// is a real one.
	Validated bool

	// SNI is the TLS server name for DoT, DoH, DoH3 and DoQ, empty for Plain.
	SNI string

	// HTTP is set for DoH and DoH3 only.
	HTTP *HTTPInfo
}

// Reply is what a Handler gives back for a query.
type Reply struct {
	// Msg is the answer. The listener may change it (it adds the cookie option
	// and may truncate it for UDP), so the handler must not share it with
	// anything, a cache included.
	Msg *dns.Msg

	// Drop sends nothing for this query. It is for Plain DNS (the silent drop
	// of SC 5.2a and 4b); on an encrypted transport it is answered as SERVFAIL,
	// because those have a stream or a request to end.
	Drop bool

	// Status, on DoH and DoH3 only, is an HTTP status with no DNS message
	// (403 for a hard-disabled Endpoint, 404 for an unknown path or token). On
	// other transports it is ignored and Msg is used.
	Status int
}

// Handler is the query path. ServeDNS is called on its own goroutine for each
// query, with a context that ends at the listener's HandlerTimeout and when
// the listener closes; it must return soon after the context ends.
type Handler interface {
	ServeDNS(ctx context.Context, req *Request) Reply
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, req *Request) Reply

// ServeDNS calls f.
func (f HandlerFunc) ServeDNS(ctx context.Context, req *Request) Reply { return f(ctx, req) }

// Truncated is the answer for a query a limit stops on UDP, or that the query
// path wants retried over TCP: TC=1 and no records (L13 (4)).
func Truncated(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.Truncated = true
	m.RecursionAvailable = false
	return m
}

// ServFail is the answer for a query whose handler failed.
func ServFail(q *dns.Msg) *dns.Msg { return rcodeReply(q, dns.RcodeServerFailure) }

// Refused is the answer for a query a limit stops on an encrypted transport.
func Refused(q *dns.Msg) *dns.Msg { return rcodeReply(q, dns.RcodeRefused) }

func rcodeReply(q *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(q, rcode)
	return m
}

// VerifyHandler serves the HTTP side of `verify` (P4 7.6): GET /v on an SNI
// of the form *.verify.<zone>. W7 implements it. The listener calls it for a
// request whose path is /v when VerifyHost says its SNI is a verify host, and
// leaves every header, the CORS answer included, to it.
type VerifyHandler interface {
	http.Handler
	// VerifyHost reports whether a TLS server name is a verify host.
	VerifyHost(sni string) bool
}

// CloseReason says why a listener closed a connection it had accepted, for
// the Observer. A connection that a limit refused before it was accepted is
// not here: see Observer.Refused.
type CloseReason uint8

const (
	CloseIdle      CloseReason = iota + 1 // idle deadline, nothing unread or unanswered
	CloseStall                            // a reply the peer did not read for the write-stall time
	CloseProtocol                         // a malformed message, or a frame that did not arrive
	CloseHandshake                        // TLS or QUIC handshake deadline or failure
	ClosePeer                             // the peer closed or reset it
	CloseShutdown                         // the listener stopped
	CloseHTTP                             // DoH only: net/http closed it (idle deadline, a protocol error) with no sign that the peer had gone
	CloseDrain                            // the drain rule (SC 8a.6): the node is no longer advertised and closed the connection gracefully
)

// Observer receives counts and no content. Every field is optional. A field is
// called from a listener goroutine and must be cheap and must not block.
type Observer struct {
	// Closed: an accepted connection was closed, and why.
	Closed func(t Transport, why CloseReason)
	// Refused: a connection limit refused a new connection before it was
	// accepted.
	Refused func(t Transport)
	// Stopped: a query limit stopped a query.
	Stopped func(t Transport)
	// Panic: a handler panicked and the query was answered SERVFAIL. The
	// panic value is never passed on: it could hold request data.
	Panic func(t Transport)
	// Dropped: a UDP datagram was dropped by a rule of step 1, or by the
	// in-flight cap.
	Dropped func(t Transport)
}
