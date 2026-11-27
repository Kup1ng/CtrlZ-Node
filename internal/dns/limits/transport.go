// Package limits is the one place where the step-1 limits of the query path
// (SC 5.2 step 1, SC 8a.11 L13) are decided and enforced.
//
// Why one package: L13 is a set of properties that must hold for every limit
// at once (a limit acts on one query and never closes a connection, a TCP 53
// limit never has a source in its key, a QUIC connection counts only after its
// handshake, the name-form exemption runs before any limit). Spread over the
// listeners those properties cannot be checked. Here every limit is an entry of
// Registry, every listener setting an entry of Listeners, the Set built from
// Registry is the only thing that counts, and a lint (N5, see lint_test.go)
// fails a limiter constructed anywhere else.
package limits

// Transport is one of the six listeners of p4-nodes.md 7.4. Limits are kept per
// transport (SC 5.2 step 1), so spoofed UDP can never use up the budget of TCP
// or TLS.
type Transport uint8

const (
	UDP  Transport = iota + 1 // Plain DNS on UDP 53
	TCP                       // Plain DNS on TCP 53
	DoT                       // DNS over TLS, TCP 853
	DoH                       // DNS over HTTPS, TCP 443 (HTTP/1.1 and HTTP/2)
	DoH3                      // DNS over HTTPS on HTTP/3, UDP 443
	DoQ                       // DNS over QUIC, UDP 853
)

// All lists the transports in a fixed order for walks and tables.
func All() []Transport { return []Transport{UDP, TCP, DoT, DoH, DoH3, DoQ} }

// Encrypted lists the transports whose connection is validated by a TLS or
// QUIC handshake. They share the per-validated-source limits of 7.5.
func Encrypted() []Transport { return []Transport{DoT, DoH, DoH3, DoQ} }

func (t Transport) String() string {
	switch t {
	case UDP:
		return "udp"
	case TCP:
		return "tcp"
	case DoT:
		return "dot"
	case DoH:
		return "doh"
	case DoH3:
		return "doh3"
	case DoQ:
		return "doq"
	}
	return "unknown"
}

// Valid reports whether t is one of the six.
func (t Transport) Valid() bool { return t >= UDP && t <= DoQ }

// Stream reports whether t carries queries on a connection the node accepts
// (every transport but Plain UDP).
func (t Transport) Stream() bool { return t.Valid() && t != UDP }

// QUIC reports whether t runs on a QUIC connection.
func (t Transport) QUIC() bool { return t == DoH3 || t == DoQ }

// Answer is what a stopped query gets (7.5; L13 (4) and Open).
type Answer uint8

const (
	// AnswerNone is what a connection limit has: it has no query to answer, a
	// refused connection is closed or left unaccepted instead.
	AnswerNone Answer = iota
	// AnswerTC is UDP only: TC=1 with no records, so the client retries over
	// TCP where no limit keyed on a source meets it (L13 (4)).
	AnswerTC
	// AnswerRefused is the encrypted transports: REFUSED on the query's own
	// stream (DoH: HTTP 200 with a REFUSED message), which ends the stream and
	// leaves the connection open (L13 (2) and Open).
	AnswerRefused
)

func (a Answer) String() string {
	switch a {
	case AnswerNone:
		return "none"
	case AnswerTC:
		return "tc"
	case AnswerRefused:
		return "refused"
	}
	return "unknown"
}
