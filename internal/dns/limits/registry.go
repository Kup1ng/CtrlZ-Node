package limits

import (
	"fmt"
	"time"
)

// Acts says what an entry limits.
type Acts uint8

const (
	// ActsQuery limits queries, after the question is read and the name-form
	// exemption has run. A stopped query is answered, never dropped silently on
	// a transport that has an answer for it.
	ActsQuery Acts = iota + 1
	// ActsConnection limits connections, counted only once the source address
	// is validated: a finished TCP handshake, or a finished QUIC handshake or a
	// valid Retry token (L13 (3)). A connection it refuses is closed at once;
	// it was never accepted. An accepted connection is never touched by it.
	ActsConnection
)

func (a Acts) String() string {
	switch a {
	case ActsQuery:
		return "query"
	case ActsConnection:
		return "connection"
	}
	return "unknown"
}

// KeyKind says whether an entry's key holds a source.
type KeyKind uint8

const (
	// KeyNone: one counter for the whole transport on this node.
	KeyNone KeyKind = iota
	// KeySource: one counter per source prefix, the prefix lengths in Key.
	KeySource
)

// Key is the key of an entry. The walk of L13 (4) reads it, so everything that
// can make a counter depend on the source or the question must be named here.
type Key struct {
	Kind KeyKind
	// V4Bits and V6Bits are the prefix lengths of KeySource, per address
	// family. 0 means the entry does not apply to that family (so the IPv4 side
	// of an IPv6-only aggregate is not limited by it).
	V4Bits, V6Bits uint8
	// Extra names every other field in the key (a query name, a response
	// field). No entry has one yet; the field is here so that the L13 walks
	// look at it when someone adds one.
	Extra []string
}

// HasSource reports whether the key includes a source address or prefix,
// alone or together with other fields.
func (k Key) HasSource() bool { return k.Kind == KeySource }

// Entry is one limit of step 1.
type Entry struct {
	Name       string
	Acts       Acts
	Transports []Transport
	Key        Key
	// Rate is events a second, Burst the bucket depth; both zero when the
	// entry only counts open connections. For ActsQuery the event is a query,
	// for ActsConnection a new validated connection.
	Rate  float64
	Burst int
	// Count is the most connections open at once (ActsConnection only).
	Count int
	// Answer is what a stopped query gets (ActsQuery only).
	Answer Answer
}

// Registry is the list of every limit of step 1 (7.5, "One registry").
type Registry []Entry

// Validate refuses an entry the engine cannot run, so a typo fails at start.
func (r Registry) Validate() error {
	seen := map[string]bool{}
	for i := range r {
		e := &r[i]
		if e.Name == "" || seen[e.Name] {
			return fmt.Errorf("limits: entry %d has an empty or repeated name", i)
		}
		seen[e.Name] = true
		if e.Acts != ActsQuery && e.Acts != ActsConnection {
			return fmt.Errorf("limits: %s: bad acts", e.Name)
		}
		if len(e.Transports) == 0 {
			return fmt.Errorf("limits: %s: no transport", e.Name)
		}
		for _, t := range e.Transports {
			if !t.Valid() {
				return fmt.Errorf("limits: %s: bad transport", e.Name)
			}
		}
		if e.Rate < 0 || e.Burst < 0 || e.Count < 0 || (e.Rate > 0) != (e.Burst > 0) {
			return fmt.Errorf("limits: %s: rate and burst go together and are not negative", e.Name)
		}
		if e.Rate == 0 && e.Count == 0 {
			return fmt.Errorf("limits: %s: neither a rate nor a count", e.Name)
		}
		if e.Acts == ActsQuery && (e.Count != 0 || e.Answer == AnswerNone) {
			return fmt.Errorf("limits: %s: a query limit has a rate and an answer, no count", e.Name)
		}
		if e.Acts == ActsConnection && e.Answer != AnswerNone {
			return fmt.Errorf("limits: %s: a connection limit has no query to answer", e.Name)
		}
		if e.Key.Kind == KeySource && (e.Key.V4Bits > 32 || e.Key.V6Bits > 128 || (e.Key.V4Bits == 0 && e.Key.V6Bits == 0)) {
			return fmt.Errorf("limits: %s: bad prefix lengths", e.Name)
		}
		if e.Key.Kind == KeyNone && (e.Key.V4Bits != 0 || e.Key.V6Bits != 0) {
			return fmt.Errorf("limits: %s: a keyless entry has no prefix lengths", e.Name)
		}
	}
	return nil
}

// Clone copies the registry so a test can change one entry.
func (r Registry) Clone() Registry {
	out := make(Registry, len(r))
	for i, e := range r {
		e.Transports = append([]Transport(nil), e.Transports...)
		e.Key.Extra = append([]string(nil), e.Key.Extra...)
		out[i] = e
	}
	return out
}

// level is one source-prefix level of the encrypted transports' limits.
type level struct {
	name string
	v4   uint8 // 0: the level has no IPv4 side
	v6   uint8
	mult int
}

// encryptedLevels are the keys of DoT, DoH, DoH3 and DoQ (7.5, "Keys and rates,
// decided"): a validated source is an IPv4 address or an IPv6 /64, with
// aggregates of four times the level below at /56, /48 and /32. A carrier NAT
// or an IPv6 site shares the limits of its address: the recorded risk of SC
// 8a.9 (Per-source limits filled for a victim).
func encryptedLevels() []level {
	return []level{
		{"src", 32, 64, 1},
		{"v6-56", 0, 56, 4},
		{"v6-48", 0, 48, 16},
		{"v6-32", 0, 32, 64},
	}
}

// Numbers of the registry (7.5, D31; provisional until the P4 load test).
const (
	encOpenPerSource  = 64 // open connections per validated source
	encNewPerSecond   = 10 // new connections a second per validated source
	encNewBurst       = 40
	encQueryPerSecond = 100 // queries a second per validated source
	encQueryBurst     = 200
	encNodeOpen       = 50000 // open connections per transport, node-wide
	udpAddrRate       = 100   // Plain UDP, per address
	udpAddrBurst      = 200
	udpPrefixRate     = 1000 // Plain UDP, per /24 or /56
	// udpPrefixBurst is not in 7.5, which gives the rate only; twice the rate,
	// the ratio the per-address limit has.
	udpPrefixBurst  = 2000
	tcpOpen         = 20000 // Plain TCP, node-wide
	tcpNewPerSecond = 2000
	// tcpNewBurst is not in 7.5 either; twice the rate.
	tcpNewBurst = 4000

	// RetryUnderLoad is the number of QUIC handshakes in progress without a
	// validated address above which the node asks for a Retry (D31).
	RetryUnderLoad = 1000

	// RetryPerSource is the number of QUIC handshakes in progress without a
	// validated address that one source may have before its next Initial is
	// answered with a Retry, load or not. A real host can start handshakes faster
	// than the first one completes, and the connection limits count a connection
	// only after its handshake, so without this a host runs as many handshakes as
	// it can start in one round trip (p4n-W6-r4-4). The source is an IPv4 address
	// or an IPv6 /64. A spoofed Initial can raise a victim's count, which costs
	// the victim one Retry round trip and nothing else.
	RetryPerSource = 8
)

// Default returns the registry the node runs with, a fresh copy each call so
// no package-level state can be changed. Tests build their own with Clone.
func Default() Registry {
	r := Registry{
		// Plain UDP. The key holds the source, so a stopped query gets TC=1
		// with no records and its TCP retry meets no per-source limit (L13 (4)).
		{Name: "udp-query-addr", Acts: ActsQuery, Transports: []Transport{UDP},
			Key:  Key{Kind: KeySource, V4Bits: 32, V6Bits: 128},
			Rate: udpAddrRate, Burst: udpAddrBurst, Answer: AnswerTC},
		{Name: "udp-query-prefix", Acts: ActsQuery, Transports: []Transport{UDP},
			Key:  Key{Kind: KeySource, V4Bits: 24, V6Bits: 56},
			Rate: udpPrefixRate, Burst: udpPrefixBurst, Answer: AnswerTC},
		// Plain TCP: no key with a source, node-wide only. A load that fills
		// these is overload (SC 8a.1 invariant 8), not a per-source limit.
		{Name: "tcp-conn-open", Acts: ActsConnection, Transports: []Transport{TCP},
			Key: Key{Kind: KeyNone}, Count: tcpOpen},
		{Name: "tcp-conn-new", Acts: ActsConnection, Transports: []Transport{TCP},
			Key: Key{Kind: KeyNone}, Rate: tcpNewPerSecond, Burst: tcpNewBurst},
	}
	for _, lv := range encryptedLevels() {
		key := Key{Kind: KeySource, V4Bits: lv.v4, V6Bits: lv.v6}
		r = append(r,
			Entry{Name: "enc-conn-open-" + lv.name, Acts: ActsConnection, Transports: Encrypted(),
				Key: key, Count: encOpenPerSource * lv.mult},
			Entry{Name: "enc-conn-new-" + lv.name, Acts: ActsConnection, Transports: Encrypted(),
				Key: key, Rate: float64(encNewPerSecond * lv.mult), Burst: encNewBurst * lv.mult},
			Entry{Name: "enc-query-" + lv.name, Acts: ActsQuery, Transports: Encrypted(),
				Key: key, Rate: float64(encQueryPerSecond * lv.mult), Burst: encQueryBurst * lv.mult, Answer: AnswerRefused},
		)
	}
	r = append(r, Entry{Name: "enc-conn-open-node", Acts: ActsConnection, Transports: Encrypted(),
		Key: Key{Kind: KeyNone}, Count: encNodeOpen})
	return r
}

// ListenerSettings are the settings of one listener, library defaults
// included (7.5): a number the library would apply on its own is written here
// as the value we pin, so the walk of L13 (2) reads all of them.
type ListenerSettings struct {
	Transport Transport
	// Port is the default port; Config can override it for tests.
	Port uint16

	// MaxQueriesPerConn and MaxConnAge are 0 on every listener: L13 (2) lets no
	// listener close an accepted connection after a number of queries or a
	// time since it opened (the default of a common Go DNS library closes
	// after 128 queries and leaves the pipelined ones unread).
	MaxQueriesPerConn int
	MaxConnAge        time.Duration

	// IdleTimeout closes a connection that has nothing unread, unanswered or
	// being written for this long. It is armed only while that holds, so it
	// never fires while a query waits; the reply due extends it (7.4).
	IdleTimeout time.Duration
	// IdleOnlyWhenQuiet and WriteStallOnlyWhenQuiet record the rule above for
	// the walk; a listener built so that either is false fails the walk.
	IdleOnlyWhenQuiet       bool
	WriteStallOnlyWhenQuiet bool
	// WriteStall closes a connection whose reply the peer has not read for this
	// long, armed only once every query read on the connection is answered
	// and nothing more is unread (7.4).
	WriteStall time.Duration

	// HandshakeTimeout is the TLS or QUIC handshake deadline.
	HandshakeTimeout time.Duration
	// ReadHeaderTimeout is the DoH request-header deadline (HTTP/1.1; HTTP/2
	// has no such deadline in net/http, its streams are capped instead).
	ReadHeaderTimeout time.Duration
	// BodyTimeout is how long one query may take to arrive once its first byte
	// is read: the DoH body, a TCP/DoT frame, a DoQ stream. It fires only
	// while a query is half received, and costs the peer that stream or
	// connection, never another peer's.
	BodyTimeout time.Duration

	MaxHeaderBytes int // DoH and DoH3
	MaxBodyBytes   int // DoH and DoH3 request body, and a dns= query decoded
	// MaxStreams is the HTTP/2 and QUIC stream cap per connection.
	MaxStreams int

	// HandlerTimeout is the deadline of the context given to the query path.
	HandlerTimeout time.Duration
	// MaxInFlight caps queries in the query path at once on this listener,
	// except those of exempt names. Beyond it a UDP query is dropped and a
	// stream query gets SERVFAIL: overload (SC 8a.1 invariant 8), not a limit
	// of step 1, and the name-form exemption bypasses it.
	MaxInFlight int
	// MaxQueuedReplies is how many queries may be waiting (in the handler, queued
	// or being written) on a TCP 53 or DoT connection before the reader stops
	// reading new ones, while the peer is behind on reading its replies. It is
	// not a query cap: a peer that reads never meets it, and a peer that does not
	// is held back by TCP flow control (L13 (2) allows this only because the
	// connection is closed by the write-stall deadline).
	MaxQueuedReplies int
	// MaxQueuedBytes bounds the reply bytes queued (TCP 53, DoT) or held by a
	// write that has not finished (DoQ, DoH, DoH3) on one connection for the
	// wire, and MaxQueuedBytesNode the same on the whole listener. Past either, a
	// reply is replaced by a SERVFAIL for its query, so a peer that does not read
	// cannot make the node hold 64 KiB for each query it sent.
	MaxQueuedBytes     int
	MaxQueuedBytesNode int
	// QUIC (DoQ and DoH3): the transport idle timer and its keep-alive, and the
	// flow-control windows. The idle timer stays above IdleTimeout and the
	// keep-alive below it, so the transport never cuts a connection that our own
	// quiet-state idle deadline (armed only with nothing unread or unanswered)
	// would leave open (L13 (2)).
	QUICMaxIdle, QUICKeepAlive time.Duration
	QUICStreamWindow           int // per stream
	QUICConnWindow             int // per connection, at most
	// HTTP/2 (DoH): the frame size and the receive buffers, which net/http would
	// otherwise choose.
	H2MaxFrame, H2StreamWindow, H2ConnWindow int
	// UDPReaders is the fixed number of goroutines reading datagrams.
	UDPReaders int
	// UDPPayload is the largest UDP reply (RFC 9715 advises 1232).
	UDPPayload int
}

// MaxDNSMessage is the largest DNS message of any transport.
const MaxDNSMessage = 65535

// Listeners returns the settings of every listener (7.5), a fresh copy each
// call.
func Listeners() []ListenerSettings {
	const (
		idle  = 10 * time.Second
		stall = 30 * time.Second
		hs    = 5 * time.Second
		body  = 5 * time.Second
		hto   = 30 * time.Second
		// The QUIC transport timer stays above our idle deadline; the keep-alive keeps
		// the path open while a query waits on a slow answer.
		quicIdle = 30 * time.Second
		quicKeep = 5 * time.Second
		infl     = 65536
		// The reply queue of a stream connection (p4n-W6-r2-1, -5): 64 queries,
		// 256 KiB a connection (four of the largest replies), 256 MiB a listener
		// (1000 connections that each hold a full queue). The byte bounds apply to
		// every transport with streams: on DoQ, DoH and DoH3 they count the reply
		// bytes held by writes the peer has not let finish (p4n-W6-r3-3).
		qrep       = 64
		qbytes     = 256 << 10
		qbytesNode = 256 << 20
	)
	return []ListenerSettings{
		{Transport: UDP, Port: 53, HandlerTimeout: hto, MaxInFlight: infl, UDPReaders: 8, UDPPayload: 1232},
		{Transport: TCP, Port: 53, IdleTimeout: idle, IdleOnlyWhenQuiet: true, WriteStall: stall, WriteStallOnlyWhenQuiet: true,
			BodyTimeout: body, HandlerTimeout: hto, MaxInFlight: infl,
			MaxQueuedReplies: qrep, MaxQueuedBytes: qbytes, MaxQueuedBytesNode: qbytesNode},
		{Transport: DoT, Port: 853, IdleTimeout: idle, IdleOnlyWhenQuiet: true, WriteStall: stall, WriteStallOnlyWhenQuiet: true,
			HandshakeTimeout: hs, BodyTimeout: body, HandlerTimeout: hto, MaxInFlight: infl,
			MaxQueuedReplies: qrep, MaxQueuedBytes: qbytes, MaxQueuedBytesNode: qbytesNode},
		{Transport: DoH, Port: 443, IdleTimeout: idle, IdleOnlyWhenQuiet: true, WriteStall: stall, WriteStallOnlyWhenQuiet: true,
			HandshakeTimeout: hs, ReadHeaderTimeout: hs, BodyTimeout: body,
			MaxHeaderBytes: 16 << 10, MaxBodyBytes: MaxDNSMessage, MaxStreams: 100, HandlerTimeout: hto, MaxInFlight: infl,
			H2MaxFrame: 16 << 10, H2StreamWindow: 128 << 10, H2ConnWindow: 1 << 20,
			MaxQueuedBytes: qbytes, MaxQueuedBytesNode: qbytesNode},
		{Transport: DoH3, Port: 443, IdleTimeout: idle, IdleOnlyWhenQuiet: true, WriteStall: stall, WriteStallOnlyWhenQuiet: true,
			HandshakeTimeout: hs, ReadHeaderTimeout: hs, BodyTimeout: body,
			MaxHeaderBytes: 16 << 10, MaxBodyBytes: MaxDNSMessage, MaxStreams: 100, HandlerTimeout: hto, MaxInFlight: infl,
			QUICMaxIdle: quicIdle, QUICKeepAlive: quicKeep, QUICStreamWindow: 128 << 10, QUICConnWindow: 2 << 20,
			MaxQueuedBytes: qbytes, MaxQueuedBytesNode: qbytesNode},
		{Transport: DoQ, Port: 853, IdleTimeout: idle, IdleOnlyWhenQuiet: true, WriteStall: stall, WriteStallOnlyWhenQuiet: true,
			HandshakeTimeout: hs, BodyTimeout: body, MaxStreams: 100, HandlerTimeout: hto, MaxInFlight: infl,
			QUICMaxIdle: quicIdle, QUICKeepAlive: quicKeep, QUICStreamWindow: 128 << 10, QUICConnWindow: 2 << 20,
			MaxQueuedBytes: qbytes, MaxQueuedBytesNode: qbytesNode},
	}
}

// SettingsFor returns the entry of ls for t.
func SettingsFor(ls []ListenerSettings, t Transport) (ListenerSettings, bool) {
	for _, s := range ls {
		if s.Transport == t {
			return s, true
		}
	}
	return ListenerSettings{}, false
}

// CloneSettings copies a settings list so a test can change one field.
func CloneSettings(ls []ListenerSettings) []ListenerSettings {
	return append([]ListenerSettings(nil), ls...)
}
