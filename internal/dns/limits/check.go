package limits

import "fmt"

// CheckRegistry reads a registry against the clauses of L13 that a table can
// show, and returns one line per breach. The unit test of 7.5 runs it on the
// registry the node uses (no breach) and on registries with one planted
// mutant each (a breach for each), so the check cannot pass by being empty.
//
// Clause (4): no limit on queries over TCP 53 or on TCP 53 connections has a
// key that includes a source address or prefix, alone or with other fields;
// every limit keyed on a source on UDP answers TC=1.
// Clause (2) and Open: a stopped query of an encrypted transport gets REFUSED
// on its own stream, and a connection limit has no answer.
// Clause (3) is a property of the callers of Set.Admit and is tested on the
// listeners; here the table only shows that no connection entry is keyed on
// something a spoofer controls beyond the source.
// 7.5: the encrypted transports are keyed per IPv4 address and IPv6 /64, with
// aggregates at /56, /48 and /32 of four times the level below.
func CheckRegistry(r Registry) []string {
	var bad []string
	add := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }
	if err := r.Validate(); err != nil {
		return []string{err.Error()}
	}
	have := map[Transport]map[string]bool{}
	for _, e := range r {
		for _, t := range e.Transports {
			if t == TCP && (e.Key.HasSource() || len(e.Key.Extra) > 0) {
				add("%s: a limit on TCP 53 has a source or another field in its key (L13 (4))", e.Name)
			}
			if t == UDP && e.Acts == ActsQuery && e.Key.HasSource() && e.Answer != AnswerTC {
				add("%s: a UDP limit keyed on a source must answer TC=1 (L13 (4))", e.Name)
			}
			if t == UDP && e.Acts == ActsConnection {
				add("%s: UDP has no connection", e.Name)
			}
			if t.Stream() && t != TCP && e.Acts == ActsQuery && e.Answer != AnswerRefused {
				add("%s: a stopped query on %s must be REFUSED on its own stream (L13 (2))", e.Name, t)
			}
			if t == TCP && e.Acts == ActsQuery {
				add("%s: no limit on queries over TCP 53 (7.5)", e.Name)
			}
			if e.Key.HasSource() && t != UDP && t != TCP {
				if e.Key.V6Bits > 64 {
					add("%s: an encrypted transport is keyed on at most an IPv6 /64", e.Name)
				}
				if e.Key.V4Bits != 0 && e.Key.V4Bits != 32 {
					add("%s: an encrypted transport is keyed on an IPv4 address", e.Name)
				}
			}
			if have[t] == nil {
				have[t] = map[string]bool{}
			}
			if e.Key.HasSource() {
				have[t][fmt.Sprintf("%s/%d", e.Acts, e.Key.V6Bits)] = true
			}
		}
	}
	for _, t := range Encrypted() {
		for _, a := range []Acts{ActsQuery, ActsConnection} {
			for _, bits := range []int{64, 56, 48, 32} {
				if !have[t][fmt.Sprintf("%s/%d", a, bits)] {
					add("%s: no %s limit keyed on IPv6 /%d (7.5)", t, a, bits)
				}
			}
		}
	}
	return bad
}

// CheckListeners reads the listener settings against L13 (2): no listener
// closes or stops reading an accepted connection after a number of queries or
// a time since it opened, other than by a deadline that can fire only while
// nothing on the connection is unread or unanswered; and the deadlines and size
// caps of 7.4 are all set (a zero is the library default, which the spec
// replaces with a number).
func CheckListeners(ls []ListenerSettings) []string {
	var bad []string
	add := func(t Transport, f string, a ...any) {
		bad = append(bad, fmt.Sprintf("%s: %s", t, fmt.Sprintf(f, a...)))
	}
	seen := map[Transport]bool{}
	for _, s := range ls {
		t := s.Transport
		if !t.Valid() {
			bad = append(bad, "listener with no transport")
			continue
		}
		if seen[t] {
			add(t, "listed twice")
		}
		seen[t] = true
		if s.MaxQueriesPerConn != 0 {
			add(t, "closes a connection after %d queries (L13 (2))", s.MaxQueriesPerConn)
		}
		if s.MaxConnAge != 0 {
			add(t, "closes a connection after an age (L13 (2))")
		}
		if t == UDP {
			if s.UDPReaders <= 0 || s.UDPPayload < 512 {
				add(t, "needs a fixed reader pool and a payload size")
			}
			continue
		}
		if s.IdleTimeout <= 0 || !s.IdleOnlyWhenQuiet {
			add(t, "needs an idle deadline that fires only while nothing is unread or unanswered")
		}
		if s.WriteStall <= 0 || !s.WriteStallOnlyWhenQuiet {
			add(t, "needs a write deadline armed only once every query is answered and nothing is unread")
		}
		if s.BodyTimeout <= 0 {
			add(t, "needs a deadline for a half-received query")
		}
		if t != TCP && s.HandshakeTimeout <= 0 {
			add(t, "needs a handshake deadline")
		}
		if t == TCP || t == DoT {
			// The reader pauses only at a count of waiting queries and only while
			// the peer is behind; a zero would leave the queue unbounded, and a
			// count below the pipelining of a healthy client would make that
			// client wait on its own replies.
			if s.MaxQueuedReplies < 64 {
				add(t, "needs a reply-queue bound of at least 64 queries")
			}
		}
		// Every stream transport bounds the reply bytes a peer that does not read can
		// make the node hold (p4n-W6-r3-3).
		if s.MaxQueuedBytes < MaxDNSMessage+2 || s.MaxQueuedBytesNode < s.MaxQueuedBytes {
			add(t, "needs a byte bound for queued or held replies that holds one largest reply, and a listener bound above it")
		}
		if t == DoH || t == DoH3 {
			if s.ReadHeaderTimeout <= 0 {
				add(t, "needs a header deadline")
			}
			if s.MaxHeaderBytes <= 0 || s.MaxHeaderBytes > 16<<10 {
				add(t, "MaxHeaderBytes must be set, at most 16 KiB (the library default is 1 MiB)")
			}
			if s.MaxBodyBytes <= 0 || s.MaxBodyBytes > MaxDNSMessage {
				add(t, "needs a body cap of at most 65535 bytes")
			}
		}
		if t == DoH3 || t == DoQ {
			// The transport's own idle timer must stay above our quiet-state idle
			// deadline, and the keep-alive below it, or the transport closes a
			// connection with a query waiting (L13 (2)); the windows are the
			// library defaults pinned to numbers.
			if s.QUICMaxIdle <= s.IdleTimeout || s.QUICKeepAlive <= 0 || s.QUICKeepAlive >= s.QUICMaxIdle {
				add(t, "the QUIC idle timer must exceed the idle deadline, with a keep-alive below it")
			}
			if s.QUICStreamWindow <= 0 || s.QUICConnWindow < s.QUICStreamWindow {
				add(t, "needs pinned QUIC flow-control windows")
			}
		}
		if t == DoH {
			if s.H2MaxFrame < 16<<10 || s.H2StreamWindow <= 0 || s.H2ConnWindow < s.H2StreamWindow {
				add(t, "needs a pinned HTTP/2 frame size and receive buffers")
			}
		}
		if t == DoH || t == DoH3 || t == DoQ {
			if s.MaxStreams <= 0 || s.MaxStreams > 100 {
				add(t, "needs a stream cap of at most 100 (the library default is not pinned)")
			}
		}
	}
	for _, t := range All() {
		if !seen[t] {
			add(t, "has no listener settings")
		}
	}
	return bad
}
