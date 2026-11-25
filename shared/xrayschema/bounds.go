package xrayschema

import (
	"regexp"
	"strconv"
	"strings"
)

// Checks of a whole object, for the limits that no single key carries (B1 round 4).
// Xray's loader of v26.11.9 judges almost none of them, and what they size is a buffer
// or a wait in the one Xray process every location of the node shares: a panic or an
// out-of-memory kill there ends the connections of every tenant, and neither the trial
// nor a probe reaches it (they stop after a few writes). A reason names the key and the
// bound and never the value.

const (
	// maxKCPSegments bounds the segments one kcp window may hold. Each held segment is a
	// buf.Buffer of 8 KiB whatever its payload is (a 1-byte segment costs the same), so
	// 4,096 of them are 32 MiB: more than any real mKCP config needs (downlinkCapacity 100
	// at mtu 1350 and tti 50 is 3,883) and far below what one connection may take from
	// a slot of 5 GiB.
	maxKCPSegments = 4096
	// maxUDPPayload is the largest datagram; one exp noise packet is built in one slice.
	maxUDPPayload = 65507
)

// memberOf finds a member of an object by key, in any case. An object that was walked
// has no key twice.
func memberOf(v *val, key string) *val {
	if v == nil || v.k != 'o' {
		return nil
	}
	for i := range v.members {
		if strings.EqualFold(v.members[i].key, key) {
			return v.members[i].v
		}
	}
	return nil
}

// intOf reads a number member as a whole number. A fraction or an exponent that makes a
// whole number counts, as in inLimit.
func intOf(v *val) (int64, bool) {
	if v == nil || v.k != 'n' {
		return 0, false
	}
	if i, err := strconv.ParseInt(v.s, 10, 64); err == nil {
		return i, true
	}
	f, err := strconv.ParseFloat(v.s, 64)
	if err != nil || f > 1<<53 || f < -(1<<53) || f != float64(int64(f)) {
		return 0, false
	}
	return int64(f), true
}

// kcpWindows bounds the two windows a kcp connection keeps (B1-r4-4). Xray computes the
// receive window as downlinkCapacity MiB / mtu / (1000 / tti) segments and the send
// queue as maxSendingWindow bytes / mtu (transport/internet/kcp/config.go). Each key is
// bounded alone by its node, yet together they reach 776,000 segments at the largest
// values and 49.9 million at mtu 21, held by a peer that never sends the next segment
// of one connection. An absent key has the default of the release.
func kcpWindows(v *val) (string, string) {
	read := func(key string, def int64) (int64, bool) {
		m := memberOf(v, key)
		if m == nil {
			return def, true
		}
		return intOf(m)
	}
	mtu, ok1 := read("mtu", 1350)
	tti, ok2 := read("tti", 50)
	down, ok3 := read("downlinkCapacity", 20)
	win, ok4 := read("maxSendingWindow", 2<<20)
	// A value outside its own bound is rejected by its node already; dividing by it would
	// only add a second message.
	if !ok1 || !ok2 || !ok3 || !ok4 || mtu < 21 || mtu > 1500 || tti < 10 || tti > 1000 || down < 0 || down > 1000 || win < 0 {
		return "", ""
	}
	recv := max(8, down<<20/mtu/(1000/tti))
	if recv > maxKCPSegments {
		return ".downlinkCapacity", "downlinkCapacity, tti and mtu make a receive window of more than " +
			strconv.Itoa(maxKCPSegments) + " segments: a peer can fill it with one buffer of 8 KiB for each"
	}
	queue := win / mtu
	if queue == 0 {
		return ".maxSendingWindow", "maxSendingWindow must be at least mtu"
	}
	if queue > maxKCPSegments {
		return ".maxSendingWindow", "maxSendingWindow and mtu make a send queue of more than " +
			strconv.Itoa(maxKCPSegments) + " segments"
	}
	return "", ""
}

// noiseExpPattern is the one of infra/conf (transport_finalmask.go): a segment of an
// exp noise program such as "<r 100><t><b 0xab>". It is compiled on each use and not
// kept in a package variable (contract 1: no package-level mutable state); only an exp
// noise reaches it, so the cost does not count.
func noiseExpPattern() *regexp.Regexp {
	return regexp.MustCompile(`<\s*([a-z]+)(?:\s+([^>]*?))?\s*>`)
}

// noiseExpSize is the most bytes an exp program writes, read as the loader reads it:
// every <r N>, <rc N> and <rd N> up to 65,535 and any number of them, which buildPacket
// joins into one slice for each new UDP connection (B1-r4-5). It reports false for a
// program it cannot size, which Xray would refuse as well.
func noiseExpSize(exp string) (int64, bool) {
	var total int64
	for _, m := range noiseExpPattern().FindAllStringSubmatch(exp, -1) {
		switch m[1] {
		case "r", "rc", "rd":
			a, b, ok := rangeEnds(m[2])
			if !ok {
				return 0, false
			}
			total += max(a, b, 0)
		case "t", "c":
			total += 4
		case "n":
			total += 8
		case "b":
			// The hex text with its blanks taken off, two digits a byte; one byte more
			// than that (and the 0x prefix is not counted out) is a safe upper bound.
			total += int64(len(strings.Join(strings.Fields(m[2]), "")))/2 + 1
		default:
			return 0, false
		}
		if total > maxUDPPayload {
			return total, true
		}
	}
	return total, true
}

// noiseExpItem judges the packet of a finalmask noise item whose type is exp, the one type
// that builds its packet from a program (the others carry the packet as text, which the
// 32 KiB fragment bounds, or a rand that its own node bounds).
func noiseExpItem(v *val) (string, string) {
	t := memberOf(v, "type")
	if t == nil || t.k != 's' || !strings.EqualFold(t.s, "exp") {
		return "", ""
	}
	p := memberOf(v, "packet")
	if p == nil || p.k != 's' {
		return ".packet", "the packet of a noise of type exp must be a program in a string"
	}
	size, ok := noiseExpSize(p.s)
	if !ok {
		return ".packet", "the program of a noise of type exp is not one Xray reads"
	}
	if size > maxUDPPayload {
		return ".packet", "the segments of a noise of type exp add up to more than " + strconv.Itoa(maxUDPPayload) +
			" bytes: Xray joins them into one slice for each connection"
	}
	return "", ""
}

// freedomNoise judges the packet of a freedom noise of type rand, which Xray reads as a
// length or a range of lengths with no upper bound (conf/freedom.go ParseNoise) and
// allocates on every UDP write through the hop (B1-r4-2). The other types carry the
// packet itself. The loader compares the type with the exact text "rand"; every case is
// judged here so a spelling cannot slip past a later loader.
func freedomNoise(v *val) (string, string) {
	t := memberOf(v, "type")
	if t == nil || t.k != 's' || !strings.EqualFold(t.s, "rand") {
		return "", ""
	}
	p := memberOf(v, "packet")
	if p == nil || p.k != 's' {
		return ".packet", "the packet of a noise of type rand must be a length or a range of lengths in a string"
	}
	if !rangeInLimit(strings.TrimSpace(p.s), &limit{lo: 1, hi: maxFragment}) {
		return ".packet", "the packet of a noise of type rand must be a length or a range of lengths from 1 to " +
			strconv.Itoa(maxFragment) + ": Xray allocates it on every write"
	}
	return "", ""
}

// finalmaskMasks judges what the udp masks of one stream do to each other (B1-r4-6). A
// salamander with packetSize is the gecko writer, which copies each packet it is given
// into a buffer of 8,192 bytes and panics on one above 8,184. Every carrier the table
// allows sends at most 1,500 bytes (kcp mtu, wireguard mtu, QUIC), but a sudoku mask
// grows each packet 4 to 9 times, so the two cannot share a list.
func finalmaskMasks(v *val) (string, string) {
	udp := memberOf(v, "udp")
	if udp == nil || udp.k != 'a' {
		return "", ""
	}
	gecko, sudoku := false, false
	for _, it := range udp.items {
		t := memberOf(it, "type")
		if t == nil || t.k != 's' {
			continue
		}
		switch strings.ToLower(t.s) {
		case "sudoku":
			sudoku = true
		case "salamander":
			if size := memberOf(memberOf(it, "settings"), "packetSize"); size != nil && rangeTop(size) > 0 {
				gecko = true
			}
		}
	}
	if gecko && sudoku {
		return ".udp", "a salamander mask with packetSize cannot share a list with a sudoku mask: sudoku makes packets larger than its buffer takes"
	}
	return "", ""
}

// rangeTop is the larger end of a range member given as a number or a string, or 0.
func rangeTop(v *val) int64 {
	switch v.k {
	case 'n':
		i, _ := intOf(v)
		return i
	case 's':
		if a, b, ok := rangeEnds(v.s); ok {
			return max(a, b)
		}
	}
	return 0
}

// streamCongestion refuses congestion "brutal" on a stream that is not Hysteria
// (B1-r4-3). The loader takes it for every transport, but only the hysteria dialer
// handles it: the xhttp h3 dialer and the xdns DoH resolver run panic(congestion) on it
// after the QUIC handshake, in a goroutine nothing recovers, so the shared process dies
// whenever the exit chooses to answer. The value is already one of the five spellings of
// the enum and in canonical case.
func streamCongestion(v *val) (string, string) {
	q := memberOf(memberOf(v, "finalmask"), "quicParams")
	c := memberOf(q, "congestion")
	if c == nil || c.k != 's' || c.s != "brutal" {
		return "", ""
	}
	if m := memberOf(v, "method"); m != nil && m.k == 's' && m.s == "hysteria" {
		return "", ""
	}
	return ".finalmask.quicParams.congestion", "congestion brutal is only for the hysteria transport; xhttp over h3 panics the Xray process with it (use bbr, reno or force-brutal)"
}

// rawValueRejected judges a value of a subtree the table has no node for by its key. A
// resolver of the xdns mask holds a QUIC config of its own, and its dialer panics on
// congestion brutal like the xhttp one.
func rawValueRejected(key string, v *val) (string, bool) {
	if strings.EqualFold(key, "congestion") && v.k == 's' && strings.EqualFold(v.s, "brutal") {
		return "congestion brutal is only for the hysteria transport; a subtree the table does not know panics the Xray process with it", true
	}
	return "", false
}

// CheckVLESSEncryption judges the encryption text of a VLESS user (B1-r4-9) and returns
// the reason it is refused, or "". The text mlkem768x25519plus.<mode>.<rtt>.<padding>...
// holds padding parts "probability-min-max" that alternate between lengths and gaps; the
// loader bounds the lengths (65,553 in all) but not the gaps, which Xray sleeps in
// time.Sleep inside the handshake with nothing to cancel it. A gap of a day holds a
// goroutine, a socket and a port long after the user has gone. It reads the text as the
// loader does and leaves what the loader refuses to the loader; the converter calls it
// to name the link parameter.
func CheckVLESSEncryption(enc string) string {
	s := strings.Split(enc, ".")
	if len(s) < 4 || s[0] != "mlkem768x25519plus" {
		return ""
	}
	i := 0
	for _, r := range s[3:] {
		if len(r) >= 20 {
			continue // a key
		}
		x := strings.Split(r, "-")
		if i%2 == 1 && len(x) >= 3 {
			for _, part := range x[1:3] {
				if n, err := strconv.Atoi(part); err == nil && n > maxWaitMs {
					return "a padding gap of the encryption text is longer than " + strconv.Itoa(maxWaitMs) + " ms: Xray sleeps it inside the handshake"
				}
			}
		}
		i++
	}
	return ""
}
