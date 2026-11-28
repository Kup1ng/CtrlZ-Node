package proxy

import (
	"errors"
	"net/netip"
	"strings"
)

// A name that reaches the proxy comes from a hostile client: the SNI of a
// ClientHello or a Host header. dns judges the name in the wire form of `names`
// and nodes never run IDNA (shared/names), so the proxy only accepts a name that is
// already in its final ASCII spelling (an A-label, never a U-label) and closes the
// connection for anything else (5.2 step 3). The set of bytes is the one that
// sock.wireName demands of a lookup, so a name this function returns can always be
// put on the link.

var errName = errors.New("proxy: not a usable name")

// normalize turns the text of an SNI or a Host into the wire name of a lookup and
// the lower-case text of the serve frame. It refuses an empty name, an IP literal
// (the proxy never dials an address the client chose), a name with a byte outside
// a-z, 0-9, hyphen and underscore, an empty or over-long label, and a name whose
// last label is a number, which a resolver would read as an IPv4 address.
func normalize(s string) (wire []byte, text string, err error) {
	if len(s) > 253+1 {
		return nil, "", errName
	}
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return nil, "", errName
	}
	if _, perr := netip.ParseAddr(strings.Trim(s, "[]")); perr == nil {
		return nil, "", errName
	}
	if len(s) > 253 {
		return nil, "", errName
	}
	labels := strings.Split(s, ".")
	w := make([]byte, 0, len(s)+2)
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return nil, "", errName
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return nil, "", errName
			}
		}
		w = append(w, byte(len(l)))
		w = append(w, l...)
	}
	w = append(w, 0)
	if len(w) > 255 {
		return nil, "", errName
	}
	last := labels[len(labels)-1]
	if allDigits(last) {
		return nil, "", errName
	}
	return w, s, nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// iranian is the built-in check of 5.2 step 4: the name is at or under .ir or
// .ایران (its A-label). It runs after the verdict and not before, because a block
// page for such a name is allowed (D42): only a kind 1 verdict for it is refused.
func iranian(text string) bool {
	switch {
	case text == "ir", strings.HasSuffix(text, ".ir"):
		return true
	case text == "xn--mgba3a4f16a", strings.HasSuffix(text, ".xn--mgba3a4f16a"):
		return true
	}
	return false
}

// hostOnly takes the host out of a Host header value: it drops a port and the
// brackets of an IPv6 literal. The result may still be an IP literal, which
// normalize refuses.
func hostOnly(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
		return h
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		return h[:i]
	}
	return h
}
