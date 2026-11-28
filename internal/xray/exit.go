package xray

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// A fragment in its normal form is {"outbounds":[...]} with the tags "0" to "7" and
// each dialerProxy naming one of them. These helpers read the places an exit sits,
// for 6.4 (the `exit` of a config) and 5.5 (the remotes that the socket counts judge).

type hop struct {
	host   string
	port   int
	secure bool // security tls or reality on the outbound that dials it
	free   bool // protocol freedom
}

func outboundsOf(frag []byte) []map[string]any {
	dec := json.NewDecoder(bytes.NewReader(frag))
	dec.UseNumber()
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if dec.Decode(&doc) != nil {
		return nil
	}
	return doc.Outbounds
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func sub(m map[string]any, k string) map[string]any {
	s, _ := m[k].(map[string]any)
	return s
}
func first(m map[string]any, k string) map[string]any {
	l, _ := m[k].([]any)
	if len(l) == 0 {
		return nil
	}
	s, _ := l[0].(map[string]any)
	return s
}

func portOf(v any) int {
	switch t := v.(type) {
	case json.Number:
		n, _ := strconv.Atoi(t.String())
		return n
	case string:
		n, _ := strconv.Atoi(t)
		return n
	}
	return 0
}

// hopOf reads the server an outbound dials: the vnext or servers element, the flat
// form, a wireguard peer, or a hysteria address.
func hopOf(o map[string]any) hop {
	h := hop{free: str(o, "protocol") == "freedom"}
	if ss := sub(o, "streamSettings"); ss != nil {
		sec := strings.ToLower(str(ss, "security"))
		h.secure = sec == "tls" || sec == "reality"
	}
	s := sub(o, "settings")
	if s == nil {
		return h
	}
	srv := first(s, "vnext")
	if srv == nil {
		srv = first(s, "servers")
	}
	if srv == nil {
		srv = s
	}
	if a := str(srv, "address"); a != "" {
		h.host, h.port = strings.ToLower(a), portOf(srv["port"])
		return h
	}
	if p := first(s, "peers"); p != nil {
		if hp, pp, err := net.SplitHostPort(str(p, "endpoint")); err == nil {
			h.host, h.port = strings.ToLower(hp), portOf(pp)
		}
	}
	return h
}

// chainOf lists the outbounds of the chain in the order they dial: the main
// outbound first, then each dialerProxy it names.
func chainOf(outs []map[string]any) []map[string]any {
	var chain []map[string]any
	seen := map[int]bool{}
	i := 0
	for len(outs) > 0 && !seen[i] && i < len(outs) {
		seen[i] = true
		chain = append(chain, outs[i])
		d := ""
		if ss := sub(outs[i], "streamSettings"); ss != nil {
			if so := sub(ss, "sockopt"); so != nil {
				d = str(so, "dialerProxy")
			}
		}
		n, err := strconv.Atoi(d)
		if d == "" || err != nil {
			break
		}
		i = n
	}
	return chain
}

// hopsOf is every outbound of the chain, the first hop included.
func hopsOf(frag []byte) []hop {
	var hs []hop
	for _, o := range chainOf(outboundsOf(frag)) {
		if h := hopOf(o); h.host != "" {
			hs = append(hs, h)
		}
	}
	return hs
}

// exitOf is the `exit` of 6.4: the first 8 bytes of the SHA-256 of the lower-case
// host and port of the last outbound of the chain that is not freedom, so configs of
// one exit share its room in dns's caps. A fragment that names no address (it
// cannot pass the schema, but a stored one may predate it) gets a key of its own.
func exitOf(id string, frag []byte) []byte {
	key := "id:" + id
	for _, o := range chainOf(outboundsOf(frag)) {
		if h := hopOf(o); !h.free && h.host != "" {
			key = h.host + ":" + strconv.Itoa(h.port)
		}
	}
	sum := sha256.Sum256([]byte(key))
	return sum[:8]
}

// hasWireguard reports a wireguard outbound, the one that cannot wait out a drain
// (7.5 step 5).
func hasWireguard(frag []byte) bool {
	for _, o := range outboundsOf(frag) {
		if str(o, "protocol") == "wireguard" {
			return true
		}
	}
	return false
}
