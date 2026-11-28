package xray

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
)

// Ports and addresses of a slot (7.4).
const (
	slotAAddr  = "127.0.0.20"
	slotBAddr  = "127.0.0.21"
	DirectPort = 20000
	// FirstPort and LastPort are the SOCKS inbounds of the configs: one port each, and
	// one more while an older generation drains.
	FirstPort = 20001
	LastPort  = 20255
)

// SlotAddr is the loopback address of a slot's inbounds.
func SlotAddr(slot string) string {
	if slot == "b" {
		return slotBAddr
	}
	return slotAAddr
}

func otherSlot(s string) string {
	if s == "a" {
		return "b"
	}
	return "a"
}

// Tags (7.4): id as 32 hex digits, g the generation, n the outbound of the chain.
func inTag(id string, g int) string       { return fmt.Sprintf("in:%s.%d", id, g) }
func ruleTag(id string, g int) string     { return fmt.Sprintf("L%s.%d", id, g) }
func outTag(id string, g, n int) string   { return fmt.Sprintf("L%s.%d.%d", id, g, n) }
func idHex(id []byte) string              { return hex.EncodeToString(id) }
func socksAddr(slot string, p int) string { return fmt.Sprintf("%s:%d", SlotAddr(slot), p) }

// runRec is one config as a slot runs it: the generation, the port of its inbound
// and the normalised fragment that xrayschema returned (never the text the panel
// stored: no byte of that reaches Xray, 7.2).
type runRec struct {
	ID       string `json:"id"`
	Gen      int    `json:"gen"`
	Port     int    `json:"port"`
	Outs     int    `json:"outs"` // number of outbounds of the chain, to remove them
	Hash     string `json:"hash"` // sha256 of the fragment the hub sent, hex
	Frag     []byte `json:"frag"` // normalised {"outbounds":[...]}
	Location uint32 `json:"loc"`
	Priority uint32 `json:"prio"`
	Stateful bool   `json:"stateful,omitempty"`
}

// baseInput is what the base configuration of a slot depends on.
type baseInput struct {
	Slot    string
	APISock string
	// Unbound is the identified Unbound, ip:port. The dns section sends every lookup
	// of Xray there and nowhere else.
	Unbound string
	// Blocked are the ranges that `direct` refuses: every non-public range and every
	// node and panel address (7.4).
	Blocked []netip.Prefix
}

// blockedRanges is the list of finalRules: the non-public ranges that Unbound and
// nftables use too (package nets), with the addresses of the nodes of the table.
func blockedRanges(addrs []netip.Addr) []netip.Prefix {
	var extra [][]netip.Prefix
	for _, a := range addrs {
		extra = append(extra, nets.ForAddr(a))
	}
	return nets.Merge(append([][]netip.Prefix{nets.NonPublic()}, extra...)...)
}

// slotConfig renders the whole configuration of a slot: the base of 7.4 and every
// running config. It is what the slot starts from, so a restart of Xray comes up
// with the running set, and what `run -test` is given.
func slotConfig(b baseInput, running []runRec) ([]byte, error) {
	direct := map[string]any{
		"tag": "direct", "protocol": "freedom",
		"settings":       map[string]any{"finalRules": finalRules(b.Blocked)},
		"streamSettings": map[string]any{"sockopt": map[string]any{"domainStrategy": "ForceIPv4"}},
	}
	outbounds := []any{map[string]any{"tag": "blocked", "protocol": "blackhole"}, direct}
	inbounds := []any{socksInbound("direct", b.Slot, DirectPort)}
	rules := []any{map[string]any{"type": "field", "inboundTag": []string{"direct"}, "outboundTag": "direct"}}

	sorted := append([]runRec(nil), running...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, r := range sorted {
		p, err := renderConfig(b, r)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, p.outbounds...)
		inbounds = append(inbounds, p.inbound)
		rules = append(rules, p.rule)
	}
	cfg := map[string]any{
		"log": map[string]any{"access": "none", "loglevel": "none"},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"handshake": 4, "connIdle": 600, "uplinkOnly": 10, "downlinkOnly": 10, "bufferSize": 16,
		}}},
		"api": map[string]any{
			"tag": "api", "listen": b.APISock + ",0600",
			"services": []string{"HandlerService", "RoutingService"},
		},
		// tcp+local goes straight to that server; tcp:// would go through routing, whose
		// first outbound is the blackhole (B0 E08).
		"dns":       map[string]any{"servers": []string{"tcp+local://" + b.Unbound}, "queryStrategy": "UseIPv4"},
		"outbounds": outbounds,
		"inbounds":  inbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	return json.Marshal(cfg)
}

func socksInbound(tag, slot string, port int) map[string]any {
	return map[string]any{
		"tag": tag, "listen": SlotAddr(slot), "port": port, "protocol": "socks",
		"settings": map[string]any{"auth": "noauth", "udp": false},
		"sniffing": map[string]any{"enabled": false},
	}
}

// pieces are the three things one config adds to a slot, in the order the API
// takes them (7.5 step 2: ado, adrules -append, adi).
type pieces struct {
	outbounds []any
	rule      any
	inbound   any
}

// renderConfig turns a normalised fragment into the outbounds, rule and inbound of
// generation r.Gen. The tag n of the normal form is the position in the chain
// (0 to 7), so `L<id>.<g>.<n>` and each dialerProxy are rewritten to it.
func renderConfig(b baseInput, r runRec) (pieces, error) {
	dec := json.NewDecoder(bytes.NewReader(r.Frag))
	dec.UseNumber()
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := dec.Decode(&doc); err != nil || len(doc.Outbounds) == 0 || len(doc.Outbounds) > 8 {
		return pieces{}, errors.New("xray: a stored fragment does not parse")
	}
	for i, o := range doc.Outbounds {
		o["tag"] = outTag(r.ID, r.Gen, i)
		if err := forceStrategy(o, r.ID, r.Gen); err != nil {
			return pieces{}, err
		}
		setFinalRules(o, b.Blocked)
	}
	in := inTag(r.ID, r.Gen)
	outs := make([]any, len(doc.Outbounds))
	for i, o := range doc.Outbounds {
		outs[i] = o
	}
	return pieces{
		outbounds: outs,
		inbound:   socksInbound(in, b.Slot, r.Port),
		rule: map[string]any{
			"type": "field", "ruleTag": ruleTag(r.ID, r.Gen),
			"inboundTag": []string{in}, "outboundTag": outTag(r.ID, r.Gen, 0),
		},
	}, nil
}

// finalRules is the allow list of a freedom outbound: it judges the address that
// was dialled, after the name was resolved (7.4).
func finalRules(blocked []netip.Prefix) []any {
	cidrs := make([]string, 0, len(blocked))
	for _, p := range blocked {
		cidrs = append(cidrs, p.String())
	}
	return []any{
		map[string]any{"action": "block", "ip": cidrs},
		map[string]any{"action": "allow", "network": []string{"tcp"}},
	}
}

// setFinalRules gives a freedom outbound of a fragment the rules of `direct`: a hop
// that ends a dialerProxy chain resolves its server's name itself, and xrayschema
// refuses finalRules in a fragment because the node writes them (7.4). A fragment
// that carried its own settings keeps them; only finalRules is set.
func setFinalRules(o map[string]any, blocked []netip.Prefix) {
	if p, _ := o["protocol"].(string); p != "freedom" {
		return
	}
	st, _ := o["settings"].(map[string]any)
	if st == nil {
		st = map[string]any{}
		o["settings"] = st
	}
	st["finalRules"] = finalRules(blocked)
}

// forceStrategy sets domainStrategy ForceIPv4 on every sockopt of an outbound at
// any depth, adds one where there is none, and rewrites dialerProxy to the tag of
// the chain position. Only a Force strategy returns the error of a failed lookup;
// with UseIP the dial falls back to the host resolver (7.4, B0 E08).
func forceStrategy(o map[string]any, id string, g int) error {
	var walk func(v any, depth int) error
	walk = func(v any, depth int) error {
		if depth > 40 {
			return errors.New("xray: a stored fragment is too deep")
		}
		switch t := v.(type) {
		case map[string]any:
			for k, c := range t {
				if k == "sockopt" {
					if so, ok := c.(map[string]any); ok {
						so["domainStrategy"] = "ForceIPv4"
						if err := rewriteDialer(so, id, g); err != nil {
							return err
						}
					}
				}
				if err := walk(c, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, c := range t {
				if err := walk(c, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(o, 0); err != nil {
		return err
	}
	// A protocol with no stream settings of its own (wireguard) is left as it is:
	// it has no sockopt to add to, and a key that its loader does not know is
	// ignored there, not refused. Whether its endpoint lookup is covered is a check
	// for a real node (not run here).
	if p, _ := o["protocol"].(string); p == "wireguard" {
		return nil
	}
	ss, _ := o["streamSettings"].(map[string]any)
	if ss == nil {
		ss = map[string]any{}
		o["streamSettings"] = ss
	}
	// A sockopt that was there has been handled by the walk above (strategy and
	// dialerProxy); only a missing one is added here.
	if _, ok := ss["sockopt"].(map[string]any); !ok {
		ss["sockopt"] = map[string]any{"domainStrategy": "ForceIPv4"}
	}
	return nil
}

func rewriteDialer(so map[string]any, id string, g int) error {
	d, ok := so["dialerProxy"]
	if !ok {
		return nil
	}
	s, _ := d.(string)
	if s == "" {
		delete(so, "dialerProxy")
		return nil
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 0 || n > 7 || fmt.Sprint(n) != s {
		return errors.New("xray: a dialerProxy is not a chain position")
	}
	so["dialerProxy"] = outTag(id, g, n)
	return nil
}

// addCalls are the three stdin texts of a live add: ado, adrules, adi.
func addCalls(b baseInput, r runRec) (ado, adrules, adi []byte, err error) {
	p, err := renderConfig(b, r)
	if err != nil {
		return nil, nil, nil, err
	}
	ado, _ = json.Marshal(map[string]any{"outbounds": p.outbounds})
	adrules, _ = json.Marshal(map[string]any{"routing": map[string]any{"rules": []any{p.rule}}})
	adi, _ = json.Marshal(map[string]any{"inbounds": []any{p.inbound}})
	return ado, adrules, adi, nil
}

// removeTags are the tags of one generation of a config, for rmrules, rmi and rmo.
func removeTags(r runRec) (rule, in string, outs []string) {
	for n := 0; n < r.Outs; n++ {
		outs = append(outs, outTag(r.ID, r.Gen, n))
	}
	return ruleTag(r.ID, r.Gen), inTag(r.ID, r.Gen), outs
}

// stringsOf reads every string of a JSON text, for the redaction of error texts.
func stringsOf(raw []byte) []string {
	var out []string
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil
	}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

// redact replaces every string value of the fragment that the error text repeats
// with <value> and clips the result (7.5 step 1: the text may hold a password or an
// address that an admin pasted), longest values first so a short value inside a
// long one does not leave the rest of it.
func redact(text string, fragment []byte) string {
	var vals []string
	seen := map[string]bool{}
	add := func(v string) {
		if len(v) >= 3 && v != "<value>" && strings.TrimSpace(v) != "" && !seen[v] {
			seen[v] = true
			vals = append(vals, v)
		}
	}
	for _, v := range stringsOf(fragment) {
		// xrayctl turns a control character into a space before the text gets here, and
		// Xray prints some values in Go's quoted form, so the value is also looked for
		// in those two spellings (a tab or a quote inside a password is no reason for it
		// to reach the panel).
		q := strconv.Quote(v)
		q = q[1 : len(q)-1]
		for _, s := range []string{v, q} {
			add(s)
			add(mapControl(s))
		}
	}
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	for _, v := range vals {
		text = strings.ReplaceAll(text, v, "<value>")
	}
	text = mapControl(strings.ToValidUTF8(text, "?"))
	if len(text) > 500 {
		text = strings.ToValidUTF8(text[:500], "")
	}
	return text
}

// mapControl is what xrayctl does to the child's text: a control character is a space.
func mapControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
