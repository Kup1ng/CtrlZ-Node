// Package xrayschema is the allow-list of Xray configuration (p4b-proxy 7.2). A
// config a tenant admin pastes or imports is parsed here, checked against the table
// of one Xray release, and written again in a normal form. The panel runs it on
// save, and the node runs it again with the release it has installed before it
// tests the config with that binary.
//
// What it protects: Xray decodes JSON with encoding/json, which matches keys without
// case and ignores keys it does not know. So the checker folds case the same way,
// refuses a key given twice, refuses every key that reaches a file, the environment,
// a process or a script engine of the host, and lets nothing it does not know pass
// without a named, per-path decision (accept_unknown). It never echoes a value of
// the fragment: a rejection names a path and a reason, because a value may be a
// password.
package xrayschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits of a fragment.
const (
	// MaxFragmentBytes is the largest fragment (D31, p4b-proxy 3.2 item 2).
	MaxFragmentBytes = 32 << 10
	// MaxDepth is the deepest nesting of arrays and objects. A table that contains
	// itself (xhttp downloadSettings) stops here.
	MaxDepth = 32
	// maxMembers and maxItems bound one object and one array.
	maxMembers = 256
	maxItems   = 256
)

// Issue is one finding. Path is outbounds[i]... with the key spelled as it was
// written for an unknown key and in canonical case otherwise.
type Issue struct {
	Path string
	Msg  string
}

// Change is one thing the normal form did to the input, or one decision that let an
// unknown thing pass. Nothing is dropped or changed without one (D11).
type Change struct {
	Path string
	Msg  string
}

// Result is what Check returns. Normalized is empty when Rejected is not. Warnings
// are blocking: a fragment passes only when both lists are empty, and a warning goes
// away only when its exact path is in accept_unknown, which turns it into a Change.
type Result struct {
	Normalized []byte
	Diff       []Change
	Warnings   []Issue
	Rejected   []Issue
}

// OK reports whether the fragment may be stored.
func (r *Result) OK() bool { return len(r.Warnings) == 0 && len(r.Rejected) == 0 }

// Table is the allow-list of one Xray release.
type Table struct {
	tag   string
	build func() *node
}

// Release is the tag of the Xray release the table was written from.
func (t Table) Release() string { return t.tag }

// ---- parsing ----------------------------------------------------------------------

type val struct {
	k       byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' boolean
	members []member
	items   []*val
	s       string // a string, or the text of a number
	b       bool
}

type member struct {
	key string
	v   *val
	// dead marks a member merged into its twin spelling; it is not written.
	dead bool
}

var errSyntax = errors.New("not valid JSON")
var errDepth = errors.New("nested deeper than the limit")

func parse(data []byte) (*val, error) {
	if !utf8.Valid(data) {
		return nil, errSyntax
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errSyntax
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (*val, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errSyntax
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth > MaxDepth {
			return nil, errDepth
		}
		switch t {
		case '{':
			v := &val{k: 'o'}
			for dec.More() {
				kt, err := dec.Token()
				key, ok := kt.(string)
				if err != nil || !ok {
					return nil, errSyntax
				}
				if len(v.members) >= maxMembers {
					return nil, errors.New("an object has too many members")
				}
				c, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				v.members = append(v.members, member{key: key, v: c})
			}
			if _, err := dec.Token(); err != nil {
				return nil, errSyntax
			}
			return v, nil
		case '[':
			v := &val{k: 'a'}
			for dec.More() {
				if len(v.items) >= maxItems {
					return nil, errors.New("an array has too many items")
				}
				c, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				v.items = append(v.items, c)
			}
			if _, err := dec.Token(); err != nil {
				return nil, errSyntax
			}
			return v, nil
		}
		return nil, errSyntax
	case string:
		return &val{k: 's', s: t}, nil
	case json.Number:
		return &val{k: 'n', s: t.String()}, nil
	case bool:
		return &val{k: 'b', b: t}, nil
	}
	// null, or anything else: a member that is null means "absent" to Go's decoder,
	// and one spelling of "absent" is enough.
	return nil, errors.New("null is not accepted")
}

// ---- the checker ------------------------------------------------------------------

type dialRef struct {
	out  int
	path string
	v    *val
}

type ctx struct {
	accept  map[string]bool
	res     *Result
	freedom bool // the outbound under the walk is freedom
	out     int
	dialers []dialRef
}

func (c *ctx) reject(path, msg string) {
	c.res.Rejected = append(c.res.Rejected, Issue{path, msg})
}

func (c *ctx) warn(path, msg string) {
	if c.accept[path] {
		c.res.Diff = append(c.res.Diff, Change{path, "accepted as unknown by the admin: " + msg})
		return
	}
	c.res.Warnings = append(c.res.Warnings, Issue{path, msg})
}

func (c *ctx) changed(path, msg string) {
	c.res.Diff = append(c.res.Diff, Change{path, msg})
}

// Check parses one fragment, judges it against the table and returns the normal
// form. accept lists the paths the admin accepted as unknown (accept_unknown): each
// must be a path of the form of ValidPath, and it passes only the thing that sits at
// exactly that path.
func (t Table) Check(fragment []byte, accept []string) Result {
	res := Result{}
	c := &ctx{accept: map[string]bool{}, res: &res}
	for _, p := range accept {
		if !ValidPath(p) {
			c.reject(clip(p), "accept_unknown path is not the path of a key inside one outbound")
			continue
		}
		c.accept[p] = true
	}
	if len(fragment) > MaxFragmentBytes {
		c.reject("", "the fragment is larger than the limit")
		return res
	}
	root, err := parse(fragment)
	if err != nil {
		c.reject("", err.Error())
		return res
	}
	if root.k != 'o' {
		c.reject("", "the fragment is not an object")
		return res
	}
	var outs *val
	for i := range root.members {
		m := &root.members[i]
		if !strings.EqualFold(m.key, "outbounds") {
			c.reject(clip(m.key), "a fragment holds one top-level key, outbounds")
			continue
		}
		if outs != nil {
			c.reject("outbounds", "key given twice")
			continue
		}
		m.key = "outbounds"
		outs = m.v
	}
	switch {
	case outs == nil:
		c.reject("outbounds", "missing")
	case outs.k != 'a' || len(outs.items) == 0 || len(outs.items) > MaxOutbounds:
		c.reject("outbounds", "must be an array of 1 to 8 outbounds")
	}
	if len(res.Rejected) != 0 {
		return res
	}
	node := t.build()
	for i, o := range outs.items {
		c.out = i
		c.freedom = isFreedom(o)
		path := "outbounds[" + strconv.Itoa(i) + "]"
		c.walk(node, o, path)
	}
	if len(res.Rejected) == 0 {
		c.chain(outs)
	}
	if len(res.Rejected) != 0 {
		res.Diff = nil
		return res
	}
	res.Normalized = encode(root)
	return res
}

func clip(s string) string {
	if len(s) > 64 {
		s = s[:64]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func isFreedom(o *val) bool {
	if o.k != 'o' {
		return false
	}
	for _, m := range o.members {
		if strings.EqualFold(m.key, "protocol") && m.v.k == 's' {
			l := strings.ToLower(m.v.s)
			return l == "freedom" || l == "direct"
		}
	}
	return false
}

// globalRejected are the keys that reach a file, the environment, a process or a
// script engine of the host, or the sockets of the host, at any depth of an outbound
// (7.2). A key of a free-form map is a value and is not judged here.
func globalRejected() map[string]string {
	return map[string]string{
		"xdrivesettings":      "the xdrive transport reads and writes files of the host",
		"script":              "a script runs in the Lua engine of the host",
		"webhook":             "a webhook sends requests from the host",
		"env":                 "reads the environment of the host",
		"metrics":             "opens a listener on the host",
		"geodata":             "reads and writes geodata files of the host",
		"process":             "reaches a process of the host",
		"redirect":            "redirects traffic of the host",
		"reverse":             "opens a reverse tunnel",
		"masterkeylog":        "writes TLS secrets to a file",
		"certificatefile":     "reads a file of the host",
		"keyfile":             "reads a file of the host",
		"dir":                 "reads a directory of the host",
		"sendthrough":         "binds the socket to an address of the host",
		"mark":                "sets a socket mark of the host",
		"interface":           "binds the socket to an interface of the host",
		"tproxy":              "changes how the host's sockets work",
		"customsockopt":       "sets raw socket options",
		"acceptproxyprotocol": "a server-side setting",
		"proxysettings":       "removed from the release; dialerProxy replaces it",
	}
}

func (c *ctx) forbiddenKey(n *node, key string) (string, bool) {
	for k, why := range globalRejected() {
		if strings.EqualFold(key, k) {
			return why, true
		}
	}
	if c.freedom && strings.EqualFold(key, "dialerProxy") {
		return "a freedom outbound is the last hop and has no dialerProxy", true
	}
	if n != nil {
		for k, why := range n.reject {
			if strings.EqualFold(key, k) {
				return why, true
			}
		}
	}
	return "", false
}

// badValue reports whether a string value, or one comma-separated part of it, starts
// like a reference to a file, the geodata or the environment of the host: ext:,
// geoip:, geosite: and env:. Xray reads env: in an address or a port list, and ext:
// and the geo prefixes in every list of rules.
func badValue(s string) bool {
	for _, part := range strings.Split(s, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		p = strings.TrimPrefix(p, "!")
		for _, pre := range []string{"ext:", "ext-ip:", "ext-domain:", "geoip:", "geosite:", "env:"} {
			if strings.HasPrefix(p, pre) {
				return true
			}
		}
	}
	return false
}

func (c *ctx) checkString(path, s string) bool {
	if badValue(s) {
		c.reject(path, "the value reaches a file, the geodata or the environment of the host")
		return false
	}
	return true
}

// scanRaw judges a subtree the table has no node for: the keys and values that are
// never allowed are refused in it too.
func (c *ctx) scanRaw(v *val, path string) {
	switch v.k {
	case 'o':
		for _, m := range v.members {
			p := path + "." + clip(m.key)
			if why, bad := c.forbiddenKey(nil, m.key); bad {
				c.reject(p, "key is never allowed: "+why)
				continue
			}
			c.scanRaw(m.v, p)
		}
	case 'a':
		for i, it := range v.items {
			c.scanRaw(it, path+"["+strconv.Itoa(i)+"]")
		}
	case 's':
		c.checkString(path, v.s)
	}
}

// lookup finds the canonical key of a member in an object node. Go's decoder takes
// an exact match first and then the first match under Unicode simple folding, and
// strings.EqualFold is that folding.
func lookup(n *node, key string) (canon string, child *node, viaAlias bool, ok bool) {
	if ch, found := n.fields[key]; found {
		return key, ch, false, true
	}
	if nw, found := n.alias[key]; found {
		return nw, n.fields[nw], true, true
	}
	keys := make([]string, 0, len(n.fields)+len(n.alias))
	for k := range n.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(key, k) {
			return k, n.fields[k], false, true
		}
	}
	olds := make([]string, 0, len(n.alias))
	for k := range n.alias {
		olds = append(olds, k)
	}
	sort.Strings(olds)
	for _, k := range olds {
		if strings.EqualFold(key, k) {
			return n.alias[k], n.fields[n.alias[k]], true, true
		}
	}
	return "", nil, false, false
}

func (c *ctx) walk(n *node, v *val, path string) {
	n = n.resolve()
	switch n.k {
	case kObj:
		if v.k != 'o' {
			c.reject(path, "expected an object")
			return
		}
		c.walkObject(n, v, path)
	case kArr:
		if v.k != 'a' {
			c.reject(path, "expected an array")
			return
		}
		for i, it := range v.items {
			c.walk(n.elem, it, path+"["+strconv.Itoa(i)+"]")
		}
	case kStr:
		if v.k != 's' {
			c.reject(path, "expected a string")
			return
		}
		if c.checkString(path, v.s) && n.dialer {
			c.dialers = append(c.dialers, dialRef{c.out, path, v})
		}
	case kNum:
		if v.k != 'n' {
			c.reject(path, "expected a number")
		}
	case kBool:
		if v.k != 'b' {
			c.reject(path, "expected true or false")
		}
	case kStrList:
		switch v.k {
		case 's':
			c.checkString(path, v.s)
		case 'a':
			for i, it := range v.items {
				if it.k != 's' {
					c.reject(path+"["+strconv.Itoa(i)+"]", "expected a string")
					continue
				}
				c.checkString(path+"["+strconv.Itoa(i)+"]", it.s)
			}
		default:
			c.reject(path, "expected a string or an array of strings")
		}
	case kRange:
		switch v.k {
		case 'n':
		case 's':
			c.checkString(path, v.s)
		default:
			c.reject(path, "expected a number or a string")
		}
	case kAny:
		switch v.k {
		case 'n', 'b':
		case 's':
			c.checkString(path, v.s)
		default:
			c.reject(path, "expected a string, a number or a boolean")
		}
	case kRaw:
		c.scanRaw(v, path)
	case kStrMap:
		if v.k != 'o' {
			c.reject(path, "expected an object")
			return
		}
		for _, m := range v.members {
			p := path + "." + clip(m.key)
			switch m.v.k {
			case 's':
				c.checkString(p, m.v.s)
			case 'a':
				for i, it := range m.v.items {
					if it.k != 's' {
						c.reject(p, "expected a string or an array of strings")
						break
					}
					c.checkString(p+"["+strconv.Itoa(i)+"]", it.s)
				}
			default:
				c.reject(p, "expected a string or an array of strings")
			}
		}
	case kEnum:
		if v.k != 's' {
			c.reject(path, "expected a string")
			return
		}
		canon, ok := n.enum[strings.ToLower(v.s)]
		if !ok {
			if n.soft {
				c.warn(path, "unknown value")
			} else {
				// A protocol, transport, security or cipher outside the table can never
				// be accepted: the table is the list of what a node may run.
				c.reject(path, "value is not allowed")
			}
			return
		}
		if canon != v.s {
			c.changed(path, "value written in its canonical form")
			v.s = canon
		}
	default:
		c.reject(path, "internal: node without a kind")
	}
}

type group struct {
	canon string
	child *node
	items []gmember
}

type gmember struct {
	m        *member
	viaAlias bool
}

func (c *ctx) walkObject(n *node, v *val, path string) {
	// The selector of a variant is read first so the member that depends on it
	// gets the right node.
	selCanon := ""
	if n.sel != nil {
		for _, m := range v.members {
			if strings.EqualFold(m.key, n.selKey) && m.v.k == 's' {
				if sn, ok := n.fields[n.selKey]; ok {
					selCanon = sn.resolve().enum[strings.ToLower(m.v.s)]
				}
			}
		}
	}
	var groups []*group
	byCanon := map[string]*group{}
	var unknown []*member
	for i := range v.members {
		m := &v.members[i]
		if why, bad := c.forbiddenKey(n, m.key); bad {
			c.reject(path+"."+clip(m.key), "key is never allowed: "+why)
			continue
		}
		canon, child, viaAlias, ok := lookup(n, m.key)
		if !ok {
			unknown = append(unknown, m)
			continue
		}
		g := byCanon[canon]
		if g == nil {
			g = &group{canon: canon, child: child}
			byCanon[canon] = g
			groups = append(groups, g)
		}
		g.items = append(g.items, gmember{m, viaAlias})
	}
	for _, g := range groups {
		p := path + "." + g.canon
		child := g.child
		if n.sel != nil && g.canon == n.selOn {
			child = n.sel[selCanon]
		}
		newSpelled, oldSpelled := 0, 0
		for _, it := range g.items {
			if it.viaAlias {
				oldSpelled++
			} else {
				newSpelled++
			}
		}
		if newSpelled > 1 || oldSpelled > 1 {
			c.reject(p, "key given twice")
			continue
		}
		for _, it := range g.items {
			if child == nil {
				// The selector is not in the table: the rejection of the selector
				// stands, and the settings are only scanned.
				c.scanRaw(it.m.v, p)
			} else {
				c.walk(child, it.m.v, p)
			}
		}
		if len(g.items) == 2 {
			a, b := g.items[0].m, g.items[1].m
			if !bytes.Equal(encode(a.v), encode(b.v)) {
				c.reject(p, "the old and the new spelling of the key hold different values")
				continue
			}
			c.changed(p, "the old and the new spelling of the key held one value; written once")
		}
		for _, it := range g.items {
			if it.m.key != g.canon {
				c.changed(p, "key written in its canonical spelling")
			}
			it.m.key = g.canon
		}
		if len(g.items) == 2 {
			// Drop the second one; both are equal and now share a key.
			g.items[1].m.dead = true
		}
	}
	for _, m := range unknown {
		p := path + "." + m.key
		if len(m.key) > 64 {
			p = path + "." + clip(m.key)
		}
		c.warn(p, "unknown key")
		c.scanRaw(m.v, p)
	}
	// Remove the merged duplicates, then force what the normal form forces.
	kept := v.members[:0]
	for _, m := range v.members {
		if !m.dead {
			kept = append(kept, m)
		}
	}
	v.members = kept
	for _, key := range n.forceTrue {
		found := false
		for i := range v.members {
			if v.members[i].key == key {
				found = true
				if v.members[i].v.k != 'b' || !v.members[i].v.b {
					c.changed(path+"."+key, "set to true: the node cannot open a kernel interface")
					v.members[i].v = &val{k: 'b', b: true}
				}
			}
		}
		if !found {
			c.changed(path+"."+key, "set to true: the node cannot open a kernel interface")
			v.members = append(v.members, member{key: key, v: &val{k: 'b', b: true}})
		}
	}
	sort.SliceStable(v.members, func(i, j int) bool { return v.members[i].key < v.members[j].key })
}

// chain judges the dialerProxy links of the fragment (7.2): each names the tag of
// exactly one other outbound, there is no cycle, every outbound is reached from the
// first, and the first is not freedom. It then writes the tags n and the links in
// the form of the normal form, so no tag of the user reaches Xray.
func (c *ctx) chain(outs *val) {
	count := map[string]int{}
	index := map[string]int{}
	for i, o := range outs.items {
		for _, m := range o.members {
			if m.key == "tag" && m.v.k == 's' && m.v.s != "" {
				count[m.v.s]++
				index[m.v.s] = i
			}
		}
	}
	edges := make([][]int, len(outs.items))
	for _, d := range c.dialers {
		if d.v.s == "" {
			continue
		}
		t, ok := index[d.v.s]
		if !ok || count[d.v.s] != 1 {
			c.reject(d.path, "dialerProxy names no outbound of the fragment, or more than one")
			continue
		}
		if t == d.out {
			c.reject(d.path, "dialerProxy names its own outbound")
			continue
		}
		edges[d.out] = append(edges[d.out], t)
	}
	if len(c.res.Rejected) != 0 {
		return
	}
	if isFreedom(outs.items[0]) {
		c.reject("outbounds[0].protocol", "the first outbound is the exit and cannot be freedom")
	}
	// Cycles, by depth-first search with colours.
	state := make([]uint8, len(edges))
	var dfs func(i int) bool
	dfs = func(i int) bool {
		state[i] = 1
		for _, j := range edges[i] {
			if state[j] == 1 || state[j] == 0 && dfs(j) {
				return true
			}
		}
		state[i] = 2
		return false
	}
	for i := range edges {
		if state[i] == 0 && dfs(i) {
			c.reject("outbounds["+strconv.Itoa(i)+"]", "the dialerProxy links make a cycle")
			return
		}
	}
	// Reached from the first.
	seen := make([]bool, len(edges))
	var visit func(i int)
	visit = func(i int) {
		if seen[i] {
			return
		}
		seen[i] = true
		for _, j := range edges[i] {
			visit(j)
		}
	}
	visit(0)
	for i, s := range seen {
		if !s {
			c.reject("outbounds["+strconv.Itoa(i)+"]", "not reached from the first outbound through dialerProxy")
		}
	}
	if len(c.res.Rejected) != 0 {
		return
	}
	for i, o := range outs.items {
		set := false
		for k := range o.members {
			if o.members[k].key == "tag" {
				o.members[k].v = &val{k: 's', s: strconv.Itoa(i)}
				set = true
			}
		}
		if !set {
			o.members = append(o.members, member{key: "tag", v: &val{k: 's', s: strconv.Itoa(i)}})
		}
		sort.SliceStable(o.members, func(a, b int) bool { return o.members[a].key < o.members[b].key })
	}
	for _, d := range c.dialers {
		if d.v.s == "" {
			continue
		}
		d.v.s = strconv.Itoa(index[d.v.s])
	}
}

// ---- output -----------------------------------------------------------------------

func encode(v *val) []byte {
	var b bytes.Buffer
	write(&b, v)
	return b.Bytes()
}

func write(b *bytes.Buffer, v *val) {
	switch v.k {
	case 'o':
		b.WriteByte('{')
		for i, m := range v.members {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, m.key)
			b.WriteByte(':')
			write(b, m.v)
		}
		b.WriteByte('}')
	case 'a':
		b.WriteByte('[')
		for i, it := range v.items {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, it)
		}
		b.WriteByte(']')
	case 's':
		writeString(b, v.s)
	case 'n':
		b.WriteString(v.s)
	case 'b':
		if v.b {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	}
}

func writeString(b *bytes.Buffer, s string) {
	e := json.NewEncoder(b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	// Encode ends the value with a newline.
	b.Truncate(b.Len() - 1)
}
