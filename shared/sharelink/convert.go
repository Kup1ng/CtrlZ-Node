package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Convert turns one share link into the text of a fragment {"outbounds":[outbound]}.
// note is the remark of the link, protocol the Xray protocol of the outbound. The
// error never holds a value of the link, only the name of a parameter.
func Convert(link string) (fragment []byte, note, protocol string, err error) {
	if len(link) > MaxLineBytes {
		return nil, "", "", errors.New("the link is too long")
	}
	if !utf8.ValidString(link) {
		return nil, "", "", errors.New("the link is not valid UTF-8")
	}
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok || rest == "" {
		return nil, "", "", errors.New("not a share link: no scheme")
	}
	var ob map[string]any
	switch strings.ToLower(scheme) {
	case "vless":
		ob, note, err = convertVLESS(rest)
	case "vmess":
		ob, note, err = convertVMess(rest)
	case "trojan":
		ob, note, err = convertTrojan(rest)
	case "ss":
		ob, note, err = convertSS(rest)
	case "hysteria2", "hy2":
		ob, note, err = convertHysteria2(rest)
	default:
		return nil, "", "", errors.New("unknown scheme: the converter knows vless, vmess, trojan, ss and hysteria2")
	}
	if err != nil {
		return nil, "", "", err
	}
	protocol, _ = ob["protocol"].(string)
	fragment, err = json.Marshal(map[string]any{"outbounds": []any{ob}})
	if err != nil {
		return nil, "", "", err
	}
	return fragment, clipNote(note), protocol, nil
}

func clipNote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 120 {
		s = string([]rune(s)[:120])
	}
	return s
}

// ---- parameters ---------------------------------------------------------------------

// params is the query of a link, by lower-case name. A name given twice is an
// error, and a name nobody read is an error too: that is how "unknown parameter" is
// found without a list per scheme.
type params struct {
	m    map[string]string
	used map[string]bool
}

func newParams() *params { return &params{m: map[string]string{}, used: map[string]bool{}} }

func parseQuery(raw string) (*params, error) {
	p := newParams()
	if raw == "" {
		return p, nil
	}
	for _, kv := range strings.Split(raw, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k, err1 := url.QueryUnescape(k)
		v, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			return nil, errors.New("a parameter is not percent-encoded correctly")
		}
		k = strings.ToLower(k)
		if _, dup := p.m[k]; dup {
			return nil, fmt.Errorf("parameter %q is given twice", clipName(k))
		}
		p.m[k] = v
	}
	return p, nil
}

func clipName(s string) string {
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.ToValidUTF8(s, "?")
}

func (p *params) get(name string) string {
	p.used[name] = true
	return p.m[name]
}

func (p *params) has(name string) bool {
	p.used[name] = true
	_, ok := p.m[name]
	return ok
}

// leftover fails on the first parameter nobody read.
func (p *params) leftover() error {
	var names []string
	for k := range p.m {
		if !p.used[k] {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("unknown parameter %q", clipName(names[0]))
}

func (p *params) boolean(name string) (bool, error) {
	switch strings.ToLower(p.get(name)) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fmt.Errorf("parameter %q is not 0, 1, true or false", name)
}

// ---- host, port ---------------------------------------------------------------------

func splitHostPort(hostport string) (string, int, error) {
	host, port := "", ""
	switch {
	case strings.HasPrefix(hostport, "["):
		end := strings.Index(hostport, "]")
		if end < 0 || end+1 >= len(hostport) || hostport[end+1] != ':' {
			return "", 0, errors.New("the address is not [host]:port")
		}
		host, port = hostport[1:end], hostport[end+2:]
	default:
		i := strings.LastIndex(hostport, ":")
		if i < 0 {
			return "", 0, errors.New("the address has no port")
		}
		host, port = hostport[:i], hostport[i+1:]
	}
	return checkHostPort(host, port)
}

func checkHostPort(host, port string) (string, int, error) {
	if host == "" || len(host) > 253 {
		return "", 0, errors.New("the host is empty or too long")
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f {
			return "", 0, errors.New("the host has a space or a control character")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", 0, errors.New("the port is not a number from 1 to 65535")
	}
	return host, n, nil
}

// parseURL reads scheme-less text after "scheme://" through net/url.
func parseURL(scheme, rest string) (*url.URL, error) {
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil {
		return nil, errors.New("the link is not a valid URL")
	}
	return u, nil
}

func hostPortOf(u *url.URL) (string, int, error) {
	return checkHostPort(u.Hostname(), u.Port())
}

// ---- stream settings ----------------------------------------------------------------

// streamParams are the parameters stream reads. Each is judged as used or stray.
func streamParams() []string {
	return []string{"type", "security", "host", "path", "headertype", "servicename", "authority", "mode", "extra", "seed",
		"sni", "fp", "alpn", "allowinsecure", "pcs", "ech", "pbk", "sid", "spx", "pqv"}
}

func parseBool(name, v string) (bool, error) {
	switch strings.ToLower(v) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fmt.Errorf("parameter %q is not 0, 1, true or false", name)
}

// stream builds streamSettings from the parameters every scheme shares. security is
// the default when the link names none. A parameter that carries a value the chosen
// transport or security does not use is an error: it would be a setting the admin
// believes is on.
func stream(p *params, defaultSecurity string) (map[string]any, error) {
	consumed := map[string]bool{}
	rd := func(name string) string { consumed[name] = true; return p.m[name] }
	ss := map[string]any{}
	typ := strings.ToLower(rd("type"))
	switch typ {
	case "", "tcp", "raw":
		ss["method"] = "raw"
		switch strings.ToLower(rd("headertype")) {
		case "", "none":
		case "http":
			req := map[string]any{}
			if path := rd("path"); path != "" {
				req["path"] = splitList(path)
			}
			if host := rd("host"); host != "" {
				req["headers"] = map[string]any{"Host": splitList(host)}
			}
			ss["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		default:
			return nil, errors.New("parameter \"headertype\" has a value the converter does not know for tcp")
		}
	case "ws", "websocket":
		ss["method"] = "ws"
		ws := map[string]any{}
		setIf(ws, "path", rd("path"))
		setIf(ws, "host", rd("host"))
		ss["wsSettings"] = ws
	case "httpupgrade":
		ss["method"] = "httpupgrade"
		hu := map[string]any{}
		setIf(hu, "path", rd("path"))
		setIf(hu, "host", rd("host"))
		ss["httpupgradeSettings"] = hu
	case "grpc":
		ss["method"] = "grpc"
		g := map[string]any{}
		setIf(g, "serviceName", rd("servicename"))
		setIf(g, "authority", rd("authority"))
		switch strings.ToLower(rd("mode")) {
		case "multi":
			g["multiMode"] = true
		case "", "gun":
		default:
			return nil, errors.New("parameter \"mode\" is not gun or multi for grpc")
		}
		ss["grpcSettings"] = g
	case "xhttp", "splithttp":
		ss["method"] = "xhttp"
		x := map[string]any{}
		setIf(x, "path", rd("path"))
		setIf(x, "host", rd("host"))
		setIf(x, "mode", rd("mode"))
		if e := rd("extra"); e != "" {
			var extra map[string]any
			if err := json.Unmarshal([]byte(e), &extra); err != nil || extra == nil {
				return nil, errors.New("parameter \"extra\" is not a JSON object")
			}
			x["extra"] = extra
		}
		ss["xhttpSettings"] = x
	case "kcp", "mkcp":
		// seed and the header type moved to the mkcp-legacy mask in this release, and a
		// guess at their mapping would be a setting the admin believes is on.
		ss["method"] = "kcp"
		if rd("seed") != "" {
			return nil, errors.New("parameter \"seed\" of kcp is not supported by the converter")
		}
		if h := strings.ToLower(rd("headertype")); h != "" && h != "none" {
			return nil, errors.New("parameter \"headertype\" of kcp is not supported by the converter")
		}
	case "h2", "http", "quic":
		return nil, errors.New("this transport was removed from Xray: use xhttp")
	default:
		return nil, errors.New("parameter \"type\" names a transport the converter does not know")
	}

	sec := strings.ToLower(rd("security"))
	if sec == "" {
		sec = defaultSecurity
	}
	switch sec {
	case "none":
	case "tls":
		ss["security"] = "tls"
		t := map[string]any{}
		setIf(t, "serverName", rd("sni"))
		setIf(t, "fingerprint", rd("fp"))
		if a := rd("alpn"); a != "" {
			t["alpn"] = splitList(a)
		}
		ins, err := parseBool("allowinsecure", rd("allowinsecure"))
		if err != nil {
			return nil, err
		}
		if ins {
			t["allowInsecure"] = true
		}
		setIf(t, "pinnedPeerCertSha256", rd("pcs"))
		setIf(t, "echConfigList", rd("ech"))
		ss["tlsSettings"] = t
	case "reality":
		ss["security"] = "reality"
		r := map[string]any{}
		setIf(r, "serverName", rd("sni"))
		setIf(r, "fingerprint", rd("fp"))
		setIf(r, "publicKey", rd("pbk"))
		setIf(r, "shortId", rd("sid"))
		setIf(r, "spiderX", rd("spx"))
		setIf(r, "mldsa65Verify", rd("pqv"))
		if r["publicKey"] == nil {
			return nil, errors.New("security reality needs parameter \"pbk\"")
		}
		ss["realitySettings"] = r
	case "xtls":
		return nil, errors.New("legacy XTLS was removed from Xray: use flow with tls or reality")
	default:
		return nil, errors.New("parameter \"security\" has a value the converter does not know")
	}
	for _, name := range streamParams() {
		p.used[name] = true
		if v := p.m[name]; v != "" && !consumed[name] && !(name == "allowinsecure" && (v == "0" || strings.EqualFold(v, "false"))) {
			return nil, fmt.Errorf("parameter %q does not apply to this transport or security", name)
		}
	}
	return ss, nil
}

func setIf(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func splitList(s string) []any {
	var out []any
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func remark(u *url.URL) string { return u.Fragment }

// ---- schemes ------------------------------------------------------------------------

func newOutbound(protocol string, settings, ss map[string]any) map[string]any {
	ob := map[string]any{"protocol": protocol, "settings": settings}
	if len(ss) > 0 {
		ob["streamSettings"] = ss
	}
	return ob
}

func convertVLESS(rest string) (map[string]any, string, error) {
	u, err := parseURL("vless", rest)
	if err != nil {
		return nil, "", err
	}
	host, port, err := hostPortOf(u)
	if err != nil {
		return nil, "", err
	}
	id := u.User.Username()
	if id == "" || len(id) > 64 {
		return nil, "", errors.New("the user id is empty or too long")
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", err
	}
	enc := p.get("encryption")
	if enc == "" {
		enc = "none"
	}
	settings := map[string]any{"address": host, "port": port, "id": id, "encryption": enc}
	setIf(settings, "flow", p.get("flow"))
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", err
	}
	if err := p.leftover(); err != nil {
		return nil, "", err
	}
	return newOutbound("vless", settings, ss), remark(u), nil
}

func convertTrojan(rest string) (map[string]any, string, error) {
	u, err := parseURL("trojan", rest)
	if err != nil {
		return nil, "", err
	}
	host, port, err := hostPortOf(u)
	if err != nil {
		return nil, "", err
	}
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok {
		pw += ":" + p
	}
	if pw == "" {
		return nil, "", errors.New("the password is empty")
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", err
	}
	if p.has("flow") {
		return nil, "", errors.New("parameter \"flow\" is not supported for trojan in this release")
	}
	ss, err := stream(p, "tls")
	if err != nil {
		return nil, "", err
	}
	if err := p.leftover(); err != nil {
		return nil, "", err
	}
	settings := map[string]any{"address": host, "port": port, "password": pw}
	return newOutbound("trojan", settings, ss), remark(u), nil
}

// decodeBase64 takes the four spellings a link may use: standard or URL alphabet,
// with or without padding.
func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func convertVMess(rest string) (map[string]any, string, error) {
	if strings.Contains(rest, "@") {
		return convertVMessURI(rest)
	}
	body, _, _ := strings.Cut(rest, "#")
	b, ok := decodeBase64(strings.TrimSpace(body))
	if !ok {
		return nil, "", errors.New("the vmess link is neither base64 JSON nor a URI")
	}
	var j map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&j); err != nil || j == nil {
		return nil, "", errors.New("the vmess link does not hold a JSON object")
	}
	str := func(k string) (string, error) {
		v, ok := j[k]
		if !ok {
			return "", nil
		}
		switch x := v.(type) {
		case string:
			return x, nil
		case json.Number:
			return x.String(), nil
		case bool:
			return strconv.FormatBool(x), nil
		}
		return "", fmt.Errorf("field %q is not a string or a number", clipName(k))
	}
	known := map[string]bool{"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true, "net": true,
		"type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true, "fp": true, "allowinsecure": true}
	lower := map[string]string{}
	var keys []string
	for k := range j {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lk := strings.ToLower(k)
		if !known[lk] {
			return nil, "", fmt.Errorf("unknown field %q", clipName(k))
		}
		if _, dup := lower[lk]; dup {
			return nil, "", fmt.Errorf("field %q is given twice", clipName(lk))
		}
		s, err := str(k)
		if err != nil {
			return nil, "", err
		}
		lower[lk] = s
	}
	if aid := lower["aid"]; aid != "" && aid != "0" {
		return nil, "", errors.New("field \"aid\" must be 0: legacy VMess is not supported")
	}
	host, port, err := checkHostPort(lower["add"], lower["port"])
	if err != nil {
		return nil, "", err
	}
	if lower["id"] == "" || len(lower["id"]) > 64 {
		return nil, "", errors.New("the user id is empty or too long")
	}
	p := newParams()
	net := strings.ToLower(lower["net"])
	switch net {
	case "", "tcp":
		p.m["type"] = "tcp"
		p.m["headertype"] = lower["type"]
		p.m["host"], p.m["path"] = lower["host"], lower["path"]
	case "ws", "httpupgrade", "xhttp":
		p.m["type"] = net
		p.m["host"], p.m["path"] = lower["host"], lower["path"]
	case "grpc":
		p.m["type"] = "grpc"
		p.m["servicename"], p.m["authority"], p.m["mode"] = lower["path"], lower["host"], lower["type"]
	case "kcp", "mkcp":
		p.m["type"] = "kcp"
		p.m["seed"], p.m["headertype"] = lower["path"], lower["type"]
	default:
		p.m["type"] = net
	}
	switch tls := strings.ToLower(lower["tls"]); tls {
	case "", "none":
		p.m["security"] = "none"
	case "tls":
		p.m["security"] = "tls"
	default:
		return nil, "", errors.New("field \"tls\" is not tls or empty")
	}
	p.m["sni"], p.m["alpn"], p.m["fp"] = lower["sni"], lower["alpn"], lower["fp"]
	p.m["allowinsecure"] = lower["allowinsecure"]
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", err
	}
	scy := lower["scy"]
	if scy == "" {
		scy = "auto"
	}
	settings := map[string]any{"address": host, "port": port, "id": lower["id"], "security": scy}
	return newOutbound("vmess", settings, ss), lower["ps"], nil
}

func convertVMessURI(rest string) (map[string]any, string, error) {
	u, err := parseURL("vmess", rest)
	if err != nil {
		return nil, "", err
	}
	host, port, err := hostPortOf(u)
	if err != nil {
		return nil, "", err
	}
	id := u.User.Username()
	if id == "" || len(id) > 64 {
		return nil, "", errors.New("the user id is empty or too long")
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", err
	}
	scy := p.get("encryption")
	if scy == "" {
		scy = "auto"
	}
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", err
	}
	if err := p.leftover(); err != nil {
		return nil, "", err
	}
	settings := map[string]any{"address": host, "port": port, "id": id, "security": scy}
	return newOutbound("vmess", settings, ss), remark(u), nil
}

// convertSS reads SIP002 (base64url or percent-encoded user info before @), SIP022
// (a plain "method:password" with a base64 key, percent-encoded) and the old whole-link
// base64 form. A plugin is refused: it would run a program on the node.
func convertSS(rest string) (map[string]any, string, error) {
	rest, frag, _ := strings.Cut(rest, "#")
	note, err := url.PathUnescape(frag)
	if err != nil {
		return nil, "", errors.New("the remark is not percent-encoded correctly")
	}
	rest, query, _ := strings.Cut(rest, "?")
	rest = strings.TrimSuffix(rest, "/")
	var method, password, hostport string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		ui, err := url.PathUnescape(rest[:i])
		if err != nil {
			return nil, "", errors.New("the user info is not percent-encoded correctly")
		}
		hostport = rest[i+1:]
		if !strings.Contains(ui, ":") {
			b, ok := decodeBase64(ui)
			if !ok {
				return nil, "", errors.New("the user info is neither base64 nor method:password")
			}
			ui = string(b)
		}
		method, password, _ = strings.Cut(ui, ":")
	} else {
		b, ok := decodeBase64(rest)
		if !ok {
			return nil, "", errors.New("the ss link is neither SIP002 nor base64")
		}
		whole := string(b)
		i := strings.LastIndex(whole, "@")
		if i < 0 {
			return nil, "", errors.New("the decoded ss link has no @")
		}
		method, password, _ = strings.Cut(whole[:i], ":")
		hostport = whole[i+1:]
	}
	if method == "" || password == "" {
		return nil, "", errors.New("the method or the password is empty")
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, "", err
	}
	p, err := parseQuery(query)
	if err != nil {
		return nil, "", err
	}
	if p.has("plugin") {
		return nil, "", errors.New("parameter \"plugin\" is refused: a plugin would run a program on the node")
	}
	ss, err := stream(p, "none")
	if err != nil {
		return nil, "", err
	}
	if err := p.leftover(); err != nil {
		return nil, "", err
	}
	settings := map[string]any{"address": host, "port": port, "method": strings.ToLower(method), "password": password}
	return newOutbound("shadowsocks", settings, ss), note, nil
}

func convertHysteria2(rest string) (map[string]any, string, error) {
	u, err := parseURL("hysteria2", rest)
	if err != nil {
		return nil, "", err
	}
	host, port, err := hostPortOf(u)
	if err != nil {
		return nil, "", err
	}
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		auth += ":" + pw
	}
	if auth == "" {
		return nil, "", errors.New("the auth is empty")
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, "", err
	}
	if p.has("mport") {
		return nil, "", errors.New("parameter \"mport\" (port hopping) is not supported by the converter")
	}
	tls := map[string]any{}
	setIf(tls, "serverName", p.get("sni"))
	if a := p.get("alpn"); a != "" {
		tls["alpn"] = splitList(a)
	}
	if ins, err := p.boolean("insecure"); err != nil {
		return nil, "", err
	} else if ins {
		tls["allowInsecure"] = true
	}
	if pin := p.get("pinsha256"); pin != "" {
		hex := strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		if len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
			return nil, "", errors.New("parameter \"pinsha256\" is not a SHA-256 in hex")
		}
		tls["pinnedPeerCertSha256"] = hex
	}
	ss := map[string]any{
		"method": "hysteria", "security": "tls", "tlsSettings": tls,
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
	}
	switch obfs := strings.ToLower(p.get("obfs")); obfs {
	case "":
		if p.has("obfs-password") {
			return nil, "", errors.New("parameter \"obfs-password\" needs obfs=salamander")
		}
	case "salamander":
		pw := p.get("obfs-password")
		if pw == "" {
			return nil, "", errors.New("obfs salamander needs parameter \"obfs-password\"")
		}
		ss["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": pw}}}}
	default:
		return nil, "", errors.New("parameter \"obfs\" is not salamander")
	}
	if err := p.leftover(); err != nil {
		return nil, "", err
	}
	settings := map[string]any{"version": 2, "address": host, "port": port}
	return newOutbound("hysteria", settings, ss), remark(u), nil
}
