package xrayschema

import (
	"strings"
	"testing"
)

// Tests for the findings of review round 5 of B1 (p4b-proxy 7.2): what a header, a
// credential, a mask order or a list can make the one Xray process of a node do, which
// the trial and the probes never reach.

func httpExit(settings string) string {
	return `{"outbounds":[{"protocol":"http","settings":{"address":"203.0.113.7","port":3128` + settings + `}}]}`
}

// B1-r5-2: the header values of an http outbound are Go templates that Xray runs on every
// connection.
func TestHTTPHeaderValuesAreNoTemplates(t *testing.T) {
	prog := `{{if eq .Target.Address.String \"evil.example\"}}{{range 9000000000}}{{printf \"%1000000d\" 0}}{{end}}{{end}}`
	r := refuse(t, "template", httpExit(`,"headers":{"X":"`+prog+`"}`))
	for _, rj := range r.Rejected {
		if strings.Contains(rj.Msg, "evil") {
			t.Errorf("the reason echoes the value: %s", rj.Msg)
		}
	}
	refuse(t, "in a list", httpExit(`,"headers":{"X":["a","{{ .Source }}"]}`))
	refuse(t, "an opener alone", httpExit(`,"headers":{"X":"a{{"}`))
	// A raw subtree with a headers member is refused in the same way, in any case.
	refuse(t, "raw headers", stream4(`"xhttpSettings":{"h2Params":{"headers":{"X":"{{ .Target }}"}}}`))
	refuse(t, "raw HEADERS", stream4(`"xhttpSettings":{"h2Params":{"a":{"HEADERS":{"X":["{{x"]}}}}`))
	refuse(t, "unknown key", stream4(`"newThing":{"headers":{"X":"{{ .Source }}"}}`), "outbounds[0].streamSettings.newThing")
	// Plain values stay, and the transports whose headers are no templates keep braces.
	mustOK(t, httpExit(`,"headers":{"X-A":"b","X-B":["c","d}"]}`))
	mustOK(t, stream4(`"method":"ws","wsSettings":{"headers":{"X":"{{ literal }}"}}`))
	mustOK(t, stream4(`"method":"xhttp","xhttpSettings":{"headers":{"X":"{{ literal }}"}}`))
	mustOK(t, stream4(`"method":"httpupgrade","httpupgradeSettings":{"headers":{"X":"{{ literal }}"}}`))
}

// B1-r5-3: SOCKS5 carries the length of the user and the password in one byte, and the
// client panics when they do not fit its buffer once the exit answers method 02.
func TestSocksCredentialsAreAtMost255Bytes(t *testing.T) {
	long := strings.Repeat("p", 256)
	ok := strings.Repeat("p", 255)
	sock := func(inner string) string {
		return `{"outbounds":[{"protocol":"socks","settings":{` + inner + `}}]}`
	}
	top := func(k, v string) string { return sock(`"address":"203.0.113.7","port":1080,"` + k + `":"` + v + `"`) }
	srv := func(k, v string) string {
		other := map[string]string{"user": "pass", "pass": "user"}[k]
		return sock(`"servers":[{"address":"203.0.113.7","port":1080,"users":[{"` + other + `":"x","` + k + `":"` + v + `"}]}]`)
	}
	for _, k := range []string{"user", "pass"} {
		r := refuse(t, "top "+k, top(k, long))
		for _, rj := range r.Rejected {
			if strings.Contains(rj.Msg, long[:20]) {
				t.Errorf("the reason echoes the value")
			}
		}
		refuse(t, "servers "+k, srv(k, long))
		refuse(t, "9000 bytes", top(k, strings.Repeat("p", 9000)))
		mustOK(t, top(k, ok))
		mustOK(t, srv(k, ok))
	}
}

// B1-r5-4: an AES mkcp-legacy mask (one with a value) after another header mask lets one
// datagram of an empty payload through the size check of the stack.
func TestAESMaskCannotFollowAHeaderMask(t *testing.T) {
	udp := func(masks ...string) string {
		return stream4(`"method":"kcp","finalmask":{"udp":[` + strings.Join(masks, ",") + `]}`)
	}
	aes := `{"type":"mkcp-legacy","settings":{"value":"secret"}}`
	srtp := `{"type":"mkcp-legacy","settings":{"header":"srtp"}}`
	sal := `{"type":"salamander","settings":{"password":"p"}}`
	gecko := `{"type":"salamander","settings":{"password":"p","packetSize":"512-1200"}}`
	noise := `{"type":"noise","settings":{"noise":[{"rand":"10-20"}]}}`
	refuse(t, "salamander then aes", udp(sal, aes))
	refuse(t, "header then aes", udp(srtp, aes))
	refuse(t, "aes then aes", udp(aes, aes))
	refuse(t, "run of three", udp(sal, srtp, aes))
	refuse(t, "case", udp(srtp, strings.Replace(aes, "mkcp-legacy", "MKCP-Legacy", 1)))
	// The safe order, a run that is broken by another mask, and the masks alone.
	mustOK(t, udp(aes, srtp))
	mustOK(t, udp(aes, sal))
	mustOK(t, udp(aes))
	mustOK(t, udp(srtp, noise, aes))
	mustOK(t, udp(srtp, gecko, aes))
	mustOK(t, udp(sal, srtp))
}

// B1-r5-5: a noise can send packets of its own, and the gecko writer panics above 8,184
// bytes, so a noise above 1,500 bytes cannot share a stream with it.
func TestNoiseBesideGeckoIsSmall(t *testing.T) {
	gecko := `{"type":"salamander","settings":{"password":"p","packetSize":"512-1200"}}`
	noise := func(items string) string {
		return `{"type":"noise","settings":{"noise":[` + items + `]}}`
	}
	udp := func(masks ...string) string {
		return stream4(`"method":"hysteria","finalmask":{"udp":[` + strings.Join(masks, ",") + `]}`)
	}
	for name, item := range map[string]string{
		"rand":        `{"rand":"1-8200"}`,
		"number rand": `{"rand":65535}`,
		"type rand":   `{"type":"rand","packet":"1500-9000"}`,
		"exp":         `{"type":"exp","packet":"<r 4000>"}`,
		"literal":     `{"type":"str","packet":"` + strings.Repeat("a", 1501) + `"}`,
	} {
		refuse(t, name+", noise first", udp(noise(item), gecko))
		refuse(t, name+", gecko first", udp(gecko, noise(item)))
		// Without the gecko mask the same noise is allowed.
		mustOK(t, udp(noise(item), `{"type":"salamander","settings":{"password":"p"}}`))
	}
	mustOK(t, udp(noise(`{"rand":"10-1500"},{"type":"exp","packet":"<r 1000><t>"}`), gecko))
	mustOK(t, udp(noise(`{"type":"str","packet":"`+strings.Repeat("a", 1500)+`"}`), gecko))
	// A freedom hop writes its noises through its own stream.
	freedom := func(settings, masks string) string {
		return `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"tag":"f","protocol":"freedom","settings":{` + settings + `},"streamSettings":{"finalmask":{"udp":[` + masks + `]}}}]}`
	}
	refuse(t, "freedom noises", freedom(`"noises":[{"type":"rand","packet":"1-8200"}]`, gecko))
	refuse(t, "freedom noise", freedom(`"noise":{"type":"rand","packet":"60000"}`, gecko))
	mustOK(t, freedom(`"noises":[{"type":"rand","packet":"1-1200"}]`, gecko))
	mustOK(t, freedom(`"noises":[{"type":"rand","packet":"1-8200"}]`, `{"type":"salamander","settings":{"password":"p"}}`))
	mustOK(t, freedom(`"noises":[{"type":"rand","packet":"1-8200"}]`, ``))
}

// B1-r5-6: the http client keeps its HTTP/2 connections in a map of the process that
// nothing closes, keyed by destination alone.
func TestHTTPExitIsStateful(t *testing.T) {
	tb := Newest()
	for name, frag := range map[string]string{
		"plain":    httpExit(``),
		"in tls":   `{"outbounds":[{"protocol":"http","settings":{"address":"203.0.113.7","port":443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"}}}]}`,
		"any case": `{"outbounds":[{"PROTOCOL":"HTTP"}]}`,
		"as a hop": `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"h"}}},{"tag":"h","protocol":"http","settings":{"address":"203.0.113.8","port":3128}}]}`,
	} {
		if !tb.Stateful([]byte(frag)) {
			t.Errorf("%s: not stateful", name)
		}
	}
}

// B1-r5-7: the dialer of the download half of xhttp panics on a missing address or a
// method other than xhttp, with no check of its own.
func TestXhttpDownloadSettingsNeedAddressAndMethod(t *testing.T) {
	dl := func(inner string) string {
		return stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{` + inner + `}}`)
	}
	extra := func(inner string) string {
		return stream4(`"method":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{` + inner + `}}}`)
	}
	for _, f := range []func(string) string{dl, extra} {
		mustOK(t, f(`"address":"203.0.113.9","port":443,"method":"xhttp"`))
		mustOK(t, f(`"address":"203.0.113.9","port":443,"method":"splithttp"`))
		mustOK(t, f(`"address":"203.0.113.9","port":443,"network":"xhttp"`))
		refuse(t, "no address", f(`"port":443,"method":"xhttp"`))
		refuse(t, "empty address", f(`"address":"","port":443,"method":"xhttp"`))
		refuse(t, "no method", f(`"address":"203.0.113.9","port":443`))
		refuse(t, "raw", f(`"address":"203.0.113.9","port":443,"method":"raw"`))
		refuse(t, "ws", f(`"address":"203.0.113.9","port":443,"method":"ws"`))
	}
	// No downloadSettings at all is the common case.
	mustOK(t, stream4(`"method":"xhttp","xhttpSettings":{"host":"a.example"}`))
}

// B1-r5-8: Xray expands a port list into one slice, so the parts are bounded in sum.
func TestUDPHopPortListIsBoundedInSum(t *testing.T) {
	hop := func(ports string) string {
		return stream4(`"method":"hysteria","finalmask":{"udp":[{"type":"udphop","settings":{"interval":30,"remotePorts":"` + ports + `"}}]}`)
	}
	mustOK(t, hop("1-65535"))
	mustOK(t, hop("20000-30000,40000,50000-50100"))
	mustOK(t, hop("443"))
	refuse(t, "700 whole ranges", hop(strings.TrimSuffix(strings.Repeat("1-65535,", 700), ",")))
	refuse(t, "two whole ranges", hop("1-65535,1-65535"))
	refuse(t, "one over", hop("1-65535,1"))
	refuse(t, "out of the port range", hop("0-10"))
}

// B1-r5-9: the gaps of a VLESS encryption text are slept one after the other.
func TestVLESSEncryptionGapsAreBoundedInSum(t *testing.T) {
	key := strings.Repeat("A", 43)
	enc := func(pad string) string { return "mlkem768x25519plus.native.1rtt." + pad + key }
	// One gap of the largest size and several small ones stay.
	if why := CheckVLESSEncryption(enc("100-35-35.1-3-10000.")); why != "" {
		t.Errorf("one gap of 10,000 ms: %s", why)
	}
	if why := CheckVLESSEncryption(enc("100-35-35.1-3-100.50-0-1.1-0-100.")); why != "" {
		t.Errorf("two small gaps: %s", why)
	}
	if why := CheckVLESSEncryption(enc("100-35-35.1-3-5000.50-0-1.1-0-5000.")); why != "" {
		t.Errorf("gaps adding up to the bound: %s", why)
	}
	if CheckVLESSEncryption(enc("100-35-35.1-3-5000.50-0-1.1-0-5001.")) == "" {
		t.Error("gaps adding up to more than the bound passed")
	}
	// The largest end of a gap counts, whichever it is.
	if CheckVLESSEncryption(enc("100-35-35.100-10000-0.0-0-0.100-0-10000.")) == "" {
		t.Error("two gaps of 10,000 ms passed")
	}
	many := strings.Repeat("0-0-0.100-10000-10000.", 1400)
	user := `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"` + enc(many) + `"}}]}`
	r := refuse(t, "1,400 gaps", user)
	for _, rj := range r.Rejected {
		if strings.Contains(rj.Msg, "10000.") {
			t.Errorf("the reason echoes the value: %s", rj.Msg)
		}
	}
}
