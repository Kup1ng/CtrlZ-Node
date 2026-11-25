package xrayschema

import (
	"bytes"
	"strings"
	"testing"
)

const (
	vlessReality = `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none","flow":"xtls-rprx-vision"},
		"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","publicKey":"PUBKEY","shortId":"ab12"}}}]}`
)

func newest(t *testing.T) Table {
	t.Helper()
	return Newest()
}

func check(t *testing.T, frag string, accept ...string) Result {
	t.Helper()
	return newest(t).Check([]byte(frag), accept)
}

func mustOK(t *testing.T, frag string, accept ...string) Result {
	t.Helper()
	r := check(t, frag, accept...)
	if !r.OK() {
		t.Fatalf("not accepted: rejected=%v warnings=%v", r.Rejected, r.Warnings)
	}
	return r
}

func mustReject(t *testing.T, what, frag string, accept ...string) Result {
	t.Helper()
	r := check(t, frag, accept...)
	if len(r.Rejected) == 0 {
		t.Errorf("%s: not rejected (warnings=%v)", what, r.Warnings)
	}
	if r.Normalized != nil {
		t.Errorf("%s: a rejected fragment has a normal form", what)
	}
	return r
}

// outboundWith builds a one-outbound fragment of a vless exit with the given extra
// text spliced into the outbound object.
func outboundWith(extra string) string {
	return `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"}` + extra + `}]}`
}

func TestAGoodFragmentPassesAndIsStable(t *testing.T) {
	r := mustOK(t, vlessReality)
	again := newest(t).Check(r.Normalized, nil)
	if !again.OK() || !bytes.Equal(again.Normalized, r.Normalized) {
		t.Fatalf("the normal form is not a fixed point:\n%s\n%s", r.Normalized, again.Normalized)
	}
	if len(again.Diff) != 0 {
		t.Errorf("the normal form changes again: %v", again.Diff)
	}
	// The user's old spelling was written as the new one, and the tag was assigned.
	s := string(r.Normalized)
	for _, want := range []string{`"method":"raw"`, `"tag":"0"`} {
		if !strings.Contains(s, want) {
			t.Errorf("normal form lacks %s: %s", want, s)
		}
	}
	if strings.Contains(s, `"network"`) {
		t.Errorf("old spelling kept: %s", s)
	}
}

func TestKeysAndValuesAreFoldedLikeTheLoader(t *testing.T) {
	r := mustOK(t, `{"OUTBOUNDS":[{"Protocol":"VLESS","SETTINGS":{"Address":"203.0.113.7","PORT":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},"streamsettings":{"Network":"WS","wsSettings":{"PATH":"/p"}}}]}`)
	s := string(r.Normalized)
	for _, want := range []string{`"protocol":"vless"`, `"settings":{`, `"address":"203.0.113.7"`, `"method":"ws"`, `"wsSettings":{"path":"/p"}`, `"streamSettings"`} {
		if !strings.Contains(s, want) {
			t.Errorf("normal form lacks %s: %s", want, s)
		}
	}
	// Unicode simple folding, as in Go's decoder: the Kelvin sign is a "k".
	r = check(t, outboundWith(`,"streamSettings":{"sockopt":{"tcpKeepAliveIdle":1}}`))
	if !r.OK() {
		t.Fatal(r.Rejected, r.Warnings)
	}
	r = check(t, outboundWith(`,"streamSettings":{"sockopt":{"tcpKeepAliveIdle":1}}`))
	if !r.OK() || !strings.Contains(string(r.Normalized), `"tcpKeepAliveIdle"`) {
		t.Errorf("a key spelled with the Kelvin sign is not the key: %v %v", r.Warnings, r.Rejected)
	}
}

func TestRepeatedKeysAreRefusedInAnyCase(t *testing.T) {
	for name, frag := range map[string]string{
		"same spelling":      outboundWith(`,"tag":"a","tag":"b"`),
		"two cases":          outboundWith(`,"tag":"a","TAG":"b"`),
		"in the settings":    `{"outbounds":[{"protocol":"vless","settings":{"port":1,"Port":2}}]}`,
		"two new spellings":  outboundWith(`,"streamSettings":{"method":"raw","Method":"raw"}`),
		"two old spellings":  outboundWith(`,"streamSettings":{"network":"raw","NETWORK":"raw"}`),
		"top level":          `{"outbounds":[],"Outbounds":[]}`,
		"in a free-form map": outboundWith(`,"streamSettings":{"wsSettings":{"headers":{"A":"1","A":"2"}}}`),
	} {
		r := check(t, frag)
		if len(r.Rejected) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBothSpellingsMustAgree(t *testing.T) {
	mustOK(t, outboundWith(`,"streamSettings":{"network":"tcp","method":"raw"}`))
	mustOK(t, outboundWith(`,"streamSettings":{"tcpSettings":{"header":{"type":"none"}},"rawSettings":{"header":{"type":"none"}}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"network":"splithttp","xhttpSettings":{"path":"/a"},"splithttpSettings":{"path":"/a"}}`))
	mustReject(t, "network and method differ", outboundWith(`,"streamSettings":{"network":"ws","method":"raw"}`))
	mustReject(t, "raw and tcp settings differ", outboundWith(`,"streamSettings":{"tcpSettings":{"header":{"type":"http"}},"rawSettings":{"header":{"type":"none"}}}`))
	mustReject(t, "xhttp and splithttp differ", outboundWith(`,"streamSettings":{"xhttpSettings":{"path":"/a"},"splithttpSettings":{"path":"/b"}}`))
	r := mustOK(t, outboundWith(`,"streamSettings":{"tcpSettings":{"header":{"type":"none"}},"rawSettings":{"header":{"type":"none"}}}`))
	if n := strings.Count(string(r.Normalized), `"header"`); n != 1 {
		t.Errorf("the merged spelling is written %d times: %s", n, r.Normalized)
	}
}

// Each key of the always-rejected list is refused at the depth where the loader
// would read it, in three case forms, and also inside a subtree the table does not know.
func TestAlwaysRejectedKeys(t *testing.T) {
	spots := map[string]string{
		"outbound":     `{"outbounds":[{"protocol":"vless","settings":{"port":1},%s}]}`,
		"settings":     `{"outbounds":[{"protocol":"vless","settings":{%s}}]}`,
		"stream":       `{"outbounds":[{"protocol":"vless","streamSettings":{%s}}]}`,
		"sockopt":      `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{%s}}}]}`,
		"tls":          `{"outbounds":[{"protocol":"vless","streamSettings":{"security":"tls","tlsSettings":{%s}}}]}`,
		"download":     `{"outbounds":[{"protocol":"vless","streamSettings":{"xhttpSettings":{"downloadSettings":{"sockopt":{%s}}}}}]}`,
		"extra":        `{"outbounds":[{"protocol":"vless","streamSettings":{"xhttpSettings":{"extra":{%s}}}}]}`,
		"finalmask":    `{"outbounds":[{"protocol":"vless","streamSettings":{"finalmask":{"udp":[{"type":"noise","settings":{%s}}]}}}]}`,
		"unknown tree": `{"outbounds":[{"protocol":"vless","streamSettings":{"somethingNew":{"a":[{%s}]}}}]}`,
	}
	keys := []string{"xdriveSettings", "script", "webhook", "env", "metrics", "geodata", "process", "redirect", "reverse",
		"masterKeyLog", "certificateFile", "keyFile", "dir", "sendThrough", "mark", "interface", "tproxy", "customSockopt",
		"acceptProxyProtocol", "proxySettings"}
	for _, key := range keys {
		for _, form := range []string{key, strings.ToLower(key), strings.ToUpper(key)} {
			for spot, tmpl := range spots {
				frag := strings.Replace(tmpl, "%s", `"`+form+`":1`, 1)
				// With every unknown path accepted a key of this list still stops it.
				r := mustReject(t, spot+" "+form, frag, "outbounds[0].streamSettings.somethingNew", "outbounds[0]."+form)
				if len(r.Rejected) > 0 && !strings.Contains(r.Rejected[0].Msg, "never allowed") {
					t.Errorf("%s %s: refused for another reason: %v", spot, form, r.Rejected)
				}
			}
		}
	}
	// dialerProxy on freedom, and nowhere else.
	mustReject(t, "freedom dialerProxy", `{"outbounds":[{"protocol":"vless"},{"protocol":"freedom","tag":"f","streamSettings":{"sockopt":{"dialerProxy":"x"}}}]}`)
	// A key of a free-form map is a value.
	mustOK(t, outboundWith(`,"streamSettings":{"network":"ws","wsSettings":{"headers":{"Env":"x","Script":"y","dir":"z"}}}`))
}

func TestNoOtherTopLevelKey(t *testing.T) {
	for _, k := range []string{"inbounds", "routing", "dns", "log", "policy", "api", "stats", "observatory", "x"} {
		mustReject(t, k, `{"outbounds":[{"protocol":"vless"}],"`+k+`":{}}`)
	}
	mustReject(t, "no outbounds", `{}`)
	mustReject(t, "empty list", `{"outbounds":[]}`)
	mustReject(t, "nine outbounds", `{"outbounds":[`+strings.TrimSuffix(strings.Repeat(`{"protocol":"vless"},`, 9), ",")+`]}`)
	mustReject(t, "not an object", `[]`)
}

func TestProtocolNetworkSecurityAndMethodOutsideTheTableAreNeverAccepted(t *testing.T) {
	cases := map[string]string{
		"loopback":   `{"outbounds":[{"protocol":"%s"}]}`,
		"blackhole":  `{"outbounds":[{"protocol":"%s"}]}`,
		"dns":        `{"outbounds":[{"protocol":"%s"}]}`,
		"tun":        `{"outbounds":[{"protocol":"%s"}]}`,
		"xdrive":     `{"outbounds":[{"protocol":"%s"}]}`,
		"masque":     `{"outbounds":[{"protocol":"%s"}]}`,
		"direct":     `{"outbounds":[{"protocol":"%s"}]}`,
		"dokodemo":   `{"outbounds":[{"protocol":"%s"}]}`,
		"newproto":   `{"outbounds":[{"protocol":"%s"}]}`,
		"quic":       `{"outbounds":[{"protocol":"vless","streamSettings":{"network":"%s"}}]}`,
		"h2":         `{"outbounds":[{"protocol":"vless","streamSettings":{"method":"%s"}}]}`,
		"xdrive ":    `{"outbounds":[{"protocol":"vless","streamSettings":{"method":"%s"}}]}`,
		"masque ":    `{"outbounds":[{"protocol":"vless","streamSettings":{"network":"%s"}}]}`,
		"xtls":       `{"outbounds":[{"protocol":"vless","streamSettings":{"security":"%s"}}]}`,
		"unknownsec": `{"outbounds":[{"protocol":"vless","streamSettings":{"security":"%s"}}]}`,
		"rc4":        `{"outbounds":[{"protocol":"shadowsocks","settings":{"method":"%s"}}]}`,
		"none":       `{"outbounds":[{"protocol":"shadowsocks","settings":{"method":"%s"}}]}`,
	}
	for val, tmpl := range cases {
		val = strings.TrimSpace(val)
		for _, form := range []string{val, strings.ToUpper(val), strings.ToTitle(val)} {
			frag := strings.Replace(tmpl, "%s", form, 1)
			// Not even a decision of the admin passes it.
			var accept []string
			for _, p := range []string{"protocol", "settings.method", "streamSettings.method", "streamSettings.network", "streamSettings.security"} {
				accept = append(accept, "outbounds[0]."+p)
			}
			r := mustReject(t, val+" as "+form, frag, accept...)
			if len(r.Warnings) != 0 && len(r.Rejected) == 0 {
				t.Errorf("%s: only a warning", form)
			}
		}
	}
	// The table's own values pass, in any case.
	for _, p := range []string{"VLESS", "Vmess", "trojan", "SHADOWSOCKS", "socks", "HTTP", "hysteria", "wireguard"} {
		r := check(t, `{"outbounds":[{"protocol":"`+p+`"}]}`)
		if len(r.Rejected) != 0 {
			t.Errorf("protocol %s refused: %v", p, r.Rejected)
		}
	}
	mustReject(t, "freedom first", `{"outbounds":[{"protocol":"freedom"}]}`)
}

func TestUnknownKeyIsABlockingWarningUntilItsPathIsAccepted(t *testing.T) {
	frag := outboundWith(`,"streamSettings":{"newThing":{"a":1}}`)
	r := check(t, frag)
	if r.OK() || len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].streamSettings.newThing" || len(r.Rejected) != 0 {
		t.Fatalf("warnings=%v rejected=%v", r.Warnings, r.Rejected)
	}
	if r.Preview == nil || r.Normalized != nil {
		t.Error("a fragment with a warning has a preview and no normal form to store")
	}
	// Another path accepts nothing, and the path must be exact (no prefix, no suffix).
	for _, p := range []string{"outbounds[0].streamSettings", "outbounds[0].streamSettings.newThing.a", "outbounds[1].streamSettings.newThing", "outbounds[0].streamSettings.newthing"} {
		if r := check(t, frag, p); r.OK() {
			t.Errorf("path %s accepted the key", p)
		}
	}
	r = check(t, frag, "outbounds[0].streamSettings.newThing")
	if !r.OK() {
		t.Fatalf("accepted path not accepted: %v %v", r.Warnings, r.Rejected)
	}
	found := false
	for _, d := range r.Diff {
		if d.Path == "outbounds[0].streamSettings.newThing" {
			found = true
		}
	}
	if !found {
		t.Errorf("an accepted unknown is not in the diff: %v", r.Diff)
	}
	// A path of a wrong form is itself refused.
	for _, p := range []string{"", "routing.rules", "outbounds[0]", "outbounds[9].a", "outbounds[0].", "outbounds[0].a b", "outbounds[0]..a", "outbounds[0].a[x]"} {
		if r := check(t, frag, p); len(r.Rejected) == 0 {
			t.Errorf("accept_unknown %q not refused", p)
		}
	}
	// Unknown keys at the top of an outbound and an unknown mask type are warnings too.
	if r := check(t, outboundWith(`,"surprise":1`)); len(r.Warnings) != 1 {
		t.Errorf("outbound key: %v", r.Warnings)
	}
	r = check(t, outboundWith(`,"streamSettings":{"finalmask":{"tcp":[{"type":"header-custom","settings":{"clients":[]}}]}}`))
	if len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].streamSettings.finalmask.tcp[0].type" {
		t.Errorf("unknown mask type: %v %v", r.Warnings, r.Rejected)
	}
}

func TestValuesThatReachTheHostAreRefused(t *testing.T) {
	for name, extra := range map[string]string{
		"address env":      `,"streamSettings":{"address":"env:SECRET"}`,
		"address env case": `,"streamSettings":{"address":"ENV:SECRET"}`,
		"ext in alpn":      `,"streamSettings":{"security":"tls","tlsSettings":{"alpn":"h2,ext:file.dat:tag"}}`,
		"geoip in filter":  `,"streamSettings":{"finalmask":{"tcp":[{"type":"filter","settings":{"blockedSourceIPs":["geoip:ir"]}}]}}`,
		"geosite negated":  `,"streamSettings":{"finalmask":{"tcp":[{"type":"filter","settings":{"blockedSourceIPs":["!geosite:x"]}}]}}`,
		"port list env":    `,"streamSettings":{"finalmask":{"udp":[{"type":"udphop","settings":{"remotePorts":"80, env:P"}}]}}`,
		"header value":     `,"streamSettings":{"network":"ws","wsSettings":{"headers":{"X":"ext:a"}}}`,
		"in unknown tree":  `,"streamSettings":{"newThing":["env:HOME"]}`,
	} {
		mustReject(t, name, outboundWith(extra), "outbounds[0].streamSettings.newThing")
	}
	// A password that merely contains the letters is fine.
	mustOK(t, `{"outbounds":[{"protocol":"trojan","settings":{"address":"203.0.113.7","port":443,"password":"next:env:ext"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"}}}]}`)
}

func TestWireguardAndFreedomRules(t *testing.T) {
	r := mustOK(t, `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"K","address":["10.0.0.2/32"],"peers":[{"publicKey":"P","endpoint":"203.0.113.9:51820"}],"noKernelTun":false}}]}`)
	if !strings.Contains(string(r.Normalized), `"noKernelTun":true`) || len(r.Diff) == 0 {
		t.Errorf("noKernelTun not forced: %s %v", r.Normalized, r.Diff)
	}
	r = mustOK(t, `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"K"}}]}`)
	if !strings.Contains(string(r.Normalized), `"noKernelTun":true`) {
		t.Errorf("noKernelTun not added: %s", r.Normalized)
	}
	mustReject(t, "isClient", `{"outbounds":[{"protocol":"wireguard","settings":{"isClient":false,"secretKey":"K"}}]}`)
	mustReject(t, "IsClient", `{"outbounds":[{"protocol":"wireguard","settings":{"IsClient":false}}]}`)
	// A freedom hop may fragment, and may not bring rules of its own.
	mustOK(t, `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"frag"}}},{"protocol":"freedom","tag":"frag","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"}}}]}`)
	mustReject(t, "finalRules", `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"protocol":"freedom","tag":"f","settings":{"finalRules":[{"action":"allow"}]}}]}`)
	mustReject(t, "ipsBlocked", `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"protocol":"freedom","tag":"f","settings":{"ipsBlocked":["geoip:private"]}}]}`)
}

func hop(tag, dialer string) string {
	s := `{"protocol":"vless","tag":"` + tag + `","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"}`
	if dialer != "" {
		s += `,"streamSettings":{"sockopt":{"dialerProxy":"` + dialer + `"}}`
	}
	return s + `}`
}

func frag(hops ...string) string { return `{"outbounds":[` + strings.Join(hops, ",") + `]}` }

func TestChains(t *testing.T) {
	r := mustOK(t, frag(hop("exit", "hop_2"), hop("hop_2", "")))
	s := string(r.Normalized)
	if strings.Contains(s, "exit") || strings.Contains(s, "hop_2") || !strings.Contains(s, `"dialerProxy":"1"`) || !strings.Contains(s, `"tag":"0"`) || !strings.Contains(s, `"tag":"1"`) {
		t.Errorf("tags of the user survive: %s", s)
	}
	long := strings.Repeat("a", 200)
	mustOK(t, frag(hop(long, "ایران"), hop("ایران", "")))
	mustOK(t, frag(hop("a", "b"), hop("b", "c"), hop("c", "")))
	mustReject(t, "self", frag(hop("a", "a")))
	mustReject(t, "A to A through B", frag(hop("a", "b"), hop("b", "a")))
	mustReject(t, "A to B to A to C", frag(hop("a", "b"), hop("b", "a"), hop("c", "")))
	mustReject(t, "missing target", frag(hop("a", "nope")))
	mustReject(t, "ambiguous target", frag(hop("a", "b"), hop("b", ""), hop("b", "")))
	mustReject(t, "an outbound nothing reaches", frag(hop("a", ""), hop("b", "")))
	mustReject(t, "freedom first", `{"outbounds":[{"protocol":"freedom","tag":"x"}]}`)
	// The same through a nested downloadSettings, and through echSockopt.
	nested := `{"protocol":"vless","tag":"a","streamSettings":{"xhttpSettings":{"downloadSettings":{"sockopt":{"dialerProxy":"b"}}}}}`
	mustOK(t, frag(nested, hop("b", "")))
	cyc := `{"protocol":"vless","tag":"b","streamSettings":{"xhttpSettings":{"downloadSettings":{"sockopt":{"dialerProxy":"a"}}}}}`
	mustReject(t, "cycle through downloadSettings", frag(nested, cyc))
	ech := `{"protocol":"vless","tag":"a","streamSettings":{"security":"tls","tlsSettings":{"echSockopt":{"dialerProxy":"b"}}}}`
	r = mustOK(t, frag(ech, hop("b", "")))
	if !strings.Contains(string(r.Normalized), `"dialerProxy":"1"`) {
		t.Errorf("echSockopt link not rewritten: %s", r.Normalized)
	}
	// An empty dialerProxy is no link.
	mustOK(t, frag(hop("a", "")))
}

func TestNoValueIsEverEchoed(t *testing.T) {
	const canary = "CANARY-pw-9f3a"
	frags := []string{
		`{"outbounds":[{"protocol":"trojan","settings":{"password":"` + canary + `"},"surprise":"` + canary + `","streamSettings":{"network":"` + canary + `"}}]}`,
		`{"outbounds":[{"protocol":"vless","settings":{"id":"` + canary + `","env":"` + canary + `"},"` + canary + `":1}]}`,
		`{"` + canary + `":1}`,
		`{"outbounds":[{"protocol":"shadowsocks","settings":{"method":"` + canary + `","password":"` + canary + `","address":"env:` + canary + `"}}]}`,
		`{"outbounds":[{"protocol":"vless","tag":"` + canary + `","streamSettings":{"sockopt":{"dialerProxy":"` + canary + `x"}}}]}`,
	}
	for _, f := range frags {
		r := check(t, f, "outbounds[0].surprise")
		var all []string
		for _, i := range r.Rejected {
			all = append(all, i.Path+" "+i.Msg)
		}
		for _, i := range r.Warnings {
			all = append(all, i.Path+" "+i.Msg)
		}
		for _, i := range r.Diff {
			all = append(all, i.Path+" "+i.Msg)
		}
		// A key the user wrote may show in a path (that is how it is named), a value never.
		for _, a := range all {
			if strings.Contains(a, canary) && !strings.Contains(f, `"`+canary+`":`) {
				t.Errorf("a value is echoed: %s", a)
			}
		}
	}
}

func TestShapeLimits(t *testing.T) {
	deep := outboundWith(`,"streamSettings":{"newThing":` + strings.Repeat(`[`, 40) + strings.Repeat(`]`, 40) + `}`)
	mustReject(t, "depth 40", deep)
	mustOK(t, `{"outbounds":[{"protocol":"vless","streamSettings":{"newThing":`+strings.Repeat(`[`, 20)+strings.Repeat(`]`, 20)+`}}]}`, "outbounds[0].streamSettings.newThing")
	mustReject(t, "null", outboundWith(`,"tag":null`))
	mustReject(t, "trailing data", vlessReality+` {}`)
	mustReject(t, "trailing garbage", vlessReality+`x`)
	mustReject(t, "truncated", vlessReality[:40])
	mustReject(t, "invalid UTF-8", strings.Replace(vlessReality, "PUBKEY", "\xff\xfe", 1))
	mustReject(t, "over 32 KiB", outboundWith(`,"tag":"`+strings.Repeat("a", MaxFragmentBytes)+`"`))
	mustReject(t, "a string where a number is", `{"outbounds":[{"protocol":"vless","settings":{"port":"443"}}]}`)
	mustReject(t, "a number where a string is", `{"outbounds":[{"protocol":"vless","tag":5}]}`)
	mustReject(t, "an array where an object is", `{"outbounds":[{"protocol":"vless","settings":[]}]}`)
	mustReject(t, "an outbound that is a string", `{"outbounds":["vless"]}`)
	// The limit is on bytes in: exactly the limit is judged.
	pad := strings.Repeat("a", MaxFragmentBytes-len(outboundWith(`,"tag":""`)))
	mustOK(t, outboundWith(`,"tag":"`+pad+`"`))
}

func TestReleases(t *testing.T) {
	if _, err := For("v0.0.1"); err == nil {
		t.Error("an unknown release has a table")
	}
	if _, err := For(""); err == nil {
		t.Error("the empty tag has a table")
	}
	rs := Releases()
	if len(rs) == 0 {
		t.Fatal("no release")
	}
	for _, tag := range rs {
		tb, err := For(tag)
		if err != nil || tb.Release() != tag || !ValidReleaseTag(tag) {
			t.Errorf("release %s: %v", tag, err)
		}
	}
	if Newest().Release() != rs[len(rs)-1] {
		t.Error("Newest is not the last release")
	}
}

func TestValidReleaseTagAndPath(t *testing.T) {
	for _, s := range []string{"v26.11.9", "v1.0.0", "v100.200.300"} {
		if !ValidReleaseTag(s) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{"", "26.11.9", "v26.11", "v26.11.9.1", "v26.11.", "v.1.2", "v1..2", "v1.2.3-rc1", "V1.2.3", "v1.2.3\n", "v1.2.x", "v1.2.3/../x"} {
		if ValidReleaseTag(s) {
			t.Errorf("%q accepted", s)
		}
	}
	for _, p := range []string{"outbounds[0].a", "outbounds[7].a.b[3].c", "outbounds[2].streamSettings.tlsSettings.alpn[0]", "outbounds[0].a_b-c"} {
		if !ValidPath(p) {
			t.Errorf("path %s refused", p)
		}
	}
	for _, p := range []string{"", "outbounds", "outbounds[0]", "outbounds[8].a", "outbounds[10].a", "outbounds[0][1]", "outbounds[0].a[]", "outbounds[0].a[1", "outbounds[0].a.", "outbounds[0].a.b c", "Outbounds[0].a", "outbounds[0].a" + strings.Repeat("a", 300)} {
		if ValidPath(p) {
			t.Errorf("path %q accepted", p)
		}
	}
}

func TestFinalmaskAndTransportsPass(t *testing.T) {
	mustOK(t, outboundWith(`,"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"a.example","alpn":["h2"],"fingerprint":"chrome"},
		"xhttpSettings":{"path":"/x","mode":"auto","xmux":{"maxConcurrency":"16-32"},"extra":{"xPaddingBytes":"100-1000","headers":{"A":["b"]}}},
		"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}}],"udp":[{"type":"salamander","settings":{"password":"p"}}],"quicParams":{"congestion":"bbr"}}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"network":"kcp","kcpSettings":{"mtu":1350,"tti":20,"header":{"type":"none"},"seed":"s"}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"s","multiMode":true}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"network":"httpupgrade","httpupgradeSettings":{"host":"h","path":"/p"}}`))
	mustOK(t, `{"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"203.0.113.7","port":443},"streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"a"},"tlsSettings":{"serverName":"h.example"}}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"shadowsocks","settings":{"address":"203.0.113.7","port":8388,"method":"2022-BLAKE3-AES-128-GCM","password":"x"}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"203.0.113.7","port":1080,"users":[{"user":"u","pass":"p"}]}]}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"203.0.113.7","port":443,"users":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","security":"auto"}]}]},"mux":{"enabled":true,"concurrency":8}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"http","settings":{"address":"203.0.113.7","port":3128,"headers":{"X-A":"b"}}}]}`)
	mustReject(t, "noise script", outboundWith(`,"streamSettings":{"finalmask":{"udp":[{"type":"noise","settings":{"script":"os.execute('x')"}}]}}`))
}

// quicParams.debug makes the release call os.Setenv in the Xray process (found in
// the source of infra/conf for v26.11.9): refused, and the other quic parameters pass.
func TestQuicDebugSetsTheEnvironmentAndIsRefused(t *testing.T) {
	mustReject(t, "quic debug", outboundWith(`,"streamSettings":{"finalmask":{"quicParams":{"debug":true}}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"finalmask":{"quicParams":{"congestion":"bbr","bbrProfile":"standard"}}}`))
}

// FuzzCheck: whatever bytes arrive, Check never panics, the normal form of an accepted
// fragment is a fixed point of Check, and a fragment is never accepted that holds a
// key of the always-rejected list at any depth.
func FuzzCheck(f *testing.F) {
	f.Add([]byte(vlessReality), "")
	f.Add([]byte(outboundWith(`,"streamSettings":{"sockopt":{"dialerProxy":"x"}}`)), "outbounds[0].a")
	f.Add([]byte(`{"outbounds":[{"protocol":"vless","tag":"a","streamSettings":{"sockopt":{"dialerProxy":"b"}}},{"protocol":"freedom","tag":"b"}]}`), "")
	f.Add([]byte(`{"outbounds":[{"protocol":"wireguard","settings":{"isClient":true}}]}`), "")
	f.Add([]byte(tlsWith(`,"echConfigList":"https://1.1.1.1/dns-query"`)), "")
	f.Add([]byte(outboundWith(`,"streamSettings":{"security":"reality","realitySettings":{"spiderX":"/?p=1"}}`)), "")
	f.Add([]byte(`{`), "")
	f.Fuzz(func(t *testing.T, data []byte, accept string) {
		r := Newest().Check(data, strings.Split(accept, ","))
		if len(r.Rejected) != 0 {
			if r.Normalized != nil {
				t.Fatal("a rejected fragment has a normal form")
			}
			return
		}
		// A fragment with a warning keeps its normal form in Preview only.
		form := r.Normalized
		if len(r.Warnings) != 0 {
			if r.Normalized != nil {
				t.Fatal("a fragment with a warning has a normal form to store")
			}
			form = r.Preview
		}
		again := Newest().Check(form, strings.Split(accept, ","))
		againForm := again.Normalized
		if len(again.Warnings) != 0 {
			againForm = again.Preview
		}
		if len(again.Rejected) != 0 || !bytes.Equal(againForm, form) {
			t.Fatalf("the normal form is not a fixed point:\n%s\n%s\n%v", form, againForm, again.Rejected)
		}
		for k := range globalRejected() {
			if bytes.Contains(bytes.ToLower(form), []byte(`"`+k+`":`)) {
				t.Fatalf("an accepted fragment holds the key %s: %s", k, form)
			}
		}
		if root, err := parse(form); err == nil {
			if key := keyedViolation(root); key != "" {
				t.Fatalf("an accepted fragment holds a bad %s: %s", key, form)
			}
		}
	})
}

// keyedViolation finds a member of the tree that keyedChecks refuse, at any depth.
func keyedViolation(v *val) string {
	for _, m := range v.members {
		if _, bad := keyedCheck(m.key, m.v); bad {
			return m.key
		}
		if k := keyedViolation(m.v); k != "" {
			return k
		}
	}
	for _, it := range v.items {
		if k := keyedViolation(it); k != "" {
			return k
		}
	}
	return ""
}
