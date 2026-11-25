package xrayschema

import (
	"sort"
	"strings"
	"testing"
)

// Tests for the findings of review round 2 of B1 (p4b-proxy 7.2).

func tlsWith(tls string) string {
	return outboundWith(`,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"` + tls + `}}`)
}

// B1-r2-1 and B1-r2-7: an echConfigList with :// (or any value that is not a base64
// list) makes Xray ask a DoH, h2c or UDP server for the ECH record with socket options
// of its own and resolve its name by the host resolver. Only a base64 list passes, in
// the table, as an unknown key, and in a subtree the table has no node for.
func TestEchConfigListIsOnlyABase64List(t *testing.T) {
	for name, v := range map[string]string{
		"https":          "https://1.1.1.1/dns-query",
		"udp":            "udp://attacker.example:53",
		"name and https": "example.com+https://1.1.1.1/dns-query",
		"name and udp":   "secret.example+udp://attacker.example:53",
		"an address":     "1.1.1.1",
		"a name":         "example.com",
		"h2c":            "h2c://1.1.1.1/dns-query",
	} {
		mustReject(t, name, tlsWith(`,"echConfigList":"`+v+`"`))
		// Any case of the key, and a path the admin names as accepted, change nothing.
		mustReject(t, name+" (case)", tlsWith(`,"ECHCONFIGLIST":"`+v+`"`), "outbounds[0].streamSettings.tlsSettings.ECHCONFIGLIST")
		mustReject(t, name+" (raw subtree)", outboundWith(`,"streamSettings":{"xhttpSettings":{"h2Params":{"echConfigList":"`+v+`"}}}`))
		mustReject(t, name+" (unknown key)", tlsWith(`,"newThing":{"echConfigList":"`+v+`"}`), "outbounds[0].streamSettings.tlsSettings.newThing")
	}
	// An unknown key that is the ech key itself, where the table has no such field.
	mustReject(t, "ech key beside a table", outboundWith(`,"streamSettings":{"echConfigList":"https://1.1.1.1/dns-query"}`),
		"outbounds[0].streamSettings.echConfigList")
	mustOK(t, tlsWith(`,"echConfigList":"AEX+DQBBAAAgACD7bQ=="`))
	mustOK(t, tlsWith(`,"echConfigList":""`))
}

// B1-r2-6: the query of spiderX is read as unbounded numbers that size goroutines and
// a strings.Repeat of the REALITY fallback, in the process every location shares.
func TestSpiderXHasNoQueryPart(t *testing.T) {
	reality := func(spx string) string {
		return outboundWith(`,"streamSettings":{"security":"reality","realitySettings":{"serverName":"a.example","publicKey":"PUB","spiderX":"` + spx + `"}}`)
	}
	mustOK(t, reality("/"))
	mustOK(t, reality("/some/path"))
	mustOK(t, reality("/a%3Fb"))
	for name, spx := range map[string]string{
		"p":          "/?p=9000000000000000000",
		"c and t":    "/?c=10000000&t=1000000000",
		"bare query": "?r=1",
		"after path": "/x?i=1",
	} {
		mustReject(t, name, reality(spx))
	}
	mustReject(t, "raw subtree", outboundWith(`,"streamSettings":{"xhttpSettings":{"h2Params":{"spiderX":"/?p=1"}}}`))
	mustReject(t, "unknown key", outboundWith(`,"streamSettings":{"newThing":{"SPIDERX":"/?p=1"}}`), "outbounds[0].streamSettings.newThing")
}

const (
	wgOutbound  = `{"protocol":"wireguard","settings":{"secretKey":"K","address":["10.0.0.2/32"],"peers":[{"publicKey":"P","endpoint":"203.0.113.7:51820"}]}}`
	hyOutbound  = `{"protocol":"hysteria","settings":{"version":2,"address":"203.0.113.7","port":443}}`
	vlessPrefix = `{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"}`
)

// B1-r2-2 and B1-r2-8: Stateful is what 7.5 step 5 acts on.
func TestStatefulConfigs(t *testing.T) {
	tb := Newest()
	xhttp := func(tls string, extra string) string {
		return `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"xhttp","security":"tls","tlsSettings":{"serverName":"a.example"` + tls + `}` + extra + `}}]}`
	}
	for name, frag := range map[string]string{
		"wireguard":              `{"outbounds":[` + wgOutbound + `]}`,
		"hysteria protocol":      `{"outbounds":[` + hyOutbound + `]}`,
		"hysteria transport":     `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"hysteria"}}]}`,
		"transport, old name":    `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"network":"Hysteria"}}]}`,
		"grpc transport":         `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"grpc"}}]}`,
		"grpc, old case":         `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"network":"GRPC"}}]}`,
		"wireguard as a hop":     `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"w"}}},` + strings.Replace(wgOutbound, `"protocol"`, `"tag":"w","protocol"`, 1) + `]}`,
		"protocol in any case":   `{"outbounds":[{"PROTOCOL":"WireGuard"}]}`,
		"xhttp h3 array":         xhttp(`,"alpn":["h3"]`, ""),
		"xhttp h3 string":        xhttp(`,"alpn":"h2, H3"`, ""),
		"xhttp old name":         strings.Replace(xhttp(`,"alpn":["h3"]`, ""), `"xhttp"`, `"splithttp"`, 1),
		"xhttp h3 in download":   xhttp(``, `,"xhttpSettings":{"downloadSettings":{"security":"tls","tlsSettings":{"alpn":["h3"]}}}`),
		"xhttp h3 in extra":      xhttp(``, `,"xhttpSettings":{"extra":{"downloadSettings":{"tlsSettings":{"alpn":"h3"}}}}`),
		"xhttp h3 in raw extras": xhttp(``, `,"xhttpSettings":{"h2Params":{"alpn":["h3"]}}`),
	} {
		if !tb.Stateful([]byte(frag)) {
			t.Errorf("%s: not stateful", name)
		}
	}
	for name, frag := range map[string]string{
		"vless reality":      vlessReality,
		"xhttp over h2":      xhttp(`,"alpn":["h2","http/1.1"]`, ""),
		"xhttp no alpn":      xhttp(``, ""),
		"ws with h3":         `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"ws","security":"tls","tlsSettings":{"alpn":["h3"]}}}]}`,
		"alpn naming h3 too": xhttp(`,"alpn":["h30"]`, ""),
		"freedom hop":        `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"tag":"f","protocol":"freedom"}]}`,
	} {
		if tb.Stateful([]byte(frag)) {
			t.Errorf("%s: stateful", name)
		}
	}
	// A fragment that cannot be read, and a table with no rules, are called stateful.
	if !tb.Stateful([]byte(`{`)) || !(Table{}).Stateful([]byte(vlessReality)) {
		t.Error("an unreadable fragment or a table with no rules is not stateful")
	}
	// The normal form says the same as the fragment.
	r := mustOK(t, xhttp(`,"alpn":["h3"]`, ""))
	if !tb.Stateful(r.Normalized) {
		t.Error("the normal form of an xhttp h3 config is not stateful")
	}
}

// G4: a protocol or a transport the table accepts but nobody classified would be
// missed by Stateful, and rmo would leave its device or session up.
func TestEveryProtocolAndTransportIsClassified(t *testing.T) {
	for _, tag := range Releases() {
		tb, _ := For(tag)
		rules := tb.rules()
		var protocols, classified []string
		for p := range tb.build().sel {
			protocols = append(protocols, p)
		}
		for p := range rules.protocols {
			classified = append(classified, p)
		}
		sort.Strings(protocols)
		sort.Strings(classified)
		if strings.Join(protocols, ",") != strings.Join(classified, ",") {
			t.Errorf("%s: protocols of the table %v, classified %v", tag, protocols, classified)
		}
		seen := map[string]bool{}
		var transports, ctransports []string
		for _, canon := range transportEnum().enum {
			if !seen[canon] {
				seen[canon] = true
				transports = append(transports, canon)
			}
		}
		for tr := range rules.transports {
			ctransports = append(ctransports, tr)
		}
		sort.Strings(transports)
		sort.Strings(ctransports)
		if strings.Join(transports, ",") != strings.Join(ctransports, ",") {
			t.Errorf("%s: transports of the table %v, classified %v", tag, transports, ctransports)
		}
	}
}
