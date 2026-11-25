package xrayschema

import (
	"strings"
	"testing"
)

// B1-r3-3 and B1-r3-4: a number that is cut from a buffer, makes one, or waits is
// bounded by the table, because the Xray process is shared by every location of the
// node and nothing recovers a panic or frees a pipe that a config sized. Each case has
// the bad values the loader of v26.11.9 lets through and one good value that real
// configs use. The same key inside xhttp "extra" and "downloadSettings" is judged by
// the same node.
func TestBoundedNumbersOfTheTable(t *testing.T) {
	stream := func(inner string) func(string) string {
		return func(v string) string {
			return outboundWith(`,"streamSettings":{` + replaceV(inner, v) + `}`)
		}
	}
	xhttp := func(key string) func(string) string {
		return stream(`"method":"xhttp","xhttpSettings":{"` + key + `":V}`)
	}
	cases := []struct {
		name  string
		build func(v string) string
		bad   []string
		good  string
	}{
		{"fragment length", stream(`"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"1-30","length":V}}]}`),
			[]string{`"-1"`, `-1`, `"-1-2000000"`, `0`, `"0-5"`, `"1-70000"`, `"x"`, `""`}, `"100-200"`},
		{"fragment lengths", stream(`"finalmask":{"tcp":[{"type":"fragment","settings":{"lengths":[V]}}]}`), []string{`"-5"`, `0`}, `"10-20"`},
		{"fragment delay", stream(`"finalmask":{"tcp":[{"type":"fragment","settings":{"delay":V}}]}`), []string{`"-1"`, `-3`, `"0-99999"`}, `"10-20"`},
		{"fragment maxSplit", stream(`"finalmask":{"tcp":[{"type":"fragment","settings":{"maxSplit":V}}]}`), []string{`"-1"`, `"1-99999"`}, `"100-200"`},
		{"noise rand", stream(`"finalmask":{"udp":[{"type":"noise","settings":{"noise":[{"rand":V}]}}]}`), []string{`"-1"`, `-5`, `"-1-10"`, `2000000000`}, `"50-100"`},
		{"noise randRange", stream(`"finalmask":{"udp":[{"type":"noise","settings":{"noise":[{"randRange":V}]}}]}`), []string{`"-1"`, `"0-300"`}, `"0-255"`},
		{"noise delay", stream(`"finalmask":{"udp":[{"type":"noise","settings":{"noise":[{"delay":V}]}}]}`), []string{`"-1"`, `2000000000`}, `"10-20"`},
		{"udphop interval", stream(`"finalmask":{"udp":[{"type":"udphop","settings":{"interval":V}}]}`), []string{`"-1"`, `0`, `-5`}, `"5-10"`},
		{"udphop ports", stream(`"finalmask":{"udp":[{"type":"udphop","settings":{"remotePorts":V}}]}`), []string{`"0-20"`, `"20000-70000"`, `"-1"`, `"1000,0"`}, `"20000-30000,443"`},
		{"freedom fragment length", func(v string) string {
			return freedomHop(`"fragment":{"packets":"tlshello","length":` + v + `}`)
		}, []string{`"-1"`, `0`, `"1-70000"`}, `"100-200"`},
		{"freedom fragment interval", func(v string) string {
			return freedomHop(`"fragment":{"interval":` + v + `}`)
		}, []string{`"-1"`, `"1-99999"`}, `"10-20"`},
		{"kcp mtu", stream(`"method":"kcp","kcpSettings":{"mtu":V}`), []string{`9000`, `8192`, `1501`, `20`, `-1`}, `1350`},
		{"kcp capacity", stream(`"method":"kcp","kcpSettings":{"uplinkCapacity":V}`), []string{`-1`, `100000`}, `5`},
		{"xhttp scMaxEachPostBytes", xhttp("scMaxEachPostBytes"), []string{`2000000000`, `"2000000000"`, `"1-2000000000"`, `0`, `-1`}, `1000000`},
		{"xhttp scMinPostsIntervalMs", xhttp("scMinPostsIntervalMs"), []string{`2000000000`, `-1`}, `30`},
		{"xhttp xPaddingBytes", xhttp("xPaddingBytes"), []string{`2000000000`, `"100-2000000"`, `-1`}, `"100-1000"`},
		{"xhttp scMaxBufferedPosts", xhttp("scMaxBufferedPosts"), []string{`2000000000`, `-1`}, `30`},
		{"xhttp uplinkChunkSize", xhttp("uplinkChunkSize"), []string{`2000000000`, `"1-2000000000"`}, `4096`},
		{"xhttp xmux maxConnections", stream(`"method":"xhttp","xhttpSettings":{"xmux":{"maxConnections":V}}`), []string{`2000000000`, `"1-2000000000"`}, `"16-32"`},
		{"xhttp extra", stream(`"method":"xhttp","xhttpSettings":{"extra":{"scMaxEachPostBytes":V}}`), []string{`2000000000`}, `1000000`},
		{"xhttp downloadSettings", stream(`"method":"xhttp","xhttpSettings":{"downloadSettings":{"method":"xhttp","xhttpSettings":{"scMinPostsIntervalMs":V}}}`), []string{`2000000000`}, `30`},
		{"grpc initial_windows_size", stream(`"method":"grpc","grpcSettings":{"initial_windows_size":V}`), []string{`2147483647`, `-1`, `33554432`}, `65535`},
		{"grpc idle_timeout", stream(`"method":"grpc","grpcSettings":{"idle_timeout":V}`), []string{`-1`, `2000000000`}, `60`},
		{"quic maxStreamReceiveWindow", stream(`"finalmask":{"quicParams":{"maxStreamReceiveWindow":V}}`), []string{`18446744073709551615`, `2147483647`, `33554433`, `-1`}, `8388608`},
		{"quic initConnectionReceiveWindow", stream(`"finalmask":{"quicParams":{"initConnectionReceiveWindow":V}}`), []string{`2147483647`}, `20971520`},
		{"quic maxIncomingStreams", stream(`"finalmask":{"quicParams":{"maxIncomingStreams":V}}`), []string{`2000000000`}, `1024`},
		{"ws heartbeatPeriod", stream(`"method":"ws","wsSettings":{"heartbeatPeriod":V}`), []string{`-1`, `2000000000`}, `30`},
		{"sockopt tcpWindowClamp", stream(`"sockopt":{"tcpWindowClamp":V}`), []string{`2147483647`, `-1`}, `65535`},
		{"mux concurrency", func(v string) string { return outboundWith(`,"mux":{"enabled":true,"concurrency":` + v + `}`) }, []string{`2000000000`, `-2`}, `-1`},
		{"wireguard mtu", func(v string) string {
			return `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"K","address":["10.0.0.2/32"],"mtu":` + v + `,"peers":[{"publicKey":"P","endpoint":"203.0.113.7:51820"}]}}]}`
		}, []string{`2000000000`, `-1`}, `1280`},
	}
	for _, c := range cases {
		mustOK(t, c.build(c.good))
		for _, bad := range c.bad {
			r := mustReject(t, c.name+" "+bad, c.build(bad))
			// The reason names the bounds and never the value the admin wrote.
			for _, rj := range r.Rejected {
				if len(bad) > 6 && strings.Contains(rj.Msg, bad) {
					t.Errorf("%s: the reason echoes the value %s", c.name, bad)
				}
			}
		}
	}
}

// The first and last values of a bound pass, and the ones beside them do not.
func TestBoundEdges(t *testing.T) {
	kcp := func(v string) string {
		return outboundWith(`,"streamSettings":{"method":"kcp","kcpSettings":{"mtu":` + v + `}}`)
	}
	mustOK(t, kcp(`21`))
	mustOK(t, kcp(`1500`))
	mustReject(t, "mtu 20", kcp(`20`))
	mustReject(t, "mtu 1501", kcp(`1501`))
	frag := func(v string) string {
		return outboundWith(`,"streamSettings":{"finalmask":{"tcp":[{"type":"fragment","settings":{"length":` + v + `}}]}}`)
	}
	mustOK(t, frag(`1`))
	mustOK(t, frag(`"1-65535"`))
	mustReject(t, "length 0", frag(`0`))
	mustReject(t, "length 65536", frag(`"1-65536"`))
}

func replaceV(s, v string) string {
	out := make([]byte, 0, len(s)+len(v))
	for i := 0; i < len(s); i++ {
		if s[i] == 'V' && (i == 0 || s[i-1] == ':' || s[i-1] == '[') && (i+1 == len(s) || s[i+1] == '}' || s[i+1] == ']' || s[i+1] == ',') {
			out = append(out, v...)
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// freedomHop is a vless exit that dials through a freedom hop with the given settings.
func freedomHop(settings string) string {
	return `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"tag":"f","protocol":"freedom","settings":{` + settings + `}}]}`
}
