package xrayschema

import (
	"strings"
	"testing"
)

// Tests for the findings of review round 4 of B1 (p4b-proxy 7.2): what a number, a
// string or a mask combination can make the one Xray process of a node do, which a
// probe or the trial never reaches.

// refuse is mustReject that also fails when the fragment is not JSON, so a typo in a
// test fragment cannot make a test pass by accident.
func refuse(t *testing.T, what, frag string, accept ...string) Result {
	t.Helper()
	r := mustReject(t, what, frag, accept...)
	for _, rj := range r.Rejected {
		if rj.Path == "" {
			t.Errorf("%s: the fragment is not read at all: %s", what, rj.Msg)
		}
	}
	return r
}

func stream4(inner string) string {
	return outboundWith(`,"streamSettings":{` + inner + `}`)
}

// B1-r4-1 and B1-r4-7: happyEyeballs races up to maxConcurrentTry ports for one dial,
// which the dial limits of 5.5 are not sized for. It is refused wherever it sits, in
// any case, and a path in accept_unknown changes nothing.
func TestHappyEyeballsIsRefusedEverywhere(t *testing.T) {
	he := `{"tryDelayMs":1,"maxConcurrentTry":16}`
	for name, frag := range map[string]string{
		"outbound sockopt": stream4(`"sockopt":{"happyEyeballs":` + he + `}`),
		"lower case":       stream4(`"sockopt":{"happyeyeballs":` + he + `}`),
		"upper case":       stream4(`"sockopt":{"HAPPYEYEBALLS":` + he + `}`),
		"echSockopt":       tlsWith(`,"echSockopt":{"happyEyeballs":` + he + `}`),
		"downloadSettings": stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{"sockopt":{"happyEyeballs":` + he + `}}}`),
		"extra":            stream4(`"method":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"sockopt":{"happyEyeballs":` + he + `}}}}`),
		"raw subtree":      stream4(`"xhttpSettings":{"h2Params":{"happyEyeballs":` + he + `}}`),
		"unknown key":      stream4(`"newThing":{"happyEyeballs":` + he + `}`),
	} {
		refuse(t, name, frag)
		refuse(t, name+" (accepted path)", frag, "outbounds[0].streamSettings.newThing.happyEyeballs", "outbounds[0].streamSettings.sockopt.happyEyeballs")
	}
	mustOK(t, stream4(`"sockopt":{"tcpKeepAliveIdle":30}`))
}

// B1-r4-2 and the second half of B1-r4-5: a freedom noise of type rand takes its length
// from a text that Xray reads with no upper bound and allocates on every UDP write.
func TestFreedomNoiseRandLengthIsBounded(t *testing.T) {
	noise := func(typ, packet string) string {
		return freedomHop(`"noises":[{"type":"` + typ + `","packet":"` + packet + `","delay":"10-16"}]`)
	}
	mustOK(t, noise("rand", "10-20"))
	mustOK(t, noise("rand", "1-65535"))
	mustOK(t, noise("rand", "100"))
	mustOK(t, noise("str", "hello"))
	mustOK(t, noise("hex", "abcd"))
	for _, bad := range []string{"1-9999999999999", "1-65536", "0-10", "0", "70000", "-5", "x", "", "10-"} {
		for _, typ := range []string{"rand", "RAND", "Rand"} {
			r := refuse(t, typ+" "+bad, noise(typ, bad))
			for _, rj := range r.Rejected {
				if len(bad) > 6 && strings.Contains(rj.Msg, bad) {
					t.Errorf("the reason echoes the value %s", bad)
				}
			}
		}
	}
	// The single noise key is the same node.
	refuse(t, "noise key", freedomHop(`"noise":{"type":"rand","packet":"1-9999999999999"}`))
	// A packet that is not text is refused for a rand: Xray would not read it.
	refuse(t, "number packet", freedomHop(`"noises":[{"type":"rand","packet":99999999}]`))
}

// B1-r4-3: congestion brutal is handled by the hysteria dialer only. The xhttp h3 dialer
// and the xdns DoH resolver run panic(congestion) on it after the handshake.
func TestBrutalCongestionIsOnlyForHysteria(t *testing.T) {
	brutal := func(inner, cong string) string {
		return stream4(inner + `"finalmask":{"quicParams":{"congestion":"` + cong + `"}}`)
	}
	for _, cong := range []string{"brutal", "BRUTAL", "Brutal"} {
		refuse(t, "xhttp "+cong, brutal(`"method":"xhttp","security":"tls","tlsSettings":{"alpn":["h3"]},`, cong))
		refuse(t, "no method "+cong, brutal(``, cong))
		refuse(t, "raw "+cong, brutal(`"method":"raw",`, cong))
		refuse(t, "in downloadSettings "+cong, stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{"method":"xhttp","finalmask":{"quicParams":{"congestion":"`+cong+`"}}}}`))
		refuse(t, "in extra "+cong, stream4(`"method":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"finalmask":{"quicParams":{"congestion":"`+cong+`"}}}}}`))
		refuse(t, "old spelling "+cong, `{"outbounds":[`+vlessPrefix+`,"streamSettings":{"network":"xhttp","finalmask":{"quicParams":{"congestion":"`+cong+`"}}}}]}`)
	}
	// A subtree the table has no node for (an xdns resolver) is judged by the key.
	refuse(t, "raw subtree", stream4(`"xhttpSettings":{"h2Params":{"quicParams":{"congestion":"brutal"}}}`))
	// The five spellings of the loader pass where the dialer handles them.
	for _, cong := range []string{"", "reno", "bbr", "force-brutal", "BBR"} {
		mustOK(t, brutal(`"method":"xhttp",`, cong))
	}
	mustOK(t, brutal(`"method":"hysteria",`, "brutal"))
	mustOK(t, brutal(`"method":"Hysteria",`, "BRUTAL"))
	// Anything else is not a value of the loader.
	refuse(t, "cubic", brutal(`"method":"xhttp",`, "cubic"))
}

// B1-r4-4 and B1-r4-8: the receive window of a kcp connection is downlinkCapacity MiB
// divided by mtu and by 1000/tti segments, each held as a buffer of 8 KiB, and the send
// queue is maxSendingWindow bytes divided by mtu.
func TestKCPWindowsAreBounded(t *testing.T) {
	kcp := func(inner string) string { return stream4(`"method":"kcp","kcpSettings":{` + inner + `}`) }
	refuse(t, "776,000 segments", kcp(`"mtu":1350,"tti":1000,"downlinkCapacity":1000`))
	refuse(t, "mtu 21", kcp(`"mtu":21,"tti":50,"downlinkCapacity":20`))
	refuse(t, "mtu 21 and the biggest numbers", kcp(`"mtu":21,"tti":1000,"downlinkCapacity":1000`))
	refuse(t, "send queue at mtu 21", kcp(`"mtu":21,"downlinkCapacity":1`))
	refuse(t, "tti 0", kcp(`"tti":0`))
	refuse(t, "tti 9", kcp(`"tti":9`))
	refuse(t, "window under mtu", kcp(`"mtu":1350,"maxSendingWindow":1000`))
	refuse(t, "window over 16 MiB", kcp(`"maxSendingWindow":100000000`))
	// The defaults of the release, and the values real mKCP configs use.
	mustOK(t, kcp(``))
	mustOK(t, kcp(`"maxSendingWindow":2097152`))
	mustOK(t, kcp(`"mtu":1350,"tti":50,"uplinkCapacity":12,"downlinkCapacity":100`))
	mustOK(t, kcp(`"mtu":1350,"tti":20,"uplinkCapacity":5,"downlinkCapacity":20`))
	mustOK(t, kcp(`"mtu":1200,"tti":100,"downlinkCapacity":40,"maxSendingWindow":2000000`))
	// Edges: 4,096 segments pass (1 MiB / 1024 bytes at one tick a second is 1,024 per MiB), 5,120 do not.
	mustOK(t, kcp(`"mtu":1024,"tti":1000,"downlinkCapacity":4`))
	refuse(t, "one over", kcp(`"mtu":1024,"tti":1000,"downlinkCapacity":5`))
	// The same node inside downloadSettings.
	refuse(t, "downloadSettings", stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{"method":"kcp","kcpSettings":{"mtu":21}}}`))
}

// B1-r4-5: an exp noise joins its segments into one slice for each new UDP connection.
func TestExpNoiseProgramIsBounded(t *testing.T) {
	noise := func(typ, packet string) string {
		return stream4(`"method":"kcp","finalmask":{"udp":[{"type":"noise","settings":{"noise":[{"type":"` + typ + `","packet":"` + packet + `"}]}}]}`)
	}
	big := strings.Repeat("<r 65535>", 3000)
	refuse(t, "3,000 segments", noise("exp", big))
	refuse(t, "EXP", noise("EXP", big))
	refuse(t, "two segments of 65,535", noise("exp", "<r 65535><r 65535>"))
	refuse(t, "rd and rc", noise("exp", "<rc 40000><rd 30000>"))
	refuse(t, "a range", noise("exp", "<r 1-65535><r 100>"))
	refuse(t, "many small ones", noise("exp", strings.Repeat("<n>", 9000)))
	refuse(t, "unknown segment", noise("exp", "<z 5>"))
	mustOK(t, noise("exp", "<b 0x1234><r 100-200><t><c><n><rc 8><rd 8>"))
	mustOK(t, noise("exp", "<r 65507>"))
	mustOK(t, noise("str", "hello"))
	mustOK(t, noise("hex", "abcd"))
	// The packet of an exp must be a string.
	refuse(t, "array packet", stream4(`"finalmask":{"udp":[{"type":"noise","settings":{"noise":[{"type":"exp","packet":[1,2]}]}}]}`))
	// Inside a share link's extra.
	refuse(t, "downloadSettings", stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{"finalmask":{"udp":[{"type":"noise","settings":{"noise":[{"type":"exp","packet":"`+big+`"}]}}]}}}`))
}

// B1-r4-6: the gecko writer (salamander with packetSize) panics on a packet above 8,184
// bytes, which a wireguard mtu of 9000 or a sudoku mask makes.
func TestGeckoCannotSeeALargePacket(t *testing.T) {
	wg := func(mtu string, masks string) string {
		return `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"K","address":["10.0.0.2/32"],"mtu":` + mtu + `,"peers":[{"publicKey":"P","endpoint":"203.0.113.7:51820"}]},"streamSettings":{"finalmask":{"udp":[` + masks + `]}}}]}`
	}
	gecko := `{"type":"salamander","settings":{"password":"p","packetSize":"512-1200"}}`
	refuse(t, "mtu 9000", wg("9000", gecko))
	refuse(t, "mtu 1501", wg("1501", gecko))
	mustOK(t, wg("1420", gecko))
	mustOK(t, wg("1500", gecko))
	refuse(t, "packetSize 4096", wg("1420", `{"type":"salamander","settings":{"password":"p","packetSize":"512-4096"}}`))
	mustOK(t, wg("1420", `{"type":"salamander","settings":{"password":"p","packetSize":"512-2048"}}`))
	sudoku := `{"type":"sudoku","settings":{"password":"p"}}`
	refuse(t, "sudoku with gecko", wg("1420", sudoku+","+gecko))
	refuse(t, "gecko with sudoku", wg("1420", gecko+","+sudoku))
	refuse(t, "case", wg("1420", `{"type":"SUDOKU","settings":{"password":"p"}},`+`{"type":"Salamander","settings":{"password":"p","packetSize":1200}}`))
	// Salamander without packetSize, and sudoku alone, are no gecko.
	mustOK(t, wg("1420", sudoku+`,{"type":"salamander","settings":{"password":"p"}}`))
	mustOK(t, wg("1420", `{"type":"salamander","settings":{"password":"p","packetSize":0}},`+sudoku))
	mustOK(t, wg("1420", gecko+`,{"type":"udphop","settings":{"interval":30}}`))
	mustOK(t, wg("1280", ``))
}

// B1-r4-9: the gaps of the padding text of VLESS encryption are sleeps in the handshake
// that nothing cancels.
func TestVLESSEncryptionGapsAreBounded(t *testing.T) {
	key := strings.Repeat("A", 43)
	enc := func(pad string) string {
		return "mlkem768x25519plus.native.1rtt." + pad + key
	}
	user := func(e string) string {
		return `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"` + e + `"}}]}`
	}
	vnext := func(e string) string {
		return `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.7","port":443,"users":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"` + e + `"}]}]}}]}`
	}
	for _, f := range []func(string) string{user, vnext} {
		mustOK(t, f("none"))
		mustOK(t, f(enc("")))
		mustOK(t, f(enc("100-111-1111.75-0-111.")))
		mustOK(t, f(enc("100-35-35.1-3-10000.50-0-3333.")))
		r := refuse(t, "a day", f(enc("100-35-35.1-3600000-86400000.")))
		for _, rj := range r.Rejected {
			if strings.Contains(rj.Msg, "86400000") {
				t.Errorf("the reason echoes the value: %s", rj.Msg)
			}
		}
		refuse(t, "one over", f(enc("100-35-35.1-3-10001.")))
		refuse(t, "the fourth part is a gap too", f(enc("100-35-35.1-0-1.100-35-35.1-0-20000.")))
		// A length part of any size is the loader's to judge (65,553 in all), not a wait.
		mustOK(t, f(enc("100-35-9000.")))
	}
	if CheckVLESSEncryption("none") != "" || CheckVLESSEncryption("") != "" || CheckVLESSEncryption("x.y") != "" {
		t.Error("a text that is not the mlkem form is not this check's to judge")
	}
}
