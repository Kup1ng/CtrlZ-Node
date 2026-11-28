package xray

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

func mustNormalize(t *testing.T, frag string) []byte {
	t.Helper()
	res := xrayschema.Newest().Check([]byte(frag), nil)
	if !res.OK() {
		t.Fatalf("fragment refused: %+v %+v", res.Rejected, res.Warnings)
	}
	return res.Normalized
}

// Two hops: the main outbound dials through a socks hop. 7.4: every tag is
// L<id>.<g>.<n>, each dialerProxy names a tag of the same form, and every sockopt
// carries ForceIPv4 whatever the fragment said.
func TestRenderChainAndForceIPv4(t *testing.T) {
	frag := `{"outbounds":[
	  {"protocol":"vless","tag":"main","settings":{"address":"198.51.100.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},
	   "streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com"},"sockopt":{"dialerProxy":"hop"}}},
	  {"protocol":"socks","tag":"hop","settings":{"address":"203.0.113.5","port":1080}}]}`
	norm := mustNormalize(t, frag)
	rec := runRec{ID: hexID(7), Gen: 3, Port: 20001, Outs: 2, Hash: "h", Frag: norm}
	base := baseInput{Slot: "a", APISock: "/run/ctrlz-xray/a/api.sock", Unbound: "127.0.0.10:5300",
		Blocked: blockedRanges([]netip.Addr{netip.MustParseAddr("9.9.9.9")})}
	b, err := slotConfig(base, []runRec{rec})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		API       map[string]any   `json:"api"`
		DNS       map[string]any   `json:"dns"`
		Outbounds []map[string]any `json:"outbounds"`
		Inbounds  []map[string]any `json:"inbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.API["listen"] != "/run/ctrlz-xray/a/api.sock,0600" {
		t.Errorf("api listen %v", cfg.API["listen"])
	}
	if s := cfg.DNS["servers"].([]any)[0]; s != "tcp+local://127.0.0.10:5300" || cfg.DNS["queryStrategy"] != "UseIPv4" {
		t.Errorf("dns %v", cfg.DNS)
	}
	if cfg.Outbounds[0]["protocol"] != "blackhole" || cfg.Outbounds[1]["tag"] != "direct" {
		t.Errorf("the first outbound is not the blackhole: %v", cfg.Outbounds[0])
	}
	if !strings.Contains(string(b), `"9.9.9.9/32"`) || !strings.Contains(string(b), `"127.0.0.0/8"`) {
		t.Error("finalRules lack the node address or the loopback range")
	}
	tags := map[string]map[string]any{}
	for _, o := range cfg.Outbounds {
		tags[o["tag"].(string)] = o
		if o["protocol"] == "blackhole" {
			continue
		}
		so := o["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
		if so["domainStrategy"] != "ForceIPv4" {
			t.Errorf("%v: no ForceIPv4", o["tag"])
		}
	}
	main, hop := tags["L"+hexID(7)+".3.0"], tags["L"+hexID(7)+".3.1"]
	if main == nil || hop == nil {
		t.Fatalf("tags %v", tags)
	}
	want := "L" + hexID(7) + ".3.1"
	if got := main["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["dialerProxy"]; got != want {
		t.Errorf("dialerProxy %v, want %s", got, want)
	}
	// Inbounds: direct and the config's, on the slot's address, no auth, no UDP.
	var found bool
	for _, in := range cfg.Inbounds {
		if in["tag"] == "in:"+hexID(7)+".3" {
			found = true
			if in["port"].(float64) != 20001 || in["listen"] != "127.0.0.20" ||
				in["settings"].(map[string]any)["auth"] != "noauth" || in["settings"].(map[string]any)["udp"] != false {
				t.Errorf("inbound %v", in)
			}
		}
	}
	if !found {
		t.Error("no inbound of the config")
	}
	last := cfg.Routing.Rules[len(cfg.Routing.Rules)-1]
	if last["ruleTag"] != "L"+hexID(7)+".3" || last["outboundTag"] != want[:len(want)-1]+"0" {
		t.Errorf("rule %v", last)
	}
}

func TestAddCallsAndRemoveTags(t *testing.T) {
	rec := runRec{ID: hexID(1), Gen: 2, Port: 20005, Outs: 2, Frag: mustNormalize(t, vless("198.51.100.7"))}
	ado, adr, adi, err := addCalls("b", rec)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"ado": ado, "adrules": adr, "adi": adi} {
		if !json.Valid(b) {
			t.Errorf("%s is not JSON", name)
		}
	}
	if !strings.Contains(string(adi), `"127.0.0.21"`) || !strings.Contains(string(adr), `"routing"`) {
		t.Errorf("adi %s adr %s", adi, adr)
	}
	rule, in, outs := removeTags(rec)
	if rule != "L"+hexID(1)+".2" || in != "in:"+hexID(1)+".2" || len(outs) != 2 || outs[1] != "L"+hexID(1)+".2.1" {
		t.Errorf("%s %s %v", rule, in, outs)
	}
}

func TestRedactTakesPastedValuesOut(t *testing.T) {
	frag := []byte(`{"outbounds":[{"protocol":"trojan","settings":{"address":"203.0.113.9","password":"hunter2-secret"}}]}`)
	got := redact("bad config: password hunter2-secret at 203.0.113.9\x01"+strings.Repeat("x", 600), frag)
	if strings.Contains(got, "hunter2-secret") || strings.Contains(got, "203.0.113.9") || strings.ContainsRune(got, 1) {
		t.Errorf("not redacted: %q", got)
	}
	if !strings.Contains(got, "<value>") || len(got) > 500 {
		t.Errorf("%d bytes: %q", len(got), got)
	}
}

func TestHealthHysteresis(t *testing.T) {
	var h health
	h.observe(false, 0)
	if h.healthy {
		t.Fatal("starts healthy")
	}
	h.observe(true, 10*time.Millisecond) // first pass: healthy at once
	if !h.healthy {
		t.Fatal("first pass did not make it healthy")
	}
	h.observe(false, 0)
	h.observe(false, 0)
	if !h.healthy {
		t.Fatal("two failures flipped it")
	}
	h.observe(true, 10*time.Millisecond) // a pass resets the run of failures
	h.observe(false, 0)
	h.observe(false, 0)
	if !h.healthy {
		t.Fatal("failures with a pass between flipped it")
	}
	h.observe(false, 0)
	if h.healthy {
		t.Fatal("three failures in a row did not flip it")
	}
	h.observe(true, 10*time.Millisecond)
	h.observe(true, 10*time.Millisecond)
	if h.healthy {
		t.Fatal("two passes flipped it back")
	}
	h.observe(true, 10*time.Millisecond)
	if !h.healthy {
		t.Fatal("three passes did not")
	}
}

func TestLatencyIsPublishedOnlyPastTheHysteresis(t *testing.T) {
	var h health
	h.observe(true, 100*time.Millisecond)
	if h.published != 100 {
		t.Fatalf("first %d", h.published)
	}
	h.observe(true, 110*time.Millisecond) // smoothed 103: inside 20% and 10 ms
	if h.published != 100 {
		t.Fatalf("small move published: %d", h.published)
	}
	for i := 0; i < 20; i++ {
		h.observe(true, 300*time.Millisecond)
	}
	if h.published < 250 {
		t.Fatalf("a large move was not published: %d", h.published)
	}
}

func TestExitIDSharedByConfigsOfOneExit(t *testing.T) {
	a := exitOf(hexID(1), mustNormalize(t, vless("198.51.100.7")))
	b := exitOf(hexID(2), mustNormalize(t, vless("198.51.100.7")))
	c := exitOf(hexID(3), mustNormalize(t, vless("198.51.100.8")))
	if len(a) != 8 || string(a) != string(b) || string(a) == string(c) {
		t.Errorf("%x %x %x", a, b, c)
	}
}

func TestStatusAndEnds(t *testing.T) {
	for _, c := range []struct {
		result string
		exit   int
		end    bool
	}{{"signal", 0, true}, {"oom-kill", 0, true}, {"exit-code", 2, true}, {"exit-code", 23, false}, {"exit-code", 255, false}, {"success", 0, false}} {
		if IsEnd(c.result, c.exit) != c.end {
			t.Errorf("%s %d", c.result, c.exit)
		}
	}
}

// A SOCKS5 server that answers like Xray: the greeting, then a success reply before
// anything is dialled (finding 20), then the bytes of the exit.
func fakeSocks(t *testing.T, answer string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				g := make([]byte, 3)
				if _, err := io.ReadFull(br, g); err != nil || g[0] != 5 {
					return
				}
				c.Write([]byte{5, 0})
				h := make([]byte, 5)
				if _, err := io.ReadFull(br, h); err != nil || h[3] != 3 {
					return
				}
				io.CopyN(io.Discard, br, int64(h[4])+2)
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				if answer == "" {
					return
				}
				br.ReadString('\n') // the request line is enough to answer
				time.Sleep(15 * time.Millisecond)
				io.WriteString(c, answer)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSocksProbe(t *testing.T) {
	p := SocksProber{Timeout: time.Second}
	ok := fakeSocks(t, "HTTP/1.1 204 No Content\r\n\r\n")
	lat, pass := p.Probe(context.Background(), ok, []string{"http://www.example.com/generate_204"})
	if !pass || lat < 10*time.Millisecond {
		t.Errorf("pass %v lat %v", pass, lat)
	}
	bad := fakeSocks(t, "HTTP/1.1 200 OK\r\n\r\n")
	if _, pass := p.Probe(context.Background(), bad, []string{"http://www.example.com/x"}); pass {
		t.Error("a 200 passed")
	}
	if _, pass := p.Probe(context.Background(), ok, []string{"https://www.example.com/x", "ftp://x/"}); pass {
		t.Error("a scheme other than http passed")
	}
	if _, pass := p.Probe(context.Background(), ok, []string{"http://www.example.com/x"}); !pass {
		t.Error("the second try failed")
	}
	// The second URL is tried when the first fails.
	if _, pass := p.Probe(context.Background(), ok, []string{"http://%", "http://cp.example.com/g"}); !pass {
		t.Error("no fallback to the second URL")
	}
	if !p.Greet(context.Background(), ok) {
		t.Error("greeting refused")
	}
	if p.Greet(context.Background(), "127.0.0.1:1") {
		t.Error("greeting answered by nothing")
	}
}
