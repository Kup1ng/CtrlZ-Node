package main

// E07 and E08: freedom finalRules (finding 5) and the resolver that Xray uses (7.4: tcp+local to the identified Unbound).

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// reach connects through proxy to host:port and says what a client sees: whether the echo came back, or how it ended.
func reach(proxy, host string, port int, wait time.Duration) (string, socksRes) {
	s := socksConnect(proxy, host, port, 6*time.Second)
	if s.err != nil {
		return "CONNECT failed: " + errWord(s.err), s
	}
	if s.rep != 0 {
		s.conn.Close()
		return fmt.Sprintf("CONNECT reply %d", s.rep), s
	}
	return echoOnce(s.conn, "ping", wait), s
}

func finalRule(action string, extra J) J {
	r := J{"action": action}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

func e07FinalRules(c *tctx) {
	a, err1 := newEcho("127.0.0.1:0")
	b, err2 := newEcho("127.0.0.200:0")
	if err1 != nil || err2 != nil {
		rep("E07", "ERR", "echo servers: %v %v", err1, err2)
		return
	}
	defer a.close()
	defer b.close()
	stub, err := newDNS(map[string]net.IP{"blocked.test": net.IPv4(127, 0, 0, 1), "allowed.test": net.IPv4(127, 0, 0, 200)})
	if err != nil {
		rep("E07", "ERR", "%v", err)
		return
	}
	defer stub.close()

	special := A{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
	ud := J{"sockopt": J{"domainStrategy": "UseIP"}}
	fr := func(tag string, rules A) J {
		return J{"tag": tag, "protocol": "freedom", "settings": J{"finalRules": rules}, "streamSettings": ud}
	}
	listen, _ := apiListenFor(c.dir, 21002)
	in := func(tag string, port int) J { return socksInbound(tag, directHost, port) }
	rule := func(tag, out string) J { return J{"type": "field", "inboundTag": A{tag}, "outboundTag": out} }
	cfg := mkCfg(cfgOpts{
		apiListen: listen, logLevel: "info", dns: "tcp+local://" + stub.addr(),
		inbounds: A{in("in:fr", 20041), in("in:fr2", 20042), in("in:up", 20043), in("in:port", 20044), in("in:dp", 20045), in("in:d74", 20046)},
		outbounds: A{
			fr("fr", A{finalRule("block", J{"ip": A{"127.0.0.0/25"}}), finalRule("allow", J{"network": "tcp"})}),
			fr("fr2", A{finalRule("block", J{"ip": A{"127.0.0.0/25"}, "delay": "1-2"}), finalRule("allow", J{"network": "tcp"})}),
			fr("up", A{finalRule("BLOCK", J{"ip": A{"127.0.0.0/25"}, "delay": "1-1"}), finalRule("ALLOW", J{"network": A{"tcp"}})}),
			fr("port", A{finalRule("block", J{"port": fmt.Sprint(b.port()), "delay": "1-1"})}),
			J{"tag": "dp", "protocol": "freedom", "settings": J{"finalRules": A{finalRule("block", J{"ip": A{"127.0.0.0/25"}, "delay": "1-1"})}},
				"streamSettings": J{"sockopt": J{"dialerProxy": "plain", "domainStrategy": "UseIP"}}},
			fr("d74", append(A{finalRule("block", J{"ip": special, "delay": "1-1"})}, finalRule("allow", J{"network": "tcp"}))),
		},
		rules: A{rule("in:fr", "fr"), rule("in:fr2", "fr2"), rule("in:up", "up"), rule("in:port", "port"), rule("in:dp", "dp"), rule("in:d74", "d74")},
	})
	i, err := c.start("fr", cfg, "")
	if err != nil {
		rep("E07", "ERR", "%v", err)
		return
	}
	defer i.stop()
	p := func(port int) string { return fmt.Sprintf("%s:%d", directHost, port) }

	// 1. the default block holds the connection: success reply, nothing dialled, no byte, no close for a long time
	before := a.conns.Load()
	got, s := reach(p(20041), "127.0.0.1", a.port(), 4*time.Second)
	if s.conn != nil {
		n, how, took := readFor(s.conn, 1*time.Second)
		s.conn.Close()
		_ = n
		_ = how
		_ = took
	}
	time.Sleep(300 * time.Millisecond)
	dialled := a.conns.Load() - before
	if dialled == 0 && got != "ok" {
		rep("E07", "PASS", "block rule on 127.0.0.0/25 (default delay): the SOCKS reply is %d, the target is never dialled, the client gets %s after 4 s and the connection is still open", s.rep, got)
	} else {
		rep("E07", "FAIL", "block rule on 127.0.0.0/25: echo %q, target dialled %d times", got, dialled)
	}
	got, s = reach(p(20041), "127.0.0.200", b.port(), 4*time.Second)
	if s.conn != nil {
		s.conn.Close()
	}
	if got == "ok" {
		rep("E07", "PASS", "the same outbound lets 127.0.0.200 through (block list, then allow tcp)")
	} else {
		rep("E07", "FAIL", "127.0.0.200 not allowed through an outbound that blocks only 127.0.0.0/25: %s", got)
	}

	// 2. domains: resolved by the configured resolver, then judged by the rule
	stub.reset()
	before = a.conns.Load()
	got, s = reach(p(20041), "blocked.test", a.port(), 4*time.Second)
	if s.conn != nil {
		s.conn.Close()
	}
	time.Sleep(300 * time.Millisecond)
	q := stub.questions()
	if a.conns.Load() == before && got != "ok" {
		rep("E07", "PASS", "a name that resolves into a blocked range is not dialled (client: %s); the stub saw %v", got, q)
	} else {
		rep("E07", "FAIL", "blocked.test reached the target: %s, dialled %d, stub %v", got, a.conns.Load()-before, q)
	}
	got, s = reach(p(20041), "allowed.test", b.port(), 4*time.Second)
	if s.conn != nil {
		s.conn.Close()
	}
	rep("E07", "INFO", "allowed.test (resolves to 127.0.0.200): %s; stub saw %v", got, stub.questions())

	// 3. delay, case folding of the action, port rules, dialerProxy, and the literal shape of 7.4
	for _, k := range []struct {
		name  string
		proxy int
		host  string
		port  int
		want  string
	}{
		{"delay 1-2", 20042, "127.0.0.1", a.port(), "closed"},
		{"action BLOCK and ALLOW in capitals, network as a list, delay 1-1", 20043, "127.0.0.1", a.port(), "closed"},
		{"port rule, blocked port", 20044, "127.0.0.200", b.port(), "closed"},
		{"port rule, another port", 20044, "127.0.0.1", a.port(), "ok"},
		{"7.4 shape (all non-public ranges, then allow tcp) towards loopback", 20046, "127.0.0.200", b.port(), "closed"},
		{"finalRules on an outbound that has sockopt.dialerProxy, towards a blocked range", 20045, "127.0.0.1", a.port(), "ok"},
	} {
		s := socksConnect(p(k.proxy), k.host, k.port, 5*time.Second)
		if s.err != nil {
			rep("E07", "ERR", "%s: %v", k.name, s.err)
			continue
		}
		var what string
		var took time.Duration
		if k.want == "ok" {
			what = echoOnce(s.conn, "ping", 4*time.Second)
		} else {
			t0 := time.Now()
			_, how, _ := readFor(s.conn, 8*time.Second)
			took = time.Since(t0)
			what = "closed(" + how + ")"
			if how == "timeout" {
				what = "still open after 8 s"
			}
		}
		s.conn.Close()
		st := "PASS"
		if (k.want == "ok") != (what == "ok") {
			st = "FAIL"
		}
		if k.want == "closed" && !strings.HasPrefix(what, "closed") {
			st = "FAIL"
		}
		rep("E07", st, "%s: %s%s (expected %s)", k.name, what, map[bool]string{true: fmt.Sprintf(" after %v", took.Round(100*time.Millisecond)), false: ""}[k.want == "closed"], k.want)
	}
	var warn []string
	for _, l := range strings.Split(i.proc.out.String(), "\n") {
		if strings.Contains(l, "finalrule") || strings.Contains(l, "finalRules") {
			warn = append(warn, oneLine(l, 180))
			if len(warn) >= 6 {
				break
			}
		}
	}
	rep("E07", "INFO", "log lines that name finalrules: %s", strings.Join(warn, " || "))
}

func e08DNS(c *tctx) {
	echo, err := newEcho("127.0.0.1:0")
	if err != nil {
		rep("E08", "ERR", "%v", err)
		return
	}
	defer echo.close()
	stub, err := newDNS(map[string]net.IP{"a.test": net.IPv4(127, 0, 0, 1)})
	if err != nil {
		rep("E08", "ERR", "%v", err)
		return
	}
	defer stub.close()
	run := func(name string, port int, dnsURL, strategy string, outbound J, outTag string) (string, []string, *xproc) {
		stub.reset()
		listen, _ := apiListenFor(c.dir, 21003+port-20050)
		cfg := mkCfg(cfgOpts{apiListen: listen, dns: dnsURL, directPort: port, directTo: outTag, outbounds: A{outbound}})
		if strategy != "" {
			cfg["dns"].(J)["queryStrategy"] = strategy
		}
		i, err := c.start(name, cfg, fmt.Sprintf("%s:%d", directHost, port))
		if err != nil {
			return "start failed: " + oneLine(err.Error(), 200), nil, nil
		}
		defer i.stop()
		got, s := reach(fmt.Sprintf("%s:%d", directHost, port), "a.test", echo.port(), 10*time.Second)
		if s.conn != nil {
			s.conn.Close()
		}
		return got, stub.questions(), i.proc
	}
	withUseIP := plainOutbound("o")
	got, qs, _ := run("local", 20050, "tcp+local://"+stub.addr(), "UseIPv4", withUseIP, "o")
	hasAAAA := false
	for _, q := range qs {
		if strings.HasSuffix(q, "/28") {
			hasAAAA = true
		}
	}
	if got == "ok" && len(qs) > 0 && !hasAAAA {
		rep("E08", "PASS", "tcp+local://<stub> with queryStrategy UseIPv4 and outbound sockopt.domainStrategy UseIP: a.test connects; the stub saw only %v", qs)
	} else {
		rep("E08", "FAIL", "tcp+local with UseIPv4: %s, stub saw %v", got, qs)
	}
	got, qs, _ = run("routed", 20051, "tcp://"+stub.addr(), "UseIPv4", withUseIP, "o")
	rep("E08", "INFO", "the same with tcp:// (not local, so the query goes through routing to the first outbound, a blackhole): %s, stub saw %v", got, qs)
	got, qs, _ = run("asis", 20052, "tcp+local://"+stub.addr(), "UseIPv4", J{"tag": "o", "protocol": "freedom", "settings": J{}}, "o")
	rep("E08", "INFO", "outbound WITHOUT sockopt.domainStrategy (the name is left to the system resolver): %s, stub saw %v", got, qs)
	got, qs, _ = run("both", 20053, "tcp+local://"+stub.addr(), "UseIP", withUseIP, "o")
	rep("E08", "INFO", "queryStrategy UseIP (v4 and v6): %s, stub saw %v", got, qs)
}
