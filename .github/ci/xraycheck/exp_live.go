package main

// E05 and E06: the API's live changes under open connections (finding 4) and what a client sees of a dead exit (finding 20).

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func idJSON(id string, g int) (in, out, rule string) {
	return fmt.Sprintf("in:%s.%d", id, g), fmt.Sprintf("L%s.%d.0", id, g), fmt.Sprintf("L%s.%d", id, g)
}

// addConfig applies one config the way 7.5 step 2 does: outbound, rule (appended), inbound. It returns the three exit codes.
func addConfig(i *inst, id string, g, port int) (codes [3]int, outs [3]string) {
	in, out, rule := idJSON(id, g)
	r := i.api("ado", mustJSON(J{"outbounds": A{plainOutbound(out)}}))
	codes[0], outs[0] = r.code, r.out
	r = i.api("adrules", mustJSON(J{"routing": J{"rules": A{J{"type": "field", "ruleTag": rule, "inboundTag": A{in}, "outboundTag": out}}}}), "-append")
	codes[1], outs[1] = r.code, r.out
	r = i.api("adi", mustJSON(J{"inbounds": A{socksInbound(in, directHost, port)}}))
	codes[2], outs[2] = r.code, r.out
	return
}

func e05Live(c *tctx) {
	echo, err := newEcho("127.0.0.1:0")
	if err != nil {
		rep("E05", "ERR", "%v", err)
		return
	}
	defer echo.close()
	listen, _ := apiListenFor(c.dir, 21000)
	i, err := c.start("live", mkCfg(cfgOpts{apiListen: listen}), "")
	if err != nil {
		rep("E05", "ERR", "%v", err)
		return
	}
	defer i.stop()

	codes, outs := addConfig(i, "aa", 0, 20001)
	if codes != [3]int{0, 0, 0} {
		rep("E05", "ERR", "generation 0 could not be added: %v %v", codes, outs)
		return
	}
	rep("E05", "PASS", "ado, adrules -append and adi read their JSON from the argument stdin: (exit 0 each); output of adi: %s", oneLine(outs[2], 120))
	for _, cmd := range []string{"lsi", "lso", "lsrules"} {
		r := i.api(cmd, "")
		rep("E05", "INFO", "%s after adding generation 0: %s", cmd, oneLine(r.out, 300))
	}

	c1 := socksConnect(fmt.Sprintf("%s:%d", directHost, 20001), "127.0.0.1", echo.port(), 5*time.Second)
	if c1.err != nil || c1.rep != 0 {
		rep("E05", "ERR", "first connection through generation 0: %v rep %d", c1.err, c1.rep)
		return
	}
	defer c1.conn.Close()
	rep("E05", "INFO", "connection 1 through in:aa.0: %s", echoOnce(c1.conn, "one", 3*time.Second))

	// generation 1 beside it, as a drain does
	codes, outs = addConfig(i, "aa", 1, 20002)
	c2 := socksConnect(fmt.Sprintf("%s:%d", directHost, 20002), "127.0.0.1", echo.port(), 5*time.Second)
	if codes != [3]int{0, 0, 0} || c2.err != nil {
		rep("E05", "ERR", "generation 1: %v %v %v", codes, outs, c2.err)
		return
	}
	defer c2.conn.Close()
	rep("E05", "PASS", "generation 1 added beside generation 0 while connection 1 is open; connection 2: %s", echoOnce(c2.conn, "two", 3*time.Second))

	// remove generation 0 in the order of 7.5 step 3: rules, inbound, outbound; ask connection 1 after each
	_, out0, rule0 := idJSON("aa", 0)
	in0, _, _ := idJSON("aa", 0)
	steps := []struct {
		name string
		do   func() cmdResult
	}{
		{"rmrules", func() cmdResult { return i.api("rmrules", "", rule0) }},
		{"rmi", func() cmdResult { return i.api("rmi", "", in0) }},
		{"rmo", func() cmdResult { return i.api("rmo", "", out0) }},
	}
	allAlive := true
	for _, s := range steps {
		r := s.do()
		w := echoOnce(c1.conn, "after-"+s.name, 3*time.Second)
		rep("E05", "INFO", "%s: exit %d (%s); connection 1 then: %s", s.name, r.code, oneLine(r.out, 80), w)
		if w != "ok" {
			allAlive = false
		}
	}
	time.Sleep(3 * time.Second)
	w := echoOnce(c1.conn, "later", 3*time.Second)
	if w != "ok" {
		allAlive = false
	}
	if allAlive {
		rep("E05", "PASS", "an open connection survives rmrules, rmi and rmo of its own generation (still echoing 3 s after)")
	} else {
		rep("E05", "FAIL", "an open connection did not survive the removal of its generation (last check %s)", w)
	}
	n := socksConnect(fmt.Sprintf("%s:%d", directHost, 20001), "127.0.0.1", echo.port(), 3*time.Second)
	if n.err != nil {
		rep("E05", "PASS", "after rmi a new connection to the old inbound port fails: %s", errWord(n.err))
	} else {
		n.conn.Close()
		rep("E05", "FAIL", "after rmi the old inbound port still accepts (reply %d)", n.rep)
	}
	rep("E05", "INFO", "connection 2 (generation 1) after all that: %s", echoOnce(c2.conn, "two-again", 3*time.Second))
	r := i.api("lsi", "")
	rep("E05", "INFO", "lsi after removal: %s", oneLine(r.out, 300))
	r = i.api("lso", "")
	rep("E05", "INFO", "lso after removal: %s", oneLine(r.out, 300))
	r = i.api("lsrules", "")
	rep("E05", "INFO", "lsrules after removal: %s", oneLine(r.out, 300))

	// the port of a removed inbound can be taken again at once
	r = i.api("adi", mustJSON(J{"inbounds": A{socksInbound("in:aa.2", directHost, 20001)}}))
	rep("E05", "INFO", "adi on the port of the removed inbound, at once: exit %d: %s", r.code, oneLine(r.out, 160))

	// errors and exit codes
	r = i.api("adi", mustJSON(J{"inbounds": A{socksInbound("in:aa.1", directHost, 20009)}}))
	rep("E05", "INFO", "adi with a tag that exists: exit %d: %s", r.code, oneLine(r.out, 200))
	for _, cmd := range [][]string{{"rmi", "no-such"}, {"rmo", "no-such"}, {"rmrules", "no-such"}} {
		r = i.api(cmd[0], "", cmd[1])
		rep("E05", "INFO", "%s of an unknown tag: exit %d: %s", cmd[0], r.code, oneLine(r.out, 200))
	}
	r = i.api("adi", "{ not json")
	rep("E05", "INFO", "adi with broken JSON: exit %d: %s", r.code, oneLine(r.out, 200))

	// a rule whose outbound is gone: the rendered order removes the rule first; this says why
	r = i.api("rmo", "", "L"+"aa.1.0")
	n2 := socksConnect(fmt.Sprintf("%s:%d", directHost, 20002), "127.0.0.1", echo.port(), 3*time.Second)
	if n2.err != nil {
		rep("E05", "INFO", "rmo of the outbound while its rule stays (exit %d); a new connection: %s", r.code, errWord(n2.err))
	} else {
		before := echo.conns.Load()
		w := echoOnce(n2.conn, "orphan", 3*time.Second)
		n2.conn.Close()
		rep("E05", "INFO", "rmo of the outbound while its rule stays (exit %d); a new connection: reply %d, echo %s, echo server saw %d new connections", r.code, n2.rep, w, echo.conns.Load()-before)
	}

	// the tag is read as a file name first: rmo opens the argument as a file, and a tag that is a file is parsed
	_ = os.WriteFile(c.path("tagfile"), []byte(`{"outbounds":[{"tag":"victim","protocol":"freedom","settings":{}}]}`), 0o600)
	i.api("ado", mustJSON(J{"outbounds": A{J{"tag": "victim", "protocol": "freedom", "settings": J{}}, J{"tag": "tagfile", "protocol": "freedom", "settings": J{}}}}))
	target := i.apiPath
	if onLinux {
		target = "unix://" + i.apiPath
	}
	r = runCmdDir(20*time.Second, c.dir, "", c.xray, "api", "rmo", "-s", target, "-t", "6", "tagfile")
	lso := i.api("lso", "").out
	rep("E05", "INFO", "rmo \"tagfile\" with a file of that name in the working directory: exit %d (%s); outbounds left: victim=%v tagfile=%v", r.code, oneLine(r.out, 100), strings.Contains(lso, "victim"), strings.Contains(lso, `"tagfile"`))
	i.api("rmo", "", "victim")

	// adrules without -append replaces the whole rule table
	before := i.api("lsrules", "").out
	r = i.api("adrules", mustJSON(J{"routing": J{"rules": A{J{"type": "field", "ruleTag": "solo", "inboundTag": A{"in:aa.1"}, "outboundTag": "blackhole"}}}}))
	after := i.api("lsrules", "").out
	d := socksConnect(fmt.Sprintf("%s:%d", directHost, 20000), "127.0.0.1", echo.port(), 3*time.Second)
	dres := "connect failed: " + errWord(d.err)
	if d.err == nil {
		dres = "echo " + echoOnce(d.conn, "direct", 3*time.Second)
		d.conn.Close()
	}
	st := "INFO"
	if strings.Contains(before, "base-direct") && !strings.Contains(after, "base-direct") {
		st = "PASS"
	}
	rep("E05", st, "adrules WITHOUT -append (exit %d) replaces the table: base-direct before=%v after=%v; the direct inbound then: %s", r.code, strings.Contains(before, "base-direct"), strings.Contains(after, "base-direct"), dres)
}

// e06DeadExit: the SOCKS inbound says "succeeded" before anything is dialled, so a dead exit shows only afterwards.
func e06DeadExit(c *tctx) {
	listen, _ := apiListenFor(c.dir, 21001)
	closed := freePort()
	in := func(tag string, port int) J { return socksInbound(tag, directHost, port) }
	cfg := mkCfg(cfgOpts{
		apiListen: listen,
		inbounds:  A{in("in:free", 20031), in("in:socks", 20032), in("in:hole", 20033)},
		outbounds: A{
			J{"tag": "o:socks", "protocol": "socks", "settings": J{"servers": A{J{"address": "127.0.0.1", "port": closed}}}},
		},
		rules: A{
			J{"type": "field", "inboundTag": A{"in:free"}, "outboundTag": "plain"},
			J{"type": "field", "inboundTag": A{"in:socks"}, "outboundTag": "o:socks"},
			J{"type": "field", "inboundTag": A{"in:hole"}, "outboundTag": "blackhole"},
		},
	})
	i, err := c.start("dead", cfg, "")
	if err != nil {
		rep("E06", "ERR", "%v", err)
		return
	}
	defer i.stop()
	echo, _ := newEcho("127.0.0.1:0")
	defer echo.close()
	cases := []struct {
		name, proxy, host string
		port              int
	}{
		{"freedom to a closed port (RST)", "127.0.0.20:20031", "127.0.0.1", closed},
		{"socks exit whose own server is a closed port", "127.0.0.20:20032", "127.0.0.1", echo.port()},
		{"blackhole outbound", "127.0.0.20:20033", "127.0.0.1", echo.port()},
	}
	allSuccess := true
	for _, k := range cases {
		s := socksConnect(k.proxy, k.host, k.port, 5*time.Second)
		if s.err != nil {
			rep("E06", "INFO", "%s: the SOCKS CONNECT itself failed: %s", k.name, s.err)
			allSuccess = false
			continue
		}
		n, how, took := readFor(s.conn, 8*time.Second)
		s.conn.Close()
		rep("E06", "INFO", "%s: reply code %d after %v; then %d bytes and %s after %v", k.name, s.rep, s.replyAt.Round(time.Millisecond), n, how, took.Round(time.Millisecond))
		if s.rep != 0 {
			allSuccess = false
		}
	}
	if allSuccess {
		rep("E06", "PASS", "the SOCKS inbound answers success (0) to CONNECT before the exit is reached; a dead exit shows only as the end of the stream afterwards")
	} else {
		rep("E06", "FAIL", "a dead exit changed the CONNECT reply (see the INFO lines)")
	}
}

// e15Scale: the API with the number of configs of 7.4 times two (a drain keeps two generations): how long the calls take, what
// the resident set does, and whether it comes back after the removal. D31's 64 configs are the figure to compare.
func e15Scale(c *tctx) {
	echo, err := newEcho("127.0.0.1:0")
	if err != nil {
		rep("E15", "ERR", "%v", err)
		return
	}
	defer echo.close()
	listen, _ := apiListenFor(c.dir, 21060)
	i, err := c.start("scale", mkCfg(cfgOpts{apiListen: listen}), "")
	if err != nil {
		rep("E15", "ERR", "%v", err)
		return
	}
	defer i.stop()
	pid := i.proc.pid()
	const n = 128
	var outs, ins, rules A
	var outTags, inTags, ruleTags []string
	for k := 0; k < n; k++ {
		id := fmt.Sprintf("%032x", k)
		in, out, rule := idJSON(id, 0)
		outs = append(outs, plainOutbound(out))
		ins = append(ins, socksInbound(in, directHost, 20001+k))
		rules = append(rules, J{"type": "field", "ruleTag": rule, "inboundTag": A{in}, "outboundTag": out})
		outTags, inTags, ruleTags = append(outTags, out), append(inTags, in), append(ruleTags, rule)
	}
	rep("E15", "INFO", "resident set of the idle process: %d KiB", rssKB(pid))
	step := func(name string, r cmdResult) {
		rep("E15", "INFO", "%s: exit %d in %v; resident set %d KiB; %s", name, r.code, r.dur.Round(time.Millisecond), rssKB(pid), oneLine(tail(r.out, 1), 80))
	}
	step(fmt.Sprintf("ado of %d outbounds in one call", n), i.api("ado", mustJSON(J{"outbounds": outs})))
	step(fmt.Sprintf("adrules -append of %d rules in one call", n), i.api("adrules", mustJSON(J{"routing": J{"rules": rules}}), "-append"))
	step(fmt.Sprintf("adi of %d inbounds in one call", n), i.api("adi", mustJSON(J{"inbounds": ins})))
	got, s := reach(fmt.Sprintf("%s:%d", directHost, 20001+n-1), "127.0.0.1", echo.port(), 5*time.Second)
	if s.conn != nil {
		s.conn.Close()
	}
	rep("E15", "INFO", "a connection through the last of them: %s", got)
	step("lsrules", i.api("lsrules", ""))
	step(fmt.Sprintf("rmrules of %d tags in one call", n), i.api("rmrules", "", ruleTags...))
	step(fmt.Sprintf("rmi of %d tags in one call", n), i.api("rmi", "", inTags...))
	step(fmt.Sprintf("rmo of %d tags in one call", n), i.api("rmo", "", outTags...))
	time.Sleep(3 * time.Second)
	rep("E15", "INFO", "resident set 3 s after the removal: %d KiB", rssKB(pid))
}
