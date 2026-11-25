package main

// E11 to E14: process life (SIGKILL, stale socket, memory kill, exit statuses), a cycle of dialerProxy, and how the real
// loader treats keys and values.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func sendSignal(x *xproc, sig syscall.Signal) error { return x.cmd.Process.Signal(sig) }

// tryStart starts xray with a config and waits up to d for it to end; it returns the process and whether it ended.
func tryStart(c *tctx, name, cfgPath string, d time.Duration) (*xproc, bool) {
	x, err := startProcEnv(name, "", c.env, c.xray, []string{"run", "-c", cfgPath}, "")
	if err != nil {
		return nil, true
	}
	return x, x.wait(d)
}

func e11Restart(c *tctx) {
	listen, _ := apiListenFor(c.dir, 0)
	sock := strings.SplitN(listen, ",", 2)[0]
	cfg := mkCfg(cfgOpts{apiListen: listen})
	cfgPath := c.path("slot.json")
	_ = writeJSON(cfgPath, cfg)
	apiUp := func() bool {
		r := apiCall(c.xray, "unix://"+sock, "lsi", "")
		return r.code == 0
	}

	// A. a process that is killed leaves its socket and its lock file behind
	x1, ended := tryStart(c, "slot1", cfgPath, 3*time.Second)
	if x1 == nil || ended {
		msg := "cannot start"
		if x1 != nil {
			msg = tail(x1.out.String(), 5)
		}
		rep("E11", "ERR", "the first start ended: %s", msg)
		return
	}
	if err := waitTCP(fmt.Sprintf("%s:20000", directHost), 10*time.Second, x1); err != nil {
		rep("E11", "ERR", "first start not up: %v", err)
		x1.kill()
		return
	}
	_ = x1.cmd.Process.Kill()
	x1.wait(5 * time.Second)
	_, errS := os.Stat(sock)
	_, errL := os.Stat(sock + ".lock")
	rep("E11", "INFO", "after SIGKILL (%s): api.sock exists=%v, api.sock.lock exists=%v", x1.status(), errS == nil, errL == nil)

	// B. a new process on the same slot with the leftovers in place
	x2, ended := tryStart(c, "slot2", cfgPath, 8*time.Second)
	if ended {
		rep("E11", "PASS", "a new process does not start over a stale api.sock: %s after %s", x2.status(), oneLine(tail(x2.out.String(), 3), 300))
	} else {
		rep("E11", "FAIL", "a new process started over a stale api.sock (alive after 8 s); api answers: %v", apiUp())
		x2.kill()
	}

	// C. only the socket removed, the stale lock file kept
	_ = os.Remove(sock)
	x3, ended := tryStart(c, "slot3", cfgPath, 4*time.Second)
	if ended {
		rep("E11", "INFO", "with the socket removed and the stale lock kept the start ended: %s %s", x3.status(), oneLine(tail(x3.out.String(), 3), 300))
	} else {
		rep("E11", "PASS", "removing api.sock is enough: a stale api.sock.lock does not block a start (the flock died with the process); api answers: %v", apiUp())
		// D. a second process on a live slot
		cfg2 := mkCfg(cfgOpts{apiListen: listen, directPort: 20071})
		cfg2Path := c.path("slot-second.json")
		_ = writeJSON(cfg2Path, cfg2)
		x4, ended := tryStart(c, "slot4", cfg2Path, 6*time.Second)
		if ended {
			rep("E11", "INFO", "a second process on a live slot ended: %s %s", x4.status(), oneLine(tail(x4.out.String(), 3), 300))
		} else {
			rep("E11", "INFO", "a second process on a live slot is still alive after 6 s (the flock on api.sock.lock waits and nothing is logged): its output %q; the first one's api answers: %v", oneLine(x4.out.String(), 200), apiUp())
			x4.kill()
		}
		x3.kill()
	}

	// E. both removed, as xray-run does
	_ = os.Remove(sock)
	_ = os.Remove(sock + ".lock")
	x5, ended := tryStart(c, "slot5", cfgPath, 4*time.Second)
	if ended {
		rep("E11", "FAIL", "with both leftovers removed the start ended: %s %s", x5.status(), tail(x5.out.String(), 4))
	} else {
		rep("E11", "PASS", "with api.sock and api.sock.lock removed a slot starts again after SIGKILL; api answers: %v", apiUp())
		x5.kill()
	}

	// F. the unit: Restart=always, a wrapper that removes the leftovers, SIGKILL and then a kill by the memory limit
	if _, err := exec.LookPath("systemd-run"); err != nil {
		rep("E11", "INFO", "no systemd-run on this machine: the unit part is skipped")
		return
	}
	if r := runCmd(15*time.Second, "", "sudo", "-n", "true"); r.code != 0 {
		rep("E11", "INFO", "no passwordless sudo: the unit part is skipped (%s)", oneLine(r.out, 100))
		return
	}
	_ = os.Remove(sock)
	_ = os.Remove(sock + ".lock")
	wrapper := c.path("slot-run.sh")
	script := "#!/bin/sh\nrm -f \"$1\" \"$1.lock\"\nexec \"$2\" run -c \"$3\"\n"
	_ = os.WriteFile(wrapper, []byte(script), 0o755)
	unit := "xraycheck-slot"
	sd := func(args ...string) cmdResult {
		return runCmd(30*time.Second, "", "sudo", append([]string{"-n", "systemctl"}, args...)...)
	}
	show := func(props ...string) string {
		a := []string{"show", unit}
		for _, p := range props {
			a = append(a, "-p", p)
		}
		return oneLine(sd(a...).out, 300)
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "runner"
	}
	r := runCmd(30*time.Second, "", "sudo", "-n", "systemd-run", "--unit="+unit, "-p", "Restart=always", "-p", "RestartSec=1", "-p", "StartLimitIntervalSec=0",
		"-p", "User="+user, "-p", "MemorySwapMax=0", "-p", "OOMPolicy=stop", "-p", "KillMode=control-group", wrapper, sock, c.xray, cfgPath)
	if r.code != 0 {
		rep("E11", "ERR", "systemd-run failed: %s", oneLine(r.out, 300))
		return
	}
	defer func() {
		sd("stop", unit)
		sd("reset-failed", unit)
	}()
	waitAPI := func(d time.Duration) bool {
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			if apiUp() {
				return true
			}
			time.Sleep(500 * time.Millisecond)
		}
		return false
	}
	pidOf := func() string {
		return strings.TrimSpace(strings.TrimPrefix(oneLine(sd("show", unit, "-p", "MainPID", "--value").out, 40), "MainPID="))
	}
	if !waitAPI(20 * time.Second) {
		rep("E11", "ERR", "the unit never answered on the API: %s; journal: %s", show("ActiveState", "SubState", "Result"), oneLine(tail(runCmd(10*time.Second, "", "sudo", "-n", "journalctl", "-u", unit, "-n", "10", "--no-pager").out, 6), 400))
		return
	}
	pid1 := pidOf()
	sd("kill", "-s", "SIGKILL", "--kill-whom=main", unit)
	t0 := time.Now()
	var pid2 string
	for time.Since(t0) < 30*time.Second {
		time.Sleep(500 * time.Millisecond)
		if p := pidOf(); p != "" && p != "0" && p != pid1 {
			pid2 = p
			break
		}
	}
	up := pid2 != "" && waitAPI(20*time.Second)
	st := "FAIL"
	if up {
		st = "PASS"
	}
	rep("E11", st, "unit with Restart=always after SIGKILL of the main process: pid %s then %s, api answers again after %v; %s", pid1, pid2, time.Since(t0).Round(100*time.Millisecond), show("NRestarts", "Result", "ExecMainStatus"))

	// memory limit: lowered at run time, so the process is killed by the kernel and not by a failed start. The first run showed a
	// resident set under 8 MB, so the limit goes down in steps until the main process is replaced.
	t1 := time.Now()
	pid3 := pidOf()
	killed := false
	for _, lim := range []string{"4M", "2M", "1M", "256K"} {
		sd("set-property", "--runtime", unit, "MemoryMax="+lim)
		end := time.Now().Add(20 * time.Second)
		for time.Now().Before(end) && !killed {
			time.Sleep(500 * time.Millisecond)
			if p := pidOf(); p != pid3 {
				killed = true
			}
		}
		rep("E11", "INFO", "MemoryMax %s: main pid %s changed=%v after %v; %s", lim, pid3, killed, time.Since(t1).Round(100*time.Millisecond), show("NRestarts", "Result", "ExecMainStatus", "ExecMainCode", "MemoryCurrent", "MemoryPeak"))
		if killed {
			break
		}
	}
	jr := runCmd(15*time.Second, "", "sudo", "-n", "journalctl", "-u", unit, "-n", "40", "--no-pager", "-o", "cat")
	var oom []string
	for _, l := range strings.Split(jr.out, "\n") {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "oom") || strings.Contains(ll, "killed") || strings.Contains(ll, "signal") || strings.Contains(ll, "memory") {
			oom = append(oom, oneLine(l, 160))
		}
	}
	rep("E11", "INFO", "journal lines about the kill: %s", strings.Join(oom, " || "))
	sd("set-property", "--runtime", unit, "MemoryMax=infinity")
	up = waitAPI(40 * time.Second)
	st = "FAIL"
	if up && killed {
		st = "PASS"
	}
	rep("E11", st, "after the kill by the memory limit and the limit lifted: the slot starts again and answers on the API=%v; %s", up, show("NRestarts", "Result", "ActiveState"))
}

func e12Exit(c *tctx) {
	listen, _ := apiListenFor(c.dir, 21030)
	good := mkCfg(cfgOpts{apiListen: listen, logLevel: "none", directPort: 20080})
	goodPath := c.path("good.json")
	_ = writeJSON(goodPath, good)
	rep("E12", "INFO", "the spec's base uses log level none: %s", "loglevel none")

	// signals on a running process
	sigs := []struct {
		name string
		sig  syscall.Signal
	}{{"SIGTERM", syscall.SIGTERM}, {"SIGINT", syscall.SIGINT}, {"SIGKILL", syscall.SIGKILL}, {"SIGABRT", syscall.SIGABRT}}
	for k, s := range sigs {
		lis, _ := apiListenFor(c.dir, 21031+k)
		cfg := mkCfg(cfgOpts{apiListen: lis, logLevel: "none", directPort: 20081 + k})
		p := c.path(fmt.Sprintf("sig%d.json", k))
		_ = writeJSON(p, cfg)
		x, ended := tryStart(c, "sig", p, 800*time.Millisecond)
		if x == nil {
			rep("E12", "ERR", "%s: cannot start", s.name)
			continue
		}
		if ended {
			rep("E12", "ERR", "%s: the process ended on its own: %s", s.name, oneLine(x.out.String(), 200))
			continue
		}
		if err := waitTCP(fmt.Sprintf("%s:%d", directHost, 20081+k), 10*time.Second, x); err != nil {
			rep("E12", "ERR", "%s: %v", s.name, err)
			x.kill()
			continue
		}
		if err := sendSignal(x, s.sig); err != nil {
			rep("E12", "INFO", "%s: cannot be sent here: %v", s.name, err)
			x.kill()
			continue
		}
		if !x.wait(10 * time.Second) {
			rep("E12", "INFO", "%s: the process was still alive 10 s later", s.name)
			x.kill()
			continue
		}
		rep("E12", "INFO", "%s on a running process: %s; output: %q", s.name, x.status(), oneLine(tail(x.out.String(), 2), 160))
	}

	// run -test
	write := func(name, text string) string {
		p := c.path(name)
		_ = os.WriteFile(p, []byte(text), 0o600)
		return p
	}
	hold, _ := net.Listen("tcp", fmt.Sprintf("%s:20090", directHost))
	busyListen, _ := apiListenFor(c.dir, 21040)
	busy := mkCfg(cfgOpts{apiListen: busyListen, directPort: 20090, logLevel: "none"})
	busyPath := c.path("busy.json")
	_ = writeJSON(busyPath, busy)
	tests := []struct {
		name string
		args []string
	}{
		{"run -test, good config", []string{"run", "-test", "-c", goodPath}},
		{"run -test, broken JSON", []string{"run", "-test", "-c", write("broken.json", "{ not json")}},
		{"run -test, unknown outbound protocol", []string{"run", "-test", "-c", write("badproto.json", `{"outbounds":[{"tag":"x","protocol":"nonesuch","settings":{}}]}`)}},
		{"run -test, no such file", []string{"run", "-test", "-c", c.path("absent.json")}},
		{"run -test, the inbound port is taken", []string{"run", "-test", "-c", busyPath}},
		{"run, broken JSON", []string{"run", "-c", write("broken2.json", "{ not json")}},
		{"run, the inbound port is taken", []string{"run", "-c", busyPath}},
		{"run, empty JSON object", []string{"run", "-c", write("empty.json", "{}")}},
	}
	for _, t := range tests {
		r := runCmd(8*time.Second, "", c.xray, t.args...)
		how := fmt.Sprintf("exit %d", r.code)
		if r.to {
			how = "still running after 8 s"
		}
		rep("E12", "INFO", "%s: %s; %s", t.name, how, lastWords(verdictLine(r.out), 260))
	}
	if hold != nil {
		hold.Close()
	}
}

func e13Cycle(c *tctx) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		rep("E13", "INFO", "no systemd-run: skipped")
		return
	}
	if r := runCmd(15*time.Second, "", "sudo", "-n", "true"); r.code != 0 {
		rep("E13", "INFO", "no passwordless sudo: skipped")
		return
	}
	echo, err := newEcho("127.0.0.1:0")
	if err != nil {
		rep("E13", "ERR", "%v", err)
		return
	}
	defer echo.close()
	hop := func(tag, next string) J {
		return J{"tag": tag, "protocol": "freedom", "settings": J{}, "streamSettings": J{"sockopt": J{"dialerProxy": next}}}
	}
	listen, _ := apiListenFor(c.dir, 0)
	sock := strings.SplitN(listen, ",", 2)[0]
	cfg := mkCfg(cfgOpts{apiListen: listen, directTo: "A", outbounds: A{hop("A", "B"), hop("B", "A")}})
	cfgPath := c.path("cycle.json")
	_ = writeJSON(cfgPath, cfg)
	t := runCmd(20*time.Second, "", c.xray, "run", "-test", "-c", cfgPath)
	rep("E13", "INFO", "run -test of a two-outbound dialerProxy cycle: exit %d: %s", t.code, oneLine(tail(t.out, 3), 200))

	// live add of the same pair to a healthy process
	live := mkCfg(cfgOpts{apiListen: strings.Replace(listen, "api.sock", "live.sock", 1), directPort: 20100})
	i, err := c.start("cyclelive", live, fmt.Sprintf("%s:20100", directHost))
	if err == nil {
		r := i.api("ado", mustJSON(J{"outbounds": A{hop("A", "B"), hop("B", "A")}}))
		rep("E13", "INFO", "ado of the cycle to a running process: exit %d: %s", r.code, oneLine(r.out, 160))
		i.stop()
	}

	// the first dial under a memory limit, so the runner is safe
	unit := "xraycheck-cycle"
	sd := func(args ...string) cmdResult {
		return runCmd(30*time.Second, "", "sudo", append([]string{"-n", "systemctl"}, args...)...)
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "runner"
	}
	_ = os.Remove(sock)
	_ = os.Remove(sock + ".lock")
	r := runCmd(30*time.Second, "", "sudo", "-n", "systemd-run", "--unit="+unit, "-p", "User="+user, "-p", "MemoryMax=600M", "-p", "MemorySwapMax=0", "-p", "RuntimeMaxSec=170",
		"-p", "Restart=no", c.xray, "run", "-c", cfgPath)
	if r.code != 0 {
		rep("E13", "ERR", "systemd-run: %s", oneLine(r.out, 300))
		return
	}
	defer func() { sd("stop", unit); sd("reset-failed", unit) }()
	if err := waitTCP(fmt.Sprintf("%s:20000", directHost), 15*time.Second, nil); err != nil {
		rep("E13", "ERR", "the cycle process did not come up: %v", err)
		return
	}
	s := socksConnect(fmt.Sprintf("%s:20000", directHost), "127.0.0.1", echo.port(), 5*time.Second)
	rep("E13", "INFO", "CONNECT through the cycle: err %v reply %d", s.err, s.rep)
	t0 := time.Now()
	var line []string
	for time.Since(t0) < 150*time.Second {
		time.Sleep(5 * time.Second)
		o := oneLine(sd("show", unit, "-p", "ActiveState", "-p", "MemoryCurrent", "-p", "Result", "-p", "ExecMainStatus", "-p", "ExecMainCode").out, 200)
		line = append(line, fmt.Sprintf("%ds: %s", int(time.Since(t0).Seconds()), strings.NewReplacer("ExecMainCode=", "code=", "ExecMainStatus=", "status=", "MemoryCurrent=", "mem=", "ActiveState=", "", "Result=", "result=").Replace(o)))
		if strings.Contains(o, "ActiveState=failed") || strings.Contains(o, "ActiveState=inactive") {
			break
		}
	}
	if s.conn != nil {
		n, how, took := readFor(s.conn, 2*time.Second)
		rep("E13", "INFO", "the client of the cycle connection: %d bytes, %s after %v", n, how, took.Round(time.Millisecond))
		s.conn.Close()
	}
	rep("E13", "INFO", "unit under MemoryMax=600M while the cycle dials: %s", strings.Join(line, " || "))
	jr := runCmd(15*time.Second, "", "sudo", "-n", "journalctl", "-u", unit, "-n", "12", "--no-pager", "-o", "cat")
	rep("E13", "INFO", "journal of the cycle unit: %s", oneLine(jr.out, 600))
}

func e14Folding(c *tctx) {
	valid := func(extra J) J {
		cfg := mkCfg(cfgOpts{noAPI: true, logLevel: "none"})
		if extra != nil {
			cfg["outbounds"] = append(cfg["outbounds"].(A), extra)
		}
		return cfg
	}
	idx := 0
	try := func(name string, cfg J) {
		idx++
		p := c.path(fmt.Sprintf("v%02d.json", idx))
		_ = writeJSON(p, cfg)
		r := runCmd(20*time.Second, "", c.xray, "run", "-test", "-c", p)
		res := "accepted"
		if r.code != 0 {
			res = fmt.Sprintf("REFUSED (exit %d)", r.code)
		}
		rep("E14", "INFO", "run -test, %s: %s %s", name, res, lastWords(verdictLine(r.out), 260))
	}
	ob := func(m J) J {
		o := J{"tag": "x", "protocol": "freedom", "settings": J{}}
		for k, v := range m {
			if v == nil {
				delete(o, k)
				continue
			}
			o[k] = v
		}
		return o
	}
	try("the base alone", valid(nil))
	try("keys in other case (TAG, Protocol, Settings)", valid(J{"TAG": "x", "Protocol": "FreeDom", "Settings": J{}}))
	try("an unknown key on the outbound", valid(ob(J{"bogus": 1})))
	try("an unknown key in freedom settings", valid(ob(J{"settings": J{"bogus": 1}})))
	try("a key repeated in two cases (tag and TAG)", valid(ob(J{"TAG": "y"})))
	for _, n := range []string{"tcp", "TCP", "raw", "RAW", "Raw"} {
		try("streamSettings.network "+n, valid(ob(J{"streamSettings": J{"network": n}})))
	}
	for _, s := range []string{"none", "NONE", "None", "tls", "TLS"} {
		try("streamSettings.security "+s, valid(ob(J{"streamSettings": J{"network": "tcp", "security": s}})))
	}
	try("sockopt.domainStrategy useip (lower case)", valid(ob(J{"streamSettings": J{"sockopt": J{"domainStrategy": "useip"}}})))
	try("sockopt.domainStrategy UseIPv4v6 (mixed case)", valid(ob(J{"streamSettings": J{"sockopt": J{"domainStrategy": "UseIPv4v6"}}})))
	try("sockopt.domainStrategy nonsense", valid(ob(J{"streamSettings": J{"sockopt": J{"domainStrategy": "nonsense"}}})))
	try("tcpSettings and rawSettings together, different headers", valid(ob(J{"streamSettings": J{"network": "raw",
		"tcpSettings": J{"header": J{"type": "none"}}, "rawSettings": J{"header": J{"type": "http"}}}})))
	try("network splithttp with splithttpSettings", valid(ob(J{"streamSettings": J{"network": "splithttp", "splithttpSettings": J{"path": "/a"}}})))
	try("network xhttp with xhttpSettings", valid(ob(J{"streamSettings": J{"network": "xhttp", "xhttpSettings": J{"path": "/a"}}})))
	try("network splithttp with both splithttpSettings and xhttpSettings", valid(ob(J{"streamSettings": J{"network": "splithttp", "splithttpSettings": J{"path": "/a"}, "xhttpSettings": J{"path": "/b"}}})))
	try("vless to a public IP with no security", valid(J{"tag": "v", "protocol": "vless", "settings": J{"address": "8.8.8.8", "port": 443, "id": "5783a3e7-e373-51cd-8642-c83782b807c5", "encryption": "none"}}))
	try("vless to a public IP with security tls", valid(J{"tag": "v", "protocol": "vless", "settings": J{"address": "8.8.8.8", "port": 443, "id": "5783a3e7-e373-51cd-8642-c83782b807c5", "encryption": "none"}, "streamSettings": J{"network": "tcp", "security": "tls", "tlsSettings": J{"serverName": "example.test"}}}))
	try("trojan to a public IP with no security", valid(J{"tag": "t", "protocol": "trojan", "settings": J{"address": "8.8.8.8", "port": 443, "password": "x"}}))
	try("proxySettings on an outbound", valid(ob(J{"proxySettings": J{"tag": "y"}})))
	try("sockopt.dialerProxy to a tag that does not exist", valid(ob(J{"streamSettings": J{"sockopt": J{"dialerProxy": "nowhere"}}})))
	try("sendThrough", valid(ob(J{"sendThrough": "10.0.0.1"})))
	try("sockopt mark, interface, tproxy, customSockopt", valid(ob(J{"streamSettings": J{"sockopt": J{"mark": 255, "interface": "lo", "tproxy": "off", "customSockopt": A{J{"type": "int", "level": "6", "opt": "1", "value": "1"}}}}})))
	try("protocol loopback", valid(ob(J{"protocol": "loopback", "settings": J{"inboundTag": "direct"}})))
	try("protocol dns", valid(ob(J{"protocol": "dns", "settings": J{}})))
	try("protocol nonesuch", valid(ob(J{"protocol": "nonesuch"})))
	try("network xdrive with xdriveSettings dir", valid(ob(J{"streamSettings": J{"network": "xdrive", "xdriveSettings": J{"dir": c.path("xdrive")}}})))
	try("a top-level key that does not exist", func() J { v := valid(nil); v["zzz"] = 1; return v }())
	try("top-level env", func() J { v := valid(nil); v["env"] = J{"XRAY_LOCATION_ASSET": "/tmp"}; return v }())
	try("top-level geodata", func() J { v := valid(nil); v["geodata"] = J{}; return v }())

	// duplicate and upper-case keys as the live API reads them: which tag does the process take?
	listen, _ := apiListenFor(c.dir, 21050)
	i, err := c.start("dup", mkCfg(cfgOpts{apiListen: listen, directPort: 20110}), fmt.Sprintf("%s:20110", directHost))
	if err != nil {
		rep("E14", "ERR", "%v", err)
		return
	}
	defer i.stop()
	r := i.api("ado", `{"outbounds":[{"tag":"first","TAG":"second","Tag":"third","Protocol":"FREEDOM","Settings":{}}]}`)
	lso := i.api("lso", "").out
	which := "none of the three"
	for _, t := range []string{"first", "second", "third"} {
		if strings.Contains(lso, `"`+t+`"`) {
			which = t
		}
	}
	rep("E14", "INFO", "ado with the keys tag, TAG and Tag (in that order) and Protocol FREEDOM: exit %d; the outbound that exists is %q (the last one in the text wins if that is 'third')", r.code, which)
	_ = filepath.Base
	_ = strconv.Itoa
}

// verdictLine is the last line of an xray run that says what happened; the banner and the "Reading config" line are noise.
func verdictLine(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" && !strings.Contains(lines[i], "Reading config") && !strings.Contains(lines[i], "anti-censorship") {
			return lines[i]
		}
	}
	return ""
}

// lastWords keeps the end of a long error, where the cause is.
func lastWords(s string, n int) string {
	s = oneLine(s, 4000)
	if len(s) > n {
		s = "..." + s[len(s)-n:]
	}
	return s
}
