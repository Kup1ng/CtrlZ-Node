package main

// E03 and E04: the two claims about unix sockets (p4b-proxy.md finding 2 and 3; 2.1 and 7.4 build on them).

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func waitFile(path string, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// e03APIUnix: the API listens on a unix socket given as an absolute path with a mode, and the `xray api` client reaches it.
func e03APIUnix(c *tctx) {
	listen, target := apiListenFor(c.dir, 0)
	i, err := c.start("api", mkCfg(cfgOpts{apiListen: listen}), "")
	if err != nil {
		rep("E03", "ERR", "%v", err)
		return
	}
	defer i.stop()
	fi, err := os.Stat(i.apiPath)
	if err != nil {
		rep("E03", "FAIL", "no socket file at %s after start: %v", i.apiPath, err)
		return
	}
	rep("E03", "INFO", "api.listen %q: file mode %v (is socket: %v)", listen, fi.Mode(), fi.Mode()&os.ModeSocket != 0)
	if fi.Mode().Perm() == 0o600 {
		rep("E03", "PASS", "the ',0600' suffix of api.listen sets the socket mode to 0600")
	} else {
		rep("E03", "FAIL", "api.listen with ',0600' gave mode %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(i.apiPath + ".lock"); err == nil {
		rep("E03", "INFO", "%s.lock exists while the process runs", filepath.Base(i.apiPath))
	} else {
		rep("E03", "INFO", "no .lock file next to the socket: %v", err)
	}
	// Client forms. grpc-go resolves "unix:///abs", "unix:/abs" and, as a plain string, treats a path as a host name.
	for _, form := range []string{target, "unix:" + i.apiPath, i.apiPath} {
		r := apiCall(c.xray, form, "lsi", "")
		ok := r.code == 0 && strings.Contains(r.out, "direct")
		st := "PASS"
		if !ok {
			st = "INFO"
		}
		rep("E03", st, "xray api lsi -s %q: exit %d in %v: %s", strings.Replace(form, c.dir, "<dir>", 1), r.code, r.dur.Round(time.Millisecond), oneLine(r.out, 160))
	}
	// The service list of the spec: Handler and Routing answer, Stats does not exist.
	r := apiCall(c.xray, target, "lsrules", "")
	rep("E03", "INFO", "lsrules over the socket: exit %d: %s", r.code, oneLine(r.out, 200))
	r = apiCall(c.xray, target, "statssys", "")
	rep("E03", "INFO", "statssys (StatsService not enabled): exit %d: %s", r.code, oneLine(r.out, 160))

	// A relative path and a path without a mode.
	rel := mkCfg(cfgOpts{apiListen: "rel.sock", directPort: 20010})
	j, err := c.start("rel", rel, fmt.Sprintf("%s:%d", directHost, 20010))
	if err != nil {
		rep("E03", "INFO", "api.listen \"rel.sock\" (not absolute): %s", oneLine(err.Error(), 300))
	} else {
		rep("E03", "INFO", "api.listen \"rel.sock\" (not absolute) started; lsi says: %s", oneLine(j.api("lsi", "").out, 160))
		j.stop()
	}
	plain := filepath.Join(c.dir, "plain", "api.sock")
	_ = os.MkdirAll(filepath.Dir(plain), 0o755)
	k, err := c.start("plain", mkCfg(cfgOpts{apiListen: plain, directPort: 20011}), fmt.Sprintf("%s:%d", directHost, 20011))
	if err != nil {
		rep("E03", "ERR", "no-mode start: %v", err)
	} else {
		fi, _ := os.Stat(plain)
		if fi != nil {
			rep("E03", "INFO", "api.listen without a mode: socket mode %v (umask decides)", fi.Mode().Perm())
		}
		k.stop()
	}
	// The abstract form is lock-free; the spec does not use it, the line says whether it works.
	ab := "@ctrlz-xraycheck-" + fmt.Sprint(os.Getpid())
	m, err := c.start("abs", mkCfg(cfgOpts{apiListen: ab, directPort: 20012}), fmt.Sprintf("%s:%d", directHost, 20012))
	if err != nil {
		rep("E03", "INFO", "api.listen %q: %s", ab, oneLine(err.Error(), 200))
	} else {
		r := apiCall(c.xray, "unix-abstract:"+strings.TrimPrefix(ab, "@"), "lsi", "")
		rep("E03", "INFO", "api.listen %q works; lsi via unix-abstract: exit %d: %s", ab, r.code, oneLine(r.out, 120))
		m.stop()
	}
}

// e04SocksUnix: a SOCKS inbound cannot serve on a unix socket (finding 3). The line says what happens when one is configured.
func e04SocksUnix(c *tctx) {
	sock := filepath.Join(c.dir, "socks.sock")
	listen, _ := apiListenFor(c.dir, 0)
	cfg := mkCfg(cfgOpts{apiListen: listen, inbounds: A{J{"tag": "usock", "listen": sock, "protocol": "socks", "settings": J{"auth": "noauth", "udp": false}}}})
	cfgPath := c.path("usock.json")
	_ = writeJSON(cfgPath, cfg)
	t := runCmd(20*time.Second, "", c.xray, "run", "-test", "-c", cfgPath)
	rep("E04", "INFO", "run -test with a socks inbound on a unix path: exit %d: %s", t.code, oneLine(t.out, 200))

	i, err := c.start("usock", cfg, "")
	if err != nil {
		rep("E04", "INFO", "start with a socks inbound on a unix path failed: %s", oneLine(err.Error(), 300))
		rep("E04", "PASS", "no usable SOCKS inbound on a unix socket (it does not start)")
		return
	}
	defer i.stop()
	if !waitFile(sock, 5*time.Second) {
		rep("E04", "PASS", "the process runs but made no socket file at %s", sock)
		return
	}
	uc, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		rep("E04", "INFO", "socket file exists, dial failed: %v", err)
		return
	}
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = uc.Write([]byte{5, 1, 0})
	b := make([]byte, 2)
	n, rerr := uc.Read(b)
	uc.Close()
	time.Sleep(1 * time.Second)
	rep("E04", "INFO", "SOCKS greeting on the unix socket: %d bytes %v, read error %v; process afterwards: alive=%v status=%s", n, b[:n], rerr, !i.proc.exited(), i.proc.status())
	if i.proc.exited() {
		rep("E04", "PASS", "a SOCKS inbound on a unix socket ends the whole process on its first client (status %s): %s", i.proc.status(), oneLine(tail(i.proc.out.String(), 6), 400))
	} else if n == 2 && b[0] == 5 {
		rep("E04", "FAIL", "the SOCKS inbound answers on a unix socket")
	} else {
		rep("E04", "PASS", "no SOCKS service on the unix socket (no answer); the process is alive")
	}
}
