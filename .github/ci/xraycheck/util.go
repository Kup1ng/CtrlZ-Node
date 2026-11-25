package main

// Helpers of the Xray start check (Plan.md D69, p4b-proxy.md 17 B0): result lines, child processes, the small servers the
// experiments talk to (echo, DNS over TCP, a source and a sink), a SOCKS5 client and a wrapper around `xray api`.
//
// Why a Go program and not a shell script: the experiments need sockets of their own (a half-open dial, a stub resolver, byte
// counts under load), and a shell would turn each of them into a pipeline of nc and sleep.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type J = map[string]any
type A = []any

// ---------------------------------------------------------------------------------------------------------------------
// Results. Every claim of the spec gets one line: PASS (the binary agrees), FAIL (the binary contradicts the spec),
// INFO (a measured fact the spec does not state), ERR (the experiment itself broke, so the claim is unproved).

type result struct{ id, status, text string }

var (
	resMu   sync.Mutex
	results []result
	started = time.Now()
)

func logf(format string, args ...any) {
	fmt.Printf("%7.1fs  %s\n", time.Since(started).Seconds(), fmt.Sprintf(format, args...))
}

func rep(id, status, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	resMu.Lock()
	results = append(results, result{id, status, text})
	resMu.Unlock()
	logf("RESULT %-6s %-4s %s", id, status, text)
}

// ---------------------------------------------------------------------------------------------------------------------
// Child processes.

type xproc struct {
	name string
	cmd  *exec.Cmd
	out  *lockedBuf
	done chan struct{}
	mu   sync.Mutex
	code int    // exit code, -1 when a signal ended it
	sig  string // the signal that ended it, "" otherwise
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 4<<20 { // a runaway log must not fill the memory of the runner
		l.b.Write(p)
	}
	return len(p), nil
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var (
	liveMu sync.Mutex
	live   = map[*xproc]bool{}
)

func (x *xproc) pid() int { return x.cmd.Process.Pid }

func (x *xproc) exited() bool {
	select {
	case <-x.done:
		return true
	default:
		return false
	}
}

// status says how the process ended, in the words the spec uses.
func (x *xproc) status() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sig != "" {
		return "signal " + x.sig
	}
	return fmt.Sprintf("exit %d", x.code)
}

// startProc starts a child with a minimal environment: Xray reads XRAY_* variables, and a runner has none of ours.
func startProc(name, bin string, args []string, stdin string) (*xproc, error) {
	return startProcDir(name, "", bin, args, stdin)
}

// startProcDir is startProc with a working directory; the default is the temp dir, so a relative path in a config lands there
// and not in the checkout.
func startProcDir(name, dir, bin string, args []string, stdin string) (*xproc, error) {
	return startProcEnv(name, dir, nil, bin, args, stdin)
}

// startProcEnv adds variables to the minimal environment (the splice control of E09 sets XRAY_BUF_SPLICE).
func startProcEnv(name, dir string, env []string, bin string, args []string, stdin string) (*xproc, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	if dir == "" {
		cmd.Dir = os.TempDir()
	}
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GODEBUG=multipathtcp=0", "HOME=" + os.TempDir(), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}
	cmd.Env = append(cmd.Env, env...)
	out := &lockedBuf{}
	cmd.Stdout, cmd.Stderr = out, out
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	x := &xproc{name: name, cmd: cmd, out: out, done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	liveMu.Lock()
	live[x] = true
	liveMu.Unlock()
	go func() {
		err := cmd.Wait()
		x.mu.Lock()
		x.code, x.sig = exitInfo(cmd, err)
		x.mu.Unlock()
		close(x.done)
		liveMu.Lock()
		delete(live, x)
		liveMu.Unlock()
	}()
	return x, nil
}

func (x *xproc) kill() {
	if x.exited() {
		return
	}
	_ = x.cmd.Process.Kill()
	x.wait(5 * time.Second)
}

func (x *xproc) wait(d time.Duration) bool {
	select {
	case <-x.done:
		return true
	case <-time.After(d):
		return false
	}
}

func killAll() {
	liveMu.Lock()
	var all []*xproc
	for x := range live {
		all = append(all, x)
	}
	liveMu.Unlock()
	for _, x := range all {
		x.kill()
	}
}

// runCmd runs a short command to the end (bounded) and returns its output and exit code.
type cmdResult struct {
	out  string
	code int
	dur  time.Duration
	to   bool
}

func runCmd(timeout time.Duration, stdin string, bin string, args ...string) cmdResult {
	return runCmdDir(timeout, "", stdin, bin, args...)
}

func runCmdDir(timeout time.Duration, dir, stdin string, bin string, args ...string) cmdResult {
	t0 := time.Now()
	x, err := startProcDir("cmd", dir, bin, args, stdin)
	if err != nil {
		return cmdResult{out: "start: " + err.Error(), code: -2, dur: time.Since(t0)}
	}
	ok := x.wait(timeout)
	if !ok {
		x.kill()
	}
	x.mu.Lock()
	code := x.code
	x.mu.Unlock()
	return cmdResult{out: x.out.String(), code: code, dur: time.Since(t0), to: !ok}
}

// tail returns the last n lines of s, for a log line that should not bury the others.
func tail(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------------------------------------------------
// Xray configuration. The base follows p4b-proxy.md 7.4: policy, api on a unix socket (a TCP address where the OS has none),
// dns with one tcp+local server and UseIPv4, a first blackhole outbound, and the inbound `direct`.

type cfgOpts struct {
	apiListen  string // value of api.listen
	dns        string // one DNS server URL, "" for no dns section
	logLevel   string // default "warning"
	inbounds   A      // after the base `direct` inbound
	outbounds  A      // after blackhole and plain
	rules      A      // after the rule that sends `direct` to directTo
	directTo   string // outbound for the `direct` inbound, default "plain"
	noDirect   bool   // leave out the `direct` inbound and its rule
	noAPI      bool
	directPort int
}

const directHost = "127.0.0.20"

func mkCfg(o cfgOpts) J {
	if o.logLevel == "" {
		o.logLevel = "warning"
	}
	if o.directTo == "" {
		o.directTo = "plain"
	}
	if o.directPort == 0 {
		o.directPort = 20000
	}
	cfg := J{
		"log":    J{"access": "none", "loglevel": o.logLevel},
		"policy": J{"levels": J{"0": J{"handshake": 4, "connIdle": 600, "uplinkOnly": 10, "downlinkOnly": 10, "bufferSize": 16}}},
	}
	if !o.noAPI {
		cfg["api"] = J{"tag": "api", "listen": o.apiListen, "services": A{"HandlerService", "RoutingService"}}
	}
	if o.dns != "" {
		cfg["dns"] = J{"servers": A{o.dns}, "queryStrategy": "UseIPv4"}
	}
	inb := A{}
	rules := A{}
	if !o.noDirect {
		inb = append(inb, J{"tag": "direct", "listen": directHost, "port": o.directPort, "protocol": "socks", "settings": J{"auth": "noauth", "udp": false}})
		rules = append(rules, J{"type": "field", "ruleTag": "base-direct", "inboundTag": A{"direct"}, "outboundTag": o.directTo})
	}
	inb = append(inb, o.inbounds...)
	rules = append(rules, o.rules...)
	cfg["inbounds"] = inb
	cfg["outbounds"] = append(A{
		J{"tag": "blackhole", "protocol": "blackhole"},
		plainOutbound("plain"),
	}, o.outbounds...)
	cfg["routing"] = J{"rules": rules}
	return cfg
}

// plainOutbound is a freedom outbound with no finalRules, the stand-in for any exit in the experiments that are about the
// handlers and not about what an exit refuses. sockopt.domainStrategy UseIP is what 7.4 sets so names resolve through the
// configured resolver.
func plainOutbound(tag string) J {
	return J{"tag": tag, "protocol": "freedom", "settings": J{}, "streamSettings": J{"sockopt": J{"domainStrategy": "UseIP"}}}
}

func socksInbound(tag, host string, port int) J {
	return J{"tag": tag, "listen": host, "port": port, "protocol": "socks", "settings": J{"auth": "noauth", "udp": false}}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------------------------------------------------
// A running Xray and its API.

type inst struct {
	t       *tctx
	name    string
	proc    *xproc
	cfgPath string
	apiPath string // the path of the socket, or host:port on an OS without unix sockets
	apiOpt  string // what api.listen got
}

// tctx is the scratch area of one experiment.
type tctx struct {
	dir  string
	bin  string
	xray string
	env  []string // extra environment for the next instances
}

func (c *tctx) path(name string) string { return filepath.Join(c.dir, name) }

// apiListenFor gives api.listen for a new slot directory under dir: an absolute unix path with a mode on Linux, as 7.4 renders
// it, or a loopback port where the OS has no unix sockets. Every call makes a directory of its own, because a killed process
// leaves its socket behind and the next instance must not trip on it (E11 is the experiment about that).
func apiListenFor(dir string, port int) (listen, target string) {
	if runtime.GOOS == "linux" {
		d := filepath.Join(dir, fmt.Sprintf("api%d", slotSeq.Add(1)))
		_ = os.MkdirAll(d, 0o755)
		p := filepath.Join(d, "api.sock")
		return p + ",0600", "unix://" + p
	}
	a := fmt.Sprintf("127.0.0.1:%d", port)
	return a, a
}

var slotSeq atomic.Int64

// start writes cfg and starts `xray run -c`. wait is the address that must accept before the instance counts as up; an
// empty wait means the direct inbound.
func (c *tctx) start(name string, cfg J, waitAddr string) (*inst, error) {
	cfgPath := c.path(name + ".json")
	if err := writeJSON(cfgPath, cfg); err != nil {
		return nil, err
	}
	x, err := startProcEnv(name, "", c.env, c.xray, []string{"run", "-c", cfgPath}, "")
	if err != nil {
		return nil, err
	}
	i := &inst{t: c, name: name, proc: x, cfgPath: cfgPath}
	if api, ok := cfg["api"].(J); ok {
		i.apiOpt, _ = api["listen"].(string)
		i.apiPath = strings.SplitN(i.apiOpt, ",", 2)[0]
	}
	if waitAddr == "" {
		waitAddr = fmt.Sprintf("%s:%d", directHost, 20000)
	}
	if waitAddr != "-" {
		if err := waitTCP(waitAddr, 15*time.Second, x); err != nil {
			x.kill()
			return nil, fmt.Errorf("%s did not come up: %v; output: %s", name, err, tail(x.out.String(), 8))
		}
	}
	return i, nil
}

func waitTCP(addr string, d time.Duration, x *xproc) error {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if x != nil && x.exited() {
			return fmt.Errorf("process ended (%s)", x.status())
		}
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("no listener at " + addr)
}

func (i *inst) stop() { i.proc.kill() }

// api runs `xray api <cmd>` against the instance. stdin, when given, is passed as the argument "stdin:".
func (i *inst) api(cmd string, stdin string, args ...string) cmdResult {
	target := i.apiPath
	if runtime.GOOS == "linux" {
		target = "unix://" + i.apiPath
	}
	return apiCall(i.t.xray, target, cmd, stdin, args...)
}

func apiCall(xray, target, cmd, stdin string, args ...string) cmdResult {
	a := []string{"api", cmd, "-s", target, "-t", "6"}
	a = append(a, args...)
	if stdin != "" {
		a = append(a, "stdin:")
	}
	return runCmd(20*time.Second, stdin, xray, a...)
}

// ---------------------------------------------------------------------------------------------------------------------
// Servers the experiments talk to.

type echoSrv struct {
	ln    net.Listener
	conns atomic.Int64
	bytes atomic.Int64
}

func newEcho(addr string) (*echoSrv, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	e := &echoSrv{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.conns.Add(1)
			go func() {
				defer c.Close()
				buf := make([]byte, 32<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						e.bytes.Add(int64(n))
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return e, nil
}

func (e *echoSrv) port() int    { return e.ln.Addr().(*net.TCPAddr).Port }
func (e *echoSrv) close()       { e.ln.Close() }
func (e *echoSrv) addr() string { return e.ln.Addr().String() }

// bulkSrv sends `send` bytes to each client and reads what the client sends, counting both. It is the far end of the
// splice experiment.
type bulkSrv struct {
	ln      net.Listener
	send    int64
	gotUp   atomic.Int64
	sentDn  atomic.Int64
	started atomic.Int64
}

func newBulk(send int64) (*bulkSrv, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &bulkSrv{ln: ln, send: send}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.started.Add(1)
			go func() {
				defer c.Close()
				done := make(chan struct{})
				go func() {
					buf := make([]byte, 64<<10)
					for {
						n, err := c.Read(buf)
						b.gotUp.Add(int64(n)) // counted as it arrives, so a missing half-close shows as a stall and not as zero
						if err != nil {
							break
						}
					}
					close(done)
				}()
				if b.send > 0 {
					chunk := make([]byte, 64<<10)
					var left = b.send
					for left > 0 {
						n := int64(len(chunk))
						if left < n {
							n = left
						}
						w, err := c.Write(chunk[:n])
						b.sentDn.Add(int64(w))
						if err != nil {
							return
						}
						left -= n
					}
					if tc, ok := c.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
				}
				select {
				case <-done:
				case <-time.After(60 * time.Second):
				}
			}()
		}
	}()
	return b, nil
}

func (b *bulkSrv) port() int { return b.ln.Addr().(*net.TCPAddr).Port }
func (b *bulkSrv) close()    { b.ln.Close() }

// dnsStub answers DNS over TCP (RFC 7766) for a fixed table and records every question. A and AAAA only; an AAAA answer is
// empty (NOERROR), a name outside the table is NXDOMAIN.
type dnsStub struct {
	ln    net.Listener
	mu    sync.Mutex
	table map[string]net.IP
	qs    []string
}

func newDNS(table map[string]net.IP) (*dnsStub, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &dnsStub{ln: ln, table: table}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(c)
		}
	}()
	return d, nil
}

func (d *dnsStub) port() int    { return d.ln.Addr().(*net.TCPAddr).Port }
func (d *dnsStub) close()       { d.ln.Close() }
func (d *dnsStub) addr() string { return d.ln.Addr().String() }

func (d *dnsStub) questions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.qs...)
}

func (d *dnsStub) reset() {
	d.mu.Lock()
	d.qs = nil
	d.mu.Unlock()
}

func (d *dnsStub) serve(c net.Conn) {
	defer c.Close()
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		resp := d.answer(msg)
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func (d *dnsStub) answer(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	i := 12
	var labels []string
	for i < len(q) && q[i] != 0 {
		n := int(q[i])
		if i+1+n > len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+n]))
		i += 1 + n
	}
	i++ // the root label
	if i+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i : i+2])
	end := i + 4
	name := strings.ToLower(strings.Join(labels, "."))
	d.mu.Lock()
	d.qs = append(d.qs, fmt.Sprintf("%s/%d", name, qtype))
	ip, known := d.table[name]
	d.mu.Unlock()
	resp := make([]byte, 0, 64)
	resp = append(resp, q[0], q[1]) // id
	rcode := byte(0)
	if !known {
		rcode = 3
	}
	answers := 0
	if known && qtype == 1 && ip.To4() != nil {
		answers = 1
	}
	resp = append(resp, 0x81, 0x80|rcode, 0, 1, 0, byte(answers), 0, 0, 0, 0)
	resp = append(resp, q[12:end]...)
	if answers == 1 {
		resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		resp = append(resp, ip.To4()...)
	}
	return resp
}

// ---------------------------------------------------------------------------------------------------------------------
// SOCKS5 client (RFC 1928), enough for CONNECT with no authentication.

type socksRes struct {
	conn    net.Conn
	rep     byte
	replyAt time.Duration // from the start of the CONNECT request to its reply
	err     error
}

func socksConnect(proxy, host string, port int, timeout time.Duration) socksRes {
	c, err := net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return socksRes{err: err}
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	fail := func(err error) socksRes { c.Close(); return socksRes{err: err} }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return fail(err)
	}
	if m[0] != 5 || m[1] != 0 {
		return fail(fmt.Errorf("method reply %v", m))
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 1)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	t0 := time.Now()
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return fail(err)
	}
	var skip int
	switch h[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return fail(err)
		}
		skip = int(l[0]) + 2
	default:
		return fail(fmt.Errorf("address type %d", h[3]))
	}
	if _, err := io.ReadFull(c, make([]byte, skip)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return socksRes{conn: c, rep: h[1], replyAt: time.Since(t0)}
}

// echoOnce writes a line and reads it back; it says what went wrong in a word.
func echoOnce(c net.Conn, payload string, d time.Duration) string {
	_ = c.SetDeadline(time.Now().Add(d))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(payload)); err != nil {
		return "write: " + errWord(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return "read: " + errWord(err)
	}
	if string(buf) != payload {
		return "echo differs"
	}
	return "ok"
}

// errWord reduces a network error to the kind that matters when failover is designed on it: end of stream, a reset, a
// timeout, a refusal.
func errWord(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, io.EOF):
		return "EOF"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "EOF (short)"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "reset"):
		return "reset"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "broken pipe"):
		return "broken pipe"
	case strings.Contains(s, "forcibly closed"):
		return "reset"
	case strings.Contains(s, "aborted"):
		return "aborted"
	}
	return s
}

// readFor reads until the connection ends or d passes and says which; it returns the bytes seen.
func readFor(c net.Conn, d time.Duration) (n int, how string, took time.Duration) {
	t0 := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 4096)
	for {
		m, err := c.Read(buf)
		n += m
		if err != nil {
			return n, errWord(err), time.Since(t0)
		}
	}
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
