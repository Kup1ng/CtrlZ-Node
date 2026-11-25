package main

// E09 and E10: splice in Xray's forwarding path, and how long a dial outlives the client that asked for it.

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// drive pushes down bytes from the far end and up bytes from the client through proxy to host:port and returns the bytes that
// arrived at the client and the time it took.
func drive(proxy, host string, port int, down, up int64, srv *bulkSrv) (got int64, took time.Duration, err error) {
	s := socksConnect(proxy, host, port, 8*time.Second)
	if s.err != nil {
		return 0, 0, s.err
	}
	defer s.conn.Close()
	if s.rep != 0 {
		return 0, 0, fmt.Errorf("reply %d", s.rep)
	}
	t0 := time.Now()
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		if up == 0 {
			return
		}
		chunk := make([]byte, 64<<10)
		for left := up; left > 0; {
			n := int64(len(chunk))
			if left < n {
				n = left
			}
			if _, err := s.conn.Write(chunk[:n]); err != nil {
				return
			}
			left -= n
		}
		if tc, ok := s.conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	if down > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		got, err = io.CopyN(io.Discard, s.conn, down)
	}
	<-upDone
	if up > 0 {
		end := time.Now().Add(60 * time.Second)
		for srv.gotUp.Load() < up && time.Now().Before(end) {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return got, time.Since(t0), err
}

var spliceLine = regexp.MustCompile(`splice\((\d+), [^,]*, (\d+), [^,]*, (\d+), [^)]*\)\s+=\s+(-?\d+)`)

type spliceStat struct {
	calls, bytes int64
	pairs        map[string]int64
}

func parseSplice(text string) spliceStat {
	st := spliceStat{pairs: map[string]int64{}}
	for _, l := range strings.Split(text, "\n") {
		m := spliceLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		n, _ := strconv.ParseInt(m[4], 10, 64)
		if n <= 0 {
			continue
		}
		st.calls++
		st.bytes += n
		st.pairs[m[1]+">"+m[2]] += n
	}
	return st
}

func ensureStrace() (string, string) {
	if p, err := exec.LookPath("strace"); err == nil {
		return p, "present"
	}
	// The runner's package mirror; announced in the report of the step. Without strace the /proc counters still speak.
	r := runCmd(180*time.Second, "", "sudo", "apt-get", "install", "-y", "-qq", "strace")
	if p, err := exec.LookPath("strace"); err == nil {
		return p, "installed by apt-get"
	}
	return "", "not available: " + oneLine(tail(r.out, 3), 200)
}

func e09Splice(c *tctx) {
	const size = 64 << 20
	down, err1 := newBulk(size)
	upSrv, err2 := newBulk(0)
	if err1 != nil || err2 != nil {
		rep("E09", "ERR", "servers: %v %v", err1, err2)
		return
	}
	defer down.close()
	defer upSrv.close()
	strace, how := ensureStrace()
	rep("E09", "INFO", "strace: %s %s", strace, how)

	type phase struct {
		name         string
		down, up     int64
		host         *bulkSrv
		spliceOff    bool
		portOnServer int
	}
	phases := []phase{
		{"download only (exit to client)", size, 0, down, false, 0},
		{"upload only (client to exit)", 0, size, upSrv, false, 0},
		{"download only, XRAY_BUF_SPLICE=disable (control)", size, 0, down, true, 0},
	}
	for pi, ph := range phases {
		c.env = nil
		if ph.spliceOff {
			c.env = []string{"XRAY_BUF_SPLICE=disable"}
		}
		listen, _ := apiListenFor(c.dir, 21010+pi)
		i, err := c.start(fmt.Sprintf("splice%d", pi), mkCfg(cfgOpts{apiListen: listen, directPort: 20060 + pi}), fmt.Sprintf("%s:%d", directHost, 20060+pi))
		c.env = nil
		if err != nil {
			rep("E09", "ERR", "%v", err)
			continue
		}
		proxy := fmt.Sprintf("%s:%d", directHost, 20060+pi)
		pid := i.proc.pid()
		var st *xproc
		out := c.path(fmt.Sprintf("strace%d.txt", pi))
		if strace != "" {
			st, err = startProc("strace", "sudo", []string{"-n", strace, "-f", "-qq", "-e", "trace=splice", "-o", out, "-p", strconv.Itoa(pid)}, "")
			if err != nil {
				st = nil
			}
			time.Sleep(2 * time.Second)
		}
		io0 := procIO(pid)
		got, took, err := drive(proxy, "127.0.0.1", ph.host.port(), ph.down, ph.up, ph.host)
		io1 := procIO(pid)
		if st != nil {
			time.Sleep(500 * time.Millisecond)
			_ = st.cmd.Process.Signal(os.Interrupt)
			st.wait(10 * time.Second)
			st.kill()
		}
		moved := ph.down + ph.up
		var d string
		if io0 != nil && io1 != nil {
			d = fmt.Sprintf("/proc io deltas: rchar %d MiB, wchar %d MiB, syscr %d, syscw %d", (io1["rchar"]-io0["rchar"])>>20, (io1["wchar"]-io0["wchar"])>>20, io1["syscr"]-io0["syscr"], io1["syscw"]-io0["syscw"])
		}
		sp := "no strace"
		var stat spliceStat
		if st != nil {
			b, rerr := os.ReadFile(out)
			if rerr != nil {
				b, _ = exec.Command("sudo", "cat", out).Output()
			}
			stat = parseSplice(string(b))
			sp = fmt.Sprintf("strace: %d splice calls moved %d MiB over fd pairs %v (file %d bytes)", stat.calls, stat.bytes>>20, stat.pairs, len(b))
		}
		rep("E09", "INFO", "%s: %d MiB moved in %v (client got %d, err %v); %s; %s", ph.name, moved>>20, took.Round(time.Millisecond), got, err, sp, d)
		i.stop()
		_ = stat
	}
	rep("E09", "INFO", "reading guide: splice calls moving about the whole payload mean that direction is spliced by the kernel; rchar/wchar near the payload mean it is copied in user space")
}

// e10DialLimit: a dial to an address that never answers (the SYN is dropped), the client closes after a second. How long does
// Xray go on dialling? The spec (5.5) says "at most 16 s".
func e10DialLimit(c *tctx) {
	f1, err1 := newFullListener()
	f2, err2 := newFullListener()
	if err1 != nil || err2 != nil {
		rep("E10", "ERR", "no black-hole stand-in: %v %v", err1, err2)
		return
	}
	defer f1.close()
	defer f2.close()
	listen, _ := apiListenFor(c.dir, 21020)
	// the policy of 7.4, with the handshake of 4 s, is part of the base
	i, err := c.start("dial", mkCfg(cfgOpts{apiListen: listen, logLevel: "info"}), "")
	if err != nil {
		rep("E10", "ERR", "%v", err)
		return
	}
	defer i.stop()
	proxy := fmt.Sprintf("%s:%d", directHost, 20000)

	sA := socksConnect(proxy, "127.0.0.1", f1.port, 5*time.Second)
	sB := socksConnect(proxy, "127.0.0.1", f2.port, 5*time.Second)
	if sA.err != nil || sB.err != nil {
		rep("E10", "ERR", "socks: %v %v", sA.err, sB.err)
		return
	}
	t0 := time.Now()
	rep("E10", "INFO", "CONNECT replies %d and %d after %v and %v (the dial has not been tried to the end yet)", sA.rep, sB.rep, sA.replyAt.Round(time.Millisecond), sB.replyAt.Round(time.Millisecond))
	type track struct {
		name          string
		port          int
		first, last   time.Duration
		appearances   int
		prev          int
		everSeen      bool
		maxConcurrent int
	}
	tA := &track{name: "A (client closes after 1 s)", port: f1.port}
	tB := &track{name: "B (client stays)", port: f2.port}
	bDone := make(chan string, 1)
	go func() {
		n, how, _ := readFor(sB.conn, 170*time.Second)
		bDone <- fmt.Sprintf("the client of B saw %s after %v (%d bytes)", how, time.Since(t0).Round(100*time.Millisecond), n)
	}()
	closedAt := time.Duration(-1)
	bMsg := ""
	idleSince := time.Time{}
	for time.Since(t0) < 175*time.Second {
		el := time.Since(t0)
		if closedAt < 0 && el >= time.Second {
			sA.conn.Close()
			closedAt = el
		}
		for _, t := range []*track{tA, tB} {
			n := synSentTo(t.port)
			if n > 0 {
				if !t.everSeen {
					t.first = el
				}
				t.everSeen = true
				t.last = el
				if t.prev == 0 {
					t.appearances++
				}
				if n > t.maxConcurrent {
					t.maxConcurrent = n
				}
			}
			t.prev = n
		}
		select {
		case m := <-bDone:
			bMsg = m
		default:
		}
		// stop when both have had no SYN_SENT socket for 6 s after being seen, and B's client has seen its end
		if tA.everSeen && tA.prev == 0 && tB.everSeen && tB.prev == 0 && bMsg != "" {
			if idleSince.IsZero() {
				idleSince = time.Now()
			}
			if time.Since(idleSince) > 6*time.Second {
				break
			}
		} else {
			idleSince = time.Time{}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if bMsg == "" {
		bMsg = "the client of B saw no end within the window"
	}
	for _, t := range []*track{tA, tB} {
		rep("E10", "INFO", "%s: SYN_SENT sockets seen from %v to %v after the CONNECT, %d separate dial attempts, at most %d at once", t.name, t.first.Round(100*time.Millisecond), t.last.Round(100*time.Millisecond), t.appearances, t.maxConcurrent)
	}
	rep("E10", "INFO", "%s", bMsg)
	outlive := tA.last - closedAt
	if outlive < 0 {
		outlive = 0
	}
	st := "PASS"
	if outlive > 17*time.Second {
		st = "FAIL"
	}
	rep("E10", st, "after its client closed at %v the dial of A went on for %v more (spec 5.5: at most 16 s); attempts %d", closedAt.Round(100*time.Millisecond), outlive.Round(100*time.Millisecond), tA.appearances)
	var lines []string
	for _, l := range strings.Split(i.proc.out.String(), "\n") {
		if strings.Contains(l, "dial") || strings.Contains(l, "timeout") || strings.Contains(l, "failed to open") {
			lines = append(lines, oneLine(l, 200))
			if len(lines) >= 5 {
				break
			}
		}
	}
	rep("E10", "INFO", "log lines about the dial: %s", strings.Join(lines, " || "))
}
