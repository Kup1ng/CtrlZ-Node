//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// exitInfo turns the end of a child into a code and, when a signal ended it, the signal's name.
func exitInfo(cmd *exec.Cmd, err error) (int, string) {
	st := cmd.ProcessState
	if st == nil {
		return -3, ""
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -1, ws.Signal().String()
	}
	return st.ExitCode(), ""
}

// fullListener is a TCP listener with a backlog of 0 whose accept queue is filled, so a further SYN to it is dropped and a
// dial stays in SYN_SENT. It needs no firewall rule and no privilege, which is why it stands in for a black-holed
// address in the dial-limit experiment.
type fullListener struct {
	fd    int
	port  int
	fills []net.Conn
}

func newFullListener() (*fullListener, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	sa := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Listen(fd, 0); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	got, err := syscall.Getsockname(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	l := &fullListener{fd: fd, port: got.(*syscall.SockaddrInet4).Port}
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", l.port), 700*time.Millisecond)
		if err != nil {
			// The queue is full: the next SYN is dropped.
			return l, nil
		}
		l.fills = append(l.fills, c)
	}
	l.close()
	return nil, fmt.Errorf("the accept queue of a backlog-0 listener never filled")
}

func (l *fullListener) close() {
	for _, c := range l.fills {
		c.Close()
	}
	syscall.Close(l.fd)
}

// synSentTo counts the sockets of this host that are in SYN_SENT towards 127.0.0.1:port, read from /proc/net/tcp.
func synSentTo(port int) int {
	b, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return -1
	}
	n := 0
	want := fmt.Sprintf(":%04X", port)
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		if f[3] == "02" && strings.HasSuffix(f[2], want) {
			n++
		}
	}
	return n
}

// procIO reads rchar, wchar, syscr and syscw of a process.
func procIO(pid int) map[string]int64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/io")
	if err != nil {
		return nil
	}
	m := map[string]int64{}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		m[k] = n
	}
	return m
}

// rssKB is the resident set of a process.
func rssKB(pid int) int64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				return n
			}
		}
	}
	return -1
}

const onLinux = true
