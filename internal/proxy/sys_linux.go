//go:build linux

package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// linuxSys reads the kernel's view of a socket: TCP_INFO for the bytes it carried,
// SIOCINQ for what waits in it, and memory.stat for the cgroup's socket memory.
type linuxSys struct{}

// NewSys is the production Sys.
func NewSys() Sys { return linuxSys{} }

func tcpFD(c net.Conn, f func(fd int)) bool {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return false
	}
	return raw.Control(func(fd uintptr) { f(int(fd)) }) == nil
}

func (linuxSys) Moved(c net.Conn) (uint64, bool) {
	var n uint64
	var good bool
	ok := tcpFD(c, func(fd int) {
		ti, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil {
			n, good = ti.Bytes_acked+ti.Bytes_received, true
		}
	})
	return n, ok && good
}

func (linuxSys) Waiting(c net.Conn) (int, bool) {
	var n int
	var good bool
	ok := tcpFD(c, func(fd int) {
		v, err := unix.IoctlGetInt(fd, unix.SIOCINQ)
		if err == nil {
			n, good = v, true
		}
	})
	return n, ok && good
}

func (linuxSys) SockMem(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := bytes.Fields(sc.Bytes())
		if len(f) == 2 && string(f[0]) == "sock" {
			return strconv.ParseUint(string(f[1]), 10, 64)
		}
	}
	return 0, errors.New("proxy: no sock line in memory.stat")
}

// tuneClient sets TCP_USER_TIMEOUT 60 s on an accepted socket (5.4): a peer that
// stops acknowledging cannot hold its buffers longer.
func tuneClient(c net.Conn) { setUserTimeout(c) }

// tuneSocks sets it on the SOCKS leg too, with 128 KiB buffers.
func tuneSocks(c net.Conn) {
	setUserTimeout(c)
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(128 << 10)
		_ = tc.SetWriteBuffer(128 << 10)
	}
}

func setUserTimeout(c net.Conn) {
	tcpFD(c, func(fd int) {
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, 60_000)
	})
}
