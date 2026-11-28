package proxy

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/config"
)

// The paths of 2.1 and the cgroups of 5.4.
const (
	LinkPath  = "/run/ctrlz-link/proxy.sock"
	ServePath = "/run/ctrlz-block/serve.sock"

	cgUnit  = "/sys/fs/cgroup/system.slice/ctrlz-proxy.service/memory.stat"
	cgSlotA = "/sys/fs/cgroup/system.slice/system-ctrlz\\x2dxray.slice/ctrlz-xray@a.service/memory.stat"
	cgSlotB = "/sys/fs/cgroup/system.slice/system-ctrlz\\x2dxray.slice/ctrlz-xray@b.service/memory.stat"
)

// Run is the process of ctrlz-proxy. It binds nothing until dns has sent a config.
func Run(ctx context.Context, _ config.Config) error {
	return New(ProductionOptions()).Run(ctx)
}

// ProductionOptions are the real sockets of a node.
func ProductionOptions() Options {
	return Options{
		DialLink: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", LinkPath)
		},
		DialServe: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", ServePath)
		},
		DialTarget: func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{KeepAlive: -1}
			d.SetMultipathTCP(false)
			c, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				tuneSocks(c)
			}
			return c, err
		},
		Listen: func(addr string) (net.Listener, error) {
			var lc net.ListenConfig
			lc.SetMultipathTCP(false) // MPTCP off (5.2 step 1)
			return lc.Listen(context.Background(), "tcp", addr)
		},
		Sys:      NewSys(),
		MemUnit:  cgUnit,
		MemSlots: []string{cgSlotA, cgSlotB},
		Retry:    time.Second,
		Logf:     log.Printf,
	}
}
