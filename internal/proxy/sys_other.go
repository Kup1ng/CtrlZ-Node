//go:build !linux

package proxy

import (
	"errors"
	"net"
)

// Off Linux there is no TCP_INFO, SIOCINQ or cgroup: the proxy still runs for a
// development check, with no idle ending and no memory trimming.
type otherSys struct{}

// NewSys is the production Sys.
func NewSys() Sys { return otherSys{} }

func (otherSys) Moved(net.Conn) (uint64, bool)  { return 0, false }
func (otherSys) Waiting(net.Conn) (int, bool)   { return 0, false }
func (otherSys) SockMem(string) (uint64, error) { return 0, errors.New("proxy: no cgroup here") }

func tuneClient(net.Conn) {}
func tuneSocks(net.Conn)  {}
