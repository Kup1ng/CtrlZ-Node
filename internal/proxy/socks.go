package proxy

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

// A minimal SOCKS5 client: no authentication, CONNECT only. The SOCKS inbounds are
// on loopback and reachable only by the accounts of the nftables rule socks_guard
// (5.5), so the method is the "no authentication required" one.

var errSocks = errors.New("proxy: socks refused")

// socksConnect speaks the handshake on c for the target host:port. host is a name
// (the exit resolves it) or an IP literal. The deadline bounds the whole exchange.
//
// Xray answers the CONNECT before its own dial to the exit has finished, so a
// success here says nothing about the target: the first byte does (5.2 step 6).
func socksConnect(c net.Conn, host string, port uint16, deadline time.Time) error {
	_ = c.SetDeadline(deadline)
	defer c.SetDeadline(time.Time{})

	// Greeting and request in one write: version 5, one method (none), then
	// CONNECT with the address.
	req := []byte{5, 1, 0, 5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			req = append(req, 1)
			req = append(req, a[:]...)
		} else {
			a := ip.As16()
			req = append(req, 4)
			req = append(req, a[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return errSocks
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var g [2]byte
	if _, err := io.ReadFull(c, g[:]); err != nil {
		return err
	}
	if g[0] != 5 || g[1] != 0 {
		return errSocks
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 5 || h[1] != 0 {
		return errSocks
	}
	// The bound address is read and thrown away.
	var skip int
	switch h[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return errSocks
	}
	_, err := io.CopyN(io.Discard, c, int64(skip))
	return err
}
