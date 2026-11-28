package xray

import (
	"context"
	"net"
	"net/netip"
)

// UnboundResolver asks the identified Unbound (ip:port) for the IPv4 addresses of a
// name, over TCP like Xray's own lookups. The remote sets of 5.5 need the addresses
// that Xray will dial, so the agent asks the same resolver and never the host's.
func UnboundResolver(addr string) func(ctx context.Context, host string) ([]netip.Addr, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		ips, err := r.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return nil, err
		}
		out := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			out = append(out, ip.Unmap())
		}
		return out, nil
	}
}
