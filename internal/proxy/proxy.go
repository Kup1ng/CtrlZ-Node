// Package proxy is the proxy role: ports 80 and 443 on PROXY_IP. It reads the
// SNI or Host, checks the Grant table, and splices bytes to Xray over a
// loopback SOCKS port.
//
// There is no global rule on a node. A connection is accepted only if a Grant
// written by a Redirect answer says this source may reach this exact name, so
// the node is never an open proxy (Plan, "Proxy and location"). The Grant
// contract is in the shared contract, section 10.4; the table itself lives in
// internal/grant.
package proxy

import "github.com/Kup1ng/CtrlZ-Node/internal/config"

// Run starts the proxy role. Stub.
func Run(cfg config.Config) error { return config.ErrNotImplemented }
