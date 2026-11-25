// Package grant is the Grant table of contract section 10.4: (source prefix,
// exact qname) -> (Endpoint, location, kind, dial host, expiry). Without a
// Grant a proxy connection is refused. A live Grant is never evicted to make
// room; the only exception is revocation for a hard-disabled or deleted
// Endpoint. Grants are never stored in the shared cache and never enter
// config_seq.
package grant

import "time"

// Grant is one entry.
type Grant struct {
	Endpoint  [16]byte
	Location  uint16
	Kind      uint8 // 1 redirect, 2 block page
	DialHost  []byte
	ExpiresAt time.Time
}
