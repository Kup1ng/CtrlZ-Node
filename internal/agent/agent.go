// Package agent is the agent role: the node's side of the panel link. It holds
// the mTLS stream to the hub, applies config log entries, reports health, and
// manages Xray, Unbound, certificates and updates.
//
// Applying an entry is shared code (quarantine.Apply): one bad blob must never
// stop the stream, and that rule is encoded once for the node and the vectors.
// The agent supplies the Fetcher and persists the State.
package agent

import (
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"

	"github.com/Kup1ng/CtrlZ-Node/internal/config"
)

// Applier applies stored config entries.
type Applier struct {
	State *quarantine.State
	Fetch quarantine.Fetcher
}

// Apply applies one stored entry (exact bytes, as hashed into the chain).
func (a *Applier) Apply(stored []byte) quarantine.Report {
	return quarantine.Apply(a.State, stored, a.Fetch)
}

// Run starts the agent role. Stub.
func Run(cfg config.Config) error { return config.ErrNotImplemented }
