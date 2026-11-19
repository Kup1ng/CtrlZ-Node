// Package store persists node state on local disk: the config log, profile
// blobs and global tables (content-addressed), the quarantine directory, and
// the encrypted certificate keys. Persistence is why a node answers correctly
// after a reboot with the panel unreachable.
package store

import "github.com/Kup1ng/CtrlZ-Shared/quarantine"

// Snapshot is the in-memory form of the persisted state. The apply transaction
// and its rules are shared code; this package only saves and loads it.
type Snapshot struct {
	State *quarantine.State
}

// Open loads state from dir. Stub: returns an empty state.
func Open(dir string) (*Snapshot, error) {
	return &Snapshot{State: quarantine.NewState()}, nil
}
