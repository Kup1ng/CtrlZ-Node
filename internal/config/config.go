// Package config holds what a node role needs to start: where its state lives
// and which addresses it binds.
//
// It deliberately does not read the panel's NodeConfig. That arrives over the
// hub stream and is applied by the agent; the values here are the few the node
// must know before it can reach the panel at all (state directory, enrolment
// result), and they live on local disk so a reboot with the panel down still
// starts the node (Plan: the node answers from its own disk).
package config

import "errors"

// ErrNotImplemented marks a stubbed role. main turns it into a distinct exit
// code so a half-built binary is never mistaken for a crash.
var ErrNotImplemented = errors.New("not implemented")

// Config is the local, pre-panel configuration of a node role.
type Config struct {
	// StateDir holds the config log, profile blobs, tables, quarantined blobs
	// and the encrypted certificate keys.
	StateDir string
}

// Load returns the configuration for this process. The stub returns defaults;
// the real loader (P4) reads /etc/ctrlz and validates paths.
func Load() Config {
	return Config{StateDir: "/var/lib/ctrlz"}
}
