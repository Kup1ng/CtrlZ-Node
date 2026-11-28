// Package xrayrun is `ctrlz-node xray-run <slot>`: the launcher that the units
// ctrlz-xray@a and ctrlz-xray@b run before Xray (p4b-proxy 7.6). It also holds the
// paths that the Xray manager, ctrlz-xrayctl and the launcher must agree on, so the
// three cannot name one file differently.
package xrayrun

import (
	"path"
	"regexp"
)

// Layout is where the files of the Xray slots live. The zero value is not usable:
// use DefaultLayout.
type Layout struct {
	// Etc is /etc/ctrlz. The unit sees an empty tmpfs there but for the slot's two
	// files and versions/xray.allow (7.6).
	Etc string
	// Lib is the root-owned directory of the installed binaries, one directory a
	// release (7.7 step 3).
	Lib string
	// Run is the prefix of the slots' run directories: the slot a lives in Run+"-a", so
	// /run/ctrlz-xray-a (p4b-proxy 3.3), a directory of its own that tmpfiles makes 0700
	// for ctrlz-xray. The slot's unit and ctrlz-xrayctl both run as that account, so the
	// agent never touches it.
	Run string
}

// DefaultLayout is the production layout.
func DefaultLayout() Layout {
	return Layout{Etc: "/etc/ctrlz", Lib: "/usr/local/lib/ctrlz/xray", Run: "/run/ctrlz-xray"}
}

// ValidSlot reports whether s is a slot name. Everything that builds a path from a
// slot checks this first, because the name comes from a socket frame or an
// argument.
func ValidSlot(s string) bool { return s == "a" || s == "b" }

var releaseRE = regexp.MustCompile(`^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

// ValidVersion reports whether v is a release tag in the form of 7.1.
func ValidVersion(v string) bool { return releaseRE.MatchString(v) }

// SlotJSON is the configuration the slot starts from.
func (l Layout) SlotJSON(slot string) string { return path.Join(l.Etc, "xray", slot+".json") }

// SlotVersion names the release the slot runs.
func (l Layout) SlotVersion(slot string) string {
	return path.Join(l.Etc, "xray", slot+".version")
}

// Allow is the file of releases that may run (7.7 step 3), one tag a line.
func (l Layout) Allow() string { return path.Join(l.Etc, "versions", "xray.allow") }

// Candidate is `xray.candidate`, which the upgrade command writes (7.7 step 4).
func (l Layout) Candidate() string { return path.Join(l.Etc, "versions", "xray.candidate") }

// Failed is `xray.failed`, written by the upgrade command (7.7 step 3).
func (l Layout) Failed() string { return path.Join(l.Etc, "versions", "xray.failed") }

// APIDir is the slot's run directory, /run/ctrlz-xray-<slot> (3.3).
func (l Layout) APIDir(slot string) string { return l.Run + "-" + slot }

// APISock is the slot's API socket, and APILock the lock beside it: the two files
// that an Xray that was killed leaves behind (B0 E11).
func (l Layout) APISock(slot string) string { return path.Join(l.APIDir(slot), "api.sock") }

// APILock is the flock file of the API socket.
func (l Layout) APILock(slot string) string { return path.Join(l.APIDir(slot), "api.sock.lock") }

// Binary is the installed binary of a release.
func (l Layout) Binary(version string) string { return path.Join(l.Lib, version, "xray") }
