// Package store is the node's directory under /var/lib/ctrlz (Plan T-074,
// spec p4-nodes 7.2): where the applied state, the stored log, the
// content-addressed blobs, the quarantine, the serving image, the persisted
// push, the keys and the two generations of NodeConfig live, and how each is
// written.
//
// Persistence is why a node answers correctly after a reboot with the panel
// unreachable, so every write that matters goes through fsx (temporary file,
// fsync, rename, fsync of the directory) and every read of a file the node
// wrote earlier checks it before use.
//
// What lives where, and who may read it (the install script gives the root its
// group `ctrlz`, which holds only the dns and agent users; this package sets
// only the mode bits):
//
//	state/       agent only  0700  applied state (state.bin)
//	log/         agent only  0700  stored entries, exact bytes
//	blobs/       group read  0750  content-addressed profile and block page blobs, files 0640
//	quarantine/  agent only  0700  set-aside bytes (SC 9.7), and incoming/ for blobs being fetched
//	image/       group read  0750  serving images, current -> <seq>
//	push/        agent only  0700  the persisted push, flag map, highest version used
//	keys/        agent only  0700  node key (0600), certificates, root.json (W3 writes these)
//	config/      group read  0750  NodeConfig generations, proof_key zeroed
//
// dns reads image/, blobs/ and config/ and nothing else. The agent hands it the
// zone table in use over the socket (7.1), so push/ has no reader but the agent.
//
// What is never written anywhere in this tree: the DNS cookie secret (SC 8a.3)
// and the real proof_key (7.2). The first is not handled here at all; the second
// is zeroed by nodecfg before it reaches a file. A test walks the whole root
// after a full cycle and searches every file for both.
package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
)

// Subdirectories of the root.
const (
	DirState      = "state"
	DirLog        = "log"
	DirBlobs      = "blobs"
	DirQuarantine = "quarantine"
	DirImage      = "image"
	DirPush       = "push"
	DirKeys       = "keys"
	DirConfig     = "config"
)

// File modes. Files dns reads are group-readable; everything else is the
// agent's alone.
const (
	ModeShared  fs.FileMode = 0o640
	ModePrivate fs.FileMode = 0o600
)

// layout lists the directories and their modes. The root itself is 0750 so the
// group can traverse it to image/, blobs/ and config/.
var layout = []struct {
	name string
	mode fs.FileMode
}{
	{"", 0o750},
	{DirState, 0o700},
	{DirLog, 0o700},
	{DirBlobs, 0o750},
	{DirQuarantine, 0o700},
	{DirImage, 0o750},
	{DirPush, 0o700},
	{DirKeys, 0o700},
	{DirConfig, 0o750},
}

// Root is an opened store directory.
type Root struct {
	dir string
	// W does every atomic write. A test installs a hook on it; production
	// leaves it empty.
	W *fsx.Writer
}

// Open creates the layout under dir when it is missing, fixes the modes of what
// exists, and removes the temporary files that an interrupted write left. It is
// what the agent calls at start. A nil w is a plain writer.
func Open(dir string, w *fsx.Writer) (*Root, error) {
	if dir == "" {
		return nil, errors.New("store: empty root directory")
	}
	if w == nil {
		w = &fsx.Writer{}
	}
	r := &Root{dir: dir, W: w}
	for _, l := range layout {
		p := filepath.Join(dir, l.name)
		if err := os.MkdirAll(p, l.mode); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", l.name, err)
		}
		// MkdirAll honours the umask, and a directory made by an older run may
		// have another mode. The modes are part of the design, so set them.
		// The install script gives the group-shared directories group ctrlz and setgid,
		// so the files and image directories made later inherit the group. chmod(2)
		// with plain permission bits clears setgid, so the bit is read first and kept.
		if err := os.Chmod(p, l.mode|fsx.KeepSetgid(p)); err != nil {
			return nil, fmt.Errorf("store: chmod %s: %w", l.name, err)
		}
	}
	if _, err := fsx.CleanTemps(dir, true); err != nil {
		return nil, fmt.Errorf("store: clean temporary files: %w", err)
	}
	// Blobs fetched by an Apply that was cut short are of no use: the next
	// Apply fetches again, and a blob is only promoted after the state names it.
	if err := os.RemoveAll(r.IncomingDir()); err != nil {
		return nil, fmt.Errorf("store: clear incoming: %w", err)
	}
	if err := os.MkdirAll(r.IncomingDir(), 0o700); err != nil {
		return nil, fmt.Errorf("store: create incoming: %w", err)
	}
	return r, nil
}

// Dir is the root directory.
func (r *Root) Dir() string { return r.dir }

// Path joins elements under the root.
func (r *Root) Path(elem ...string) string {
	return filepath.Join(append([]string{r.dir}, elem...)...)
}

// IncomingDir is where fetched blobs wait until the state that names them is
// committed. It sits under quarantine/ so dns cannot read it.
func (r *Root) IncomingDir() string { return r.Path(DirQuarantine, "incoming") }

// KeyPath is where a file of keys/ is. W3 writes the node key, the certificate,
// node_ca.pem, the hub key pin, the sealed zone keys, root.json and the highest
// manifest versions there; this package owns only the layout and the modes.
func (r *Root) KeyPath(name string) string { return r.Path(DirKeys, name) }

// WriteKey writes a file of keys/ atomically with mode 0600: everything in that
// directory is the agent's alone, the node key above all (7.2), and dns never
// reads it. name must be a plain file name.
func (r *Root) WriteKey(name string, data []byte) error {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("store: %q is not a plain file name", name)
	}
	return r.W.WriteFile(r.KeyPath(name), data, ModePrivate)
}
