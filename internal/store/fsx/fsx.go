// Package fsx writes files the way a node must: so that a power cut or a kill
// at any instant leaves either the whole old file or the whole new one, never a
// mix (T-074).
//
// The sequence is the classic one: a temporary file in the same directory (so
// the rename cannot cross a filesystem), write, fsync of the file, rename over
// the target, fsync of the directory. Each step is a named Step that a Writer's
// Hook sees before it runs. A test makes the hook fail at one step to prove the
// previous state is still loadable; the production hook is nil.
//
// A failure injected by the hook leaves the temporary file behind, because that
// is what a crash leaves. CleanTemps removes such files at the next start.
//
// Files that need a self-check (a bit flip on disk must not be read as valid)
// are sealed: magic, SHA-256 of the body, body. Seal and Unseal are here so the
// state, config and image files share one format of that kind.
package fsx

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Step is one stage of an atomic write, in the order they run.
type Step uint8

const (
	StepCreate  Step = iota + 1 // the temporary file is created
	StepWrite                   // its bytes are written
	StepSync                    // the file is fsynced
	StepRename                  // it is renamed over the target
	StepSyncDir                 // the directory is fsynced
)

func (s Step) String() string {
	switch s {
	case StepCreate:
		return "create"
	case StepWrite:
		return "write"
	case StepSync:
		return "sync"
	case StepRename:
		return "rename"
	case StepSyncDir:
		return "syncdir"
	}
	return "step?"
}

// Steps lists every step, for a test that fails each in turn.
func Steps() []Step { return []Step{StepCreate, StepWrite, StepSync, StepRename, StepSyncDir} }

// ErrInjected is what a test hook usually returns.
var ErrInjected = errors.New("fsx: injected failure")

// tempMarker is in the name of every temporary file, so CleanTemps never
// touches a real one.
const tempMarker = ".tmp-"

// Writer does atomic writes. The zero value is ready to use.
type Writer struct {
	// Hook, when set, is called before each step with the final path of the
	// write. A non-nil error stops the write there and is returned as is.
	Hook func(path string, s Step) error
}

func (w *Writer) step(path string, s Step) error {
	if w != nil && w.Hook != nil {
		return w.Hook(path, s)
	}
	return nil
}

// WriteFile replaces path with data, atomically, with the given mode. The mode
// is set on the temporary file before the rename, so the file is never visible
// with a looser one.
func (w *Writer) WriteFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := w.step(path, StepCreate); err != nil {
		return err
	}
	tmp, err := createTemp(dir, filepath.Base(path))
	if err != nil {
		return err
	}
	name := tmp.Name()
	// fail removes the temporary file after a real failure. A hook failure
	// returns without it, as a crash would.
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := w.step(path, StepWrite); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		return fail(err)
	}
	if err := w.step(path, StepSync); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := w.step(path, StepRename); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	if err := w.step(path, StepSyncDir); err != nil {
		return err
	}
	return SyncDir(dir)
}

// RenameFile moves a finished file to its final name, durably. It is the
// promotion step for a file that was written and synced under another name.
func (w *Writer) RenameFile(from, to string) error {
	if err := w.step(to, StepRename); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil {
		return err
	}
	if err := w.step(to, StepSyncDir); err != nil {
		return err
	}
	if err := SyncDir(filepath.Dir(to)); err != nil {
		return err
	}
	if filepath.Dir(from) != filepath.Dir(to) {
		return SyncDir(filepath.Dir(from))
	}
	return nil
}

// RenameDir moves a finished directory to its final name and makes the move
// durable. The files inside must already be synced (WriteFile does that); a
// directory built from them is complete the moment it has its final name.
func (w *Writer) RenameDir(from, to string) error {
	if err := w.step(to, StepRename); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil {
		return err
	}
	if err := w.step(to, StepSyncDir); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(to))
}

// ReplaceSymlink points link at target, atomically: a new symlink under a
// temporary name is renamed over the old one, so a reader that resolves link
// sees the old target or the new one and never a missing link.
func (w *Writer) ReplaceSymlink(link, target string) error {
	dir := filepath.Dir(link)
	if err := w.step(link, StepCreate); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(link)+tempMarker+randSuffix())
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := w.step(link, StepRename); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := w.step(link, StepSyncDir); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so a rename or a create inside it survives a power
// cut. Windows cannot open a directory for this and its filesystem gives the
// guarantee another way, so there it does nothing: the node runs on Linux only
// and this keeps development builds working.
func SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// CleanTemps removes the temporary files and directories that interrupted
// writes left under dir (not below its subdirectories unless recurse is set).
// It returns how many it removed. Call it at start, before anything reads.
func CleanTemps(dir string, recurse bool) (int, error) {
	n := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), tempMarker) {
			if err := os.RemoveAll(p); err != nil {
				return n, err
			}
			n++
			continue
		}
		if recurse && e.IsDir() {
			m, err := CleanTemps(p, true)
			n += m
			if err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// TempDir returns a fresh temporary directory name next to final, which
// CleanTemps recognises. The caller creates it.
func TempDir(final string) string {
	return filepath.Join(filepath.Dir(final), "."+filepath.Base(final)+tempMarker+randSuffix())
}

func createTemp(dir, base string) (*os.File, error) {
	for i := 0; i < 8; i++ {
		name := filepath.Join(dir, "."+base+tempMarker+randSuffix())
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("fsx: cannot find a free temporary name")
}

func randSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on a working system; a fixed suffix only
		// risks a name clash, which createTemp retries and then reports.
		return "000000000000"
	}
	return hex.EncodeToString(b[:])
}

// ErrCorrupt is returned by Unseal for a file that is not what Seal made.
var ErrCorrupt = errors.New("fsx: sealed file is corrupt")

// Seal frames body as magic (4 bytes), SHA-256 of the body, body.
func Seal(magic string, body []byte) []byte {
	if len(magic) != 4 {
		panic("fsx: magic must be 4 bytes")
	}
	sum := sha256.Sum256(body)
	out := make([]byte, 0, 4+32+len(body))
	out = append(out, magic...)
	out = append(out, sum[:]...)
	return append(out, body...)
}

// Unseal checks the frame Seal made and returns the body, which aliases data.
func Unseal(magic string, data []byte) ([]byte, error) {
	if len(data) < 36 || string(data[:4]) != magic {
		return nil, fmt.Errorf("%w: bad frame", ErrCorrupt)
	}
	body := data[36:]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], data[4:36]) {
		return nil, fmt.Errorf("%w: checksum", ErrCorrupt)
	}
	return body, nil
}

// KeepSetgid returns fs.ModeSetgid when the directory at path has the setgid bit
// and 0 otherwise. A chmod that sets only permission bits clears setgid, and the
// install script relies on that bit to give every file and directory the agent
// creates under the group-shared directories the group ctrlz, which is how dns
// can read them.
func KeepSetgid(path string) fs.FileMode {
	if st, err := os.Stat(path); err == nil {
		return st.Mode() & fs.ModeSetgid
	}
	return 0
}
