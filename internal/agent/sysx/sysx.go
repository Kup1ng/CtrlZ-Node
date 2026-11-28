// Package sysx is the agent's only door to the host: commands (systemctl, nft,
// unbound-control, chrony) and the files it reads or writes outside the store.
//
// Why interfaces: the agent runs as an unprivileged user with narrow rights
// (CAP_NET_ADMIN for its nftables table, a polkit rule for a fixed set of units)
// and development is on Windows. Every other package takes a Runner or a Files
// and never calls os/exec itself, so a test checks the exact text and the exact
// command line with a fake, and a unit that must not run a command (the
// no-shell, no-apt rule of 7.1) has one place to be checked in.
package sysx

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// MaxOutput bounds what a command may hand back. unbound-control and systemctl
// print a few lines; more than this is a fault, not data to keep.
const MaxOutput = 1 << 20

// DefaultTimeout is the longest a command may run when the caller's context has
// no deadline of its own.
const DefaultTimeout = 30 * time.Second

// Runner runs one command. name is a program name or path with no shell around
// it: arguments are never joined into a string. stdin may be nil. The result is
// stdout; stderr is dropped, because a command's error text can hold an address
// or a name and the agent must not forward it (no trace, SC 5.2a).
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// Files is the file access of the agent outside the store's own atomic writer.
type Files interface {
	ReadFile(path string) ([]byte, error)
	// WriteFile writes data atomically (temporary file, rename) with mode.
	WriteFile(path string, data []byte, mode fs.FileMode) error
}

// ErrOutputTooLong is returned when a command printed more than MaxOutput.
var ErrOutputTooLong = errors.New("sysx: command output over the cap")

// ExecRunner runs real commands.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out capped
	cmd.Stdout = &out
	// stderr goes nowhere on purpose, see Runner.
	if err := cmd.Run(); err != nil {
		return out.b, err
	}
	if out.over {
		return out.b, ErrOutputTooLong
	}
	return out.b, nil
}

type capped struct {
	b    []byte
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := MaxOutput - len(c.b); len(p) > room {
		c.b = append(c.b, p[:room]...)
		c.over = true
		return len(p), nil
	}
	c.b = append(c.b, p...)
	return len(p), nil
}

// OSFiles is Files over the real file system.
type OSFiles struct{}

// ReadFile implements Files.
func (OSFiles) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteFile implements Files: the data goes to a temporary file in the same
// directory and is renamed over path, so a reader (Unbound, chrony, nft) never
// sees half a file.
func (OSFiles) WriteFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
