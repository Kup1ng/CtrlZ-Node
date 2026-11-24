// Package upgrade is `sudo ctrlz-node upgrade <version>`: the root one-shot that
// installs a node bundle the agent has downloaded (p4-nodes 7.1).
//
// The agent only downloads a bundle by FetchBundle into /var/lib/ctrlz/bundles and
// verifies it; it has no install right of any kind (R16). So nothing the agent
// wrote is trusted here:
//
//  1. The manifest is copied into a root-owned directory and verified there by the
//     root-owned ctrlz-verify, against the root-owned root.json and the highest
//     version installed (/etc/ctrlz/versions/node), never the agent's keys/. A
//     version that is not above the installed one is refused, and so is a manifest
//     for another version than the one asked for.
//  2. Only the files that manifest lists are copied, each at most its listed size
//     and only if it is a regular file, so a symlink, a device or a file that grows
//     cannot make root read or write anything else. Files the manifest does not list
//     are never copied.
//  3. ctrlz-verify checks the whole copy again, and apply.sh from the copy installs
//     it, as 4.2 step 2 does for a first install.
//
// Merge C wires Run into the ctrlz-node binary as the subcommand `upgrade`.
package upgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
	"github.com/Kup1ng/CtrlZ-Node/internal/verify"
)

// Production paths (p4-nodes 7.1, 7.2).
const (
	DefaultBundles = "/var/lib/ctrlz/bundles"
	DefaultVersion = "/etc/ctrlz/versions/node"
	DefaultRoot    = "/etc/ctrlz/root.json"
	DefaultVerify  = "/usr/local/sbin/ctrlz-verify"
	DefaultStage   = "/var/lib"
	// maxTotal bounds one bundle copy; ctrlz-verify refuses a manifest above it too.
	maxTotal = verify.MaxBundleTotal
)

// Runner runs a command with the given streams. A test replaces it.
type Runner interface {
	Run(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) error
}

// ExecRunner runs real commands, with no shell and a fixed PATH.
type ExecRunner struct{}

// killDelay is how long a command gets to finish its own cleanup after the TERM that
// a cancelled context sends it, before it is killed.
const killDelay = 10 * time.Minute

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	// A cancelled context (the operator pressed Ctrl-C or the SSH session dropped) asks
	// the command to stop with TERM, and does not kill it: apply.sh restarts the units it
	// stopped from its exit trap, and a SIGKILL would skip that (p4n-W5c-r6-2).
	c.Cancel = func() error { return c.Process.Signal(syscall.SIGTERM) }
	c.WaitDelay = killDelay
	c.Stdout, c.Stderr = stdout, stderr
	c.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	return c.Run()
}

// Env is where things are; Default fills the production paths.
type Env struct {
	// Bundles is the agent's download directory; the bundle is Bundles/node/<version>.
	Bundles string
	// VersionFile, RootJSON and Verify are root-owned.
	VersionFile, RootJSON, Verify string
	// StageParent is a root-owned directory in which the staging directory is made.
	StageParent string
	Runner      Runner
	Geteuid     func() int
	Stdout      io.Writer
	Stderr      io.Writer
}

// Default is the production environment.
func Default() Env {
	return Env{
		Bundles: DefaultBundles, VersionFile: DefaultVersion, RootJSON: DefaultRoot, Verify: DefaultVerify,
		StageParent: DefaultStage, Runner: ExecRunner{}, Geteuid: os.Geteuid, Stdout: os.Stdout, Stderr: os.Stderr,
	}
}

// Run is the subcommand: ctrlz-node upgrade <version>. It returns the exit code.
func Run(args []string) int { return Default().MainSignals(args) }

// MainSignals is Main with HUP, INT and TERM turned into a cancelled context instead of
// the default death of the process. The upgrade copies a whole bundle into a staging
// directory and runs apply.sh, whose exit trap restarts the units it stopped: an
// operator's Ctrl-C or a dropped SSH session must end the run through that path, with
// the staging directory removed, and not leave 2 GiB in /var/lib behind (p4n-W5c-r6-2).
func (e Env) MainSignals(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return e.Main(ctx, args)
}

// Main parses the arguments and runs Do.
func (e Env) Main(ctx context.Context, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(e.Stderr, "usage: ctrlz-node upgrade <version>")
		return 2
	}
	v, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil || v == 0 || args[0] != strconv.FormatUint(v, 10) {
		fmt.Fprintln(e.Stderr, "ctrlz-node upgrade: the version is a number")
		return 2
	}
	if err := e.Do(ctx, v); err != nil {
		fmt.Fprintf(e.Stderr, "ctrlz-node upgrade: %v\n", err)
		return 1
	}
	return 0
}

// ErrNotRoot is returned when the one-shot is not run by root: it would then
// change nothing, and a half-run that looks like a success is worse than a refusal.
var ErrNotRoot = errors.New("must run as root")

// Installed reads the highest installed version. A host with none has no install
// to upgrade.
func (e Env) Installed() (uint64, error) {
	b, err := os.ReadFile(e.VersionFile)
	if err != nil {
		return 0, errors.New("no installed version found; this host was not installed by node.sh")
	}
	s := strings.TrimSpace(string(b))
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("the installed version file is not a number")
	}
	return v, nil
}

// Do upgrades to the bundle of version v.
func (e Env) Do(ctx context.Context, v uint64) error {
	if e.Geteuid() != 0 {
		return ErrNotRoot
	}
	installed, err := e.Installed()
	if err != nil {
		return err
	}
	if v <= installed {
		return fmt.Errorf("version %d is not above the installed version %d", v, installed)
	}

	stage, err := os.MkdirTemp(e.StageParent, "ctrlz-upgrade-")
	if err != nil {
		return fmt.Errorf("staging directory: %w", err)
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return err
	}

	src, err := os.OpenRoot(filepath.Join(e.Bundles, "node", strconv.FormatUint(v, 10)))
	if err != nil {
		return errors.New("no downloaded bundle of that version")
	}
	defer src.Close()

	// 1. The manifest first, verified before any other byte is taken.
	manPath := filepath.Join(stage, bundle.ManifestFile)
	if err := copyBounded(src, bundle.ManifestFile, manPath, 8<<20); err != nil {
		return fmt.Errorf("the manifest: %w", err)
	}
	verifyArgs := []string{"--root", e.RootJSON, "--manifest", manPath, "--installed", strconv.FormatUint(installed, 10), "--above", "--version", strconv.FormatUint(v, 10)}
	var list strings.Builder
	if err := e.Runner.Run(ctx, &list, e.Stderr, e.Verify, append([]string{"list"}, verifyArgs...)...); err != nil {
		return errors.New("the manifest did not verify; nothing was installed")
	}

	// 2. Only the listed files, each at most its listed size. The sizes come from
	// the manifest the verifier just accepted; the verifier prints the paths, and
	// the sizes are read from the staged manifest here with the same shared code.
	m, err := loadManifest(manPath)
	if err != nil {
		return err
	}
	sizes := map[string]uint64{}
	for _, f := range m.Files {
		sizes[f.Path] = f.Size
	}
	var total uint64
	for _, p := range strings.Split(strings.TrimSpace(list.String()), "\n") {
		size, ok := sizes[p]
		if !ok {
			return errors.New("the verifier listed a path that the manifest does not hold")
		}
		if total += size; total > maxTotal {
			return errors.New("the bundle is over the size cap")
		}
		dst := filepath.Join(stage, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := copyBounded(src, p, dst, size); err != nil {
			return fmt.Errorf("copying a bundle file: %w", err)
		}
	}

	// 3. The whole copy, again, by the root-owned verifier; then the install.
	if err := e.Runner.Run(ctx, io.Discard, e.Stderr, e.Verify, append([]string{"check"}, append(verifyArgs, "--dir", stage)...)...); err != nil {
		return errors.New("the bundle did not verify; nothing was installed")
	}
	apply := filepath.Join(stage, "packaging", "install", "apply.sh")
	if err := e.Runner.Run(ctx, e.Stdout, e.Stderr, "sh", apply, "upgrade", "--stage", stage, "--version", strconv.FormatUint(v, 10)); err != nil {
		return errors.New("the install of the bundle failed; see the messages above")
	}
	return nil
}

func loadManifest(manPath string) (*signv1.Manifest, error) {
	env, err := bundle.ReadEnvelope(manPath)
	if err != nil {
		return nil, err
	}
	m := &signv1.Manifest{}
	// The payload was verified by the verifier a moment ago, against this same
	// staged file, which root alone can write.
	if err := proto.Unmarshal(env.Payload, m); err != nil {
		return nil, errors.New("the staged manifest does not decode")
	}
	if err := manifest.CheckManifest(m); err != nil {
		return nil, err
	}
	return m, nil
}

// copyBounded copies the regular file rel of src to dst (mode 0600, root), reading
// at most max bytes.
// A symlink, a directory or any other type is refused, and a file longer than max
// is refused instead of truncated.
func copyBounded(src *os.Root, rel, dst string, max uint64) error {
	if err := manifest.CheckPath(rel); err != nil {
		return err
	}
	// Open first, then look at the handle: a type check made on the path before the
	// open could be raced by the agent, which owns this directory.
	in, err := openRegular(src, rel)
	if err != nil {
		return errors.New("the file is missing or cannot be opened")
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return errors.New("the file cannot be inspected")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("the file is not a regular file")
	}
	if fi.Size() < 0 || uint64(fi.Size()) > max {
		return errors.New("the file is over its size")
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, int64(max)+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if uint64(n) > max {
		return errors.New("the file is over its size")
	}
	return nil
}
