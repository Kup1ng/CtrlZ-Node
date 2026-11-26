// Package verify is the check behind ctrlz-verify: a node bundle's signed
// manifest against a root, and the bundle directory against the manifest
// (p4-nodes 4.2 step 2, 7.1).
//
// It runs before anything of the bundle is installed and it never runs the
// binary it is checking: ctrlz-verify is itself checked against a SHA-256 the
// release job wrote into node.sh. Every failure is a Failure whose Check names
// the step that failed and carries no file content, no file name and no byte of
// the manifest, so a hostile bundle cannot write into the admin's terminal.
package verify

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
	"github.com/Kup1ng/CtrlZ-Node/internal/labroot"
)

// Exit codes, one per class of failure, so node.sh and an operator can tell a
// wrong root from a tampered file without reading a message.
const (
	ExitOK       = 0
	ExitUsage    = 2
	ExitRoot     = 10 // root.json unreadable, malformed or expired (or its bundle grant), or a lab root in a production binary
	ExitManifest = 11 // signature, threshold, role grant, kind, a manifest that does not parse
	ExitFresh    = 12 // manifest expired, older than installed, not the version asked
	ExitFiles    = 13 // a file not listed, missing, of another size or hash, or not a regular file
)

// Failure is a failed check.
type Failure struct {
	Code int
	// Check is a fixed name of the step, safe to print.
	Check string
	// Err is the cause for tests and logs of the program itself; Error() hides it.
	Err error
}

func (f *Failure) Error() string { return "check failed: " + f.Check }

// Unwrap exposes the cause to errors.Is.
func (f *Failure) Unwrap() error { return f.Err }

func fail(code int, check string, err error) *Failure {
	return &Failure{Code: code, Check: check, Err: err}
}

// MaxBundleTotal bounds the listed sizes of one bundle together: a node bundle is tens
// of megabytes, and node.sh and the upgrade both make room on disk for what the
// manifest lists. One number for both paths, so a signed manifest that lists more is
// refused before a byte is fetched or copied.
const MaxBundleTotal = 2 << 30

// Options say what to check.
type Options struct {
	RootPath     string
	ManifestPath string
	// Installed is the highest node version already installed, 0 for a first
	// install. A manifest below it is a rollback (SC 13).
	Installed uint64
	// Above makes an equal version a failure too: an upgrade installs something new.
	Above bool
	// WantVersion, when not 0, is the version the caller asked for; the manifest
	// must carry exactly it, so a bundle directory cannot be passed off as another.
	WantVersion uint64
	// Now is the clock; zero means time.Now.
	Now int64
}

// Manifest loads the root and the manifest and checks them: the lab deny list,
// the signatures against the root's bundle grant, the kind, freshness and
// version. It checks no file.
func Manifest(o Options) (*signv1.Manifest, error) {
	root, err := bundle.ReadRoot(o.RootPath)
	if err != nil {
		return nil, fail(ExitRoot, "root-readable", err)
	}
	if err := labroot.Check(root); err != nil {
		return nil, fail(ExitRoot, "root-lab-key", err)
	}
	env, err := bundle.ReadEnvelope(o.ManifestPath)
	if err != nil {
		return nil, fail(ExitManifest, "manifest-readable", err)
	}
	now := o.Now
	if now == 0 {
		now = time.Now().Unix()
	}
	m, err := manifest.VerifyManifest(env, root, signv1.Kind_KIND_NODE, now)
	if err != nil {
		check := classifyManifest(err)
		return nil, fail(manifestCode(check), check, err)
	}
	if err := manifest.CheckManifestFresh(m, now, o.Installed); err != nil {
		return nil, fail(ExitFresh, classifyFresh(err), err)
	}
	if o.Above && m.Version <= o.Installed {
		return nil, fail(ExitFresh, "version-not-above-installed", manifest.ErrRollback)
	}
	if o.WantVersion != 0 && m.Version != o.WantVersion {
		return nil, fail(ExitFresh, "version-not-the-one-asked", errors.New("version differs"))
	}
	var total uint64
	for _, f := range m.Files {
		// Each size is at most MaxFileSize (CheckManifest), so the sum cannot wrap.
		if total += f.Size; total > MaxBundleTotal {
			return nil, fail(ExitManifest, "bundle-total-size", errors.New("listed sizes over the cap"))
		}
	}
	return m, nil
}

func classifyManifest(err error) string {
	switch {
	case errors.Is(err, manifest.ErrThreshold), errors.Is(err, manifest.ErrTooManySignatures):
		return "manifest-signatures"
	case errors.Is(err, manifest.ErrNoRole), errors.Is(err, manifest.ErrRoleMismatch):
		return "manifest-grant"
	case errors.Is(err, manifest.ErrRootExpired), errors.Is(err, manifest.ErrRoleExpired), errors.Is(err, manifest.ErrNoExpiry):
		return "root-expired"
	case errors.Is(err, manifest.ErrBadRoot):
		return "root-malformed"
	case errors.Is(err, manifest.ErrPayloadType), errors.Is(err, manifest.ErrKindMismatch):
		return "manifest-kind"
	}
	return "manifest-malformed"
}

func classifyFresh(err error) string {
	switch {
	case errors.Is(err, manifest.ErrManifestExpired):
		return "manifest-expired"
	case errors.Is(err, manifest.ErrRollback):
		return "version-below-installed"
	}
	return "manifest-malformed"
}

// Dir checks a bundle directory against a verified manifest: every entry of
// the directory is a regular file the manifest lists, of the listed size and
// SHA-256, and every listed file is there. The manifest file at the top is the
// one entry the manifest cannot list.
//
// The directory is opened as an os.Root, so a symlink cannot lead a read out of
// it, and symlinks are refused anyway (Index.CheckEntry wants regular files).
func Dir(m *signv1.Manifest, dir string) error {
	ix, err := manifest.NewIndex(m)
	if err != nil {
		return fail(ExitManifest, "manifest-malformed", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fail(ExitFiles, "bundle-dir", err)
	}
	defer root.Close()

	want := map[string]*signv1.FileEntry{}
	for _, f := range m.Files {
		want[f.Path] = f
	}
	seen := 0
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		if p == bundle.ManifestFile && want[p] == nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 {
			return errors.New("negative size")
		}
		if err := ix.CheckEntry(p, info.Mode(), uint64(info.Size())); err != nil {
			return fail(ExitFiles, classifyEntry(err), err)
		}
		if err := hashMatches(root, p, want[p]); err != nil {
			return err
		}
		seen++
		return nil
	})
	if err != nil {
		var f *Failure
		if errors.As(err, &f) {
			return f
		}
		return fail(ExitFiles, "bundle-walk", err)
	}
	if seen != len(want) {
		return fail(ExitFiles, "file-missing", errors.New("a listed file is absent"))
	}
	return nil
}

func classifyEntry(err error) string {
	switch {
	case errors.Is(err, manifest.ErrNotListed):
		return "file-not-listed"
	case errors.Is(err, manifest.ErrNotRegular):
		return "file-not-regular"
	case errors.Is(err, manifest.ErrSizeMismatch):
		return "file-size"
	}
	return "file-path"
}

func hashMatches(root *os.Root, p string, f *signv1.FileEntry) error {
	h, err := root.Open(p)
	if err != nil {
		return fail(ExitFiles, "file-open", err)
	}
	defer h.Close()
	sum := sha256.New()
	// One byte over the listed size, so a file that grew after the size check
	// fails here instead of hashing without bound.
	n, err := io.Copy(sum, io.LimitReader(h, int64(f.Size)+1))
	if err != nil {
		return fail(ExitFiles, "file-read", err)
	}
	if uint64(n) != f.Size {
		return fail(ExitFiles, "file-size", manifest.ErrSizeMismatch)
	}
	if subtle.ConstantTimeCompare(sum.Sum(nil), f.Sha256) != 1 {
		return fail(ExitFiles, "file-hash", fmt.Errorf("hash differs"))
	}
	return nil
}

// List is what `ctrlz-verify list` prints: the file paths of a verified manifest,
// each already past manifest.CheckPath, so a script can fetch them one by one.
func List(m *signv1.Manifest) []string {
	out := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		out = append(out, f.Path)
	}
	return out
}

// Listed is one entry of the manifest as `ctrlz-verify sizes` prints it.
type Listed struct {
	Size uint64
	Path string
}

// Sizes is List with the signed size of each file, so node.sh can bound every
// download by what the manifest says: a hostile hub under the pin cannot make the
// installer write more than the listed bytes of a file before ctrlz-verify check.
func Sizes(m *signv1.Manifest) []Listed {
	out := make([]Listed, 0, len(m.Files))
	for _, f := range m.Files {
		out = append(out, Listed{Size: f.Size, Path: f.Path})
	}
	return out
}

// manifestCode puts a root that is malformed or out of date under ExitRoot, next to
// the unreadable root: the runbook sends the admin to root.json for 10 and to the
// bundle for 11, but VerifyManifest reports both kinds of fault through one call.
func manifestCode(check string) int {
	if check == "root-malformed" || check == "root-expired" {
		return ExitRoot
	}
	return ExitManifest
}
