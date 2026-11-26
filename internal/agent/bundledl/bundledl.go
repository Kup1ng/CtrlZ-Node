// Package bundledl is how the agent downloads a node bundle for an upgrade
// (p4-nodes 7.1, T-359).
//
// The agent only downloads and verifies; it has no install right (R16), and the
// owner's root-owned `ctrlz-node upgrade` verifies again before anything is
// installed. What this package settles is where the bytes may come from and where
// they may go:
//
//   - From the hub alone, through FetchBundle on the node's own mutual-TLS
//     connection. There is no HTTP client in this package (TestNoHTTPClient), so a
//     URL, a redirect or a mirror cannot be followed, and a name that is not a
//     plain relative path inside the bundle is refused before a request is made.
//   - Into /var/lib/ctrlz/bundles/node/<version> alone, through os.Root, staged in
//     a directory of its own and renamed into place only after the manifest verified
//     against the trusted root and every listed file matched its size and SHA-256.
//     Nothing the hub names decides a local path: the names come from the signed
//     manifest and have passed manifest.CheckPath.
package bundledl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
	"github.com/Kup1ng/CtrlZ-Node/internal/verify"
)

// DefaultDir is where the root-owned upgrade reads a downloaded bundle from.
const DefaultDir = "/var/lib/ctrlz/bundles"

// IdleTimeout is how long one FetchBundle stream may go without a chunk.
const IdleTimeout = 30 * time.Second

// maxManifest bounds manifest.json, the one file whose size no manifest states.
const maxManifest = 8 << 20

var (
	// ErrOutsideHub is a URL, an absolute or a network path: anything that is not a
	// name inside the bundle the hub serves.
	ErrOutsideHub = errors.New("bundledl: a bundle is fetched from the hub by a relative name only")
	// ErrTooBig is a file that grows past the size its manifest lists.
	ErrTooBig = errors.New("bundledl: the hub sent more than the listed size")
)

// Hub is the one call of the node's hub client the downloader uses.
type Hub interface {
	FetchBundle(ctx context.Context, in *hubv1.FetchBundleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[hubv1.BlobChunk], error)
}

// Config is what a Downloader needs.
type Config struct {
	// Hub returns the current transfer client, so a replaced connection is used.
	Hub func() Hub
	// Root is the root of trust, as for heads and pushes.
	Root func() (*signv1.Root, error)
	// Dir is the bundles directory, DefaultDir in production.
	Dir string
	// Installed is the highest node version installed (0 when unknown), for the
	// rollback check of SC 13.
	Installed func() uint64
	// Now is the hub-corrected clock in Unix seconds; nil means the host clock.
	Now func() int64
	// Idle replaces IdleTimeout, for tests.
	Idle time.Duration
}

// Downloader downloads node bundles.
type Downloader struct{ cfg Config }

// New returns a Downloader.
func New(cfg Config) *Downloader {
	if cfg.Dir == "" {
		cfg.Dir = DefaultDir
	}
	if cfg.Idle == 0 {
		cfg.Idle = IdleTimeout
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.Installed == nil {
		cfg.Installed = func() uint64 { return 0 }
	}
	return &Downloader{cfg: cfg}
}

// CheckRef refuses what is not a relative name inside the bundle. A URL has a colon
// or starts with slashes, which manifest.CheckPath refuses too, but the answer here
// says why, so an operator or a test can tell a URL from a name with "..".
func CheckRef(ref string) error {
	if strings.Contains(ref, ":") || strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, `\`) {
		return ErrOutsideHub
	}
	if err := manifest.CheckPath(ref); err != nil {
		return fmt.Errorf("bundledl: %w", err)
	}
	return nil
}

// Dest is the directory a downloaded bundle of the version ends in.
func (d *Downloader) Dest(version uint64) string {
	return filepath.Join(d.cfg.Dir, "node", strconv.FormatUint(version, 10))
}

// Download fetches the node bundle of the version, verifies it and leaves it in
// Dest(version). A failure leaves nothing there: the staging directory is removed.
func (d *Downloader) Download(ctx context.Context, version uint64) (*signv1.Manifest, error) {
	if version == 0 {
		return nil, errors.New("bundledl: a version is required")
	}
	parent := filepath.Join(d.cfg.Dir, "node")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("bundledl: %w", err)
	}
	stage := filepath.Join(parent, "."+strconv.FormatUint(version, 10)+".part")
	if err := os.RemoveAll(stage); err != nil {
		return nil, fmt.Errorf("bundledl: %w", err)
	}
	if err := os.Mkdir(stage, 0o755); err != nil {
		return nil, fmt.Errorf("bundledl: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(stage)
		}
	}()
	root, err := os.OpenRoot(stage)
	if err != nil {
		return nil, fmt.Errorf("bundledl: %w", err)
	}
	defer root.Close()

	if err := d.fetchTo(ctx, root, version, bundle.ManifestFile, maxManifest); err != nil {
		return nil, err
	}
	m, err := d.verifyManifest(stage, version)
	if err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		if err := d.fetchTo(ctx, root, version, f.Path, int64(f.Size)); err != nil {
			return nil, err
		}
	}
	// Every listed file, of the listed size and hash, and nothing else in the tree.
	if err := verify.Dir(m, stage); err != nil {
		return nil, fmt.Errorf("bundledl: the downloaded bundle does not match its manifest: %w", err)
	}
	root.Close() // an open handle on the directory would stop the rename on some hosts
	dest := d.Dest(version)
	if err := os.RemoveAll(dest); err != nil {
		return nil, fmt.Errorf("bundledl: %w", err)
	}
	if err := os.Rename(stage, dest); err != nil {
		return nil, fmt.Errorf("bundledl: %w", err)
	}
	ok = true
	return m, nil
}

// verifyManifest checks the manifest the hub sent against the trusted root and
// freshness, and that it is the version asked for. The hub is not trusted to say
// which version it is serving.
func (d *Downloader) verifyManifest(stage string, version uint64) (*signv1.Manifest, error) {
	env, err := bundle.ReadEnvelope(filepath.Join(stage, bundle.ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("bundledl: the manifest does not read: %w", err)
	}
	trust, err := d.cfg.Root()
	if err != nil {
		return nil, fmt.Errorf("bundledl: no trusted root: %w", err)
	}
	now := d.cfg.Now()
	m, err := manifest.VerifyManifest(env, trust, signv1.Kind_KIND_NODE, now)
	if err != nil {
		return nil, fmt.Errorf("bundledl: the manifest is not signed by the root: %w", err)
	}
	if err := manifest.CheckManifestFresh(m, now, d.cfg.Installed()); err != nil {
		return nil, fmt.Errorf("bundledl: %w", err)
	}
	if m.Version != version {
		return nil, errors.New("bundledl: the manifest is of another version than the one asked")
	}
	var total uint64
	for _, f := range m.Files {
		if total += f.Size; total > verify.MaxBundleTotal {
			return nil, errors.New("bundledl: the listed sizes are over the cap")
		}
	}
	return m, nil
}

// fetchTo streams one named file into the staging root, at most limit bytes.
func (d *Downloader) fetchTo(ctx context.Context, root *os.Root, version uint64, name string, limit int64) error {
	if err := CheckRef(name); err != nil {
		return err
	}
	if dir := filepath.Dir(filepath.FromSlash(name)); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("bundledl: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(d.cfg.Idle, cancel)
	defer idle.Stop()

	st, err := d.cfg.Hub().FetchBundle(ctx, &hubv1.FetchBundleRequest{Kind: signv1.Kind_KIND_NODE, Version: version, Path: name})
	if err != nil {
		return fmt.Errorf("bundledl: the hub would not serve a file: %w", err)
	}
	f, err := root.OpenFile(filepath.FromSlash(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("bundledl: %w", err)
	}
	defer f.Close()
	var off int64
	for {
		ch, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("bundledl: the transfer broke: %w", err)
		}
		if int64(ch.Offset) != off {
			return errors.New("bundledl: a chunk at an unexpected offset")
		}
		// Only data counts as progress: a hub that sends empty chunks forever must
		// not keep the idle timer alive, so an empty chunk that ends nothing is refused.
		if len(ch.Data) == 0 && !ch.Last {
			return errors.New("bundledl: an empty chunk that is not the last")
		}
		idle.Reset(d.cfg.Idle)
		if off+int64(len(ch.Data)) > limit {
			return ErrTooBig
		}
		if _, err := f.Write(ch.Data); err != nil {
			return fmt.Errorf("bundledl: %w", err)
		}
		off += int64(len(ch.Data))
		if ch.Last {
			break
		}
	}
	return f.Close()
}
