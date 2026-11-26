// Package bundle builds and signs the node bundle and reads the files around it
// (p4-nodes 3.3, 7.1, SC 13).
//
// A node bundle is a directory:
//
//	manifest.json                       the signed Envelope (protojson), not listed in itself
//	bin/ctrlz-node, bin/ctrlz-verify    the binaries
//	packaging/...                       units, polkit rule, sysctl and account lists, install scripts
//	debs/*.deb                          unbound, dns-root-data, chrony and what a clean 24.04 lacks
//
// The release job calls Build, which writes everything and an unsigned manifest
// (an Envelope with no signature); the owner signs it offline. Build never signs
// and holds no key. Sign exists for dev and lab builds, whose test root is
// public by design (package labroot).
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
)

// File names and paths inside a bundle.
const (
	// ManifestFile is the signed manifest, at the bundle's root.
	ManifestFile = "manifest.json"
	// UnsignedSuffix is appended to the bundle directory's path to name the unsigned
	// manifest Build writes for the offline signer. It sits beside the bundle, not in
	// it: the bundle holds exactly what the signed manifest lists, plus manifest.json.
	UnsignedSuffix = ".manifest.unsigned.json"

	NodeBinary   = "bin/ctrlz-node"
	VerifyBinary = "bin/ctrlz-verify"
	NodeScript   = "packaging/install/node.sh"
	DebsDir      = "debs"

	// VerifyPlaceholder is replaced in node.sh by the SHA-256 of ctrlz-verify. It
	// must appear exactly once, so a second copy of the check cannot keep an old
	// value.
	VerifyPlaceholder = "@CTRLZ_VERIFY_SHA256@"
	// VersionPlaceholder is replaced in node.sh by the bundle version, so the script
	// fetches the bundle it was built with and no other.
	VersionPlaceholder = "@CTRLZ_BUNDLE_VERSION@"

	maxMarshalled = 8 << 20
)

// Options are the inputs of Build.
type Options struct {
	// Out is the bundle directory to create; it must not exist.
	Out string
	// Version and MinVersion are the manifest's. MinVersion is the lowest version an
	// automatic rollback may go back to (SC 13).
	Version, MinVersion  uint64
	CreatedAt, ExpiresAt int64
	Tag                  string
	// Packaging is the packaging/ directory of the repository.
	Packaging string
	// NodeBin and VerifyBin are the built binaries.
	NodeBin, VerifyBin string
	// Debs is the directory of .deb files the release job collected; may be empty
	// only in a test.
	Debs string
}

// Build writes the bundle directory and the unsigned manifest next to it (at
// UnsignedPath) and returns the manifest.
func Build(o Options) (*signv1.Manifest, error) {
	if o.Out == "" || o.Version == 0 || o.MinVersion > o.Version {
		return nil, errors.New("bundle: out, a version and a min_version not above it are required")
	}
	if _, err := os.Lstat(o.Out); err == nil {
		return nil, errors.New("bundle: the output directory exists")
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return nil, err
	}
	var entries []*signv1.FileEntry
	put := func(rel string, data []byte) error {
		if err := manifest.CheckPath(rel); err != nil {
			return fmt.Errorf("bundle: %s: %w", rel, err)
		}
		dst := filepath.Join(o.Out, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
		h := sha256.Sum256(data)
		entries = append(entries, &signv1.FileEntry{Path: rel, Sha256: h[:], Size: uint64(len(data))})
		return nil
	}

	verifyBytes, err := readRegular(o.VerifyBin)
	if err != nil {
		return nil, fmt.Errorf("bundle: ctrlz-verify: %w", err)
	}
	nodeBytes, err := readRegular(o.NodeBin)
	if err != nil {
		return nil, fmt.Errorf("bundle: ctrlz-node: %w", err)
	}
	if err := put(NodeBinary, nodeBytes); err != nil {
		return nil, err
	}
	if err := put(VerifyBinary, verifyBytes); err != nil {
		return nil, err
	}
	vsum := sha256.Sum256(verifyBytes)

	// Everything under packaging/, regular files only (a symlink in the tree would
	// put another file's bytes in the bundle under this name).
	var rels []string
	err = filepath.WalkDir(o.Packaging, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("bundle: %s is not a regular file", p)
		}
		rel, err := filepath.Rel(o.Packaging, p)
		if err != nil {
			return err
		}
		rels = append(rels, "packaging/"+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(rels)
	sawScript := false
	for _, rel := range rels {
		src := filepath.Join(o.Packaging, filepath.FromSlash(strings.TrimPrefix(rel, "packaging/")))
		b, err := readRegular(src)
		if err != nil {
			return nil, err
		}
		if rel == NodeScript {
			sawScript = true
			if b, err = Stamp(b, vsum, o.Version); err != nil {
				return nil, err
			}
		} else if bytes.Contains(b, []byte(VerifyPlaceholder)) || bytes.Contains(b, []byte(VersionPlaceholder)) {
			return nil, fmt.Errorf("bundle: %s holds the ctrlz-verify placeholder; only node.sh may", rel)
		}
		if err := put(rel, b); err != nil {
			return nil, err
		}
	}
	if !sawScript {
		return nil, errors.New("bundle: packaging/install/node.sh is missing")
	}

	if o.Debs != "" {
		des, err := os.ReadDir(o.Debs)
		if err != nil {
			return nil, err
		}
		for _, d := range des {
			if !strings.HasSuffix(d.Name(), ".deb") {
				continue
			}
			b, err := readRegular(filepath.Join(o.Debs, d.Name()))
			if err != nil {
				return nil, err
			}
			if err := put(path.Join(DebsDir, d.Name()), b); err != nil {
				return nil, err
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	m := &signv1.Manifest{
		Kind: signv1.Kind_KIND_NODE, Version: o.Version, CreatedAt: o.CreatedAt, ExpiresAt: o.ExpiresAt,
		MinVersion: o.MinVersion, Files: entries, Tag: o.Tag,
	}
	if err := manifest.CheckManifest(m); err != nil {
		return nil, err
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	unsigned := &signv1.Envelope{PayloadType: manifest.ManifestPayloadType(signv1.Kind_KIND_NODE), Payload: payload}
	raw, err := MarshalEnvelope(unsigned)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(UnsignedPath(o.Out), raw, 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

// Stamp writes the SHA-256 of ctrlz-verify and the bundle version into node.sh.
// Each placeholder must appear exactly once.
func Stamp(script []byte, verifySum [32]byte, version uint64) ([]byte, error) {
	for _, ph := range []string{VerifyPlaceholder, VersionPlaceholder} {
		if n := bytes.Count(script, []byte(ph)); n != 1 {
			return nil, fmt.Errorf("bundle: node.sh holds the placeholder %s %d times, want 1", ph, n)
		}
	}
	out := bytes.Replace(script, []byte(VerifyPlaceholder), []byte(hex.EncodeToString(verifySum[:])), 1)
	return bytes.Replace(out, []byte(VersionPlaceholder), []byte(strconv.FormatUint(version, 10)), 1), nil
}

func readRegular(p string) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if fi.Size() > manifest.MaxFileSize {
		return nil, fmt.Errorf("%s is over the file size cap", p)
	}
	return os.ReadFile(p)
}

// MarshalEnvelope encodes an Envelope as protojson, the form of manifest.json.
func MarshalEnvelope(e *signv1.Envelope) ([]byte, error) {
	b, err := protojson.MarshalOptions{Multiline: true}.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ReadEnvelope reads an Envelope file, capped at what a manifest may be.
func ReadEnvelope(p string) (*signv1.Envelope, error) {
	b, err := readCapped(p, maxMarshalled)
	if err != nil {
		return nil, err
	}
	e := &signv1.Envelope{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(b, e); err != nil {
		return nil, errors.New("bundle: the envelope does not decode")
	}
	return e, nil
}

// ReadRoot reads root.json (protojson Root).
func ReadRoot(p string) (*signv1.Root, error) {
	b, err := readCapped(p, 1<<20)
	if err != nil {
		return nil, err
	}
	r := &signv1.Root{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(b, r); err != nil {
		return nil, errors.New("bundle: root.json does not decode")
	}
	return r, nil
}

func readCapped(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("bundle: %s is over %d bytes", filepath.Base(p), limit)
	}
	return b, nil
}

// Sign appends one signature per key to e. It is for dev and lab builds: the
// production signing runs offline with the owner's root keys and never here.
func Sign(e *signv1.Envelope, keys ...ed25519.PrivateKey) {
	msg := manifest.SigningInput(e.PayloadType, e.Payload)
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		e.Signatures = append(e.Signatures, &signv1.Signature{KeyId: manifest.KeyID(pub), Sig: ed25519.Sign(k, msg)})
	}
}

// ReadSeed reads a hex Ed25519 seed file (the lab test keys) as a private key.
func ReadSeed(p string) (ed25519.PrivateKey, error) {
	b, err := readCapped(p, 4096)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("bundle: a seed file is 64 hex characters")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// UnsignedPath is where Build writes the unsigned manifest of the bundle at dir.
func UnsignedPath(dir string) string { return filepath.Clean(dir) + UnsignedSuffix }
