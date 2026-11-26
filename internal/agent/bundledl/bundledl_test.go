package bundledl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
)

// fakeHub serves the files of one bundle directory, the way the hub's
// OpenBundleFile does: by exact name from the manifest or manifest.json. It
// records every request.
type fakeHub struct {
	mu    sync.Mutex
	dir   string
	asked []string
	// tamper changes what a file's bytes are on the way.
	tamper func(name string, b []byte) []byte
	// stall makes the stream of this name send nothing.
	stall string
	// empties makes the stream of this name send empty chunks for ever.
	empties string
	// listed is the manifest's index: like the real hub, a name outside it is not
	// found, with manifest.json the one stated exception (see the note on the real
	// hub in the commit: its gRPC door does not serve it yet).
	listed map[string]bool
}

func (h *fakeHub) FetchBundle(ctx context.Context, in *hubv1.FetchBundleRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[hubv1.BlobChunk], error) {
	h.mu.Lock()
	h.asked = append(h.asked, in.Path)
	h.mu.Unlock()
	if in.Kind != signv1.Kind_KIND_NODE {
		return nil, errors.New("not found")
	}
	if in.Path != bundle.ManifestFile && !h.listed[in.Path] {
		return nil, errors.New("not found")
	}
	b, err := os.ReadFile(filepath.Join(h.dir, filepath.FromSlash(in.Path)))
	if err != nil {
		return nil, errors.New("not found")
	}
	if h.tamper != nil {
		b = h.tamper(in.Path, b)
	}
	return &stream{ctx: ctx, b: b, stall: h.stall == in.Path, empties: h.empties == in.Path}, nil
}

func (h *fakeHub) requests() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.asked...)
}

type stream struct {
	grpc.ClientStream
	ctx   context.Context
	b     []byte
	off   int
	stall bool
	done  bool
	// empties sends a chunk with no data at the current offset, again and again.
	empties bool
}

func (s *stream) Recv() (*hubv1.BlobChunk, error) {
	if s.stall {
		<-s.ctx.Done()
		return nil, s.ctx.Err()
	}
	if s.done {
		return nil, io.EOF
	}
	if s.empties {
		return &hubv1.BlobChunk{Offset: uint64(s.off)}, nil
	}
	n := min(len(s.b)-s.off, 7) // a small chunk, so a file takes several
	ch := &hubv1.BlobChunk{Offset: uint64(s.off), Data: s.b[s.off : s.off+n]}
	s.off += n
	if s.off == len(s.b) {
		ch.Last, s.done = true, true
	}
	return ch, nil
}

type rig struct {
	hub  *fakeHub
	root *signv1.Root
	dl   *Downloader
	dir  string // the agent's bundles directory
	man  *signv1.Manifest
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newRig builds a signed bundle of the version, a root that trusts it and a
// downloader whose hub serves it. The root has random keys: a production-built test
// binary refuses the lab root.
func newRig(t *testing.T, version uint64) *rig {
	t.Helper()
	var keys []ed25519.PrivateKey
	r := &signv1.Root{Version: 1, ExpiresAt: time.Now().Add(24 * time.Hour).Unix(), Threshold: 2}
	var ids [][]byte
	for i := 0; i < 3; i++ {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
		pub := k.Public().(ed25519.PublicKey)
		r.Keys = append(r.Keys, &signv1.PublicKey{KeyId: manifest.KeyID(pub), Ed25519: pub})
		ids = append(ids, manifest.KeyID(pub))
	}
	r.RootKeyIds = ids
	r.Roles = []*signv1.RoleGrant{{Role: signv1.Role_ROLE_BUNDLE, KeyIds: ids, Threshold: 2, ExpiresAt: r.ExpiresAt}}

	d := t.TempDir()
	write(t, filepath.Join(d, "pkg/install/node.sh"), "V='"+bundle.VerifyPlaceholder+"' N='"+bundle.VersionPlaceholder+"'\n")
	write(t, filepath.Join(d, "pkg/install/apply.sh"), "echo hi\n")
	write(t, filepath.Join(d, "node"), "NODE-BINARY-BYTES")
	write(t, filepath.Join(d, "verify"), "VERIFY")
	write(t, filepath.Join(d, "debs/a_1_amd64.deb"), "DEB-A")
	out := filepath.Join(d, "bundle")
	m, err := bundle.Build(bundle.Options{
		Out: out, Version: version, MinVersion: 1, CreatedAt: 1, ExpiresAt: r.ExpiresAt, Packaging: filepath.Join(d, "pkg"),
		NodeBin: filepath.Join(d, "node"), VerifyBin: filepath.Join(d, "verify"), Debs: filepath.Join(d, "debs"),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	env := &signv1.Envelope{PayloadType: manifest.ManifestPayloadType(m.Kind), Payload: payload}
	bundle.Sign(env, keys[0], keys[1])
	raw, err := bundle.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, bundle.ManifestFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	rg := &rig{hub: &fakeHub{dir: out, listed: listedOf(m)}, root: r, dir: filepath.Join(t.TempDir(), "bundles"), man: m}
	rg.dl = New(rg.cfg())
	return rg
}

func (r *rig) cfg() Config {
	return Config{
		Hub:  func() Hub { return r.hub },
		Root: func() (*signv1.Root, error) { return r.root, nil },
		Dir:  r.dir,
		Idle: 300 * time.Millisecond,
	}
}

func (r *rig) leftovers(t *testing.T) []string {
	t.Helper()
	var out []string
	es, err := os.ReadDir(filepath.Join(r.dir, "node"))
	if err != nil {
		return nil
	}
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestDownloadsAVerifiedBundleIntoTheBundlesDirectory(t *testing.T) {
	r := newRig(t, 5)
	m, err := r.dl.Download(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		got, err := os.ReadFile(filepath.Join(r.dl.Dest(5), filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(filepath.Join(r.hub.dir, filepath.FromSlash(f.Path)))
		if string(got) != string(want) {
			t.Errorf("%s differs", f.Path)
		}
	}
	if _, err := os.Stat(filepath.Join(r.dl.Dest(5), bundle.ManifestFile)); err != nil {
		t.Error("manifest.json missing")
	}
	if got := r.leftovers(t); len(got) != 1 || got[0] != "5" {
		t.Errorf("the node directory holds %v, want only 5", got)
	}
	// Every request was a bare name inside the bundle.
	for _, p := range r.hub.requests() {
		if CheckRef(p) != nil {
			t.Errorf("a request for %q", p)
		}
	}
}

// T-359: a URL, an absolute path, a network path and a name that climbs out are
// refused before any request reaches the hub. Mutant: an agent that accepts a URL
// (CheckRef returns nil for it, or fetchTo skips it) sends the request, which the
// fake hub records, and this fails.
func TestRefusesAnythingOutsideTheHub(t *testing.T) {
	r := newRig(t, 5)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, ref := range []string{
		"https://mirror.example.org/node.tar", "http://203.0.113.9/bin/ctrlz-node", "//evil.example/x", "/etc/passwd",
		`\\host\share\x`, "../../etc/shadow", "bin/../../x", "file:///etc/passwd", "c:/windows/x", "",
	} {
		err := r.dl.fetchTo(context.Background(), root, 5, ref, 100)
		if err == nil {
			t.Errorf("%q was fetched", ref)
		}
	}
	if got := r.hub.requests(); len(got) != 0 {
		t.Errorf("the hub was asked for %v", got)
	}
	if err := CheckRef("https://mirror.example.org/x"); !errors.Is(err, ErrOutsideHub) {
		t.Errorf("a URL is %v, want ErrOutsideHub", err)
	}
	if err := CheckRef("bin/ctrlz-node"); err != nil {
		t.Errorf("a plain name is refused: %v", err)
	}
}

// The agent has no way to reach anything but the hub: no HTTP client, no dialer.
// Mutant: importing net/http (or net) into the package.
func TestNoHTTPClient(t *testing.T) {
	fs := token.NewFileSet()
	pkgs, err := parser.ParseDir(fs, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		for name, f := range p.Files {
			for _, im := range f.Imports {
				switch strings.Trim(im.Path.Value, `"`) {
				case "net/http", "net", "net/url", "crypto/tls", "os/exec":
					t.Errorf("%s imports %s", name, im.Path.Value)
				}
			}
		}
	}
}

// A hub that serves another manifest, a tampered file, a longer file or a stalled
// stream gets nothing installed and no staging left behind.
func TestRefusesWhatDoesNotVerify(t *testing.T) {
	cases := map[string]struct {
		mut  func(r *rig)
		want string
	}{
		"tampered file": {func(r *rig) {
			r.hub.tamper = func(n string, b []byte) []byte {
				if n == "bin/ctrlz-node" {
					c := append([]byte(nil), b...)
					c[0] ^= 1
					return c
				}
				return b
			}
		}, "does not match its manifest"},
		"a file longer than listed": {func(r *rig) {
			r.hub.tamper = func(n string, b []byte) []byte {
				if n == "debs/a_1_amd64.deb" {
					return append(append([]byte(nil), b...), 'x')
				}
				return b
			}
		}, "more than the listed size"},
		"tampered manifest": {func(r *rig) {
			r.hub.tamper = func(n string, b []byte) []byte {
				if n == bundle.ManifestFile {
					// Decode and re-encode rather than edit the text: protojson's
					// spacing differs between builds, so a text replace matched
					// on one host and silently changed nothing on another.
					e := &signv1.Envelope{}
					if err := protojson.Unmarshal(b, e); err != nil {
						t.Fatal(err)
					}
					e.Payload = append([]byte{0}, e.Payload...)
					out, err := bundle.MarshalEnvelope(e)
					if err != nil {
						t.Fatal(err)
					}
					if string(out) == string(b) {
						t.Fatal("the tamper changed nothing")
					}
					return out
				}
				return b
			}
		}, "manifest"},
		"empty chunks for ever": {func(r *rig) { r.hub.empties = "bin/ctrlz-verify" }, "empty chunk"},
		"unsigned manifest": {func(r *rig) {
			r.root.Roles[0].Threshold = 3
		}, "not signed by the root"},
		"rollback": {func(r *rig) {
			r.dl = New(Config{Hub: r.cfg().Hub, Root: r.cfg().Root, Dir: r.dir, Installed: func() uint64 { return 9 }})
		}, "lower than the highest"},
		"stalled stream": {func(r *rig) { r.hub.stall = "bin/ctrlz-verify" }, "transfer broke"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 5)
			c.mut(r)
			_, err := r.dl.Download(context.Background(), 5)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if got := r.leftovers(t); len(got) != 0 {
				t.Errorf("left behind: %v", got)
			}
		})
	}
}

// The hub is not believed about the version: a manifest of version 6 served for a
// request of 5 is refused.
func TestRefusesAManifestOfAnotherVersion(t *testing.T) {
	r := newRig(t, 6)
	_, err := r.dl.Download(context.Background(), 5)
	if err == nil || !strings.Contains(err.Error(), "another version") {
		t.Fatalf("got %v", err)
	}
	if len(r.leftovers(t)) != 0 {
		t.Error("left behind")
	}
}

func TestVersionZeroIsRefused(t *testing.T) {
	r := newRig(t, 5)
	if _, err := r.dl.Download(context.Background(), 0); err == nil {
		t.Fatal("version 0 accepted")
	}
}

func listedOf(m *signv1.Manifest) map[string]bool {
	out := map[string]bool{}
	for _, f := range m.Files {
		out[f.Path] = true
	}
	return out
}
