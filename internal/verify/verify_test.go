package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
)

// world is a signed bundle on disk and the root that signs it. The root is made
// here with random keys, because a production-built test binary refuses the lab
// root (that refusal has its own test).
type world struct {
	dir, rootPath, manPath string
	root                   *signv1.Root
	keys                   []ed25519.PrivateKey // three root keys
	policy                 ed25519.PrivateKey
	m                      *signv1.Manifest
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubOf(k ed25519.PrivateKey) *signv1.PublicKey {
	p := k.Public().(ed25519.PublicKey)
	return &signv1.PublicKey{KeyId: manifest.KeyID(p), Ed25519: p}
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

func newWorld(t *testing.T, version uint64, signers ...int) *world {
	t.Helper()
	w := &world{}
	for i := 0; i < 3; i++ {
		w.keys = append(w.keys, newKey(t))
	}
	w.policy = newKey(t)
	exp := time.Now().Add(24 * time.Hour).Unix()
	var ids [][]byte
	r := &signv1.Root{Version: 1, ExpiresAt: exp, Threshold: 2}
	for _, k := range w.keys {
		r.Keys = append(r.Keys, pubOf(k))
		ids = append(ids, pubOf(k).KeyId)
	}
	r.Keys = append(r.Keys, pubOf(w.policy))
	r.RootKeyIds = ids
	r.Roles = []*signv1.RoleGrant{
		{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{pubOf(w.policy).KeyId}, Threshold: 1, ExpiresAt: exp},
		{Role: signv1.Role_ROLE_BUNDLE, KeyIds: ids, Threshold: 2, ExpiresAt: exp},
	}
	w.root = r

	d := t.TempDir()
	write(t, filepath.Join(d, "pkg/install/node.sh"), "V='"+bundle.VerifyPlaceholder+"' N='"+bundle.VersionPlaceholder+"'\n")
	write(t, filepath.Join(d, "pkg/install/apply.sh"), "echo hi\n")
	write(t, filepath.Join(d, "node"), "NODE")
	write(t, filepath.Join(d, "verify"), "VERIFY")
	write(t, filepath.Join(d, "debs/a_1_amd64.deb"), "DEB-A")
	out := filepath.Join(d, "bundle")
	m, err := bundle.Build(bundle.Options{
		Out: out, Version: version, MinVersion: 1, CreatedAt: 1, ExpiresAt: exp, Packaging: filepath.Join(d, "pkg"),
		NodeBin: filepath.Join(d, "node"), VerifyBin: filepath.Join(d, "verify"), Debs: filepath.Join(d, "debs"),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.m, w.dir = m, out
	if len(signers) == 0 {
		signers = []int{0, 1}
	}
	var sk []ed25519.PrivateKey
	for _, i := range signers {
		if i < 3 {
			sk = append(sk, w.keys[i])
		} else {
			sk = append(sk, w.policy)
		}
	}
	w.sign(t, w.m, sk...)
	b, err := protojson.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	w.rootPath = filepath.Join(d, "root.json")
	write(t, w.rootPath, string(b))
	return w
}

func (w *world) sign(t *testing.T, m *signv1.Manifest, keys ...ed25519.PrivateKey) {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	e := &signv1.Envelope{PayloadType: manifest.ManifestPayloadType(m.Kind), Payload: payload}
	bundle.Sign(e, keys...)
	raw, err := bundle.MarshalEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	w.manPath = filepath.Join(w.dir, bundle.ManifestFile)
	if err := os.WriteFile(w.manPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (w *world) opts() Options {
	return Options{RootPath: w.rootPath, ManifestPath: w.manPath}
}

func (w *world) run(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	code := Main(args, &o, &e)
	return code, o.String(), e.String()
}

func wantFailure(t *testing.T, err error, code int, check string) {
	t.Helper()
	f, ok := err.(*Failure)
	if !ok {
		t.Fatalf("got %v, want a Failure %d %s", err, code, check)
	}
	if f.Code != code || f.Check != check {
		t.Fatalf("got code %d check %q (%v), want %d %q", f.Code, f.Check, f.Err, code, check)
	}
}

func TestGoodBundlePasses(t *testing.T) {
	w := newWorld(t, 7)
	m, err := Manifest(w.opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := Dir(m, w.dir); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.run("check", "--root", w.rootPath, "--manifest", w.manPath, "--dir", w.dir, "--version", "7")
	if code != 0 || errOut != "" || out != "" {
		t.Fatalf("check: %d %q %q", code, out, errOut)
	}
	code, out, _ = w.run("list", "--root", w.rootPath, "--manifest", w.manPath)
	if code != 0 || !strings.Contains(out, "bin/ctrlz-node\n") || !strings.Contains(out, "debs/a_1_amd64.deb\n") {
		t.Fatalf("list: %d %q", code, out)
	}
}

func TestOneSignatureIsNotEnough(t *testing.T) {
	w := newWorld(t, 7, 0)
	_, err := Manifest(w.opts())
	wantFailure(t, err, ExitManifest, "manifest-signatures")
}

// A manifest signed by the policy key (an online key) or by a key outside the
// bundle grant must not install code (SC 13: bundle kinds verify offline only).
func TestSignedOutsideTheBundleGrant(t *testing.T) {
	w := newWorld(t, 7, 3, 3)
	_, err := Manifest(w.opts())
	wantFailure(t, err, ExitManifest, "manifest-signatures")

	w = newWorld(t, 7, 0)
	w.sign(t, w.m, w.keys[0], newKey(t), newKey(t))
	_, err = Manifest(w.opts())
	if err == nil {
		t.Fatal("two unknown signers plus one root key accepted")
	}
	wantFailure(t, err, ExitManifest, "manifest-signatures")
}

func TestManifestOfAnotherKindIsRefused(t *testing.T) {
	w := newWorld(t, 7)
	other := proto.Clone(w.m).(*signv1.Manifest)
	other.Kind = signv1.Kind_KIND_XRAY
	w.sign(t, other, w.keys[0], w.keys[1])
	_, err := Manifest(w.opts())
	wantFailure(t, err, ExitManifest, "manifest-kind")
}

func TestTamperedFiles(t *testing.T) {
	cases := []struct {
		name  string
		do    func(t *testing.T, w *world)
		check string
	}{
		{"same size, other bytes", func(t *testing.T, w *world) { write(t, filepath.Join(w.dir, "bin/ctrlz-node"), "NODX") }, "file-hash"},
		{"other size", func(t *testing.T, w *world) { write(t, filepath.Join(w.dir, "bin/ctrlz-node"), "NODE+") }, "file-size"},
		{"file not in the index", func(t *testing.T, w *world) { write(t, filepath.Join(w.dir, "debs/evil.deb"), "x") }, "file-not-listed"},
		{"listed file missing", func(t *testing.T, w *world) {
			if err := os.Remove(filepath.Join(w.dir, "debs/a_1_amd64.deb")); err != nil {
				t.Fatal(err)
			}
		}, "file-missing"},
		{"a second manifest-like file", func(t *testing.T, w *world) { write(t, filepath.Join(w.dir, "manifest.json.bak"), "{}") }, "file-not-listed"},
	}
	for _, c := range cases {
		w := newWorld(t, 7)
		c.do(t, w)
		m, err := Manifest(w.opts())
		if err != nil {
			t.Fatal(err)
		}
		wantFailure(t, Dir(m, w.dir), ExitFiles, c.check)
	}
}

func TestSymlinkIsRefused(t *testing.T) {
	w := newWorld(t, 7)
	if err := os.Remove(filepath.Join(w.dir, "bin/ctrlz-node")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(w.dir, "bin/ctrlz-verify"), filepath.Join(w.dir, "bin/ctrlz-node")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	m, err := Manifest(w.opts())
	if err != nil {
		t.Fatal(err)
	}
	wantFailure(t, Dir(m, w.dir), ExitFiles, "file-not-regular")
}

func TestFreshness(t *testing.T) {
	w := newWorld(t, 7)
	o := w.opts()
	o.Installed = 8
	_, err := Manifest(o)
	wantFailure(t, err, ExitFresh, "version-below-installed")

	o.Installed, o.Above = 7, true
	_, err = Manifest(o)
	wantFailure(t, err, ExitFresh, "version-not-above-installed")

	o.Installed, o.Above = 6, true
	if _, err = Manifest(o); err != nil {
		t.Fatal(err)
	}
	o.WantVersion = 9
	_, err = Manifest(o)
	wantFailure(t, err, ExitFresh, "version-not-the-one-asked")

	o = w.opts()
	o.Now = time.Now().Add(48 * time.Hour).Unix()
	_, err = Manifest(o)
	wantFailure(t, err, ExitRoot, "root-expired")

	// Root still alive, manifest expired.
	w2 := newWorld(t, 7)
	m2 := proto.Clone(w2.m).(*signv1.Manifest)
	m2.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	w2.sign(t, m2, w2.keys[0], w2.keys[1])
	_, err = Manifest(w2.opts())
	wantFailure(t, err, ExitFresh, "manifest-expired")
}

func TestRootProblems(t *testing.T) {
	w := newWorld(t, 7)
	_, err := Manifest(Options{RootPath: filepath.Join(w.dir, "absent.json"), ManifestPath: w.manPath})
	wantFailure(t, err, ExitRoot, "root-readable")
	write(t, filepath.Join(w.dir, "garbage.json"), "{{")
	_, err = Manifest(Options{RootPath: filepath.Join(w.dir, "garbage.json"), ManifestPath: w.manPath})
	wantFailure(t, err, ExitRoot, "root-readable")

	// A malformed root (a bundle grant naming a key that is not a root key).
	bad := proto.Clone(w.root).(*signv1.Root)
	bad.RootKeyIds = bad.RootKeyIds[:2]
	b, _ := protojson.Marshal(bad)
	write(t, filepath.Join(w.dir, "bad.json"), string(b))
	_, err = Manifest(Options{RootPath: filepath.Join(w.dir, "bad.json"), ManifestPath: w.manPath})
	wantFailure(t, err, ExitRoot, "root-malformed")
}

func TestManifestFileProblems(t *testing.T) {
	w := newWorld(t, 7)
	write(t, w.manPath, "not json")
	_, err := Manifest(w.opts())
	wantFailure(t, err, ExitManifest, "manifest-readable")
}

// The messages name the failed check and nothing from the bundle: no file name,
// no content (a hostile bundle must not write into the admin's terminal).
func TestMessagesCarryNothingFromTheBundle(t *testing.T) {
	w := newWorld(t, 7)
	write(t, filepath.Join(w.dir, "debs/SECRET-NAME.deb"), "SECRET-CONTENT")
	write(t, filepath.Join(w.dir, "bin/ctrlz-node"), "SECRET-CONTENT")
	code, out, errOut := w.run("check", "--root", w.rootPath, "--manifest", w.manPath, "--dir", w.dir)
	if code != ExitFiles {
		t.Fatalf("exit %d", code)
	}
	for _, s := range []string{out, errOut} {
		if strings.Contains(s, "SECRET") || strings.Contains(s, "evil") {
			t.Fatalf("message carries bundle data: %q", s)
		}
	}
	if !strings.HasPrefix(errOut, "ctrlz-verify: check failed: ") {
		t.Fatalf("message %q", errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	w := newWorld(t, 7)
	for _, args := range [][]string{
		nil, {"bogus"}, {"check"}, {"list", "--root", w.rootPath}, {"check", "--root", w.rootPath, "--manifest", w.manPath},
		{"list", "--root", w.rootPath, "--manifest", w.manPath, "extra"}, {"list", "--bogus"},
	} {
		if code, _, _ := w.run(args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
	}
}

// node.sh bounds every download by the signed size, so `sizes` must print exactly
// "SIZE PATH" for every listed file and nothing else.
func TestSizesPrintsTheSignedSizeOfEveryFile(t *testing.T) {
	w := newWorld(t, 7)
	code, out, errOut := w.run("sizes", "--root", w.rootPath, "--manifest", w.manPath, "--version", "7")
	if code != 0 || errOut != "" {
		t.Fatalf("sizes: %d %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(w.m.Files) {
		t.Fatalf("%d lines for %d files: %q", len(lines), len(w.m.Files), out)
	}
	for i, f := range w.m.Files {
		if want := strconv.FormatUint(f.Size, 10) + " " + f.Path; lines[i] != want {
			t.Errorf("line %d: %q, want %q", i, lines[i], want)
		}
	}
	// A manifest that does not verify prints nothing.
	bad := newWorld(t, 7, 0)
	if code, out, _ := bad.run("sizes", "--root", bad.rootPath, "--manifest", bad.manPath); code != ExitManifest || out != "" {
		t.Fatalf("an under-signed manifest: %d %q", code, out)
	}
}

// A signed manifest whose listed sizes add up to more than the cap is refused by
// list, sizes and check alike, before any file is fetched or copied.
func TestListedSizesOverTheTotalCapAreRefused(t *testing.T) {
	w := newWorld(t, 7)
	m := proto.Clone(w.m).(*signv1.Manifest)
	m.Files[0].Size = manifest.MaxFileSize / 2
	m.Files[1].Size = manifest.MaxFileSize / 2
	w.sign(t, m, w.keys[0], w.keys[1])
	_, err := Manifest(w.opts())
	wantFailure(t, err, ExitManifest, "bundle-total-size")
	for _, cmd := range []string{"list", "sizes"} {
		if code, out, _ := w.run(cmd, "--root", w.rootPath, "--manifest", w.manPath); code != ExitManifest || out != "" {
			t.Errorf("%s over the cap: %d %q", cmd, code, out)
		}
	}
}

// A root that decodes but is malformed (a duplicate key) is a root fault: exit 10, the
// same as an unreadable one (p4n-W5c-r4-4). The runbook and the exit constants say so.
func TestDuplicateKeyRootIsARootFault(t *testing.T) {
	w := newWorld(t, 7)
	bad := proto.Clone(w.root).(*signv1.Root)
	bad.Keys = append(bad.Keys, proto.Clone(bad.Keys[0]).(*signv1.PublicKey))
	b, _ := protojson.Marshal(bad)
	write(t, filepath.Join(w.dir, "dup.json"), string(b))
	_, err := Manifest(Options{RootPath: filepath.Join(w.dir, "dup.json"), ManifestPath: w.manPath})
	wantFailure(t, err, ExitRoot, "root-malformed")
}
