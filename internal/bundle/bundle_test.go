package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func inputs(t *testing.T) Options {
	d := t.TempDir()
	write(t, filepath.Join(d, "pkg/install/node.sh"), "VERIFY='"+VerifyPlaceholder+"' VER='"+VersionPlaceholder+"'\n")
	write(t, filepath.Join(d, "pkg/install/apply.sh"), "echo apply\n")
	write(t, filepath.Join(d, "pkg/systemd/a.service"), "[Unit]\n")
	write(t, filepath.Join(d, "node"), "NODE")
	write(t, filepath.Join(d, "verify"), "VERIFY")
	write(t, filepath.Join(d, "debs/x_1_amd64.deb"), "DEB")
	write(t, filepath.Join(d, "debs/notes.txt"), "not a deb")
	return Options{
		Out: filepath.Join(d, "out"), Version: 7, MinVersion: 5, CreatedAt: 100, ExpiresAt: 4102444800, Tag: "t",
		Packaging: filepath.Join(d, "pkg"), NodeBin: filepath.Join(d, "node"), VerifyBin: filepath.Join(d, "verify"),
		Debs: filepath.Join(d, "debs"),
	}
}

func TestBuildListsEveryFileAndStampsTheScript(t *testing.T) {
	o := inputs(t)
	m, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*signv1.FileEntry{}
	for _, f := range m.Files {
		got[f.Path] = f
	}
	for _, p := range []string{NodeBinary, VerifyBinary, NodeScript, "packaging/install/apply.sh", "packaging/systemd/a.service", "debs/x_1_amd64.deb"} {
		if got[p] == nil {
			t.Errorf("%s is not in the manifest", p)
		}
	}
	if len(got) != 6 {
		t.Errorf("manifest has %d files, want 6 (a non-deb in debs/ must not be bundled)", len(got))
	}
	script, _ := os.ReadFile(filepath.Join(o.Out, filepath.FromSlash(NodeScript)))
	want := sha256.Sum256([]byte("VERIFY"))
	if !strings.Contains(string(script), hex.EncodeToString(want[:])) || bytes.Contains(script, []byte(VerifyPlaceholder)) {
		t.Fatalf("node.sh not stamped: %q", script)
	}
	if !strings.Contains(string(script), "VER='7'") || bytes.Contains(script, []byte(VersionPlaceholder)) {
		t.Fatalf("node.sh does not carry the bundle version: %q", script)
	}
	// The manifest holds the stamped script's hash, not the template's.
	h := sha256.Sum256(script)
	if !bytes.Equal(got[NodeScript].Sha256, h[:]) {
		t.Fatal("manifest holds the hash of the unstamped script")
	}
	ix, err := manifest.NewIndex(m)
	if err != nil {
		t.Fatal(err)
	}
	for p, f := range got {
		b, _ := os.ReadFile(filepath.Join(o.Out, filepath.FromSlash(p)))
		if err := ix.CheckEntry(p, 0o644, uint64(len(b))); err != nil || f.Size != uint64(len(b)) {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestBuildRefusals(t *testing.T) {
	o := inputs(t)
	o.MinVersion = o.Version + 1
	if _, err := Build(o); err == nil {
		t.Error("min_version above version accepted")
	}
	o = inputs(t)
	write(t, filepath.Join(o.Packaging, "install/node.sh"), "no placeholder")
	if _, err := Build(o); err == nil {
		t.Error("node.sh without the placeholder accepted")
	}
	o = inputs(t)
	write(t, filepath.Join(o.Packaging, "install/node.sh"), VerifyPlaceholder+VerifyPlaceholder+VersionPlaceholder)
	if _, err := Build(o); err == nil {
		t.Error("node.sh with two placeholders accepted")
	}
	o = inputs(t)
	write(t, filepath.Join(o.Packaging, "systemd/b.service"), VerifyPlaceholder)
	if _, err := Build(o); err == nil {
		t.Error("a placeholder outside node.sh accepted")
	}
	o = inputs(t)
	if _, err := Build(o); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(o); err == nil {
		t.Error("an existing output directory accepted")
	}
}

func TestSignedEnvelopeRoundTripsAndVerifies(t *testing.T) {
	o := inputs(t)
	m, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := ReadEnvelope(UnsignedPath(o.Out))
	if err != nil {
		t.Fatal(err)
	}
	if len(unsigned.Signatures) != 0 {
		t.Fatal("Build signed the manifest")
	}
	lab := filepath.Join("..", "labroot", "testdata")
	root, err := ReadRoot(filepath.Join(lab, "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	k1, err := ReadSeed(filepath.Join(lab, "root-1.seed"))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ReadSeed(filepath.Join(lab, "root-2.seed"))
	if err != nil {
		t.Fatal(err)
	}
	Sign(unsigned, k1, k2)
	raw, err := MarshalEnvelope(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(o.Out, ManifestFile)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	back, err := ReadEnvelope(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := manifest.VerifyManifest(back, root, signv1.Kind_KIND_NODE, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, m) {
		t.Fatal("manifest changed in the round trip")
	}
}

func TestReadersCapAndRefuse(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "bad"), "{not json")
	if _, err := ReadEnvelope(filepath.Join(d, "bad")); err == nil {
		t.Error("garbage envelope accepted")
	}
	if _, err := ReadRoot(filepath.Join(d, "bad")); err == nil {
		t.Error("garbage root accepted")
	}
	if err := os.WriteFile(filepath.Join(d, "big"), make([]byte, 2<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRoot(filepath.Join(d, "big")); err == nil {
		t.Error("a root over the cap accepted")
	}
	write(t, filepath.Join(d, "seed"), "zz")
	if _, err := ReadSeed(filepath.Join(d, "seed")); err == nil {
		t.Error("bad seed accepted")
	}
}
