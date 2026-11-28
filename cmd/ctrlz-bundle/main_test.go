package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
)

func fixture(t *testing.T) (out string, args []string) {
	t.Helper()
	d := t.TempDir()
	w := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("pkg/install/node.sh", "V='"+bundle.VerifyPlaceholder+"' N='"+bundle.VersionPlaceholder+"'\n")
	w("node", "N")
	w("verify", "V")
	w("debs/a_1_all.deb", "D")
	out = filepath.Join(d, "out")
	args = []string{"build", "--out", out, "--version", "2", "--min-version", "1", "--created", "1", "--expires", "4102444800",
		"--packaging", filepath.Join(d, "pkg"), "--node-bin", filepath.Join(d, "node"), "--verify-bin", filepath.Join(d, "verify"), "--debs", filepath.Join(d, "debs")}
	return out, args
}

func TestBuildWritesTheBundleAndTheUnsignedManifest(t *testing.T) {
	out, args := fixture(t)
	if code := run(args); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(bundle.UnsignedPath(out)); err != nil {
		t.Fatal(err)
	}
	// The signed manifest is the offline signer's; the builder writes none.
	if _, err := os.Stat(filepath.Join(out, bundle.ManifestFile)); err == nil {
		t.Fatal("the builder wrote a signed manifest")
	}
}

func TestBuildNeedsItsInputs(t *testing.T) {
	_, args := fixture(t)
	for i := 1; i < len(args); i += 2 {
		if args[i] == "--tag" || args[i] == "--created" || args[i] == "--expires" || args[i] == "--min-version" || args[i] == "--version" || args[i] == "--out" {
			continue
		}
		cut := append(append([]string{}, args[:i]...), args[i+2:]...)
		if code := run(cut); code != 2 {
			t.Errorf("without %s: exit %d, want 2", args[i], code)
		}
	}
	if run(nil) != 2 || run([]string{"bogus"}) != 2 {
		t.Error("usage errors must exit 2")
	}
}
