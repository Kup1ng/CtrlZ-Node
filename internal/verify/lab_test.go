package verify

import (
	"path/filepath"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
	"github.com/Kup1ng/CtrlZ-Node/internal/labroot"
)

// The install refuses a manifest whose root is the lab test root unless the
// binary is a lab build (p4-nodes 7.1: a test each, at install). The bundle is
// signed with the lab keys, as a lab run does, so a refusal here is the deny list
// and not a bad signature.
func TestLabRootByBuild(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "pkg/install/node.sh"), "V='"+bundle.VerifyPlaceholder+"' N='"+bundle.VersionPlaceholder+"'\n")
	write(t, filepath.Join(d, "node"), "N")
	write(t, filepath.Join(d, "verify"), "V")
	out := filepath.Join(d, "b")
	if _, err := bundle.Build(bundle.Options{Out: out, Version: 1, MinVersion: 1, ExpiresAt: 4102444800, Packaging: filepath.Join(d, "pkg"),
		NodeBin: filepath.Join(d, "node"), VerifyBin: filepath.Join(d, "verify")}); err != nil {
		t.Fatal(err)
	}
	lab := filepath.Join("..", "labroot", "testdata")
	doc, err := bundle.ReadEnvelope(bundle.UnsignedPath(out))
	if err != nil {
		t.Fatal(err)
	}
	var keys = []string{"root-1.seed", "root-2.seed"}
	for _, k := range keys {
		pk, err := bundle.ReadSeed(filepath.Join(lab, k))
		if err != nil {
			t.Fatal(err)
		}
		bundle.Sign(doc, pk)
	}
	raw, _ := bundle.MarshalEnvelope(doc)
	write(t, filepath.Join(out, bundle.ManifestFile), string(raw))

	m, err := Manifest(Options{RootPath: filepath.Join(lab, "root.json"), ManifestPath: filepath.Join(out, bundle.ManifestFile)})
	if labroot.Lab {
		if err != nil {
			t.Fatalf("lab build refused the lab root: %v", err)
		}
		if err := Dir(m, out); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantFailure(t, err, ExitRoot, "root-lab-key")
}

// The clock flag is a test hook: a release verifier must not take it, or anyone who
// can pick its arguments could verify an expired manifest.
func TestNowFlagOnlyInLabBuilds(t *testing.T) {
	w := newWorld(t, 7)
	code, _, _ := w.run("list", "--root", w.rootPath, "--manifest", w.manPath, "--now", "1")
	if labroot.Lab && code != 0 {
		t.Fatalf("lab build: --now gave %d", code)
	}
	if !labroot.Lab && code != ExitUsage {
		t.Fatalf("release build: --now gave %d, want usage", code)
	}
}
