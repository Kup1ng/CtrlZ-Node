//go:build ctrlz_lab

package main

import (
	"path/filepath"
	"testing"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
)

func TestSignLabMakesAManifestTheLabRootVerifies(t *testing.T) {
	out, args := fixture(t)
	if code := run(args); code != 0 {
		t.Fatalf("build: exit %d", code)
	}
	lab := filepath.Join("..", "..", "internal", "labroot", "testdata")
	if code := run([]string{"sign-lab", "--dir", out, "--seed", filepath.Join(lab, "root-1.seed"), "--seed", filepath.Join(lab, "root-3.seed")}); code != 0 {
		t.Fatalf("sign-lab: exit %d", code)
	}
	root, err := bundle.ReadRoot(filepath.Join(lab, "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := bundle.ReadEnvelope(filepath.Join(out, bundle.ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.VerifyManifest(env, root, signv1.Kind_KIND_NODE, 1000); err != nil {
		t.Fatal(err)
	}
	// One signature of the two needed does not.
	if code := run([]string{"sign-lab", "--dir", out, "--seed", filepath.Join(lab, "root-1.seed")}); code != 0 {
		t.Fatal("sign-lab with one seed")
	}
	env, _ = bundle.ReadEnvelope(filepath.Join(out, bundle.ManifestFile))
	if _, err := manifest.VerifyManifest(env, root, signv1.Kind_KIND_NODE, 1000); err == nil {
		t.Fatal("one signature verified")
	}
}
