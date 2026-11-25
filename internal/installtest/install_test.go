// Package installtest runs node.sh, apply.sh and the upgrade in a clean
// ubuntu:24.04 container with no network (p4-nodes 11.5, N7 and N11).
//
// It needs Docker and the image, so it runs only when CTRLZ_INSTALL_TEST=1; every
// other `go test ./...` skips it, and the structural half of N11 (package
// pkgcheck) runs everywhere. The scenarios are in sh/scenarios.sh.
package installtest

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// image is the base image of the test, the one the install targets. The digest
// the lane recorded is in the notes; the test uses the tag so a refreshed image
// is a visible change of the run, not a silent one.
const image = "ubuntu:24.04"

var scenarios = []string{
	"happy", "os-release", "wrong-root", "wrong-verify", "wrong-script", "outside-grant", "one-signature",
	"file-tampered", "file-not-listed", "lab-root-in-production", "old-unbound", "group-drift",
	"token-arguments", "bad-addresses", "upgrade", "upgrade-tampered", "timesyncd", "planted-links", "agent-running", "account-drift", "oversized", "host-quirks", "upgrade-failure", "newer-package", "unbound-restart", "apt-purge", "apt-partial",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func goBuild(t *testing.T, root, out string, tags string, pkg string) {
	t.Helper()
	args := []string{"build", "-trimpath", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, pkg)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, out)
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInstallInContainer(t *testing.T) {
	if os.Getenv("CTRLZ_INSTALL_TEST") != "1" {
		t.Skip("set CTRLZ_INSTALL_TEST=1 to run the container install test (needs Docker and the ubuntu:24.04 image)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	if out, err := exec.Command("docker", "image", "inspect", image).CombinedOutput(); err != nil {
		t.Fatalf("the image %s is not present (pull it once): %v\n%s", image, err, out)
	}
	root := repoRoot(t)
	work := t.TempDir()
	bin := filepath.Join(work, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The same code as the release: ctrlz-verify and the builder in a lab build (they
	// accept the lab test root) and a production verifier (it must refuse it).
	goBuild(t, root, filepath.Join(bin, "verify-lab"), "ctrlz_lab", "./cmd/ctrlz-verify")
	goBuild(t, root, filepath.Join(bin, "verify-prod"), "", "./cmd/ctrlz-verify")
	goBuild(t, root, filepath.Join(bin, "bundle-lab"), "ctrlz_lab", "./cmd/ctrlz-bundle")
	goBuild(t, root, filepath.Join(bin, "upgradeshim"), "ctrlz_lab", "./internal/installtest/upgradeshim")
	copyDir(t, filepath.Join(root, "packaging"), filepath.Join(work, "packaging"))
	copyDir(t, filepath.Join(root, "internal", "installtest", "sh"), filepath.Join(work, "sh"))
	copyDir(t, filepath.Join(root, "internal", "labroot", "testdata"), filepath.Join(work, "lab"))

	for _, name := range scenarios {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			// One container per scenario: no state carries over, and a scenario that
			// installs the node does not disturb the one that checks nothing changed.
			cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--cpus", "2",
				"--name", "ctrlz-node-test-w5c-install-"+name,
				"-v", work+":/work:ro", image, "sh", "/work/sh/scenarios.sh", name)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("scenario %s: %v\n%s", name, err, out.String())
			}
			if !strings.Contains(out.String(), "PASS "+name) {
				t.Fatalf("scenario %s printed no PASS:\n%s", name, out.String())
			}
		})
	}
}
