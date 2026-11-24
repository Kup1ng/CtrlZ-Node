//go:build linux

package image_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
)

// dns is another user in the group, so an image directory must be 0750 whatever
// the agent's umask is, and must keep the setgid bit of image/ so its files get
// the group (review round 2, r2-1 and r2-2).
func TestImageDirectoryModeIgnoresUmaskAndKeepsSetgid(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750|fs.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	name, err := image.Build(&fsx.Writer{}, dir, input(t, 1, 2))
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o750 || st.Mode()&fs.ModeSetgid == 0 {
		t.Fatalf("image directory mode %v", st.Mode())
	}
}
