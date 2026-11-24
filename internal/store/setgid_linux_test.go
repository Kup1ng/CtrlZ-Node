//go:build linux

package store_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// The install script gives the group-shared directories setgid so that what the
// agent creates later gets group ctrlz. Open fixes modes at every start and must
// not drop that bit (review round 2, r2-1).
func TestOpenKeepsSetgidOnTheSharedDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ctrlz")
	open(t, dir, nil)
	shared := []string{"", store.DirBlobs, store.DirImage, store.DirConfig}
	for _, n := range shared {
		if err := os.Chmod(filepath.Join(dir, n), 0o750|fs.ModeSetgid); err != nil {
			t.Fatal(err)
		}
	}
	open(t, dir, nil)
	for _, n := range shared {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode()&fs.ModeSetgid == 0 || st.Mode().Perm() != 0o750 {
			t.Fatalf("%q: mode %v after Open", n, st.Mode())
		}
	}
	// A directory that never had the bit does not gain it.
	st, _ := os.Stat(filepath.Join(dir, store.DirState))
	if st.Mode()&fs.ModeSetgid != 0 {
		t.Fatal("state/ gained setgid")
	}
}
