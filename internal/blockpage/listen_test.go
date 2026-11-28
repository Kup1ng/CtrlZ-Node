package blockpage

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// INT2-r1-7: the socket ends at 0660 and nothing wider. The order (group first, mode
// last) cannot be seen from outside a setgid directory, which the lab covers.
func TestListenUnixModeIs0660(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	p := filepath.Join(t.TempDir(), "s.sock")
	ln, err := listenUnix(p, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Errorf("mode %o, want 660", got)
	}
}
