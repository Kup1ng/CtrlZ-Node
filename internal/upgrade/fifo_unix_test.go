//go:build unix

package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO where a listed file should be must be refused, not waited for: a blocking
// open of a FIFO with no writer never returns, and the upgrade runs as root. The
// agent can swap a file for a FIFO between any check and the open, so the open
// itself must not block (open_unix.go).
func TestFifoInTheDownloadIsRefusedWithoutBlocking(t *testing.T) {
	h := newHost(t, 2)
	p := filepath.Join(h.src, "bin/ctrlz-node")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	applied := false
	h.runner.onApply = func(call) error { applied = true; return nil }
	done := make(chan error, 1)
	go func() { done <- h.env.Do(context.Background(), 4) }()
	select {
	case err := <-done:
		if err == nil || applied {
			t.Fatalf("a FIFO was installed: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the upgrade blocked on a FIFO")
	}
}
