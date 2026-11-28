//go:build unix

package upgrade

import (
	"os"
	"syscall"
)

// openRegular opens rel for reading without ever blocking and without following a
// final symlink. The bundle directory belongs to the agent, so a check made before
// the open (Lstat) says nothing about what is opened: the agent may swap the file
// for a FIFO in between, and a blocking open of a FIFO waits for a writer that never
// comes, which would hang the root upgrade. O_NONBLOCK makes that open return, and
// the caller then inspects the handle it holds.
func openRegular(src *os.Root, rel string) (*os.File, error) {
	return src.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
