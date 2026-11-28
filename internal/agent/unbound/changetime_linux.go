package unbound

import (
	"os"
	"syscall"
	"time"
)

// fileChangeTime is the later of a file's modification and status-change time. A
// package manager keeps the modification time the package was built with, so only
// the status-change time says when dpkg put the file there.
func fileChangeTime(path string) (time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	t := fi.ModTime()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if c := time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)); c.After(t) {
			t = c
		}
	}
	return t, nil
}
