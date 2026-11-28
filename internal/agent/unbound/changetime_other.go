//go:build !linux

package unbound

import (
	"os"
	"time"
)

// fileChangeTime on a development host: the node runs only on Linux.
func fileChangeTime(path string) (time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}
