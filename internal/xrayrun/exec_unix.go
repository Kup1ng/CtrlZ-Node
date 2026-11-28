//go:build unix

package xrayrun

import (
	"os"
	"syscall"
)

func execve(path string, argv []string) error { return syscall.Exec(path, argv, os.Environ()) }
