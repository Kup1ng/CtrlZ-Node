//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

// The experiments that need Linux (unix sockets, /proc, systemd, strace) are skipped elsewhere; this file lets the program
// build and run its portable half on a developer machine.

func exitInfo(cmd *exec.Cmd, err error) (int, string) {
	if cmd.ProcessState == nil {
		return -3, ""
	}
	return cmd.ProcessState.ExitCode(), ""
}

type fullListener struct{ port int }

func newFullListener() (*fullListener, error) { return nil, errors.New("not on linux") }
func (l *fullListener) close()                {}
func synSentTo(port int) int                  { return -1 }
func procIO(pid int) map[string]int64         { return nil }
func rssKB(pid int) int64                     { return -1 }

const onLinux = false
