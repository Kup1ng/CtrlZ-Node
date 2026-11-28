//go:build linux

package xrayctl

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child in a group of its own and makes the timeout kill
// the group, so a child that forked is not left behind (7.5: "kills the child's
// group after 10 s").
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
