//go:build !linux

package xrayctl

import "os/exec"

// setProcessGroup is a no-op off Linux: the node runs only there, and this keeps the
// package building on a developer machine.
func setProcessGroup(*exec.Cmd) {}
