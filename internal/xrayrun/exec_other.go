//go:build !unix

package xrayrun

import "errors"

func execve(string, []string) error { return errors.New("xrayrun: exec is not available here") }
