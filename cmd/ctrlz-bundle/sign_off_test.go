//go:build !ctrlz_lab

package main

import "testing"

// A release build has no signing command at all: production manifests are signed
// offline by the owner (3.3), never by this tool.
func TestReleaseBuildCannotSign(t *testing.T) {
	if code := run([]string{"sign-lab", "--dir", "x", "--seed", "y"}); code != 2 {
		t.Fatalf("exit %d", code)
	}
}
