//go:build !ctrlz_lab

package main

import (
	"fmt"
	"os"
)

// signLab does not exist in a release build: production manifests are signed
// offline with the owner's root keys, never by this tool.
func signLab([]string) int {
	fmt.Fprintln(os.Stderr, "ctrlz-bundle: sign-lab is in lab builds only (tag ctrlz_lab)")
	return 2
}
