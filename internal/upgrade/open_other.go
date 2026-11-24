//go:build !unix

package upgrade

import "os"

// The node runs on Linux only; this keeps the package building on a development host.
func openRegular(src *os.Root, rel string) (*os.File, error) { return src.Open(rel) }
