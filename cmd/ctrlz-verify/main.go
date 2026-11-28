// Command ctrlz-verify is the small static verifier of the node install
// (p4-nodes 4.2 step 2, 7.1). node.sh checks its SHA-256 against the value the
// release job wrote into the script, then runs it on the downloaded manifest and
// bundle before anything is installed. It reads no network and holds no secret.
package main

import (
	"os"

	"github.com/Kup1ng/CtrlZ-Node/internal/verify"
)

func main() { os.Exit(verify.Main(os.Args[1:], os.Stdout, os.Stderr)) }
