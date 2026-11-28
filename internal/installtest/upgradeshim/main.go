// Command upgradeshim runs upgrade.Run as a program, for the container install
// test: the real ctrlz-node binary gets the subcommand at merge C, and the test
// must exercise the same code path (the staging copy, the root-owned ctrlz-verify,
// apply.sh) today.
package main

import (
	"os"

	"github.com/Kup1ng/CtrlZ-Node/internal/upgrade"
)

func main() { os.Exit(upgrade.Run(os.Args[1:])) }
