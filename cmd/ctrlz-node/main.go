// Command ctrlz-node is the one node binary. systemd starts it three times as
// separate services (dns, proxy, agent), so a crash in the proxy cannot take
// DNS down and each service gets only the privileges and sockets it needs. One
// binary keeps the three in lockstep: they cannot be upgraded out of sync.
//
// Everything here is a stub for now. The roles exist so the package layout,
// the build and the shared-module wiring are real before any logic lands.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/config"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns"
	"github.com/Kup1ng/CtrlZ-Node/internal/proxy"
)

// version is stamped at release time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ctrlz-node dns|proxy|agent|version")
		return 2
	}
	var err error
	switch args[0] {
	case "version":
		fmt.Println(version)
		return 0
	case "dns":
		err = dns.Run(config.Load())
	case "proxy":
		err = proxy.Run(config.Load())
	case "agent":
		err = agent.Run(config.Load())
	default:
		fmt.Fprintf(os.Stderr, "unknown role %q\n", args[0])
		return 2
	}
	if errors.Is(err, config.ErrNotImplemented) {
		fmt.Fprintf(os.Stderr, "ctrlz-node %s: not implemented yet (P4)\n", args[0])
		return 3
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctrlz-node %s: %v\n", args[0], err)
		return 1
	}
	return 0
}
