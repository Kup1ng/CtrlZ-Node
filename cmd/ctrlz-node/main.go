// Command ctrlz-node is the one node binary. systemd starts it as separate
// services (dns, proxy, agent), so a crash in the proxy cannot take DNS down and
// each service gets only the privileges and sockets it needs. One binary keeps
// the roles in lockstep: they cannot be upgraded out of sync.
//
// Roles: dns serves queries, agent holds the panel link and the host side, proxy
// is idle in P4 and binds nothing, block serves the branded block page (internal/blockpage), upgrade is the root one-shot that installs a
// downloaded node bundle (internal/upgrade), version prints the version.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/blockpage"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/upgrade"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayctl"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// version is stamped at release time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ctrlz-node dns|proxy|agent|block|xrayctl|xray-run <slot>|upgrade <version>|version")
		return 2
	}
	if args[0] == "version" {
		fmt.Println(version)
		return 0
	}
	// upgrade is the root one-shot of 7.1. It handles HUP, INT and TERM itself, so that
	// apply.sh's exit trap runs and the staging directory is removed; it must not sit
	// under the signal context below, which would turn the first signal into a plain
	// cancel that nothing here waits for.
	// xray-run replaces itself with Xray (7.6), so it too needs no signal context.
	if args[0] == "xray-run" {
		return xrayrun.Run(args[1:], xrayrun.OSEnv())
	}
	if args[0] == "upgrade" {
		return upgrade.Run(args[1:])
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "dns":
		err = runDNS(ctx)
	case "proxy":
		// Idle in P4: the proxy role binds nothing and holds nothing. The unit exists
		// so the install and the sandbox are the final ones when P4b fills it.
		<-ctx.Done()
	case "agent":
		// The parts that live in packages importing agent (the Xray manager) are built
		// by the tune hook, because boot cannot import them without a cycle.
		err = runAgent(ctx, version, agent.MainWith)
	case "block":
		// The branded block page process (p4b-proxy 10): unit ctrlz-block, no capability.
		err = blockpage.Run(ctx, blockpage.Config{})
	case "xrayctl":
		// The privileged Xray helper (p4b-proxy 3.2): starts and stops Xray for the manager.
		err = xrayctl.Main(ctx, "")
	default:
		fmt.Fprintf(os.Stderr, "unknown role %q\n", args[0])
		return 2
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "ctrlz-node %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// runAgent starts the agent with the parts that live outside package agent. mainWith is
// agent.MainWith in production; a test hands its own to see what this passes as the
// tune, because a merge that drops the line leaves the agent without the Xray manager
// and builds and passes every test of the manager alone.
func runAgent(ctx context.Context, version string, mainWith func(context.Context, string, func(*agent.Config)) error) error {
	return mainWith(ctx, version, wireXray)
}

func runDNS(ctx context.Context) error {
	return dnsrole.Run(ctx, dnsrole.Config{
		Root:      envOr("CTRLZ_ROOT", agent.DefaultRoot),
		AgentConf: envOr("CTRLZ_AGENT_CONF", agent.DefaultConf),
		SockPath:  envOr("CTRLZ_AGENT_SOCK", agent.DefaultSock),
		Build:     queryPath(),
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
