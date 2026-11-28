package agent

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/bundledl"
)

// installedVersionPath is the root-owned record of the node version installed by
// node.sh or `ctrlz-node upgrade`; the agent may read it and cannot change it.
const installedVersionPath = "/etc/ctrlz/versions/node"

// FetchNodeBundle downloads the node bundle of a version from the hub into
// <root>/bundles/node/<version> and verifies it against the trusted root (p4-nodes
// 7.1, T-359). It installs nothing: the owner's `sudo ctrlz-node upgrade <version>`
// verifies again as root. What asks for a version is the owner's tooling; the hub's
// protocol carries no upgrade announcement in P4.
func (a *Agent) FetchNodeBundle(ctx context.Context, version uint64) (*signv1.Manifest, error) {
	d := bundledl.New(bundledl.Config{
		Hub:  func() bundledl.Hub { return a.xferPool.Client() },
		Root: a.cfg.TrustRoot,
		Dir:  filepath.Join(a.cfg.Root, "bundles"),
		Installed: func() uint64 {
			b, err := a.cfg.Files.ReadFile(installedVersionPath)
			if err != nil {
				return 0
			}
			v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			return v
		},
		Now: a.hubNow,
	})
	return d.Download(ctx, version)
}
