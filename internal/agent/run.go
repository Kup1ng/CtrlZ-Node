package agent

import (
	"context"
	"os"
	"sync"
	"time"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/labroot"
)

// Production paths (p4-nodes 7.1, 7.2).
const (
	DefaultRoot = "/var/lib/ctrlz"
	DefaultConf = "/etc/ctrlz/agent.conf"
	DefaultSock = "/run/ctrlz/agent.sock"
	SockGroup   = "ctrlz"
	DNSUser     = "ctrlz-dns"
	// UnboundConfDir is where the agent writes both Unbound configs; the two Unbound
	// units read them from here (packaging/systemd).
	UnboundConfDir   = "/etc/ctrlz/unbound"
	rootRefreshEvery = time.Minute
)

// Main is the agent role: it reads agent.conf and the keys, enrols the node when it
// has no certificate yet, builds the real Config and runs until ctx ends.
// Environment overrides exist for development only and are not read when unset:
// CTRLZ_ROOT, CTRLZ_AGENT_CONF, CTRLZ_AGENT_SOCK.
func Main(ctx context.Context, version string) error {
	return boot(ctx, bootEnv{
		Version:  version,
		Root:     envOr("CTRLZ_ROOT", DefaultRoot),
		ConfPath: envOr("CTRLZ_AGENT_CONF", DefaultConf),
		SockPath: envOr("CTRLZ_AGENT_SOCK", DefaultSock),
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// rootCache reads keys/root.json and re-reads it at most once a minute, so a
// root rotation installed by the root-owned upgrade is seen without a restart.
type rootCache struct {
	path string
	mu   sync.Mutex
	at   time.Time
	root *signv1.Root
	err  error
}

func (c *rootCache) get() (*signv1.Root, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.root != nil && time.Since(c.at) < rootRefreshEvery {
		return c.root, nil
	}
	r, err := hubconn.LoadRoot(c.path)
	if err == nil {
		// A build without the ctrlz_lab tag never trusts the lab test root, whose private
		// keys are public (7.1). The check is on every load, not only the first: a lab
		// root dropped in later is treated as an unreadable file, so the last good root
		// stays in force and the lab one is never used.
		err = labroot.Check(r)
	}
	if err != nil {
		if c.root != nil {
			return c.root, nil // keep the last good root while the file is being replaced
		}
		return nil, err
	}
	c.root, c.at = r, time.Now()
	return r, nil
}

// load reads the root once at start, so a lab root is refused before the node says
// anything to the hub, and tells that refusal apart from a file that is merely
// missing or unreadable (the agent then runs as it did before, without a root,
// and every head is refused until one is installed).
func (c *rootCache) load() error {
	_, err := c.get()
	if err != nil && isLabRoot(err) {
		return err
	}
	return nil
}
