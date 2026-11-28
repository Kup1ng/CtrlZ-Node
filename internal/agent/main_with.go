package agent

import "context"

// MainWith is Main with a hook that edits the Config before the agent is built. The
// parts of P4b (the Xray manager and the others) live in packages that import this
// one, so the boot code cannot build them without a cycle: the caller builds them and
// hands them in here, in Config.Parts, with the Faults and the DNS they share.
func MainWith(ctx context.Context, version string, tune func(*Config)) error {
	return boot(ctx, bootEnv{
		Version:  version,
		Root:     envOr("CTRLZ_ROOT", DefaultRoot),
		ConfPath: envOr("CTRLZ_AGENT_CONF", DefaultConf),
		SockPath: envOr("CTRLZ_AGENT_SOCK", DefaultSock),
		Tune:     tune,
	})
}
