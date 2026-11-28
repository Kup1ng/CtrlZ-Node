package main

import "testing"

func TestRunRolesThatNeedNoSystem(t *testing.T) {
	if got := run(nil); got != 2 {
		t.Errorf("no role: exit %d", got)
	}
	if got := run([]string{"nope"}); got != 2 {
		t.Errorf("unknown role: exit %d", got)
	}
	if got := run([]string{"version"}); got != 0 {
		t.Errorf("version: exit %d", got)
	}
}

func TestTheQueryPathIsJoined(t *testing.T) {
	// A nil factory would run the refusing handler: the node would serve nothing.
	if queryPath() == nil {
		t.Fatal("the dns role has no query path")
	}
}

// The upgrade subcommand reaches internal/upgrade (it is not an unknown role, which
// exits 2 with "unknown role"): a bad version is its own usage error, and a good one
// is refused on a host that was not installed by node.sh (or, off root, as not root).
func TestUpgradeSubcommandIsWired(t *testing.T) {
	if got := run([]string{"upgrade"}); got != 2 {
		t.Errorf("upgrade with no version: exit %d", got)
	}
	if got := run([]string{"upgrade", "one"}); got != 2 {
		t.Errorf("upgrade with a bad version: exit %d", got)
	}
	if got := run([]string{"upgrade", "4000000000"}); got != 1 {
		t.Errorf("upgrade on a host with no install: exit %d, want a refusal (1)", got)
	}
}
