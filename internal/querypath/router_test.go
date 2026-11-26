package querypath

import (
	"testing"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

func cfgWith(version uint64, mode commonv1.ResolveMode, addr string) *hubv1.NodeConfig {
	return &hubv1.NodeConfig{
		Version: version, ProofKey: []byte{byte(version)}, Zones: []string{"dns.example.net"}, PanelHostnames: []string{"panel.example.net"},
		Mode:      mode,
		Upstreams: []*hubv1.Upstream{{Id: make([]byte, 16), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr, TimeoutMs: 3000, HealthIntervalS: 1}},
		Rules:     []*hubv1.ResolverRule{{Order: 1, MatchValue: "example.com", Group: "g"}},
	}
}

// p4n-MB-r1-1: a NodeConfig that arrives again, or with only a version, a proof_key
// or a hostname changed, must not rebuild the Router (which purges the cache and
// resets every upstream's health); a change in what the Router is built from must.
func TestResolveKeyIgnoresWhatTheRouterDoesNotUse(t *testing.T) {
	base := cfgWith(1, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, "192.0.2.1:53")
	same := cfgWith(2, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, "192.0.2.1:53")
	same.PanelHostnames = []string{"other.example.net"}
	same.Zones = nil
	if resolveKey(base) != resolveKey(same) {
		t.Fatal("a version, proof_key, zone or hostname change alone changed the resolve key")
	}
	if resolveKey(base) != resolveKey(cfgWith(1, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, "192.0.2.1:53")) {
		t.Fatal("equal configs gave different keys")
	}
	for name, c := range map[string]*hubv1.NodeConfig{
		"mode":     cfgWith(1, commonv1.ResolveMode_RESOLVE_MODE_HYBRID, "192.0.2.1:53"),
		"upstream": cfgWith(1, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, "192.0.2.2:53"),
	} {
		if resolveKey(base) == resolveKey(c) {
			t.Errorf("a change of the %s did not change the resolve key", name)
		}
	}
	ruled := cfgWith(1, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, "192.0.2.1:53")
	ruled.Rules[0].MatchValue = "example.org"
	if resolveKey(base) == resolveKey(ruled) {
		t.Error("a change of a rule did not change the resolve key")
	}
	// The Plain-only fallback is rebuilt from nothing each call: it must be stable.
	nilA := &hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE}
	nilB := &hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE}
	if resolveKey(nilA) != resolveKey(nilB) {
		t.Error("the fallback config has no stable key")
	}
}
