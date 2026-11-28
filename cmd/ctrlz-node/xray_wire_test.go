package main

import (
	"context"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/xray"
)

// The Xray manager lives in a package that imports agent, so boot cannot build it and
// the agent role hands it in through the tune hook. This test is the INT-r1-1 check of
// that wiring: a role that stops passing wireXray, or a wireXray that stops adding the
// manager or stops sharing the Faults and the DNS with the other parts, fails here
// although every test of the manager alone still passes.
func TestAgentRoleWiresTheXrayManager(t *testing.T) {
	var tune func(*agent.Config)
	err := runAgent(context.Background(), "test", func(_ context.Context, version string, f func(*agent.Config)) error {
		if version != "test" {
			t.Errorf("version %q", version)
		}
		tune = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tune == nil {
		t.Fatal("the agent role passes no tune: no Xray manager would be built")
	}
	cfg := agent.Config{Root: t.TempDir()}
	tune(&cfg)
	var m *xray.Manager
	for _, p := range cfg.Parts {
		if x, ok := p.(*xray.Manager); ok {
			m = x
		}
	}
	if m == nil {
		t.Fatal("the tune adds no Xray manager to the parts")
	}
	// The parts that boot makes after the tune (block, peer) fill Faults and DNS only
	// when they are nil, so these two must be set for all of them to share one pair.
	if cfg.Faults == nil || cfg.DNS == nil {
		t.Fatalf("faults %v, dns %v: the parts would not share them", cfg.Faults != nil, cfg.DNS != nil)
	}
}
