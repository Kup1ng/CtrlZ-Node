package agent_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
)

// p4n-MC-r1-7: a certificate whose subject is no node id must not give the agent an
// all-zero identity (it would not find itself in the PairTable and would probe its
// own address as a peer). The agent refuses to be built; a dashed UUID is a node id.
func TestAgentRefusesACertificateThatIsNoNodeID(t *testing.T) {
	for _, cn := range []string{"node-1", "", "a0a0", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"} {
		l := newLab(t)
		l.cfg.Identity, _ = newIdentityCN(t, false, cn)
		if _, err := agent.New(l.cfg); err == nil {
			t.Errorf("an agent was built for the subject %q", cn)
		}
	}
	l := newLab(t)
	l.cfg.Identity, _ = newIdentityCN(t, false, "a0a0a0a0-a0a0-a0a0-a0a0-a0a0a0a0a0a0")
	if _, err := agent.New(l.cfg); err != nil {
		t.Errorf("a dashed UUID subject was refused: %v", err)
	}
}
