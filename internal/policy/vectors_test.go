package policy

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/vectors"
)

// TestGoldenVectors runs every shared golden vector from the node module with the
// shared reference harness, which proves the node's copy of shared passes. The
// harness that drives the node's own glue (system names step, answer conversion,
// the handler's environment) is TestGoldenVectorsThroughTheGlue in internal/dns,
// because it needs the handler; a node whose glue drifts from the shared
// evaluator fails there (R45).
func TestGoldenVectors(t *testing.T) {
	vectors.Run(t, vectors.Reference{})
}
