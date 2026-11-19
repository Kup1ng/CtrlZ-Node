package policy

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/vectors"
)

// TestGoldenVectors runs every shared golden vector from the node module. Today
// the harness is the shared reference one, which proves the node's copy of
// shared passes. In P4 this is replaced by a harness that drives the real glue
// (mmap loader, EndpointView conversion, cache and router) over the same files,
// and a node whose glue drifts from the shared evaluator then fails here.
func TestGoldenVectors(t *testing.T) {
	vectors.Run(t, vectors.Reference{})
}
