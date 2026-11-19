// Package policy is the node's hot-path glue around the shared evaluator
// (contract section 1: "node internal/policy holds hot-path glue only").
//
// It converts compiled records into the evaluator's runtime types
// (policy.EndpointView, policy.Stack), owns mmap of blobs and tables, and
// supplies the Resolver port backed by the cache and router. It must not
// contain a decision rule of its own: every rule lives in the shared module and
// is pinned by the golden vectors, which this package runs (R45).
package policy

import (
	"context"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"

	"github.com/Kup1ng/CtrlZ-Node/internal/config"
)

// Resolver adapts the node's cache and router to the evaluator's Resolver port.
type Resolver struct{}

// Lookup implements the shared policy.Resolver. Stub.
func (Resolver) Lookup(ctx context.Context, n names.Name, qtype uint16, p sharedpolicy.ResolveParams) (*sharedpolicy.TrueAnswer, error) {
	return nil, config.ErrNotImplemented
}

var _ sharedpolicy.Resolver = Resolver{}
