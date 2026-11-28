package querypath

import (
	"context"
	"sync/atomic"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Node/internal/resolve"
)

// backend is the policy.Backend the resolver holds for the node's whole life. The
// Router behind it is swapped whole when the NodeConfig's resolve part changes,
// which keeps the Resolver and the Handler built once. A nil Router is a node with
// no usable path (every upstream of an upstream-only config is a node's own
// address): every miss fails and the evaluator answers SERVFAIL (SC 5.12).
type backend struct {
	r atomic.Pointer[resolve.Router]
}

func (b *backend) Route(n *names.Name, qtype uint16) string {
	if r := b.r.Load(); r != nil {
		return r.Route(n, qtype)
	}
	return ""
}

func (b *backend) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	r := b.r.Load()
	if r == nil {
		return nil, "", resolve.ErrNoPath
	}
	return r.Exchange(ctx, req)
}
