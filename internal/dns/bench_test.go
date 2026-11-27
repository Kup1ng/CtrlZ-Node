package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// The identified path on a cache hit: identity, 4b, SelectStack, Pre, cache, Post
// and the message built. It is the cost of one query that the node serves from its
// cache, and the number T-412 compares with the 20,000 a second a node must hold.
func BenchmarkIdentifiedCacheHit(b *testing.B) {
	w := newWorld(b)
	req := &listen.Request{Msg: mkq("www.example.com", dns.TypeA, qopt{}), Transport: listen.DoT, Source: netip.MustParseAddrPort("127.0.0.1:5000"), Validated: true, SNI: rid(epB) + "." + testZone}
	ctx := context.Background()
	w.h.ServeDNS(ctx, req) // fill
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if r := w.h.ServeDNS(ctx, req); r.Msg == nil {
				b.Fatal("no reply")
			}
		}
	})
}
