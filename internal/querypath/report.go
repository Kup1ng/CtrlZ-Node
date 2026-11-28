package querypath

import (
	"context"
	"sync/atomic"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
)

// reporter turns what the query path reports into the Sink's calls. The Sink is
// best effort and never blocks, which is what the Handler requires of a Reporter
// (it runs on the query's goroutine). None of the messages holds a query name.
type reporter struct{ sink *dnsrole.Sink }

func (r reporter) Proof(p *hubv1.ProofObservation) {
	r.sink.Outbound(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: p}})
}

func (r reporter) LearnedIP(l *hubv1.LearnedIP) {
	r.sink.Outbound(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_LearnedIp{LearnedIp: l}})
}

func (r reporter) Activity(e *telemetryv1.ActivityEntry) {
	if len(e.EndpointId) != 16 {
		return
	}
	r.sink.Activity([16]byte(e.EndpointId), e.ClientLabel, e.ClaimId, e.SourceIpHash, e.Protocol, time.Unix(e.LastSeenBucket, 0))
}

// counters are the node's own numbers. They hold no name and no address.
type counters struct {
	queries  atomic.Uint64
	rejected atomic.Uint64 // answers the Sanity Gate refused (SC 11)
}

// Rejected is how many answers the Sanity Gate has refused since the start, for
// the injection alert.
func (j *Join) Rejected() uint64 { return j.cnt.rejected.Load() }

// counted counts the queries the listeners hand over, for Heartbeat.qps.
type counted struct {
	h listen.Handler
	n *atomic.Uint64
}

func (c counted) ServeDNS(ctx context.Context, req *listen.Request) listen.Reply {
	c.n.Add(1)
	return c.h.ServeDNS(ctx, req)
}

func (j *Join) counting() listen.Handler { return counted{h: j.Handler, n: &j.cnt.queries} }
