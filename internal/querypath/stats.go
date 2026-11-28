package querypath

import (
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/cache"
)

// window is how far back Heartbeat.qps and cache_hit_permille look (SC 8a.4: the
// last 60 s).
const window = 60 * time.Second

type sample struct {
	at           time.Time
	queries      uint64
	hits, misses uint64
}

type meter struct {
	mu sync.Mutex
	s  []sample
}

// stats is the function the Sink calls every 5 s for the numbers of the Heartbeat
// that only dns knows. qps and the hit rate are over the last 60 s (or since the
// start while it is younger), taken from counters that never reset.
func (j *Join) stats() sock.Stats {
	now := time.Now()
	cs := j.Cache.Stats(cache.Shared)
	cur := sample{at: now, queries: j.cnt.queries.Load(), hits: cs.Hits, misses: cs.Misses}

	j.meter.mu.Lock()
	if len(j.meter.s) == 0 {
		j.meter.s = append(j.meter.s, j.start)
	}
	j.meter.s = append(j.meter.s, cur)
	for len(j.meter.s) > 2 && now.Sub(j.meter.s[1].at) >= window {
		j.meter.s = j.meter.s[1:]
	}
	old := j.meter.s[0]
	j.meter.mu.Unlock()

	st := sock.Stats{Isolated: j.isolatedNow()}
	if dt := cur.at.Sub(old.at).Seconds(); dt > 0 {
		st.QPS = uint32(float64(cur.queries-old.queries)/dt + 0.5)
	}
	if lookups := (cur.hits - old.hits) + (cur.misses - old.misses); lookups > 0 {
		st.CacheHitPermille = uint32((cur.hits - old.hits) * 1000 / lookups)
	}
	st.Upstreams = j.upstreamHealth()
	return st
}

func (j *Join) isolatedNow() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.isolated()
}

// upstreamHealth lists the health of every resolve path: the Router's own list
// (local Unbound, each upstream, and the upstreams it refused to build as down) and
// the upstreams left out because they point at a node (down as well).
func (j *Join) upstreamHealth() []sock.Health {
	var out []sock.Health
	if r := j.be.r.Load(); r != nil {
		for _, h := range r.Health() {
			out = append(out, sock.Health{ID: h.ID[:], Healthy: h.Healthy, LatencyMS: h.LatencyMS})
		}
	}
	j.mu.Lock()
	loops := j.loops
	j.mu.Unlock()
	for id := range loops {
		out = append(out, sock.Health{ID: append([]byte(nil), id[:]...), Healthy: false})
	}
	return out
}
