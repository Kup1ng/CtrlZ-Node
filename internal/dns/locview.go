package dns

import (
	"encoding/binary"
	"sort"

	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// locView is the node's view of its proxy locations (6.4), built from one
// `locations` message of the agent and never changed afterwards, so a query that
// holds one sees a whole list. It implements policy.LocationView and also orders
// the SOCKS targets of a verdict.
type locView struct {
	guard    bool
	direct   string
	draining map[string]bool
	// held is every SOCKS address of the list: configs, direct and draining ones. A
	// connection on an address outside it is ended (4.6).
	held   map[string]bool
	byLoc  map[uint16][]cfgInfo // healthy configs, sorted (priority, latency, id)
	exitOf map[string]string    // SOCKS address to exit key, for every config
}

type cfgInfo struct {
	id    [16]byte
	socks string
	exit  string
	prio  uint32
	ms    uint32
}

// noLocations is the view of a node with no usable location: every location is
// unavailable, so a Redirect to one is a Bypass with FlagLocationUnavailable.
var noLocations = &locView{held: map[string]bool{}, byLoc: map[uint16][]cfgInfo{}, exitOf: map[string]string{}}

func newLocView(l *sock.Locations) *locView {
	v := &locView{guard: l.Guard, direct: l.Direct, draining: map[string]bool{}, held: map[string]bool{},
		byLoc: map[uint16][]cfgInfo{}, exitOf: map[string]string{}}
	for _, d := range l.Draining {
		v.draining[d] = true
		v.held[d] = true
	}
	if l.Direct != "" {
		v.held[l.Direct] = true
		v.exitOf[l.Direct] = "direct"
	}
	for _, c := range l.Configs {
		v.held[c.Socks] = true
		ci := cfgInfo{socks: c.Socks, exit: string(c.Exit), prio: c.Priority, ms: c.LatencyMS}
		copy(ci.id[:], c.ID)
		v.exitOf[c.Socks] = ci.exit
		if !c.Healthy || c.Location > 0xFFFF || v.draining[c.Socks] {
			continue
		}
		v.byLoc[uint16(c.Location)] = append(v.byLoc[uint16(c.Location)], ci)
	}
	for _, cs := range v.byLoc {
		sort.Slice(cs, func(i, j int) bool {
			a, b := cs[i], cs[j]
			if a.prio != b.prio {
				return a.prio < b.prio
			}
			if a.ms != b.ms {
				return a.ms < b.ms
			}
			return string(a.id[:]) < string(b.id[:])
		})
	}
	return v
}

// usable is false while the nftables guard is off: with it every location counts as
// unavailable (5.5).
func (v *locView) usable() bool { return v != nil && v.guard }

// Healthy: the node has a healthy config of the location.
func (v *locView) Healthy(wire uint16) bool { return v.usable() && len(v.byLoc[wire]) > 0 }

// best is the latency of a location: the best of its healthy configs of the lowest
// priority number (6.4).
func (v *locView) best(wire uint16) uint32 {
	cs := v.byLoc[wire]
	m := ^uint32(0)
	for _, c := range cs {
		if c.prio != cs[0].prio {
			break
		}
		m = min(m, c.ms)
	}
	return m
}

// Auto returns the candidate with the lowest published latency. The agent already
// holds the hysteresis (it publishes a value only when it moved by more than 20% and
// 10 ms), so the pick is a plain minimum, the lowest wire id on a tie.
func (v *locView) Auto(cands []uint16) (uint16, bool) {
	if !v.usable() {
		return 0, false
	}
	var best uint16
	bm, found := ^uint32(0), false
	for _, c := range cands {
		if len(v.byLoc[c]) == 0 {
			continue
		}
		if m := v.best(c); !found || m < bm || m == bm && c < best {
			best, bm, found = c, m, true
		}
	}
	return best, found
}

// targets are the configs of a location in the order of 6.4, at most max: the healthy
// ones of the lowest priority number first (fixed and Auto by latency, Random
// starting at the config its day hash names), then the rest as later targets.
func (v *locView) targets(loc uint16, random bool, endpoint [16]byte, name []byte, now int64, max int) []cfgInfo {
	if !v.usable() {
		return nil
	}
	cs := v.byLoc[loc]
	if len(cs) == 0 {
		return nil
	}
	n := 0
	for n < len(cs) && cs[n].prio == cs[0].prio {
		n++
	}
	first := append([]cfgInfo(nil), cs[:n]...)
	if random && n > 1 {
		// Sorted by id, so every node and every day-start picks the same config, as for
		// RandomPick over locations; the rest of the group follows in latency order.
		ids := append([]cfgInfo(nil), first...)
		sort.Slice(ids, func(i, j int) bool { return string(ids[i].id[:]) < string(ids[j].id[:]) })
		buf := make([]byte, 0, 16+len(name)+4)
		buf = append(buf, endpoint[:]...)
		buf = append(buf, name...)
		buf = binary.BigEndian.AppendUint32(buf, uint32(now/86400))
		pick := ids[names.Hash64(names.ProfileKey(), buf)%uint64(len(ids))]
		rest := make([]cfgInfo, 0, n)
		for _, c := range first {
			if c.id != pick.id {
				rest = append(rest, c)
			}
		}
		first = append([]cfgInfo{pick}, rest...)
	}
	out := append(first, cs[n:]...)
	if len(out) > max {
		out = out[:max]
	}
	return out
}
