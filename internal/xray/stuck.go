package xray

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// The three limits of 5.5 rule 2, all over the TCP sockets of uid ctrlz-xray with
// both slots together (D31).
const (
	LimitExitSilent = 3000
	LimitExitOpen   = 28000
	LimitAllSilent  = 36000
	// stuckStreak is the number of counts in a row, 5 s apart, that asks for a rebuild.
	stuckStreak = 3
)

// SockCounts is one dump of the kernel's sockets of the uid. A remote is "ip:port".
// Silent is ESTABLISHED, not loopback, with no byte ever received and first seen at
// least dial_hold and 10 s ago; Open is every ESTABLISHED, not loopback socket to
// it.
type SockCounts struct {
	Silent    map[string]int
	Open      map[string]int
	AllSilent int
}

// SocketCounter takes that dump. The real one asks the kernel with
// NETLINK_SOCK_DIAG and the tcp_info extension (5.5); it is not part of this package
// yet (it needs a node to be proved on), so a node without it has the check off.
type SocketCounter interface {
	Count(ctx context.Context) (SockCounts, error)
}

type backoff struct {
	start time.Time
	dur   time.Duration
}

func (b backoff) end() time.Time { return b.start.Add(b.dur) }

// stuckState is the memory of 5.5 rule 2. A restart of the agent forgets it: the
// sockets went with the slot.
type stuckState struct {
	mu sync.Mutex // the resolver goroutine writes `resolved`

	resolved    map[string][]netip.Addr
	resolveAt   time.Time
	resolving   bool
	sig         string
	cfgRemotes  map[string][]string // config id -> remotes
	secure      map[string]bool     // remote -> every config reaches it over tls or reality
	streak      map[string]int
	markedR     map[string]bool
	bo          map[string]backoff
	rebuilding  bool
	allStreak   int
	allMarked   map[string]bool
	allRebuild  bool
	lastCount   time.Time
	rebuildNote map[string]bool
}

func newStuckState() stuckState {
	return stuckState{
		resolved: map[string][]netip.Addr{}, cfgRemotes: map[string][]string{}, secure: map[string]bool{},
		streak: map[string]int{}, markedR: map[string]bool{}, bo: map[string]backoff{},
		allMarked: map[string]bool{}, rebuildNote: map[string]bool{},
	}
}

// marked reports whether a config holds a remote that is marked stuck.
func (s *stuckState) marked(id string) bool {
	for _, r := range s.cfgRemotes[id] {
		if s.markedR[r] || s.allMarked[r] {
			return true
		}
	}
	return false
}

func (s *stuckState) any() bool {
	return len(s.markedR) > 0 || len(s.allMarked) > 0
}

// rebuildEnded clears the latches of the rebuild requests that a finished, failed or
// dropped rebuild carried, whichever reason it ran under: a request that was merged
// into another one has no rebuild of its own to clear them.
func (s *stuckState) rebuildEnded(stuck, allSilent bool) {
	if stuck {
		s.rebuilding = false
	}
	if allSilent {
		s.allRebuild = false
	}
}

func remoteKey(a netip.Addr, port int) string {
	return netip.AddrPortFrom(a.Unmap(), uint16(port)).String()
}

// refreshRemotes rebuilds the address sets of the running configs: each outbound of
// the chain, the first hop included (5.5). A name needs the identified Unbound, asked
// in a goroutine every ResolveEvery; until it answers, only IP literals count.
func (m *Manager) refreshRemotes(ctx context.Context, now time.Time) {
	s := &m.stuck
	ids := make([]string, 0, len(m.st.Running))
	for _, r := range m.st.Running {
		ids = append(ids, r.ID+":"+r.Hash)
	}
	sort.Strings(ids)
	sig := strings.Join(ids, ",")
	s.mu.Lock()
	start := m.opt.Resolve != nil && !s.resolving && now.Sub(s.resolveAt) >= m.t.ResolveEvery
	if start {
		s.resolving, s.resolveAt = true, now
	}
	s.mu.Unlock()
	if start {
		hosts := map[string]bool{}
		for _, r := range m.st.Running {
			for _, h := range hopsOf(r.Frag) {
				if _, err := netip.ParseAddr(h.host); err != nil {
					hosts[h.host] = true
				}
			}
		}
		go func() {
			out := map[string][]netip.Addr{}
			for h := range hosts {
				cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				if as, err := m.opt.Resolve(cctx, h); err == nil {
					out[h] = as
				}
				cancel()
			}
			s.mu.Lock()
			s.resolved = out
			s.resolving = false
			s.sig = "" // the sets are computed again at the next count
			s.mu.Unlock()
		}()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sig == s.sig {
		return
	}
	s.sig = sig
	s.cfgRemotes = map[string][]string{}
	secure := map[string]bool{}
	for _, r := range m.st.Running {
		seen := map[string]bool{}
		for _, h := range hopsOf(r.Frag) {
			var as []netip.Addr
			if a, err := netip.ParseAddr(h.host); err == nil {
				as = []netip.Addr{a}
			} else {
				as = s.resolved[h.host]
			}
			for _, a := range as {
				k := remoteKey(a, h.port)
				if !seen[k] {
					seen[k] = true
					s.cfgRemotes[r.ID] = append(s.cfgRemotes[r.ID], k)
				}
				if prev, ok := secure[k]; ok {
					secure[k] = prev && h.secure
				} else {
					secure[k] = h.secure
				}
			}
		}
	}
	s.secure = secure
}

// checkSockets is one count of 5.5 rule 2, every SocketEvery.
func (m *Manager) checkSockets(ctx context.Context, now time.Time) {
	s := &m.stuck
	if m.opt.Sockets == nil || now.Sub(s.lastCount) < m.t.SocketEvery {
		return
	}
	s.lastCount = now
	m.refreshRemotes(ctx, now)
	c, err := m.opt.Sockets.Count(ctx)
	if err != nil {
		return
	}
	s.mu.Lock()
	secure := s.secure
	s.mu.Unlock()

	remotes := map[string]bool{}
	for r := range c.Open {
		remotes[r] = true
	}
	for r := range c.Silent {
		remotes[r] = true
	}
	for r := range s.markedR {
		remotes[r] = true
	}
	for r := range remotes {
		silent, open := c.Silent[r], c.Open[r]
		over := (secure[r] && silent > LimitExitSilent) || open > LimitExitOpen
		under90 := !(secure[r] && silent*10 >= LimitExitSilent*9) && open*10 < LimitExitOpen*9
		active := now.Before(s.bo[r].end())
		switch {
		case over:
			s.markedR[r] = true
			s.streak[r]++
		default:
			s.streak[r] = 0
			// The mark lasts the backoff, and after it while the old slot's drain still
			// holds the stuck sockets (the count above 90% of the limit).
			if s.markedR[r] && !active && under90 {
				delete(s.markedR, r)
			}
		}
		if s.streak[r] >= stuckStreak && !active && !s.rebuilding {
			s.streak[r] = 0
			s.bo[r] = m.nextBackoff(s.bo[r], now)
			s.rebuilding = true
			m.queueRebuild(rbStuck, "")
		}
	}
	m.checkAllSilent(c, now)
	m.setFault(hubv1.NodeFault_NODE_FAULT_XRAY_STUCK, s.any())
}

// nextBackoff is 10 min from the request, doubling (20, 40, at most 60 min) for a
// request for the same remote within an hour after the end of the last backoff.
func (m *Manager) nextBackoff(prev backoff, now time.Time) backoff {
	d := 10 * time.Minute
	if prev.dur > 0 && now.Sub(prev.end()) <= time.Hour {
		d = min(prev.dur*2, time.Hour)
	}
	return backoff{start: now, dur: d}
}

// checkAllSilent is the memory limit of the uid: over 36,000 silent sockets, the
// configs of the remotes with the most silent sockets are marked until the rest is
// under it, and three counts in a row ask for the immediate rebuild.
func (m *Manager) checkAllSilent(c SockCounts, now time.Time) {
	s := &m.stuck
	if c.AllSilent <= LimitAllSilent {
		s.allStreak = 0
		s.allMarked = map[string]bool{}
		return
	}
	s.allStreak++
	type rs struct {
		r string
		n int
	}
	var list []rs
	for r, n := range c.Silent {
		list = append(list, rs{r, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].r < list[j].r
	})
	s.allMarked = map[string]bool{}
	rest := c.AllSilent
	for _, e := range list {
		if rest <= LimitAllSilent {
			break
		}
		s.allMarked[e.r] = true
		rest -= e.n
	}
	if s.allStreak >= stuckStreak && !s.allRebuild {
		s.allRebuild, s.allStreak = true, 0
		m.queueRebuild(rbAllSilent, "")
	}
}

// formatPort is a helper for tests that build remotes.
func formatPort(p int) string { return strconv.Itoa(p) }
