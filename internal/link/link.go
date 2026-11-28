// Package link is the server end of proxy.sock (p4b-proxy 2.1, 5.1): dns serves it,
// the proxy connects (internal/proxy is the client). It owns the connection, the
// peer checks and the message loop, and nothing else: what a verdict holds, what a
// Grant is, and what a close frees belong to the Backend, so this package can be
// tested against a proxy that is only a fake.
//
// What the socket promises, and why:
//
//   - The peer is judged by SO_PEERCRED before a frame is read. A peer of uid 0
//     (the reader of `ctrlz-node grants-stats`) may send `stats` and nothing else; the
//     proxy's account may send what MayProxySend names. A frame of the other end's
//     type closes the connection.
//   - Nothing in an error, a log line or a counter name holds a name, an address or
//     a source.
//   - One proxy at a time: a new connection of the proxy's account replaces the
//     old, because a restarted proxy must not wait for the dead one's timeout.
package link

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/grant"
)

// Backend is what the link asks of dns. Every method may be called from several
// goroutines, except LinkUp and LinkDown, which come one after the other.
type Backend interface {
	// ProxyConfig is `config`: ok is false until dns has a bind address for the
	// proxy, and the link asks again.
	ProxyConfig() (cfg sock.ProxyConfig, ok bool)
	// LinkUp gets the proxy's whole `open` list. It rebuilds its connection table,
	// judges it against the served image and sends `end` for what must not live
	// (through End), before the link sends `config`.
	LinkUp(run uint64, items []grant.OpenItem)
	LinkDown()
	// Source is the pool question: does the source have a live entry.
	Source(src netip.Addr) bool
	// Lookup answers a verdict. It may wait (200 ms for a Put, 300 ms for a lookup).
	Lookup(ctx context.Context, id uint64, src netip.Addr, name []byte, port uint16) *sock.LinkVerdict
	Moved(*sock.LinkMoved)
	Closed(*sock.LinkClosed)
	State(*sock.LinkState)
	Stats() *sock.LinkStatsRes
}

// Config is what a Server needs.
type Config struct {
	Backend  Backend
	Get      sock.UIDGetter
	ProxyUID uint32
	// HelloWithin bounds the wait for hello and for the open list; zero is 10 s.
	HelloWithin time.Duration
	// MaxLookups bounds the lookups being answered at once; zero is 8192 (12).
	MaxLookups int
}

// Server is the end of proxy.sock that dns runs.
type Server struct {
	cfg Config

	mu  sync.Mutex
	cur *session

	// gate keeps the frames of a replaced session out of the Backend. A frame is
	// handed to the Backend under the read side with a check that its session is
	// still current; the replacement and the Backend's LinkUp (the rebuild) run under
	// the write side. So no late moved, closed or state of the old proxy lands in the
	// table the new proxy's open list built (ids restart with each proxy run).
	gate sync.RWMutex
}

// New makes a Server.
func New(cfg Config) *Server {
	if cfg.HelloWithin == 0 {
		cfg.HelloWithin = 10 * time.Second
	}
	if cfg.MaxLookups == 0 {
		cfg.MaxLookups = 8192
	}
	if cfg.Get == nil {
		cfg.Get = sock.PeerUID
	}
	return &Server{cfg: cfg}
}

type session struct {
	c    net.Conn
	wmu  sync.Mutex
	done chan struct{}
	once sync.Once
	// ctx ends with the session, at once when another proxy replaces it, so the
	// lookups the old session still has in flight stop and are not answered.
	ctx    context.Context
	cancel context.CancelFunc
}

func newSession(c net.Conn) *session {
	ctx, cancel := context.WithCancel(context.Background())
	return &session{c: c, done: make(chan struct{}), ctx: ctx, cancel: cancel}
}

const writeTimeout = 5 * time.Second

func (s *session) send(m *sock.LinkMsg) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	select {
	case <-s.done:
		return errors.New("link: closed")
	default:
	}
	_ = s.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := sock.LinkCodec.Write(s.c, m); err != nil {
		s.close()
		return err
	}
	return nil
}

func (s *session) close() {
	s.once.Do(func() {
		s.cancel()
		close(s.done)
		_ = s.c.Close()
	})
}

// Up reports whether a proxy is connected and has been given its config.
func (s *Server) Up() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur != nil
}

// End tells the proxy to close connections, by id or by SOCKS address. It reports
// whether a proxy was there to be told; a proxy that is not has no connection that
// lives past its own restart, and the next link-up judges the table again.
func (s *Server) End(ids []uint64, socks []string) bool {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur == nil {
		return false
	}
	for len(ids) > 0 {
		n := min(len(ids), sock.MaxIDsPerMsg)
		if cur.send(&sock.LinkMsg{Type: sock.TLinkEnd, End: &sock.LinkEnd{IDs: ids[:n]}}) != nil {
			return false
		}
		ids = ids[n:]
	}
	for len(socks) > 0 {
		n := min(len(socks), sock.MaxIDsPerMsg)
		if cur.send(&sock.LinkMsg{Type: sock.TLinkEnd, End: &sock.LinkEnd{Socks: socks[:n]}}) != nil {
			return false
		}
		socks = socks[n:]
	}
	return true
}

// Serve accepts connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	wait := 5 * time.Millisecond
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(wait)
			if wait < time.Second {
				wait *= 2
			}
			continue
		}
		wait = 5 * time.Millisecond
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	who, err := sock.PeerRole(s.cfg.Get, c, s.cfg.ProxyUID)
	if err != nil {
		_ = c.Close()
		return
	}
	ss := newSession(c)
	defer ss.close()
	if who == sock.WhoRoot {
		s.serveRoot(ss)
		return
	}
	s.serveProxy(ss)
}

// serveRoot answers one `stats`. A peer of uid 0 may send nothing else.
func (s *Server) serveRoot(ss *session) {
	_ = ss.c.SetReadDeadline(time.Now().Add(s.cfg.HelloWithin))
	m, err := sock.LinkCodec.Read(ss.c)
	if err != nil || m.Type != sock.TLinkStats {
		return
	}
	_ = ss.send(&sock.LinkMsg{Type: sock.TLinkStatsRes, StatsRes: s.cfg.Backend.Stats()})
}

func (s *Server) serveProxy(ss *session) {
	_ = ss.c.SetReadDeadline(time.Now().Add(s.cfg.HelloWithin))
	m, err := sock.LinkCodec.Read(ss.c)
	if err != nil || m.Type != sock.TLinkHello {
		return
	}
	run := m.Hello.Run
	var asm sock.ListAssembler[sock.OpenItem]
	var items []sock.OpenItem
	for {
		m, n, err := sock.LinkCodec.ReadSized(ss.c)
		if err != nil || m.Type != sock.TLinkOpen {
			return
		}
		all, done, err := asm.Add(m.Open.Items, n, m.Open.Last)
		if err != nil {
			return
		}
		if done {
			items = all
			break
		}
	}
	_ = ss.c.SetReadDeadline(time.Time{})

	// The new proxy replaces the old one before the table is rebuilt: the old one's
	// connections are gone with it, and its `closed` frames must not reach the new
	// table.
	installed := s.install(ss, run, items)
	defer func() {
		s.mu.Lock()
		last := s.cur == ss
		if last {
			s.cur = nil
		}
		s.mu.Unlock()
		if last {
			s.cfg.Backend.LinkDown()
		}
	}()
	if !installed {
		return
	}

	// config goes out once dns has a bind address; until then the proxy listens on
	// nothing, which is the safe state (5.1).
	go s.sendConfig(ss)
	s.loop(ss)
}

// install makes ss the current session and hands the Backend its open list. The old
// session is closed first, which cancels its lookups, and nothing of it reaches the
// Backend once the write side of the gate is released. It reports false when the
// list holds an address that does not read; the session is then current and the
// caller ends it.
func (s *Server) install(ss *session, run uint64, items []sock.OpenItem) bool {
	s.gate.Lock()
	defer s.gate.Unlock()
	s.mu.Lock()
	old := s.cur
	s.cur = ss
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
	open := make([]grant.OpenItem, 0, len(items))
	for _, it := range items {
		a, ok := netip.AddrFromSlice(it.Source)
		if !ok {
			return false
		}
		open = append(open, grant.OpenItem{ID: it.ID, Source: a.Unmap(), Socks: it.Socks, Tag: it.Tag})
	}
	s.cfg.Backend.LinkUp(run, open)
	return true
}

// current runs f with the gate held for reading when ss is still the current
// session, and says whether it ran.
func (s *Server) current(ss *session, f func()) bool {
	s.gate.RLock()
	defer s.gate.RUnlock()
	s.mu.Lock()
	ok := s.cur == ss
	s.mu.Unlock()
	if ok {
		f()
	}
	return ok
}

func (s *Server) sendConfig(ss *session) {
	for {
		if cfg, ok := s.cfg.Backend.ProxyConfig(); ok {
			_ = ss.send(&sock.LinkMsg{Type: sock.TLinkConfig, Config: &cfg})
			return
		}
		select {
		case <-ss.done:
			return
		case <-time.After(time.Second):
		}
	}
}

// Reconfigure sends the proxy a new `config` (a changed bind address).
func (s *Server) Reconfigure() {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur == nil {
		return
	}
	if cfg, ok := s.cfg.Backend.ProxyConfig(); ok {
		_ = cur.send(&sock.LinkMsg{Type: sock.TLinkConfig, Config: &cfg})
	}
}

func (s *Server) loop(ss *session) {
	ctx := ss.ctx
	sem := make(chan struct{}, s.cfg.MaxLookups)
	b := s.cfg.Backend
	for {
		m, err := sock.LinkCodec.Read(ss.c)
		if err != nil || !sock.MayProxySend(m.Type) {
			return
		}
		switch m.Type {
		case sock.TLinkSource:
			a, ok := netip.AddrFromSlice(m.Source.Source)
			if !ok {
				return
			}
			known := b.Source(a.Unmap())
			if ss.send(&sock.LinkMsg{Type: sock.TLinkSourceKnown, SourceKnown: &sock.LinkSourceKnown{ID: m.Source.ID, Known: known}}) != nil {
				return
			}
		case sock.TLinkLookup:
			a, ok := netip.AddrFromSlice(m.Lookup.Source)
			if !ok {
				return
			}
			select {
			case sem <- struct{}{}:
			default:
				// Over the node's lookups in flight: the answer is none, which closes the
				// connection with no byte, as an overloaded gate should.
				if ss.send(&sock.LinkMsg{Type: sock.TLinkVerdict, Verdict: &sock.LinkVerdict{ID: m.Lookup.ID, Kind: sock.VerdictNone}}) != nil {
					return
				}
				continue
			}
			l := *m.Lookup
			go func() {
				defer func() { <-sem }()
				v := b.Lookup(ctx, l.ID, a.Unmap(), l.Name, l.Port)
				if ctx.Err() != nil {
					return // the session was replaced or closed: nobody reads this verdict
				}
				if v == nil {
					v = &sock.LinkVerdict{Kind: sock.VerdictNone}
				}
				v.ID = l.ID
				_ = ss.send(&sock.LinkMsg{Type: sock.TLinkVerdict, Verdict: v})
			}()
		case sock.TLinkMoved:
			if !s.current(ss, func() { b.Moved(m.Moved) }) {
				return
			}
		case sock.TLinkClosed:
			if !s.current(ss, func() { b.Closed(m.Closed) }) {
				return
			}
		case sock.TLinkState:
			if !s.current(ss, func() { b.State(m.State) }) {
				return
			}
		case sock.TLinkOpen, sock.TLinkHello:
			return // the list comes once, right after hello
		}
	}
}

// Listen binds the socket at path for the production process: the group of the
// socket is `ctrlz-link` and its mode 0660, set in that order (the directory is not
// setgid, so the socket is born in dns's own group and must be moved before it is
// opened to a group), and the proxy's uid is resolved now so a node whose account is
// missing does not start with a check that allows nobody.
func Listen(path, group, proxyUser string) (net.Listener, uint32, error) {
	uids, err := sock.LookupUIDs(nil, proxyUser)
	if err != nil {
		return nil, 0, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, 0, errors.New("link: the path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, 0, errors.New("link: the stale socket cannot be removed")
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, 0, errors.New("link: listen failed")
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			ln.Close()
			return nil, 0, errors.New("link: the socket's group is unknown")
		}
		gid, err := strconv.Atoi(g.Gid)
		if err == nil {
			err = os.Chown(path, -1, gid)
		}
		if err != nil {
			ln.Close()
			return nil, 0, errors.New("link: the group of the socket cannot be set")
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, 0, errors.New("link: chmod failed")
	}
	return ln, uids[0], nil
}

// FetchStats is the client of `sudo ctrlz-node grants-stats` (4.3): a peer of uid 0 asks
// dns for its counters over proxy.sock and may send nothing else. The counters hold no
// name and no address, so the output may go to a terminal or a ticket.
func FetchStats(path string, within time.Duration) (*sock.LinkStatsRes, error) {
	c, err := net.DialTimeout("unix", path, within)
	if err != nil {
		return nil, errors.New("link: dns is not serving proxy.sock")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(within))
	if err := sock.LinkCodec.Write(c, &sock.LinkMsg{Type: sock.TLinkStats, Stats: &sock.LinkStats{}}); err != nil {
		return nil, err
	}
	m, err := sock.LinkCodec.Read(c)
	if err != nil {
		return nil, err
	}
	if m.Type != sock.TLinkStatsRes {
		return nil, errors.New("link: an answer that is not stats_res")
	}
	return m.StatsRes, nil
}
