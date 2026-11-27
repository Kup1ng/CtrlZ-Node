package sock

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PeerCheck decides whether the process on the other end of a connection may
// have anything handed to it. It runs on every connection before the agent
// sends a byte (7.1: SO_PEERCRED, uid of ctrlz-dns). The production check is
// UIDCheck; tests pass their own.
type PeerCheck func(c net.Conn) error

// Handlers receive what dns sends. Each is optional and is called on the
// connection's reader goroutine, so it must not block; a panic in one costs the
// message, not the agent.
type Handlers struct {
	ImageAck   func(name string)
	FreeCounts func(items []FreeCount)
	Activity   func(items []ActivityItem)
	Stats      func(s Stats)
	Outbound   func(nodeMessage []byte)
	// Message gets the P4b types dns sends (grant_res, grant_out, proxy_state), whole,
	// on the reader goroutine; the same rule as the handlers above: it must not block.
	Message func(m *Msg)
	// Connected is called with true after a dns connection passed the check and
	// was given its state, and with false when it ends.
	Connected func(up bool)
}

// ServerConfig is what Listen needs.
type ServerConfig struct {
	Path string
	// Mode of the socket file, 0660 in production.
	Mode fs.FileMode
	// Group is the group that owns the file ("ctrlz"); empty leaves it alone.
	Group string
	// Check is required: a server with no peer check hands keys to anyone who can
	// connect.
	Check PeerCheck
	RunID uint64
	H     Handlers
}

const (
	writeTimeout = 10 * time.Second
	sendQueue    = 256
)

// Server is the agent's end.
type Server struct {
	cfg ServerConfig
	ln  net.Listener

	mu        sync.Mutex
	state     map[string]*Msg
	cur       *conn
	rejected  int
	closed    bool
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type conn struct {
	c      net.Conn
	out    chan *Msg
	done   chan struct{}
	closer sync.Once
}

func (c *conn) close() { c.closer.Do(func() { close(c.done); _ = c.c.Close() }) }

// Listen creates the socket. A stale socket file left by a crashed agent is
// removed; anything else at the path is an error.
func Listen(cfg ServerConfig) (*Server, error) {
	if cfg.Check == nil {
		return nil, errors.New("sock: a peer check is required")
	}
	if cfg.Mode == 0 {
		cfg.Mode = 0o660
	}
	if fi, err := os.Lstat(cfg.Path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, errors.New("sock: the path exists and is not a socket")
		}
		if err := os.Remove(cfg.Path); err != nil {
			return nil, fmt.Errorf("sock: remove the stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("sock: listen: %w", err)
	}
	// The mode is set right after the bind. Until then the peer check is the
	// only guard, which is why it exists.
	if err := os.Chmod(cfg.Path, cfg.Mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("sock: chmod: %w", err)
	}
	if cfg.Group != "" {
		g, err := user.LookupGroup(cfg.Group)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("sock: group %q: %w", cfg.Group, err)
		}
		gid, err := strconv.Atoi(g.Gid)
		if err == nil {
			err = os.Chown(cfg.Path, -1, gid)
		}
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("sock: chown: %w", err)
		}
	}
	return &Server{cfg: cfg, ln: ln, state: map[string]*Msg{}}, nil
}

// Serve accepts connections until ctx ends or Close is called.
func (s *Server) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		// Add and Wait must not overlap: Close sets closed under the same lock before
		// it waits, so after that no connection is added to the group.
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

// Close stops accepting, ends the current connection and removes the socket file.
// It returns only when all of that is done, whichever caller got there first: Serve
// closes the server when its context ends and so does the agent's Run, and a second
// caller that returned early let a new server bind the same path before the first
// Close removed the file, which then removed the new server's socket.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		cur := s.cur
		s.mu.Unlock()
		_ = s.ln.Close()
		if cur != nil {
			cur.close()
		}
		s.wg.Wait()
		_ = os.Remove(s.cfg.Path)
	})
}

// Rejected is how many connections failed the peer check.
func (s *Server) Rejected() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejected
}

// Connected reports whether a dns connection is up.
func (s *Server) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur != nil
}

// keyOf is the slot a message occupies in the snapshot: a new message of the
// same slot replaces the old.
func keyOf(m *Msg) (string, bool) {
	switch m.Type {
	case TypeImage, TypeTable, TypeFacts, TypeConfig, TypeRevocations, TypeLocations:
		return m.Type, true
	case TypeZoneKey:
		if m.ZoneKey == nil {
			return "", false
		}
		sans := append([]string(nil), m.ZoneKey.SANs...)
		sort.Strings(sans)
		return "zonekey:" + strings.Join(sans, ","), true
	case TypeAcme:
		if m.Acme == nil {
			return "", false
		}
		return "acme:" + hex.EncodeToString(m.Acme.TokenID), true
	}
	return "", false
}

// order of the snapshot sent on connect: the config and keys first, so that by
// the time dns hears of the image it can already answer.
var snapshotOrder = []string{TypeConfig, "zonekey:", TypeImage, TypeTable, TypeRevocations, "acme:", TypeFacts}

func snapRank(k string) int {
	for i, p := range snapshotOrder {
		if k == p || strings.HasPrefix(k, p) && strings.HasSuffix(p, ":") {
			return i
		}
	}
	return len(snapshotOrder)
}

// Publish records a message as the latest of its slot and sends it to the
// connected dns, if any. It never blocks: a dns that does not keep up loses its
// connection and gets the whole snapshot again when it reconnects.
func (s *Server) Publish(m *Msg) error {
	k, ok := keyOf(m)
	if !ok {
		return errors.New("sock: a message of this type cannot be published")
	}
	if isP4bType(m.Type) {
		if err := checkP4b(m); err != nil {
			return err
		}
	}
	// The enqueue is under the lock, so two Publishes of one slot reach the
	// connection in the order they were stored; enqueue never blocks.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state[k] = m
	if s.cur != nil {
		s.enqueue(s.cur, m)
	}
	return nil
}

// Forget removes a slot from the snapshot (an expired ACME challenge, a
// retired zone key). The slot is named by the message that filled it.
func (s *Server) Forget(m *Msg) {
	if k, ok := keyOf(m); ok {
		s.mu.Lock()
		delete(s.state, k)
		s.mu.Unlock()
	}
}

func (s *Server) enqueue(c *conn, m *Msg) {
	select {
	case c.out <- m:
	case <-c.done:
	default:
		c.close() // dns is not reading: it reconnects and gets the snapshot
	}
}

func (s *Server) handle(nc net.Conn) {
	if err := s.cfg.Check(nc); err != nil {
		s.mu.Lock()
		s.rejected++
		s.mu.Unlock()
		_ = nc.Close()
		return
	}
	c := &conn{c: nc, out: make(chan *Msg, sendQueue), done: make(chan struct{})}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = nc.Close()
		return
	}
	old := s.cur
	s.cur = c
	snap := make([]string, 0, len(s.state))
	for k := range s.state {
		snap = append(snap, k)
	}
	sort.Slice(snap, func(i, j int) bool {
		ri, rj := snapRank(snap[i]), snapRank(snap[j])
		if ri != rj {
			return ri < rj
		}
		return snap[i] < snap[j]
	})
	first := []*Msg{{Type: TypeHello, Hello: &Hello{Version: Version, RunID: s.cfg.RunID}}}
	for _, k := range snap {
		first = append(first, s.state[k])
	}
	// The snapshot is queued under the lock, before any later Publish can queue
	// its message: it goes first into the same queue. A snapshot longer than the
	// queue ends the connection.
	for _, m := range first {
		select {
		case c.out <- m:
		default:
			c.close()
		}
	}
	s.mu.Unlock()
	if old != nil {
		old.close()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer c.close()
		for {
			select {
			case m := <-c.out:
				_ = nc.SetWriteDeadline(time.Now().Add(writeTimeout))
				if err := Write(nc, m, MaxFrameToDNS); err != nil {
					return
				}
			case <-c.done:
				return
			}
		}
	}()
	if s.cfg.H.Connected != nil {
		s.cfg.H.Connected(true)
	}
	s.readLoop(c)
	c.close()
	wg.Wait()
	s.mu.Lock()
	last := s.cur == c
	if last {
		s.cur = nil
	}
	s.mu.Unlock()
	// A connection replaced by a newer one is not "down": dns reconnected.
	if last && s.cfg.H.Connected != nil {
		s.cfg.H.Connected(false)
	}
}

func (s *Server) readLoop(c *conn) {
	for {
		m, err := Read(c.c, MaxFrameFromDNS)
		if err != nil {
			return
		}
		if !s.dispatch(m) {
			return
		}
	}
}

// dispatch hands a message to its handler under recover. It returns false for a
// message of a type dns may not send, which ends the connection.
func (s *Server) dispatch(m *Msg) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = true // a handler's panic costs the message
		}
	}()
	h := s.cfg.H
	switch m.Type {
	case TypeImageAck:
		if m.ImageAck != nil && h.ImageAck != nil {
			h.ImageAck(m.ImageAck.Name)
		}
	case TypeFreeCounts:
		if m.FreeCounts != nil && h.FreeCounts != nil && len(m.FreeCounts.Items) <= MaxItems {
			h.FreeCounts(m.FreeCounts.Items)
		}
	case TypeActivity:
		if m.Activity != nil && h.Activity != nil && len(m.Activity.Items) <= MaxItems {
			h.Activity(m.Activity.Items)
		}
	case TypeStats:
		if m.Stats != nil && h.Stats != nil {
			h.Stats(*m.Stats)
		}
	case TypeOutbound:
		if m.Outbound != nil && h.Outbound != nil {
			h.Outbound(m.Outbound.NodeMessage)
		}
	case TypeGrantRes, TypeGrantOut, TypeProxyState:
		if h.Message != nil {
			h.Message(m)
		}
	default:
		return false
	}
	return true
}

// Send queues an event for the connected dns and reports whether it was queued: an
// event is not part of the snapshot, so a dns that is not connected, or that does
// not keep up, simply does not get it. grant_in and grant_sent are events, and their
// senders have a rule for the loss (a forward that is unanswered is `unsent`, 4.5).
func (s *Server) Send(m *Msg) bool {
	if m.Type != TypeGrantIn && m.Type != TypeGrantSent {
		return false
	}
	// Check before queueing: a writer that fails on a bad message would otherwise
	// close the connection of a dns that did nothing wrong.
	if err := checkP4b(m); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return false
	}
	select {
	case s.cur.out <- m:
		return true
	default:
		s.cur.close()
		return false
	}
}
