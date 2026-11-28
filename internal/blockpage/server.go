package blockpage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Production paths and groups (p4b-proxy 2.1, 3.3). serve.sock is the proxy's door
// (group ctrlz-link); agent.sock is the agent's (group ctrlz-blockkey, whose one
// member is ctrlz-agent). The group of a socket only lets its peer open the file:
// who is on the other end is decided again by SO_PEERCRED at accept.
const (
	DefaultServeSock = "/run/ctrlz-block/serve.sock"
	DefaultAgentSock = "/run/ctrlz-block/agent.sock"
	GroupServe       = "ctrlz-link"
	GroupAgent       = "ctrlz-blockkey"
)

// Config is what Run needs. Production fills only the defaults; tests give their
// own paths and peer checks.
type Config struct {
	ServePath, AgentPath   string
	ServeGroup, AgentGroup string
	// ServeCheck and AgentCheck are the peer checks. Nil resolves the accounts of
	// the sockets (ctrlz-proxy, ctrlz-agent) now and refuses to start when one is
	// unknown.
	ServeCheck, AgentCheck sock.PeerCheck
	Now                    func() time.Time
}

// Server is the state of the process. Everything on it is safe for concurrent use.
type Server struct {
	now   func() time.Time
	link  agentLink
	pages *pageCache
	keys  *keyring
	leafs *leafMaker
	unb   *unblocker

	slots   chan struct{} // MaxConns tokens: the connections in service
	refused atomic.Uint64
	wg      sync.WaitGroup
}

// New builds the state without sockets.
func New(now func() time.Time) (*Server, error) {
	if now == nil {
		now = time.Now
	}
	s := &Server{now: now, slots: make(chan struct{}, MaxConns)}
	lm, err := newLeafMaker(now)
	if err != nil {
		return nil, err
	}
	s.leafs = lm
	if s.unb, err = newUnblocker(now); err != nil {
		return nil, err
	}
	s.pages = newPageCache(func(hash []byte) bool {
		return s.link.send(&sock.BlockMsg{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: hash}})
	}, now)
	s.keys = newKeyring(func(endpoint, account []byte) bool {
		return s.link.send(&sock.BlockMsg{Type: sock.BlockNeedKey, NeedKey: &sock.NeedKey{Endpoint: endpoint, Account: account}})
	}, lm.cache.purge, now)
	return s, nil
}

// Run opens both sockets and serves until ctx ends.
func Run(ctx context.Context, cfg Config) error {
	if cfg.ServePath == "" {
		cfg.ServePath = DefaultServeSock
	}
	if cfg.AgentPath == "" {
		cfg.AgentPath = DefaultAgentSock
	}
	if cfg.ServeGroup == "" {
		cfg.ServeGroup = GroupServe
	}
	if cfg.AgentGroup == "" {
		cfg.AgentGroup = GroupAgent
	}
	var err error
	if cfg.ServeCheck == nil {
		if cfg.ServeCheck, err = sock.UsersCheck(false, sock.UserProxy); err != nil {
			return fmt.Errorf("blockpage: serve socket: %w", err)
		}
	}
	if cfg.AgentCheck == nil {
		if cfg.AgentCheck, err = sock.UsersCheck(false, sock.UserAgent); err != nil {
			return fmt.Errorf("blockpage: agent socket: %w", err)
		}
	}
	s, err := New(cfg.Now)
	if err != nil {
		return err
	}
	serveLn, err := listenUnix(cfg.ServePath, cfg.ServeGroup)
	if err != nil {
		return fmt.Errorf("blockpage: serve socket: %w", err)
	}
	agentLn, err := listenUnix(cfg.AgentPath, cfg.AgentGroup)
	if err != nil {
		serveLn.Close()
		return fmt.Errorf("blockpage: agent socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		serveLn.Close()
		agentLn.Close()
	}()
	go acceptLoop(agentLn, cfg.AgentCheck, s.ServeAgent)
	acceptLoop(serveLn, cfg.ServeCheck, s.dispatchServe)
	s.link.close()
	s.wg.Wait()
	return ctx.Err()
}

// dispatchServe takes a connection slot or refuses at once.
func (s *Server) dispatchServe(c net.Conn) {
	select {
	case s.slots <- struct{}{}:
	default:
		s.refused.Add(1)
		_ = c.Close()
		return
	}
	s.wg.Add(1)
	go func() {
		defer func() { <-s.slots; s.wg.Done() }()
		s.ServeConn(c)
	}()
}

// acceptLoop checks the peer of each connection before any frame is read. 32 KiB
// buffers on both ends of serve.sock are the spec's (10.2): the default of a unix
// socket is larger and a connection of 128 KiB in all (12) is the budget.
func acceptLoop(ln net.Listener, check sock.PeerCheck, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if err := check(c); err != nil {
			_ = c.Close()
			continue
		}
		if uc, ok := c.(*net.UnixConn); ok {
			_ = uc.SetReadBuffer(32 << 10)
			_ = uc.SetWriteBuffer(32 << 10)
		}
		handle(c)
	}
}

// listenUnix binds a socket at path, group-owned and 0660. A stale socket file is
// removed; anything else at the path is an error. The group is set right after the
// bind, and until then the peer check is the only guard, which is why it exists.
func listenUnix(path, group string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, errors.New("the path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, errors.New("the stale socket cannot be removed")
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("listen failed")
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, errors.New("chmod failed")
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("group %q is unknown", group)
		}
		gid, err := strconv.Atoi(g.Gid)
		if err == nil {
			err = os.Chown(path, -1, gid)
		}
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("the group of the socket cannot be set to %q", group)
		}
	}
	return ln, nil
}

// ---- the agent's connection

// agentLink is the one connection of the agent. A new connection replaces the old
// one: an agent that restarted does not wait for the old end to time out.
type agentLink struct {
	mu   sync.Mutex
	conn net.Conn
}

const agentWriteTimeout = 2 * time.Second

// send writes one frame and reports whether it went. A failed write ends the
// connection; the reader then notices and the keys stop being used.
func (l *agentLink) send(m *sock.BlockMsg) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return false
	}
	_ = l.conn.SetWriteDeadline(time.Now().Add(agentWriteTimeout))
	if err := sock.BlockCodec.Write(l.conn, m); err != nil {
		_ = l.conn.Close()
		l.conn = nil
		return false
	}
	return true
}

func (l *agentLink) attach(c net.Conn) {
	l.mu.Lock()
	old := l.conn
	l.conn = c
	l.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

// detach clears c if it is still the current connection and reports that it was.
func (l *agentLink) detach(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != c {
		return false
	}
	l.conn = nil
	return true
}

func (l *agentLink) close() {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// ServeAgent runs the agent's connection until it ends. The peer was checked at
// accept; every frame is checked for being one the agent may send, and a frame
// that is not ends the connection (2.1).
func (s *Server) ServeAgent(c net.Conn) {
	s.link.attach(c)
	go func() {
		defer func() { _ = c.Close() }()
		for {
			m, err := sock.BlockCodec.Read(c)
			if err != nil || !sock.MayAgentSend(m.Type) {
				break
			}
			switch m.Type {
			case sock.BlockPage:
				s.pages.deliver(m.Page.Hash, m.Page.Blob)
			case sock.BlockEpoch:
				s.keys.setEpoch(m.Epoch.Epoch)
			case sock.BlockIntermediate:
				if err := s.keys.put(m.Intermediate); err != nil {
					log.Printf("blockpage: an intermediate was refused: %v", err)
				}
			}
		}
		if s.link.detach(c) {
			s.keys.lost()
		}
	}()
}
