// Package xrayctl is the unit ctrlz-xrayctl (p4b-proxy 7.5, 7.6). It is the one
// process that runs the Xray binary on text an admin pasted: `xray run -test` and
// `xray api <op>` on a slot's API socket. It always runs as ctrlz-xray, so the
// binary never has another uid, and a parser bug in it gets only that account's
// rights. It takes the fixed operations of 2.1 and never a path: a version, a slot
// and tags in the forms of 7.4, which package sock has already checked, and a JSON
// text on stdin.
package xrayctl

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// Limits of one operation. An api call or a test takes a fraction of a second
// (B0 E15: 128 configs in 26 ms); 10 s is the kill of 7.5.
const (
	RunTimeout = 10 * time.Second
	// apiTimeoutSeconds is the `-t` of an api call; it is below RunTimeout so the
	// client reports its own failure before the kill does.
	apiTimeoutSeconds = "5"
	// maxOutput bounds what is read from the child. The error text sent back is
	// clipped to sock.MaxCtlError, and a child that prints more is cut here.
	maxOutput = 64 << 10
)

// Runner runs the binary once. exit is -1 when the child did not end by itself
// (killed on the timeout, or it never started).
type Runner interface {
	Run(ctx context.Context, bin string, args []string, stdin []byte) (exit int, out []byte, err error)
}

// Server answers ctl.sock.
type Server struct {
	Layout xrayrun.Layout
	Runner Runner
	// Check is the peer check, the agent and root (sock.UsersCheck(true, UserAgent)).
	Check sock.PeerCheck
	// Binary names the binary of a release; the default is Layout.Binary. A test
	// points it at its own fake.
	Binary func(version string) string
	// ReadFile reads the allow file; the default is os.ReadFile.
	ReadFile func(string) ([]byte, error)

	// gate makes the operations run one at a time (7.5): two test runs of an admin's
	// text must not add up to a memory spike, and the API calls of one apply are
	// ordered by their caller. It is a channel and not a mutex so that an operation
	// whose client has gone leaves the queue.
	gate chan struct{}
	once sync.Once
}

// Serve accepts connections until ctx ends or the listener fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.Handle(ctx, c)
	}
}

// Handle serves one connection: a peer that fails the check, sends a frame that is
// not `run`, or sends a bad frame is closed at once.
func (s *Server) Handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	if s.Check != nil {
		if err := s.Check(c); err != nil {
			return
		}
	}
	for {
		m, err := sock.CtlCodec.Read(c)
		if err != nil || m.Type != sock.CtlTypeRun || m.Run == nil {
			return
		}
		res, alive := s.execWatched(ctx, c, m.Run)
		if !alive {
			return
		}
		if err := sock.CtlCodec.Write(c, &sock.CtlMsg{Type: sock.CtlTypeResult, Result: res}); err != nil {
			return
		}
	}
}

// execWatched runs an operation for as long as its client is there. The client sends
// nothing between its request and our answer, so a read that returns means it gave
// up (its call has a deadline of 15 s) or broke the protocol: an operation that was
// queued behind another one must then not run later, or it would leave a handler
// that the agent already undid and forgot (7.5).
func (s *Server) execWatched(ctx context.Context, c net.Conn, r *sock.CtlRun) (*sock.CtlResult, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	gone := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := c.Read(b[:]) // a byte before the answer is a broken client too
		gone <- err
		cancel()
	}()
	res := s.Exec(ctx, r)
	// Unblock the watcher and take its read back before the next request is read: only
	// the deadline that is set here ends it for a client that is still there.
	_ = c.SetReadDeadline(time.Now())
	err := <-gone
	_ = c.SetReadDeadline(time.Time{})
	return res, errors.Is(err, os.ErrDeadlineExceeded)
}

// Exec runs one operation and describes how it ended. The error text is the
// child's own words, which the agent treats as untrusted.
func (s *Server) Exec(ctx context.Context, r *sock.CtlRun) *sock.CtlResult {
	res := &sock.CtlResult{ID: r.ID}
	fail := func(msg string) *sock.CtlResult { res.Exit, res.Error = xrayrun.CtlNotJudged, msg; return res }

	if !xrayrun.ValidVersion(r.Version) || (r.Op != sock.OpTest && !xrayrun.ValidSlot(r.Slot)) {
		return fail("bad request")
	}
	read := s.ReadFile
	if read == nil {
		read = osReadFile
	}
	allow, err := read(s.Layout.Allow())
	if err != nil || !xrayrun.Allowed(allow, r.Version) {
		return fail("release is not allowed")
	}
	args, err := s.args(r)
	if err != nil {
		return fail("bad request")
	}
	bin := s.Layout.Binary(r.Version)
	if s.Binary != nil {
		bin = s.Binary(r.Version)
	}

	s.once.Do(func() { s.gate = make(chan struct{}, 1) })
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-ctx.Done():
		return fail("cancelled")
	}
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	cctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	exit, out, err := s.Runner.Run(cctx, bin, args, r.Stdin)
	res.Exit = int32(exit)
	// Each way of giving no status of its own has its own code, so the agent can tell a
	// fragment that stalls or kills the binary from a binary that cannot run (B5 r1-2, r1-5).
	var ee *exec.ExitError
	switch {
	case errors.Is(cctx.Err(), context.DeadlineExceeded):
		res.Exit, res.Error = xrayrun.CtlTimeout, "timeout"
	case err != nil && exit < 0 && errors.As(err, &ee):
		// The process started and a signal ended it: ExitError with no status of its own.
		res.Exit, res.Error = xrayrun.CtlSignal, "the binary was killed"
	case err != nil && exit < 0:
		res.Exit, res.Error = xrayrun.CtlNoRun, "the binary did not run"
	case exit != 0:
		res.Error = clip(out)
	}
	return res
}

// args builds the argument list from the request's checked fields. Nothing in it is
// a path but the API socket, which comes from the layout and the slot name.
func (s *Server) args(r *sock.CtlRun) ([]string, error) {
	if r.Op == sock.OpTest {
		return []string{"run", "-test", "-c", "stdin:"}, nil
	}
	api := []string{"api"}
	switch r.Op {
	case sock.OpAddOut, sock.OpAddIn, sock.OpRmOut, sock.OpRmIn, sock.OpRmRules:
		api = append(api, r.Op)
	case sock.OpAddRules:
		// Without -append the call replaces the whole table (B0 E05).
		api = append(api, r.Op, "-append")
	default:
		return nil, errors.New("operation")
	}
	api = append(api, "-s", "unix://"+s.Layout.APISock(r.Slot), "-t", apiTimeoutSeconds)
	switch r.Op {
	case sock.OpAddOut, sock.OpAddIn, sock.OpAddRules:
		api = append(api, "stdin:")
	default:
		api = append(api, r.Tags...)
	}
	return api, nil
}

// clip makes the child's output a text of at most sock.MaxCtlError bytes that is
// valid UTF-8 and has no control character but a space.
func clip(out []byte) string {
	out = bytes.TrimSpace(out)
	s := strings.ToValidUTF8(string(out), "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > sock.MaxCtlError {
		s = s[:sock.MaxCtlError]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// limited reads at most maxOutput bytes and drops the rest.
type limited struct {
	buf bytes.Buffer
}

func (l *limited) Write(p []byte) (int, error) {
	if room := maxOutput - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

var _ io.Writer = (*limited)(nil)
