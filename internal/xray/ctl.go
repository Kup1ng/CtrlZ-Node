package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Ctl is the manager's way to the Xray binary: one operation at a time through
// ctrlz-xrayctl. A non-zero exit of the child is a *CtlError; any other error means
// the call itself did not work (the socket, the timeout).
type Ctl interface {
	Do(ctx context.Context, r sock.CtlRun) error
}

// CtlError is a child that ended with a status other than 0. Text is the child's
// own words and untrusted: it may repeat what the admin pasted, so it is redacted
// before it is kept (redact) and never logged.
type CtlError struct {
	Exit int32
	Text string
}

func (e *CtlError) Error() string {
	return fmt.Sprintf("xray: the binary exited with status %d", e.Exit)
}

// SockCtl is the Ctl of the real node: it dials /run/ctrlz-xrayctl/ctl.sock for
// each call. A call takes at most 15 s, which is the 10 s kill of xrayctl and a
// margin for the queue behind another call.
type SockCtl struct {
	Path string
	ids  atomic.Uint64
}

// Do implements Ctl.
func (s *SockCtl) Do(ctx context.Context, r sock.CtlRun) error {
	r.ID = s.ids.Add(1)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", s.Path)
	if err != nil {
		return errors.New("xray: ctl.sock does not answer")
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := sock.CtlCodec.Write(c, &sock.CtlMsg{Type: sock.CtlTypeRun, Run: &r}); err != nil {
		return errors.New("xray: a ctl frame was refused")
	}
	m, err := sock.CtlCodec.Read(c)
	if err != nil || m.Type != sock.CtlTypeResult || m.Result == nil || m.Result.ID != r.ID {
		return errors.New("xray: ctl.sock gave no answer")
	}
	if m.Result.Exit != 0 {
		return &CtlError{Exit: m.Result.Exit, Text: m.Result.Error}
	}
	return nil
}

// binaryRefused is a judgment of the Xray binary: it ran and exited with its own non-zero
// status. xrayctl answers exit -1 for a timeout, a binary that did not run, a release the
// allow file does not name and a cancelled call, and none of those says anything about the
// fragment, so they are no verdict and nothing may be refused or deleted on them (B5 r2-4).
func binaryRefused(err error) bool {
	var ce *CtlError
	return asCtl(err, &ce) && ce.Exit > 0
}
