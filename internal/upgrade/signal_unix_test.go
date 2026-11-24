//go:build unix

package upgrade

import (
	"context"
	"errors"
	"io"
	"syscall"
	"testing"
	"time"
)

// sigRunner plays apply.sh: when it starts it makes the operator's TERM arrive, then
// waits as the real script would, for the cancelled context to reach it.
type sigRunner struct {
	*fakeRunner
	sawCancel bool
}

func (s *sigRunner) Run(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) error {
	if name != "sh" {
		return s.fakeRunner.Run(ctx, stdout, stderr, name, args...)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		s.sawCancel = true
	case <-time.After(10 * time.Second):
	}
	return errors.New("terminated")
}

// A TERM, HUP or INT during the upgrade ends the run through the normal return, so the
// staging directory (a full copy of the bundle) is removed and the child gets its chance
// to clean up. Without the handler Go's default action kills the process here and this
// test dies with it (p4n-W5c-r6-2).
func TestSignalDuringUpgradeRemovesTheStagingDirectory(t *testing.T) {
	h := newHost(t, 2)
	sr := &sigRunner{fakeRunner: h.runner}
	h.env.Runner = sr
	if code := h.env.MainSignals([]string{"4"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !sr.sawCancel {
		t.Error("the signal did not cancel the context the install runs under")
	}
	if len(h.stages(t)) != 0 {
		t.Errorf("staging left behind: %v", h.stages(t))
	}
}
