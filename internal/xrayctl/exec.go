package xrayctl

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

// ExecRunner runs the real binary with an empty environment (but for the one
// setting the units use), in a directory with nothing in it, so that no argument
// can name a file by accident (B0: `rmo` opens each argument as a file first).
type ExecRunner struct {
	// Dir is the working directory; it should hold nothing.
	Dir string
}

// Run implements Runner. The child's whole process group is killed when ctx ends.
func (e ExecRunner) Run(ctx context.Context, bin string, args []string, stdin []byte) (int, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = e.Dir
	cmd.Env = []string{"GODEBUG=multipathtcp=0"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out := &limited{}
	cmd.Stdout, cmd.Stderr = out, out
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.buf.Bytes(), nil
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode(), out.buf.Bytes(), nil
	default:
		return -1, out.buf.Bytes(), err
	}
}
