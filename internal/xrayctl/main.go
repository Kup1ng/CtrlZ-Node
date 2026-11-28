package xrayctl

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// DefaultSock is where the unit listens.
const DefaultSock = "/run/ctrlz-xrayctl/ctl.sock"

// Main is `ctrlz-node xrayctl`: it listens on ctl.sock for the agent and root and
// runs the fixed operations until ctx ends. The unit runs it as ctrlz-xray with a
// RuntimeDirectory, so the directory exists and belongs to that account.
func Main(ctx context.Context, sockPath string) error {
	if sockPath == "" {
		sockPath = DefaultSock
	}
	// The peers are the agent and root (2.1); the account of the unit itself is not
	// one of them.
	check, err := sock.UsersCheck(true, sock.UserAgent)
	if err != nil {
		return err
	}
	// A socket that an earlier process left would make the bind fail.
	if err := os.Remove(sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	// The peer check is the gate; the mode keeps the socket out of reach of the rest
	// of the host as well.
	if err := os.Chmod(sockPath, 0o660); err != nil {
		_ = ln.Close()
		return err
	}
	s := &Server{
		Layout: xrayrun.DefaultLayout(), Runner: ExecRunner{Dir: workDir()}, Check: check,
	}
	return s.Serve(ctx, ln)
}

// workDir is a directory with nothing in it: the unit's RuntimeDirectory (the
// socket's parent) holds only the socket, which no tag of the allowed forms names.
func workDir() string { return filepath.Dir(DefaultSock) }
