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
// runs the fixed operations until ctx ends. The unit runs it as ctrlz-xray, and the
// directory of the socket is made by tmpfiles (2750, setgid, group ctrlz-xrayctl;
// p4b-proxy 3.3), so ctl.sock is born in a group that the agent is a member of and the
// Xray slots are not. The unit must not declare RuntimeDirectory=: systemd would reset
// the directory to the unit's own user and group, mode 0755 and no setgid, at every
// start, and the agent could no longer connect.
func Main(ctx context.Context, sockPath string) error {
	if err := xrayrun.RefuseRoot(os.Geteuid()); err != nil {
		return err
	}
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

// workDir is a directory with nothing in it: the socket's parent (made by tmpfiles,
// see Main) holds only the socket, which no tag of the allowed forms names.
func workDir() string { return filepath.Dir(DefaultSock) }
