//go:build linux

package sock

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// PeerUID returns the effective uid of the process on the other end of a unix
// connection, as the kernel recorded it when the peer connected (SO_PEERCRED). A
// uid read from anywhere the peer controls would be no check at all; this one is
// the kernel's.
func PeerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("sock: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("sock: raw connection: %w", err)
	}
	var cred *syscall.Ucred
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("sock: control: %w", err)
	}
	if gerr != nil {
		return 0, fmt.Errorf("sock: SO_PEERCRED: %w", gerr)
	}
	return cred.Uid, nil
}

// UIDCheck accepts a connection only from a process whose uid is uid. It is the
// check of 7.1: the uid of ctrlz-dns.
func UIDCheck(uid uint32) PeerCheck { return UIDsCheckWith(PeerUID, uid) }
