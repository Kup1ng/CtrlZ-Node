//go:build linux

package sock

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// UIDCheck accepts a connection only from a process whose effective uid, as the
// kernel recorded it when the peer connected (SO_PEERCRED), is uid. It is the
// check of 7.1: the uid of ctrlz-dns. A uid that is read from anywhere the peer
// controls would be no check at all; this one is the kernel's.
func UIDCheck(uid uint32) PeerCheck {
	return func(c net.Conn) error {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return errors.New("sock: not a unix connection")
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return fmt.Errorf("sock: raw connection: %w", err)
		}
		var cred *syscall.Ucred
		var gerr error
		if err := raw.Control(func(fd uintptr) {
			cred, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		}); err != nil {
			return fmt.Errorf("sock: control: %w", err)
		}
		if gerr != nil {
			return fmt.Errorf("sock: SO_PEERCRED: %w", gerr)
		}
		if cred.Uid != uid {
			return errors.New("sock: peer uid is not the expected one")
		}
		return nil
	}
}
