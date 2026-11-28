//go:build !linux

package sock

import (
	"errors"
	"net"
)

// PeerUID refuses everything off Linux: SO_PEERCRED is a Linux interface and the
// node runs on Ubuntu only. Development builds on other systems use a fake in
// their tests (UIDsCheckWith, sockfake).
func PeerUID(net.Conn) (uint32, error) {
	return 0, errors.New("sock: peer credentials need Linux")
}

// UIDCheck refuses everything off Linux, like PeerUID.
func UIDCheck(uid uint32) PeerCheck { return UIDsCheckWith(PeerUID, uid) }
