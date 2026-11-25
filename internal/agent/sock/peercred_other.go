//go:build !linux

package sock

import (
	"errors"
	"net"
)

// UIDCheck refuses everything off Linux: SO_PEERCRED is a Linux interface and
// the node runs on Ubuntu only. Development builds on other systems use a fake
// PeerCheck in their tests.
func UIDCheck(uid uint32) PeerCheck {
	return func(net.Conn) error { return errors.New("sock: peer credentials need Linux") }
}
