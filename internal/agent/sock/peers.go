package sock

import (
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"
)

// Accounts of the node's processes (packaging/accounts.conf). The peer checks of
// the P4b sockets are built from these names, resolved to uids once, when the
// socket is created: a uid is never read from a file the peer can write.
const (
	UserDNS   = "ctrlz-dns"
	UserAgent = "ctrlz-agent"
	UserProxy = "ctrlz-proxy"
	UserBlock = "ctrlz-block"
	// UserXray is also the account of ctrlz-xrayctl (7.5): there is no account of
	// its own, and ctl.sock's peers are the agent and root.
	UserXray = "ctrlz-xray"
)

// UIDGetter reads a connection's peer uid. PeerUID is the real one; tests give
// their own, so the decision logic runs where SO_PEERCRED does not exist.
type UIDGetter func(net.Conn) (uint32, error)

// UIDsCheckWith accepts a connection whose peer uid, read by get, is in uids.
func UIDsCheckWith(get UIDGetter, uids ...uint32) PeerCheck {
	allowed := make(map[uint32]struct{}, len(uids))
	for _, u := range uids {
		allowed[u] = struct{}{}
	}
	return func(c net.Conn) error {
		uid, err := get(c)
		if err != nil {
			return err
		}
		if _, ok := allowed[uid]; !ok {
			return errors.New("sock: peer uid is not an expected one")
		}
		return nil
	}
}

// UIDsCheck accepts only the given uids.
func UIDsCheck(uids ...uint32) PeerCheck { return UIDsCheckWith(PeerUID, uids...) }

// LookupUIDs resolves account names to uids. It fails when a name is unknown: a
// socket whose check would silently allow nobody, or the wrong one, must not start.
func LookupUIDs(lookup func(name string) (*user.User, error), names ...string) ([]uint32, error) {
	if lookup == nil {
		lookup = user.Lookup
	}
	out := make([]uint32, 0, len(names))
	for _, n := range names {
		u, err := lookup(n)
		if err != nil {
			return nil, fmt.Errorf("sock: account %q: %w", n, err)
		}
		id, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("sock: account %q has no numeric uid", n)
		}
		out = append(out, uint32(id))
	}
	return out, nil
}

// UsersCheck is the peer check for the accounts named, resolved now. withRoot
// adds uid 0, for the sockets that root may read (the stats of proxy.sock, the
// control socket of xrayctl). Root's reach is then limited by what it may send
// (MayRootSend), not by the connection.
func UsersCheck(withRoot bool, names ...string) (PeerCheck, error) {
	uids, err := LookupUIDs(nil, names...)
	if err != nil {
		return nil, err
	}
	if withRoot {
		uids = append(uids, 0)
	}
	return UIDsCheck(uids...), nil
}

// Who says which of the two peers a link connection is, from its uid. dns calls it
// after the check passed, so the answer is only ever proxy or root.
type Who int

const (
	WhoProxy Who = iota + 1
	WhoRoot
)

// PeerRole reads the connection's uid and tells root from the proxy's account.
func PeerRole(get UIDGetter, c net.Conn, proxyUID uint32) (Who, error) {
	uid, err := get(c)
	if err != nil {
		return 0, err
	}
	switch uid {
	case 0:
		return WhoRoot, nil
	case proxyUID:
		return WhoProxy, nil
	}
	return 0, errors.New("sock: peer uid is not an expected one")
}

// May reports whether a peer of this role may send a type on proxy.sock.
func (w Who) May(t string) bool {
	switch w {
	case WhoProxy:
		return MayProxySend(t)
	case WhoRoot:
		return MayRootSend(t)
	}
	return false
}
