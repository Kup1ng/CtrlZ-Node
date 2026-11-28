// Package sockfake is what the packages that meet on the P4b sockets (B3 to B6p)
// test against: an in-memory connection that carries a peer uid, and an endpoint
// that sends and reads the frames of any socket's codec. B3, B4, B5, B6 and B6p
// meet only in the messages of internal/agent/sock, so each one drives its own side
// with one of these playing the other.
//
// It is for tests only; nothing in a production binary imports it.
package sockfake

import (
	"errors"
	"net"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Conn is a net.Conn with a peer uid, the thing SO_PEERCRED would have said.
type Conn struct {
	net.Conn
	uid uint32
}

// UID is the uid the far end claims, for GetUID.
func (c *Conn) UID() uint32 { return c.uid }

// Pair returns the two ends of an in-memory connection. serverSees is the uid that
// the server end reads as its peer's (the connecting process); clientSees the uid
// that the client end reads (the serving process).
func Pair(serverSees, clientSees uint32) (server, client *Conn) {
	s, c := net.Pipe()
	return &Conn{Conn: s, uid: serverSees}, &Conn{Conn: c, uid: clientSees}
}

// GetUID is a sock.UIDGetter that reads a Conn's uid; any other connection is
// refused, as a real check would refuse one that is not a unix connection.
func GetUID(c net.Conn) (uint32, error) {
	fc, ok := c.(*Conn)
	if !ok {
		return 0, errors.New("sockfake: not a fake connection")
	}
	return fc.uid, nil
}

// Endpoint sends and receives the frames of one codec over a connection.
type Endpoint[M any] struct {
	Conn  net.Conn
	Codec sock.Codec[M]
	// Timeout bounds each Send and Recv, so a test that misses a message fails
	// instead of hanging. Zero means 5 s.
	Timeout time.Duration
}

func (e *Endpoint[M]) wait() time.Time {
	d := e.Timeout
	if d == 0 {
		d = 5 * time.Second
	}
	return time.Now().Add(d)
}

// Send validates and writes one frame.
func (e *Endpoint[M]) Send(m *M) error {
	_ = e.Conn.SetWriteDeadline(e.wait())
	return e.Codec.Write(e.Conn, m)
}

// SendRaw writes bytes as they are (a length with a bad body, a frame of a type
// that does not exist), for the tests that hand a reader what it must refuse.
func (e *Endpoint[M]) SendRaw(b []byte) error {
	_ = e.Conn.SetWriteDeadline(e.wait())
	_, err := e.Conn.Write(b)
	return err
}

// Recv reads and validates one frame.
func (e *Endpoint[M]) Recv() (*M, error) {
	_ = e.Conn.SetReadDeadline(e.wait())
	return e.Codec.Read(e.Conn)
}

// Close closes the connection.
func (e *Endpoint[M]) Close() { _ = e.Conn.Close() }

// The uids of the fake processes. They are distinct and only root is 0: a pair that
// gave every end uid 0 would make the proxy read as root, and a test that wanted
// its frames accepted would then be tempted to skip the role check.
const (
	UIDDNS   uint32 = 1001
	UIDProxy uint32 = 1002
	UIDAgent uint32 = 1003
	UIDBlock uint32 = 1004
	UIDXray  uint32 = 1005 // ctrlz-xray, the account of xrayctl
	UIDRoot  uint32 = 0
)

// LinkPair is the two ends of proxy.sock: the dns end and the proxy end. dns reads
// its peer as UIDProxy and the proxy reads dns as UIDDNS, so PeerRole with
// UIDProxy says WhoProxy.
func LinkPair() (dns, proxy *Endpoint[sock.LinkMsg]) {
	return LinkPairAs(UIDProxy)
}

// LinkPairAs is LinkPair with the uid that dns reads its peer as: UIDRoot for the
// client of stats, another value for a stranger.
func LinkPairAs(peerUID uint32) (dns, proxy *Endpoint[sock.LinkMsg]) {
	s, c := Pair(peerUID, UIDDNS)
	return &Endpoint[sock.LinkMsg]{Conn: s, Codec: sock.LinkCodec}, &Endpoint[sock.LinkMsg]{Conn: c, Codec: sock.LinkCodec}
}

// BlockPair is the two ends of the block agent socket: block and the agent.
func BlockPair() (block, agent *Endpoint[sock.BlockMsg]) {
	s, c := Pair(UIDAgent, UIDBlock)
	return &Endpoint[sock.BlockMsg]{Conn: s, Codec: sock.BlockCodec}, &Endpoint[sock.BlockMsg]{Conn: c, Codec: sock.BlockCodec}
}

// CtlPair is the two ends of ctl.sock: xrayctl and its client. The client reads
// the server as UIDXray, the account xrayctl runs as.
func CtlPair() (ctl, client *Endpoint[sock.CtlMsg]) {
	s, c := Pair(UIDAgent, UIDXray)
	return &Endpoint[sock.CtlMsg]{Conn: s, Codec: sock.CtlCodec}, &Endpoint[sock.CtlMsg]{Conn: c, Codec: sock.CtlCodec}
}
