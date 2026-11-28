package listen

import (
	"sync"
	"sync/atomic"
)

// held counts the bytes of packed replies that a QUIC or HTTP/2 connection
// holds for a peer that does not take them, from the moment a reply is packed
// until its write ends. TCP 53 and DoT bound the same thing in their reply
// queue (stream.go); on DoQ, DoH and DoH3 the reply sits in the goroutine that
// is blocked writing it, so without this count a peer with a zero flow-control
// window holds up to 64 KiB for each query it can send, on as many connections
// as its address may open (p4n-W6-r3-3).
//
// Past the bound the reply is replaced by a SERVFAIL for its query: the peer
// that does not read gets a few dozen bytes held in place of up to 64 KiB, and
// the peer that reads is never near it.
type held struct {
	node *atomic.Int64 // the whole listener's bytes

	mu   sync.Mutex
	conn int // this connection's bytes
}

func newHeld(node *atomic.Int64) *held { return &held{node: node} }

// hold takes b into the count and returns what the caller must write: b, or
// alt() when b would pass the per-connection cap or the listener cap (overCaps:
// a connection that holds nothing is always admitted by the connection cap, and
// by the listener cap when b is small, so a full listener never turns away a
// healthy client or an exempt name, p4n-W6-r6-1, and a large first reply meets
// the listener cap, p4n-W6-r7-1). A cap of 0 is no cap. The returned bytes are
// counted in either case; the caller calls release with their length when the
// write ends. A nil held counts nothing.
func (h *held) hold(b []byte, connCap, nodeCap int, alt func() []byte) []byte {
	if h == nil {
		return b
	}
	h.mu.Lock()
	if overCaps(h.conn, len(b), h.node, connCap, nodeCap) {
		if a := alt(); a != nil {
			b = a
		}
	}
	h.conn += len(b)
	h.node.Add(int64(len(b)))
	h.mu.Unlock()
	return b
}

// release gives back n bytes that hold counted.
func (h *held) release(n int) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.conn -= n
	h.mu.Unlock()
	h.node.Add(-int64(n))
}

// heldKey carries a connection's held count on the context of its requests.
type heldKey struct{}
