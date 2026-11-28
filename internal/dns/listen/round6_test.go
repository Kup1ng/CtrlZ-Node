package listen

import (
	"sync/atomic"
	"testing"
)

// A connection that holds nothing is never turned away by the listener-wide
// reply cap, however full other peers (that do not read) have made it: its
// first reply is real, so an exempt name still gets its answer (L13, L14).
// Before the fix every reply on the listener became a SERVFAIL once the node
// total passed the cap (p4n-W6-r6-1).
func TestNodeCapNeverTurnsAwayAConnectionThatHoldsNothing(t *testing.T) {
	var node atomic.Int64
	const nodeCap, connCap = 1000, 5000
	alt := func() []byte { return make([]byte, 10) }
	hog, healthy := newSconn(nil, &node), newSconn(nil, &node)

	// The hog fills the listener: its first reply fits, the next is replaced.
	hog.push(outFrame{id: 1, b: make([]byte, 1200)}, connCap, nodeCap, alt)
	hog.push(outFrame{id: 2, b: make([]byte, 1200)}, connCap, nodeCap, alt)
	if got := len(hog.out[1].b); got != 10 {
		t.Fatalf("a connection that holds bytes got %d bytes past the listener cap, want the %d-byte alternative", got, 10)
	}
	if node.Load() <= nodeCap {
		t.Fatalf("listener holds %d, the test did not fill it", node.Load())
	}
	// A connection that holds nothing still gets its real reply.
	healthy.push(outFrame{id: 1, b: make([]byte, 900)}, connCap, nodeCap, alt)
	if got := len(healthy.out[0].b); got != 900 {
		t.Fatalf("a connection that holds nothing got %d bytes, want its real 900", got)
	}
	// Once it holds bytes of its own, it meets the cap like the hog.
	healthy.push(outFrame{id: 2, b: make([]byte, 900)}, connCap, nodeCap, alt)
	if got := len(healthy.out[1].b); got != 10 {
		t.Fatalf("the second reply of a connection over the cap was %d bytes, want the alternative", got)
	}
}
