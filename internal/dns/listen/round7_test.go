package listen

import (
	"sync/atomic"
	"testing"
)

// Many connections that each send a large first reply and read nothing must not
// take the listener past its cap: a first reply above firstReplyFree meets the
// listener cap, while a small one (an exempt name's answer) is still delivered
// on a connection that holds nothing (p4n-W6-r7-1).
func TestLargeFirstRepliesMeetTheListenerCap(t *testing.T) {
	var node atomic.Int64
	const nodeCap, connCap = 100 << 10, 256 << 10
	alt := func() []byte { return make([]byte, 20) }
	big := func() []byte { return make([]byte, 60<<10) }

	full := 0
	for i := 0; i < 200; i++ {
		c := newSconn(nil, &node)
		c.push(outFrame{id: 1, b: big()}, connCap, nodeCap, alt)
		if len(c.out[0].b) == len(big()) {
			full++
		}
	}
	if full != 1 {
		t.Fatalf("%d large first replies kept, want 1 (the cap holds one 60 KiB reply)", full)
	}
	if got := node.Load(); got > nodeCap+200*20 {
		t.Fatalf("listener holds %d bytes, cap %d", got, nodeCap)
	}

	// A small reply on a connection that holds nothing is real, however full the
	// listener is.
	node.Store(10 * nodeCap)
	c := newSconn(nil, &node)
	c.push(outFrame{id: 1, b: make([]byte, 300)}, connCap, nodeCap, alt)
	if got := len(c.out[0].b); got != 300 {
		t.Fatalf("an exempt-sized first reply was %d bytes on a full listener, want 300", got)
	}
}

// The frame the writer has in hand is still held (a peer with a zero window
// blocks the write), so it counts against the connection and the listener until
// the write ends, and the next reply is not a free first reply (p4n-W6-r7-2).
func TestFrameInTheWritersHandStaysCounted(t *testing.T) {
	var node atomic.Int64
	const nodeCap, connCap = 10000, 256 << 10
	alt := func() []byte { return make([]byte, 20) }
	c := newSconn(nil, &node)

	c.push(outFrame{id: 1, b: make([]byte, 3000)}, connCap, nodeCap, alt)
	f, ok := c.pop()
	if !ok || len(f.b) != 3000 {
		t.Fatal("pop did not return the queued frame")
	}
	if node.Load() != 3000 || c.qbytes != 3000 {
		t.Fatalf("frame in hand counted as %d on the listener and %d on the connection, want 3000", node.Load(), c.qbytes)
	}
	// With the listener full, a second reply on this connection meets the cap.
	node.Add(8000)
	c.push(outFrame{id: 2, b: make([]byte, 3000)}, connCap, nodeCap, alt)
	if got := len(c.out[0].b); got != 20 {
		t.Fatalf("second reply was %d bytes, want the alternative: the connection holds the frame in hand", got)
	}
	node.Add(-8000)

	c.wrote()
	if want := int64(20); node.Load() != want || c.qbytes != 20 {
		t.Fatalf("after the write: listener %d, connection %d, want %d", node.Load(), c.qbytes, want)
	}
	// A connection that ends with a frame in hand gives everything back once.
	f, _ = c.pop()
	c.drop()
	c.wrote()
	if node.Load() != 0 || c.qbytes != 0 {
		t.Fatalf("after drop: listener %d, connection %d, want 0", node.Load(), c.qbytes)
	}
	_ = f
}

func TestHeldLargeFirstReplyMeetsTheListenerCap(t *testing.T) {
	var node atomic.Int64
	node.Store(1 << 20)
	h := newHeld(&node)
	alt := func() []byte { return make([]byte, 10) }
	if got := len(h.hold(make([]byte, 60<<10), 256<<10, 1<<20, alt)); got != 10 {
		t.Fatalf("a large first reply on a full listener was %d bytes, want the alternative", got)
	}
	h2 := newHeld(&node)
	if got := len(h2.hold(make([]byte, 300), 256<<10, 1<<20, alt)); got != 300 {
		t.Fatalf("a small first reply on a full listener was %d bytes, want 300", got)
	}
}
