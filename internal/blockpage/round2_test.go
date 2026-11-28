package blockpage

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

// failConn is a connection whose writes can be made to fail, as an EPIPE or a
// missed write deadline does, while the read side is still blocked.
type failConn struct {
	net.Conn
	fail atomic.Bool
}

func (c *failConn) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("write failed")
	}
	return c.Conn.Write(b)
}

func keyHeld(s *Server, acct []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := s.keys.get(ctx, ids(9), acct)
	return err == nil
}

// A write that fails ends the connection through the reader's detach, so the keys
// go with it and a reconnect that sends nothing finds none (B6-r2-4).
func TestFailedSendStillDropsKeysAndEpoch(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.link.close)
	acct, epoch := ids(1), []byte("EPOCH001")
	srv, cli := net.Pipe()
	fc := &failConn{Conn: srv}
	s.ServeAgent(fc)
	// The agent's side reads what the block process asks, as the real one does.
	go func() {
		for {
			if _, err := sock.BlockCodec.Read(cli); err != nil {
				return
			}
		}
	}()
	if err := sock.BlockCodec.Write(cli, &sock.BlockMsg{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: epoch}}); err != nil {
		t.Fatal(err)
	}
	if err := sock.BlockCodec.Write(cli, &sock.BlockMsg{Type: sock.BlockIntermediate, Intermediate: newAuthority(t, "a").bundle(acct, epoch)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return keyHeld(s, acct) })

	fc.fail.Store(true)
	if s.link.send(&sock.BlockMsg{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: make([]byte, 32)}}) {
		t.Fatal("a failing write reported success")
	}
	waitFor(t, func() bool { return !keyHeld(s, acct) })

	// The agent redials and, with an empty epoch, sends nothing: no key is used.
	srv2, cli2 := net.Pipe()
	defer cli2.Close()
	go func() {
		for {
			if _, err := sock.BlockCodec.Read(cli2); err != nil {
				return
			}
		}
	}()
	s.ServeAgent(srv2)
	if keyHeld(s, acct) {
		t.Fatal("a key outlived the connection that failed")
	}
}

// A frame of a replaced connection's reader is not applied (B6-r2-3).
func TestFrameOfReplacedConnectionIsNotApplied(t *testing.T) {
	var l agentLink
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	lost := 0
	l.attach(c1, func() { lost++ })
	l.attach(c2, func() { lost++ })
	if lost != 1 {
		t.Fatalf("lost ran %d times", lost)
	}
	ran := false
	l.apply(c1, func() { ran = true })
	if ran {
		t.Fatal("a frame of the old connection was applied")
	}
	l.apply(c2, func() { ran = true })
	if !ran {
		t.Fatal("a frame of the current connection was not applied")
	}
	// A detach of the old connection after the replacement must not wipe the new one.
	l.detach(c1, func() { lost++ })
	if lost != 1 {
		t.Fatalf("a stale detach ran lost (%d)", lost)
	}
}

// A visitor whose form could not be relayed is told to try again, and the try is
// not spent (B6-r2-2).
func TestUnblockQuotaNotSpentWhenAgentIsAway(t *testing.T) {
	h := newHarness(t)
	hash := h.addPage(formPage(policyv1.UnblockMode_UNBLOCK_MODE_REQUEST))
	f := frame("bank.example", 80, hash)
	tok := h.formToken(f)

	h.s.link.close()
	for i := 0; i < UnblockPerSource+2; i++ {
		if r := h.post(f, tok, "hi", ""); r.StatusCode != 503 {
			t.Fatalf("try %d: status %d", i, r.StatusCode)
		}
	}
	block, agent := sockfake.BlockPair()
	h.s.ServeAgent(block.Conn)
	t.Cleanup(func() { agent.Close() })
	got := make(chan *sock.UnblockMsg, 1)
	go func() {
		for {
			m, err := agent.Recv()
			if err != nil {
				return
			}
			if m.Type == sock.BlockUnblock {
				got <- m.Unblock
			}
		}
	}()
	if r := h.post(f, tok, "hi", ""); r.StatusCode != 200 {
		t.Fatalf("after the agent returned: status %d", r.StatusCode)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("the request was not relayed after the failed tries")
	}
}
