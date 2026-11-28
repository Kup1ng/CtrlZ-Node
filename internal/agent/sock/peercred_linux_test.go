//go:build linux

package sock

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// The real check, on a real kernel: a peer with the expected uid passes and the
// same peer under another expected uid does not.
func TestUIDCheckUsesSOPeerCred(t *testing.T) {
	self := uint32(os.Getuid())
	for _, tc := range []struct {
		name string
		uid  uint32
		ok   bool
	}{{"own uid", self, true}, {"another uid", self + 1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := startServer(t, ServerConfig{Check: UIDCheck(tc.uid)})
			c, err := net.Dial("unix", s.cfg.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			m, err := Read(c, MaxFrameToDNS)
			if tc.ok && (err != nil || m.Type != TypeHello) {
				t.Fatalf("a peer with the right uid was refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("a peer with the wrong uid got a frame")
			}
			if !tc.ok {
				eventually(t, "rejected", func() bool { return s.Rejected() == 1 })
			}
		})
	}
	var _ context.Context
}
