package xray

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayctl"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

type echoRunner struct{ last []string }

func (e *echoRunner) Run(_ context.Context, _ string, args []string, stdin []byte) (int, []byte, error) {
	e.last = args
	if string(stdin) == "bad" {
		return 23, []byte("config error"), nil
	}
	return 0, nil, nil
}

// The client of the manager against the server of ctrlz-xrayctl over a real unix
// socket: an ok, a child that fails, and a frame the server refuses.
func TestSockCtlAgainstTheServer(t *testing.T) {
	// Not t.TempDir: a socket file cannot always be removed on a developer machine, and
	// that would fail a test whose body passed or skipped.
	dir, err := os.MkdirTemp("", "xs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l := xrayrun.Layout{Etc: dir, Lib: dir, Run: dir}
	if err := os.MkdirAll(filepath.Join(dir, "versions"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.Allow(), []byte("v26.11.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", path)
	t.Cleanup(func() { _ = os.Remove(path) })
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	if c, err := net.Dial("unix", path); err != nil {
		t.Skipf("this host cannot dial its own unix socket: %v", err)
	} else {
		c.Close()
	}
	runner := &echoRunner{}
	srv := &xrayctl.Server{Layout: l, Runner: runner}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	c := &SockCtl{Path: path}
	if err := c.Do(ctx, sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	err = c.Do(ctx, sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("bad")})
	var ce *CtlError
	if !errors.As(err, &ce) || ce.Exit != 23 || ce.Text != "config error" {
		t.Fatalf("%v", err)
	}
	// A frame that fails the codec's own check never leaves the client.
	if err := c.Do(ctx, sock.CtlRun{Version: "../x", Op: sock.OpTest, Stdin: []byte("{}")}); err == nil {
		t.Fatal("a bad version was sent")
	}
	if err := (&SockCtl{Path: filepath.Join(dir, "none.sock")}).Do(ctx, sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")}); err == nil {
		t.Fatal("no error without a socket")
	}
}
