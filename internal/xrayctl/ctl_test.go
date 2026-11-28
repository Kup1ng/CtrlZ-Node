package xrayctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/xrayrun"
)

// TestMain lets the test binary stand in for Xray: the real runner executes it with
// the arguments of an operation and it behaves like a tiny fake of the binary. The
// fake is built by the test itself, so nothing downloads Xray.
func TestMain(m *testing.M) {
	if os.Getenv("GODEBUG") == "multipathtcp=0" && len(os.Args) > 1 && (os.Args[1] == "run" || os.Args[1] == "api") {
		fakeXray()
		return
	}
	os.Exit(m.Run())
}

func fakeXray() {
	in, _ := io.ReadAll(os.Stdin)
	switch {
	case strings.Contains(string(in), "SLEEP"):
		time.Sleep(time.Minute)
	case strings.Contains(string(in), "BAD"):
		fmt.Printf("failed to load config: %s\x01\n", in)
		os.Exit(23)
	}
	fmt.Println("ok", strings.Join(os.Args[1:], " "))
}

type fakeRunner struct {
	bin   string
	args  []string
	stdin []byte
	exit  int
	out   string
}

func (f *fakeRunner) Run(_ context.Context, bin string, args []string, stdin []byte) (int, []byte, error) {
	f.bin, f.args, f.stdin = bin, args, stdin
	return f.exit, []byte(f.out), nil
}

func server(r Runner) *Server {
	return &Server{
		Layout:   xrayrun.Layout{Etc: "/e", Lib: "/l", Run: "/r"},
		Runner:   r,
		ReadFile: func(string) ([]byte, error) { return []byte("v26.11.9\n"), nil },
	}
}

func TestArguments(t *testing.T) {
	tag := "L" + strings.Repeat("a", 32) + ".1.0"
	for _, c := range []struct {
		run  sock.CtlRun
		want string
	}{
		{sock.CtlRun{Op: sock.OpTest, Stdin: []byte("{}")}, "run -test -c stdin:"},
		{sock.CtlRun{Op: sock.OpAddOut, Slot: "a", Stdin: []byte("{}")}, "api ado -s unix:///r-a/api.sock -t 5 stdin:"},
		{sock.CtlRun{Op: sock.OpAddRules, Slot: "b", Stdin: []byte("{}")}, "api adrules -append -s unix:///r-b/api.sock -t 5 stdin:"},
		{sock.CtlRun{Op: sock.OpRmOut, Slot: "a", Tags: []string{tag}}, "api rmo -s unix:///r-a/api.sock -t 5 " + tag},
	} {
		f := &fakeRunner{}
		c.run.Version = "v26.11.9"
		res := server(f).Exec(context.Background(), &c.run)
		if res.Exit != 0 || res.Error != "" {
			t.Fatalf("%s: %+v", c.run.Op, res)
		}
		if got := strings.Join(f.args, " "); got != c.want || f.bin != "/l/v26.11.9/xray" {
			t.Errorf("%s: %q on %s", c.run.Op, got, f.bin)
		}
	}
}

func TestRefusals(t *testing.T) {
	s := server(&fakeRunner{})
	for name, r := range map[string]sock.CtlRun{
		"bad version": {Version: "../x", Op: sock.OpTest, Stdin: []byte("{}")},
		"bad slot":    {Version: "v26.11.9", Op: sock.OpAddIn, Slot: "../a", Stdin: []byte("{}")},
		"bad op":      {Version: "v26.11.9", Op: "run", Slot: "a"},
	} {
		if res := s.Exec(context.Background(), &r); res.Exit == 0 {
			t.Errorf("%s: ran", name)
		}
	}
	s.ReadFile = func(string) ([]byte, error) { return []byte("v26.10.0\n"), nil }
	if res := s.Exec(context.Background(), &sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")}); res.Exit == 0 {
		t.Error("a release that xray.allow does not hold ran")
	}
	s.ReadFile = func(string) ([]byte, error) { return nil, fs.ErrNotExist }
	if res := s.Exec(context.Background(), &sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")}); res.Exit == 0 {
		t.Error("a missing allow file let it run")
	}
}

func TestErrorTextIsClippedAndClean(t *testing.T) {
	f := &fakeRunner{exit: 23, out: strings.Repeat("é", 4000) + "\x00\x1b[31m"}
	res := server(f).Exec(context.Background(), &sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")})
	if res.Exit != 23 || len(res.Error) > sock.MaxCtlError || strings.ContainsAny(res.Error, "\x00\x1b") {
		t.Fatalf("exit %d, %d bytes", res.Exit, len(res.Error))
	}
}

func TestServeOverASocket(t *testing.T) {
	f := &fakeRunner{}
	s := server(f)
	a, b := net.Pipe()
	go s.Handle(context.Background(), a)
	defer b.Close()
	req := &sock.CtlMsg{Type: sock.CtlTypeRun, Run: &sock.CtlRun{ID: 7, Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")}}
	if err := sock.CtlCodec.Write(b, req); err != nil {
		t.Fatal(err)
	}
	m, err := sock.CtlCodec.Read(b)
	if err != nil || m.Result == nil || m.Result.ID != 7 || m.Result.Exit != 0 {
		t.Fatalf("%v %+v", err, m)
	}
	// A frame that is not `run` ends the connection.
	if err := sock.CtlCodec.Write(b, &sock.CtlMsg{Type: sock.CtlTypeResult, Result: &sock.CtlResult{}}); err != nil {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := sock.CtlCodec.Read(b); err == nil {
		t.Fatal("the server answered a frame it must not accept")
	}
}

func TestPeerCheckClosesTheConnection(t *testing.T) {
	f := &fakeRunner{}
	s := server(f)
	s.Check = func(net.Conn) error { return fmt.Errorf("no") }
	a, b := net.Pipe()
	go s.Handle(context.Background(), a)
	defer b.Close()
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("read from a refused peer")
	}
	if f.args != nil {
		t.Fatal("an operation ran for a refused peer")
	}
}

// The real runner, with the test binary as the fake Xray.
func TestExecRunnerWithTheFakeBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	s := server(ExecRunner{Dir: t.TempDir()})
	s.Binary = func(string) string { return self }

	res := s.Exec(context.Background(), &sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte(`{"a":1}`)})
	if res.Exit != 0 {
		t.Fatalf("%+v", res)
	}
	res = s.Exec(context.Background(), &sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte(`BAD`)})
	if res.Exit != 23 || !strings.Contains(res.Error, "failed to load config") || strings.Contains(res.Error, "\x01") {
		t.Fatalf("%+v", res)
	}
}

func TestExecRunnerKillsATimedOutChild(t *testing.T) {
	self, _ := os.Executable()
	s := server(ExecRunner{Dir: t.TempDir()})
	s.Binary = func(string) string { return self }
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := s.Exec(ctx, &sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("SLEEP")})
	if res.Exit != xrayrun.CtlTimeout || time.Since(start) > 10*time.Second {
		t.Fatalf("%+v after %v", res, time.Since(start))
	}
}

// gateRunner holds the first operation until released and counts the runs.
type gateRunner struct {
	mu      sync.Mutex
	runs    int
	hold    chan struct{}
	started chan struct{}
}

func (g *gateRunner) Run(ctx context.Context, _ string, _ []string, _ []byte) (int, []byte, error) {
	g.mu.Lock()
	g.runs++
	first := g.runs == 1
	g.mu.Unlock()
	if first {
		close(g.started)
		select {
		case <-g.hold:
		case <-ctx.Done():
		}
	}
	return 0, nil, nil
}

// An operation that was queued behind another one while its client gave up must not
// run afterwards: the agent has undone it and forgotten it (B5 r1-25).
func TestQueuedOperationOfAClientThatLeftNeverRuns(t *testing.T) {
	g := &gateRunner{hold: make(chan struct{}), started: make(chan struct{})}
	s := server(g)
	req := &sock.CtlMsg{Type: sock.CtlTypeRun, Run: &sock.CtlRun{ID: 1, Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")}}

	a1, b1 := net.Pipe()
	defer b1.Close()
	go s.Handle(context.Background(), a1)
	if err := sock.CtlCodec.Write(b1, req); err != nil {
		t.Fatal(err)
	}
	<-g.started

	a2, b2 := net.Pipe()
	done := make(chan struct{})
	go func() { s.Handle(context.Background(), a2); close(done) }()
	if err := sock.CtlCodec.Write(b2, req); err != nil {
		t.Fatal(err)
	}
	b2.Close() // the client's deadline ran out
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the queued operation of a client that left still waits")
	}

	close(g.hold)
	b1.SetReadDeadline(time.Now().Add(3 * time.Second))
	if m, err := sock.CtlCodec.Read(b1); err != nil || m.Result == nil || m.Result.Exit != 0 {
		t.Fatalf("the first client: %v %+v", err, m)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.runs != 1 {
		t.Errorf("%d runs, want the first only", g.runs)
	}
}

type errRunner struct{ err error }

func (e errRunner) Run(context.Context, string, []string, []byte) (int, []byte, error) {
	return -1, nil, e.err
}

// A child that a signal ended, a binary that cannot be executed and one that ran past its
// limit answer three different codes, so the agent can tell a fragment that kills the
// binary from a binary that is not there (B5 r1-2, r1-5).
func TestNoStatusHasItsOwnCode(t *testing.T) {
	run := &sock.CtlRun{Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")}
	if res := server(errRunner{&exec.ExitError{}}).Exec(context.Background(), run); res.Exit != xrayrun.CtlSignal {
		t.Errorf("a signal: %+v", res)
	}
	if res := server(errRunner{errors.New("exec format error")}).Exec(context.Background(), run); res.Exit != xrayrun.CtlNoRun {
		t.Errorf("no run: %+v", res)
	}
	s := server(ExecRunner{Dir: t.TempDir()})
	s.Binary = func(string) string { return filepath.Join(t.TempDir(), "missing") }
	if res := s.Exec(context.Background(), run); res.Exit != xrayrun.CtlNoRun {
		t.Errorf("a missing binary: %+v", res)
	}
	s.ReadFile = func(string) ([]byte, error) { return []byte("v26.10.0\n"), nil }
	if res := s.Exec(context.Background(), run); res.Exit != xrayrun.CtlNotJudged {
		t.Errorf("a release not allowed: %+v", res)
	}
}
