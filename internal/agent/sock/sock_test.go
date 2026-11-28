package sock

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func allow(net.Conn) error { return nil }

func sockPath(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "a.sock")
}

func startServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	if cfg.Path == "" {
		cfg.Path = sockPath(t)
	}
	if cfg.Check == nil {
		cfg.Check = allow
	}
	s, err := Listen(cfg)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Serve(ctx)
	t.Cleanup(func() { cancel(); s.Close() })
	return s
}

func dial(t *testing.T, path string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readMsg(t *testing.T, c net.Conn) *Msg {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := Read(c, MaxFrameToDNS)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return m
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSnapshotThenUpdates(t *testing.T) {
	s := startServer(t, ServerConfig{RunID: 42})
	_ = s.Publish(&Msg{Type: TypeImage, Image: &Image{Name: "7"}})
	_ = s.Publish(&Msg{Type: TypeImage, Image: &Image{Name: "8"}}) // replaces
	_ = s.Publish(&Msg{Type: TypeConfig, Config: &Config{NodeConfig: []byte("nc")}})
	_ = s.Publish(&Msg{Type: TypeZoneKey, ZoneKey: &ZoneKey{SANs: []string{"b.example", "a.example"}, Key: []byte("k1")}})
	_ = s.Publish(&Msg{Type: TypeFacts, Facts: &Facts{ServerTimeSeen: true}})
	c := dial(t, s.cfg.Path)
	h := readMsg(t, c)
	if h.Type != TypeHello || h.Hello.RunID != 42 || h.Hello.Version != Version {
		t.Fatalf("first frame: %+v", h)
	}
	var types []string
	var image string
	for i := 0; i < 4; i++ {
		m := readMsg(t, c)
		types = append(types, m.Type)
		if m.Type == TypeImage {
			image = m.Image.Name
		}
	}
	// config and keys come before the image, the facts last
	want := []string{TypeConfig, TypeZoneKey, TypeImage, TypeFacts}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("order %v, want %v", types, want)
		}
	}
	if image != "8" {
		t.Errorf("image %q: the old message of the slot was sent", image)
	}
	_ = s.Publish(&Msg{Type: TypeTable, Table: &Table{Version: 3, InUse: true}})
	if m := readMsg(t, c); m.Type != TypeTable || m.Table.Version != 3 {
		t.Errorf("update: %+v", m)
	}
	// a same-SAN-set zone key replaces, regardless of the order of its SANs
	_ = s.Publish(&Msg{Type: TypeZoneKey, ZoneKey: &ZoneKey{SANs: []string{"a.example", "b.example"}, Key: []byte("k2")}})
	readMsg(t, c)
	c2 := dial(t, s.cfg.Path)
	readMsg(t, c2) // hello
	readMsg(t, c2) // config
	if m := readMsg(t, c2); m.Type != TypeZoneKey || string(m.ZoneKey.Key) != "k2" {
		t.Errorf("the snapshot holds the old key: %+v", m)
	}
	if err := s.Publish(&Msg{Type: TypeStats}); err == nil {
		t.Error("a dns-to-agent type was published")
	}
}

func TestPeerCheckRunsBeforeAnythingIsSent(t *testing.T) {
	var calls atomic.Int32
	s := startServer(t, ServerConfig{Check: func(net.Conn) error { calls.Add(1); return errors.New("no") }})
	_ = s.Publish(&Msg{Type: TypeConfig, Config: &Config{NodeConfig: []byte("secret-proof-key")}})
	c := dial(t, s.cfg.Path)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("a rejected peer received %d bytes", n)
	}
	eventually(t, "rejected counter", func() bool { return s.Rejected() == 1 })
	if s.Connected() {
		t.Error("a rejected peer is connected")
	}
	// it cannot send either: its message reaches no handler
	var got atomic.Int32
	s2 := startServer(t, ServerConfig{Check: func(net.Conn) error { return errors.New("no") }, H: Handlers{Stats: func(Stats) { got.Add(1) }}})
	c2 := dial(t, s2.cfg.Path)
	_ = Write(c2, &Msg{Type: TypeStats, Stats: &Stats{QPS: 1}}, MaxFrameFromDNS)
	time.Sleep(100 * time.Millisecond)
	if got.Load() != 0 {
		t.Error("a handler ran for a rejected peer")
	}
}

func TestHandlersAndHostileFrames(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	rec := func(s string) { mu.Lock(); seen = append(seen, s); mu.Unlock() }
	s := startServer(t, ServerConfig{H: Handlers{
		ImageAck:   func(n string) { rec("ack:" + n) },
		FreeCounts: func(i []FreeCount) { rec("free") },
		Activity:   func(i []ActivityItem) { rec("act") },
		Stats:      func(Stats) { panic("handler bug") },
		Outbound:   func(b []byte) { rec("out:" + string(b)) },
	}})
	c := dial(t, s.cfg.Path)
	readMsg(t, c)
	send := func(m *Msg) { _ = Write(c, m, MaxFrameFromDNS) }
	send(&Msg{Type: TypeImageAck, ImageAck: &ImageAck{Name: "9"}})
	send(&Msg{Type: TypeStats, Stats: &Stats{}}) // panics in the handler, connection lives
	send(&Msg{Type: TypeFreeCounts, FreeCounts: &FreeCounts{Items: make([]FreeCount, MaxItems+1)}})
	send(&Msg{Type: TypeActivity, Activity: &Activity{Items: []ActivityItem{{Label: "x"}}}})
	send(&Msg{Type: TypeOutbound, Outbound: &Outbound{NodeMessage: []byte("nm")}})
	eventually(t, "handlers", func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) == 3 })
	mu.Lock()
	want := []string{"ack:9", "act", "out:nm"}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("seen %v", seen)
		}
	}
	mu.Unlock()

	// a type that only the agent may send ends the connection
	send(&Msg{Type: TypeImage, Image: &Image{Name: "x"}})
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, err := Read(c, MaxFrameToDNS); err != nil {
			break
		}
	}
	eventually(t, "disconnect", func() bool { return !s.Connected() })

	// an oversized length is refused before the body is read
	c = dial(t, s.cfg.Path)
	readMsg(t, c)
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], MaxFrameFromDNS+1)
	_, _ = c.Write(h[:])
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, err := Read(c, MaxFrameToDNS); err != nil {
			break
		}
	}
	eventually(t, "disconnect after the oversized frame", func() bool { return !s.Connected() })

	// garbage JSON, unknown fields and an empty type
	for _, body := range []string{"{not json", `{"t":"stats","zzz":1}`, `{"t":""}`} {
		c = dial(t, s.cfg.Path)
		readMsg(t, c)
		binary.BigEndian.PutUint32(h[:], uint32(len(body)))
		_, _ = c.Write(append(h[:], body...))
		eventually(t, "disconnect after "+body, func() bool { return !s.Connected() })
	}
}

func TestNewConnectionReplacesOld(t *testing.T) {
	var ups, downs atomic.Int32
	s := startServer(t, ServerConfig{H: Handlers{Connected: func(up bool) {
		if up {
			ups.Add(1)
		} else {
			downs.Add(1)
		}
	}}})
	c1 := dial(t, s.cfg.Path)
	readMsg(t, c1)
	c2 := dial(t, s.cfg.Path)
	readMsg(t, c2)
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, err := Read(c1, MaxFrameToDNS); err != nil {
			break
		}
	}
	_ = s.Publish(&Msg{Type: TypeImage, Image: &Image{Name: "1"}})
	if m := readMsg(t, c2); m.Type != TypeImage {
		t.Fatalf("the new connection got %+v", m)
	}
	if downs.Load() != 0 || ups.Load() != 2 {
		t.Errorf("ups=%d downs=%d: a replaced connection is not a down", ups.Load(), downs.Load())
	}
	c2.Close()
	eventually(t, "down", func() bool { return downs.Load() == 1 })
}

func TestSlowReaderIsDroppedNotWaitedFor(t *testing.T) {
	s := startServer(t, ServerConfig{})
	c := dial(t, s.cfg.Path)
	readMsg(t, c)
	// c never reads again. Publishing must not block, and the connection ends.
	big := make([]byte, 256<<10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			_ = s.Publish(&Msg{Type: TypeZoneKey, ZoneKey: &ZoneKey{SANs: []string{"a" + string(rune('a'+i%26)) + ".example", string(rune('a' + i/26%26))}, Key: big}})
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Publish blocked on a dns that does not read")
	}
	eventually(t, "slow dns dropped", func() bool { return !s.Connected() })
}

func TestListenPathRules(t *testing.T) {
	p := sockPath(t)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ServerConfig{Path: p, Check: allow}); err == nil {
		t.Error("replaced a regular file")
	}
	if _, err := Listen(ServerConfig{Path: p}); err == nil {
		t.Error("no peer check accepted")
	}
	_ = os.Remove(p)
	s := startServer(t, ServerConfig{Path: p})
	if runtime.GOOS == "linux" {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o660 {
			t.Errorf("mode %v %v", fi.Mode().Perm(), err)
		}
	}
	s.Close()
	// a stale socket from a crashed agent is replaced
	s2, err := Listen(ServerConfig{Path: p, Check: allow})
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

func TestClientReconnectsAndSendsWhileUp(t *testing.T) {
	p := sockPath(t)
	var got atomic.Int32
	cfg := ServerConfig{Path: p, Check: allow, H: Handlers{Stats: func(Stats) { got.Add(1) }}}
	s, err := Listen(cfg)
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx)
	_ = s.Publish(&Msg{Type: TypeImage, Image: &Image{Name: "5"}})

	var mu sync.Mutex
	var msgs []string
	var ups []bool
	cl := NewClient(p, ClientHandlers{
		Message: func(m *Msg) { mu.Lock(); msgs = append(msgs, m.Type); mu.Unlock() },
		State:   func(up bool) { mu.Lock(); ups = append(ups, up); mu.Unlock() },
	})
	if cl.Send(&Msg{Type: TypeStats, Stats: &Stats{}}) {
		t.Fatal("sent while down")
	}
	go cl.Run(ctx)
	eventually(t, "client up", cl.Up)
	eventually(t, "image delivered", func() bool { mu.Lock(); defer mu.Unlock(); return len(msgs) == 2 })
	if !cl.Send(&Msg{Type: TypeStats, Stats: &Stats{}}) {
		t.Fatal("send while up")
	}
	eventually(t, "stats", func() bool { return got.Load() == 1 })

	s.Close() // the agent goes away
	eventually(t, "client down", func() bool { return !cl.Up() })
	if cl.Send(&Msg{Type: TypeStats, Stats: &Stats{}}) {
		t.Error("send while down")
	}
	s2, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go s2.Serve(ctx)
	defer s2.Close()
	eventually(t, "client up again", cl.Up)
	mu.Lock()
	defer mu.Unlock()
	if len(ups) < 3 || !ups[0] || ups[1] || !ups[2] {
		t.Errorf("states %v", ups)
	}
}

func TestFactsFreeOK(t *testing.T) {
	f := Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: true, FreeSet: true, FreeEnabled: true, FreeVersion: 10, OffFloor: 10}
	if !f.FreeOK() {
		t.Fatal("all hold")
	}
	for name, mut := range map[string]func(*Facts){
		"no server time":  func(f *Facts) { f.ServerTimeSeen = false },
		"not caught up":   func(f *Facts) { f.CaughtUpOnce = false },
		"lagging":         func(f *Facts) { f.LagOK = false },
		"no value":        func(f *Facts) { f.FreeSet = false },
		"disabled":        func(f *Facts) { f.FreeEnabled = false },
		"under the floor": func(f *Facts) { f.OffFloor = 11 },
	} {
		g := f
		mut(&g)
		if g.FreeOK() {
			t.Errorf("%s: free path on", name)
		}
	}
}

// p4n-W5b-r1-12: Serve added to its WaitGroup while Close was waiting on it, which
// the race detector reports (and which lets a connection outlive Close). Connections
// arriving while the server closes must be refused or finished before Close returns.
func TestServeCloseRaceWithIncomingConnections(t *testing.T) {
	for i := 0; i < 60; i++ {
		p := sockPath(t)
		s, err := Listen(ServerConfig{Path: p, Check: allow})
		if err != nil {
			t.Skip(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go s.Serve(ctx)
		var dials sync.WaitGroup
		for j := 0; j < 4; j++ {
			dials.Add(1)
			go func() {
				defer dials.Done()
				if c, err := net.DialTimeout("unix", p, time.Second); err == nil {
					defer c.Close()
					_, _ = c.Read(make([]byte, 1))
				}
			}()
		}
		s.Close()
		dials.Wait()
		cancel()
	}
}

// A second Close must not return before the first has finished. Run closes the
// server and so does Serve when its context ends; if the second returned early a new
// agent could bind the same path and then lose its socket file to the first Close's
// os.Remove (seen as a dns that never reconnected after an agent restart).
func TestSecondCloseWaitsForTheFirst(t *testing.T) {
	p := sockPath(t)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	s, err := Listen(ServerConfig{Path: p, Check: allow, H: Handlers{Connected: func(up bool) {
		if up {
			entered <- struct{}{}
			<-gate // the connection's handler is slow to finish
		}
	}}})
	if err != nil {
		t.Skip(err)
	}
	go s.Serve(context.Background())
	c, err := net.DialTimeout("unix", p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-entered
	first, second := make(chan struct{}), make(chan struct{})
	go func() { s.Close(); close(first) }()
	time.Sleep(50 * time.Millisecond)
	go func() { s.Close(); close(second) }()
	select {
	case <-second:
		t.Fatal("the second Close returned while the first was still waiting")
	case <-time.After(200 * time.Millisecond):
	}
	close(gate)
	<-first
	<-second
	// the path is free for the next server, and its socket stays
	s2, err := Listen(ServerConfig{Path: p, Check: allow})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the new server's socket is gone: %v", err)
	}
}

// FreeOn is (a) and FreeCaughtUp is (c): the free path's counters name the first
// that fails, so each must move with its own facts only.
func TestFactsFreeGateParts(t *testing.T) {
	f := Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: true, FreeSet: true, FreeEnabled: true, FreeVersion: 10, OffFloor: 10}
	if !f.FreeOn() || !f.FreeCaughtUp() {
		t.Fatal("all hold")
	}
	for name, c := range map[string]struct {
		mut      func(*Facts)
		on, caug bool
	}{
		"no value":        {func(f *Facts) { f.FreeSet = false }, false, true},
		"disabled":        {func(f *Facts) { f.FreeEnabled = false }, false, true},
		"under the floor": {func(f *Facts) { f.OffFloor = 11 }, false, true},
		"no server time":  {func(f *Facts) { f.ServerTimeSeen = false }, true, false},
		"not caught up":   {func(f *Facts) { f.CaughtUpOnce = false }, true, false},
		"lagging":         {func(f *Facts) { f.LagOK = false }, true, false},
	} {
		g := f
		c.mut(&g)
		if g.FreeOn() != c.on || g.FreeCaughtUp() != c.caug || g.FreeOK() {
			t.Errorf("%s: on %v caught up %v ok %v", name, g.FreeOn(), g.FreeCaughtUp(), g.FreeOK())
		}
	}
}
