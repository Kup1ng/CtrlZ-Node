package proxy

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

// unitProxy is a proxy with a link installed by hand, for tests of the locking
// between the link, the connections and the listeners.
func unitProxy(t *testing.T, o Options) (*Proxy, *link) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	p := New(o)
	lk := newLink(a)
	p.lk = lk
	return p, lk
}

func unitConn(p *Proxy, id uint64) *conn {
	a, b := net.Pipe()
	_ = b.Close()
	cn := &conn{p: p, id: id, c: a}
	p.conns[id] = cn
	return cn
}

// B4-r1-2: a kind 1 connection names its first exit from the verdict on, so the open
// list does not read it as a block page connection and `end` finds it. Nothing was
// dialled, so its close frees the place at once.
func TestVerdictNamesTheFirstExitBeforeAnyDial(t *testing.T) {
	p, lk := unitProxy(t, Options{})
	cn := unitConn(p, 1)
	v := &sock.LinkVerdict{Kind: sock.VerdictProxy, Tag: []byte("t"), Targets: []sock.Target{{Socks: "a:1"}, {Socks: "b:1"}}}
	if !cn.setVerdict(lk, v) {
		t.Fatal("verdict refused")
	}
	it, ok := cn.openItem()
	if !ok || it.Socks != "a:1" {
		t.Fatalf("open item %+v %v", it, ok)
	}
	if cn.socksAddr() != "a:1" {
		t.Fatal("end by socks would not find the connection")
	}
	cn.kill()
	if len(p.closedPending) != 0 || len(p.closedIDs) != 1 {
		t.Fatalf("a close before any dial left a pending dial: ids %v pending %v", p.closedIDs, p.closedPending)
	}
}

// B4-r1-2: a verdict that came over a link that is no longer the proxy's is refused.
// The new dns does not hold a place for the connection and could never end it.
func TestVerdictOfAnOldLinkIsRefused(t *testing.T) {
	p, old := unitProxy(t, Options{})
	cn := unitConn(p, 1)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	p.mu.Lock()
	p.lk = newLink(a)
	p.mu.Unlock()
	if cn.setVerdict(old, &sock.LinkVerdict{Kind: sock.VerdictProxy, Targets: []sock.Target{{Socks: "a:1"}}}) {
		t.Fatal("a verdict of the old link was taken")
	}
	if _, ok := cn.openItem(); ok {
		t.Fatal("the connection is in the open list")
	}
}

// B4-r1-5: a connection that was ended queues no moved, and one that is queued is
// queued before the closed of the same connection.
func TestMovedIsNeverQueuedAfterClosed(t *testing.T) {
	p, lk := unitProxy(t, Options{})
	cn := unitConn(p, 1)
	cn.setVerdict(lk, &sock.LinkVerdict{Kind: sock.VerdictProxy, Targets: []sock.Target{{Socks: "a:1"}, {Socks: "b:1"}}})
	if !p.sendMoved(cn, &sock.LinkMoved{ID: 1, Socks: "b:1"}) {
		t.Fatal("a live connection could not move")
	}
	if cn.socksAddr() != "b:1" || len(p.movedQ) != 1 {
		t.Fatalf("socks %q, queue %d", cn.socksAddr(), len(p.movedQ))
	}
	cn.kill()
	if p.sendMoved(cn, &sock.LinkMoved{ID: 1, Socks: "c:1"}) {
		t.Fatal("a moved was queued for a connection that is closed")
	}
	if len(p.movedQ) != 1 {
		t.Fatalf("queue %d after the close", len(p.movedQ))
	}
}

// B4-r1-1: the link that carries a moved is the one that is up when it is sent. With
// none up the connection stops, because dns has nowhere to be told.
func TestMovedUsesTheLinkOfNow(t *testing.T) {
	p, _ := unitProxy(t, Options{})
	cn := unitConn(p, 1)
	p.mu.Lock()
	p.lk = nil
	p.mu.Unlock()
	if p.sendMoved(cn, &sock.LinkMoved{ID: 1, Socks: "b:1"}) {
		t.Fatal("moved with no link")
	}
}

// B4-r1-1: dns restarts while a connection waits for the first byte of its first
// exit. The connection goes on to its second exit and tells the new dns.
func TestFailoverSurvivesALinkRestart(t *testing.T) {
	cfg := testConfig()
	cfg.DialFirstByteMS = 500
	dns2, prox2 := sockfake.LinkPair()
	r := newRig(t, nil)
	r.more <- prox2.Conn
	r.handshake(cfg)
	silent := newSocks(t, hangForever)
	live := newSocks(t, answerThenEcho)
	c := dialClient(t, r.addr(1))
	_, _ = c.Write(clientHello(t, "example.com"))
	r.route(true, proxyVerdict(silent.addr(), live.addr()))
	waitPoll(t, "the first exit got the hello", func() bool { return len(silent.requests()) == 1 })
	r.dns.Close()

	r2 := &rig{t: t, dns: dns2, p: r.p, listeners: r.listeners}
	items := r2.handshake(nil)
	if len(items) != 1 || items[0].Socks != silent.addr() {
		t.Fatalf("open list %+v", items)
	}
	mv := r2.recvType(sock.TLinkMoved).Moved
	if mv.Socks != live.addr() {
		t.Fatalf("moved %+v", mv)
	}
	if got := readSome(t, c, 3*time.Second); string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	dns2.Close()
}

// B4-r1-6: a bind that began on a link that has since gone down does not open the
// listeners. The test plays the cleanup of session by hand while ensureListening
// waits for lmu, which is where the old code had already read its snapshot.
func TestNoBindAfterTheLinkWentDown(t *testing.T) {
	var binds atomic.Int32
	p, _ := unitProxy(t, Options{Listen: func(string) (net.Listener, error) {
		binds.Add(1)
		return net.Listen("tcp", "127.0.0.1:0")
	}})
	p.mu.Lock()
	p.cfg = &sock.ProxyConfig{BindIP: "127.0.0.1"}
	p.mu.Unlock()

	p.lmu.Lock() // the cleanup holds it
	done := make(chan struct{})
	go func() { p.ensureListening(); close(done) }()
	time.Sleep(50 * time.Millisecond)
	p.mu.Lock()
	p.lk, p.cfg = nil, nil
	p.mu.Unlock()
	p.closeListenersLocked()
	p.lmu.Unlock()
	<-done
	if binds.Load() != 0 || p.Listening() {
		t.Fatalf("listeners opened with no link: %d binds", binds.Load())
	}
}

// B4-r1-3: the idle end, the age cap and the memory trim go on while the link to dns
// is down, on the limits of the last config (5.1 keeps open connections, 5.4 bounds
// them). Before the fix the sweeper read the config that the link end clears.
func TestSweepGoesOnWhileTheLinkIsDown(t *testing.T) {
	sys := &fakeSys{moved: map[net.Conn]uint64{}, waiting: map[net.Conn]int{}, mem: map[string]uint64{}}
	p, lk := unitProxy(t, Options{
		Sys: sys, MemUnit: "unit",
		Listen: func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") },
	})
	t.Cleanup(p.closeListeners)
	cfg := testConfig()
	cfg.IdleS, cfg.MaxAgeS, cfg.MemUnit = 1, 3600, 100
	p.applyConfig(lk, cfg)

	mk := func(id uint64) *conn {
		cn := unitConn(p, id)
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		cn.serve = a
		cn.kind, cn.opened, cn.lastMove = sock.VerdictProxy, time.Now(), time.Now()
		sys.moved[cn.c], sys.moved[a] = 5, 5
		return cn
	}
	idle, old := mk(1), mk(2)
	old.opened = time.Now().Add(-2 * time.Hour)

	// The session cleanup of the link end.
	p.mu.Lock()
	p.lk, p.cfg = nil, nil
	p.mu.Unlock()

	now := time.Now()
	p.samplePass(now)
	if !old.isDead() {
		t.Error("the age cap did not run with the link down")
	}
	// Nothing moved for longer than IdleS: every connection that is left goes idle.
	stalledDelta := func(cn *conn, d uint64) {
		cn.sampMu.Lock()
		cn.delta = d
		cn.sampMu.Unlock()
	}
	p.samplePass(now.Add(2 * time.Second))
	if !idle.isDead() {
		t.Error("the idle end did not run with the link down")
	}

	// Memory: a fresh pair, one with bytes waiting.
	cn := mk(3)
	stalledDelta(cn, 1)
	sys.waiting[cn.c] = 1
	sys.mem["unit"] = 50
	p.memCheck()
	if cn.isDead() {
		t.Fatal("trimmed while under the value")
	}
	sys.mem["unit"] = 500
	p.memCheck()
	if !cn.isDead() {
		t.Error("the memory trim did not run with the link down")
	}
}
