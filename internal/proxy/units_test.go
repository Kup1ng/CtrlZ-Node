package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"Example.COM":     "example.com",
		"example.com.":    "example.com",
		"a_b.example":     "a_b.example",
		"xn--mgba3a4f16a": "xn--mgba3a4f16a",
	}
	for in, want := range ok {
		w, text, err := normalize(in)
		if err != nil || text != want {
			t.Errorf("%q: %q %v", in, text, err)
		}
		if err == nil && sock.LinkCodec.Check != nil {
			// What normalize returns must pass the link's own check.
			m := &sock.LinkMsg{Type: sock.TLinkLookup, Lookup: &sock.LinkLookup{Source: []byte{1, 2, 3, 4}, Name: w, Port: 443}}
			if err := sock.LinkCodec.Check(m); err != nil {
				t.Errorf("%q: the link refuses it: %v", in, err)
			}
		}
	}
	for _, in := range []string{"", ".", "..", "a..b", "127.0.0.1", "::1", "[::1]", "2001:db8::1", "bücher.example", "a b.example", "exa$mple.com", "example.123", string(make([]byte, 300))} {
		if _, _, err := normalize(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	long := ""
	for i := 0; i < 4; i++ {
		long += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
	}
	if _, _, err := normalize(long + "com"); err == nil {
		t.Error("a name over 253 bytes accepted")
	}
	if _, _, err := normalize("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example"); err == nil {
		t.Error("a label over 63 bytes accepted")
	}
}

func TestIranian(t *testing.T) {
	for in, want := range map[string]bool{
		"ir": true, "a.ir": true, "a.b.ir": true, "xn--mgba3a4f16a": true, "x.xn--mgba3a4f16a": true,
		"air": false, "ir.com": false, "example.com": false, "xir": false,
	} {
		if iranian(in) != want {
			t.Errorf("%q", in)
		}
	}
}

func TestHostOnly(t *testing.T) {
	for in, want := range map[string]string{"a.example": "a.example", "a.example:8080": "a.example", "[::1]:80": "::1", "[::1]": "::1", "::1": "::1"} {
		if got := hostOnly(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestPoolEvictsTheSourceOwnOldestFirst(t *testing.T) {
	p := newPool(2, 100)
	var closed []int
	mk := func(n int) func() { return func() { closed = append(closed, n) } }
	a, b := keyOf([]byte{1, 1, 1, 1}), keyOf([]byte{2, 2, 2, 2})
	p.admit(a, mk(1))
	p.admit(b, mk(10))
	p.admit(a, mk(2))
	p.admit(a, mk(3)) // over a's cap of 2: a's oldest goes, never b's
	if len(closed) != 1 || closed[0] != 1 {
		t.Fatalf("closed %v", closed)
	}
	if p.size() != 3 {
		t.Fatalf("size %d", p.size())
	}
}

func TestPoolOverCapClosesTheLargestSourcesOldest(t *testing.T) {
	p := newPool(100, 5)
	var closed []int
	mk := func(n int) func() { return func() { closed = append(closed, n) } }
	big, small := keyOf([]byte{1, 1, 1, 1}), keyOf([]byte{2, 2, 2, 2})
	for i := 1; i <= 4; i++ {
		p.admit(big, mk(i))
	}
	p.admit(small, mk(100))
	// Full. A newcomer from the small source costs the big source its oldest.
	p.admit(small, mk(101))
	if len(closed) != 1 || closed[0] != 1 {
		t.Fatalf("closed %v", closed)
	}
	if p.size() != 5 {
		t.Fatalf("size %d", p.size())
	}
}

func TestPoolRelease(t *testing.T) {
	p := newPool(2, 10)
	k := keyOf([]byte{1, 1, 1, 1})
	e := p.admit(k, func() {})
	p.release(e)
	p.release(e)
	if p.size() != 0 {
		t.Fatal("not released once")
	}
}

func TestRateBucket(t *testing.T) {
	r := newRate(10, 3)
	k := keyOf([]byte{1, 1, 1, 1})
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !r.allow(k, now) {
			t.Fatal("burst refused")
		}
	}
	if r.allow(k, now) {
		t.Fatal("over the burst")
	}
	if !r.allow(k, now.Add(150*time.Millisecond)) {
		t.Fatal("no refill")
	}
	if !r.allow(keyOf([]byte{9, 9, 9, 9}), now) {
		t.Fatal("another source shares the bucket")
	}
}

func TestCounter(t *testing.T) {
	c := newCounter(2, 3)
	a, b := keyOf([]byte{1}), keyOf([]byte{2})
	if !c.take(a) || !c.take(a) || c.take(a) {
		t.Fatal("per source")
	}
	if !c.take(b) || c.take(b) {
		t.Fatal("node")
	}
	c.put(a)
	if !c.take(b) {
		t.Fatal("not released")
	}
}

// A sweep with a fake kernel: the idle splice, and the memory trim that closes the
// stalled connections first.
func TestSweepIdleAndMemory(t *testing.T) {
	cfg := testConfig()
	cfg.IdleS = 1
	cfg.MemUnit = 100
	r := newRig(t, func(o *Options) { o.MemUnit = "unit"; o.Sweep = time.Hour })
	r.Sys.moved, r.Sys.waiting, r.Sys.mem = map[net.Conn]uint64{}, map[net.Conn]int{}, map[string]uint64{}
	r.handshake(cfg)
	s := newSocks(t, answerThenEcho)
	var cs []net.Conn
	for i := 0; i < 3; i++ {
		c := dialClient(t, r.addr(1))
		_, _ = c.Write(clientHello(t, "example.com"))
		r.route(true, proxyVerdict(s.addr()))
		readSome(t, c, 3*time.Second)
		cs = append(cs, c)
	}
	conns := r.p.snapshot()
	if len(conns) != 3 {
		t.Fatalf("%d connections", len(conns))
	}
	// Give every connection a client and a far socket in the fake kernel.
	for i, cn := range conns {
		r.Sys.moved[cn.c] = uint64(100 * (i + 1))
		r.Sys.moved[cn.far()] = 1
	}
	now := time.Now()
	r.p.samplePass(now)
	// Nothing moves for longer than IdleS: the next pass ends them all.
	r.p.samplePass(now.Add(2 * time.Second))
	if r.p.Open() != 0 {
		t.Fatalf("%d connections left after the idle time", r.p.Open())
	}
	if r.p.refused[rIdle].Load() != 3 {
		t.Fatalf("idle count %d", r.p.refused[rIdle].Load())
	}
	_ = cs

	// Memory: three more, two stalled, the slowest stalled one goes first.
	var live []net.Conn
	for i := 0; i < 3; i++ {
		c := dialClient(t, r.addr(1))
		_, _ = c.Write(clientHello(t, "example.com"))
		r.route(true, proxyVerdict(s.addr()))
		readSome(t, c, 3*time.Second)
		live = append(live, c)
	}
	conns = r.p.snapshot()
	for i, cn := range conns {
		cn.sampMu.Lock()
		cn.delta = uint64(10 * (i + 1))
		cn.sampMu.Unlock()
		r.Sys.waiting[cn.c] = 1
	}
	// One of them has nothing waiting, so it is not a candidate.
	r.Sys.waiting[conns[0].c] = 0
	r.Sys.mem["unit"] = 50 // under the value: nothing happens
	r.p.memCheck()
	if r.p.Open() != 3 {
		t.Fatal("trimmed while under")
	}
	r.Sys.mem["unit"] = 500
	r.p.memCheck()
	if r.p.Open() != 1 || r.p.refused[rMem].Load() != 2 {
		t.Fatalf("open %d, trimmed %d", r.p.Open(), r.p.refused[rMem].Load())
	}
	if !conns[0].held() {
		t.Fatal("the connection with nothing waiting was closed")
	}
}
