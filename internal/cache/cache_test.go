package cache

import (
	"errors"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
)

func nm(s string) names.Name { return names.MustString(s) }

func aRR(n names.Name, ttl uint32, ip string) policy.RR {
	a := netip.MustParseAddr(ip)
	return policy.RR{Name: n, Type: policy.TypeA, Class: policy.ClassIN, TTL: ttl, Data: a.AsSlice()}
}

func ansFor(n names.Name, ttl uint32, ip string) *policy.TrueAnswer {
	return &policy.TrueAnswer{Chain: []names.Name{n}, Answer: []policy.RR{aRR(n, ttl, ip)}}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newCache(clk *clock) *Cache {
	return New(Config{SharedBytes: 1 << 20, FreeBytes: 1 << 20, Now: clk.now})
}

func TestPutGetAgesTTL(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	n := nm("www.example.com")
	k := KeyOf(n, 1, 1, policy.ResolveParams{}, "")
	if err := c.Put(Shared, k, n, ansFor(n, 60, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	clk.add(20 * time.Second)
	got, ok := c.Get(Shared, k)
	if !ok || got.Answer[0].TTL != 40 {
		t.Fatalf("ok=%v ttl=%v", ok, got)
	}
	clk.add(41 * time.Second)
	if _, ok := c.Get(Shared, k); ok {
		t.Fatal("expired entry served")
	}
}

// The two segments never share an entry: a free query cannot read what an
// identified one fetched, nor the reverse (T-559).
func TestSegmentsDoNotCross(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	n := nm("www.example.com")
	k := KeyOf(n, 1, 1, policy.ResolveParams{}, "")
	if err := c.Put(Shared, k, n, ansFor(n, 60, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(Free, k); ok {
		t.Fatal("free segment read a shared entry")
	}
	if err := c.Put(Free, k, n, ansFor(n, 60, "192.0.2.2")); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Get(Shared, k)
	if got.Answer[0].Data[3] != 1 {
		t.Fatal("free Put changed the shared entry")
	}
}

func TestKeyFieldsSeparateEntries(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	n := nm("www.example.com")
	base := policy.ResolveParams{}
	cd := policy.ResolveParams{EffectiveCD: true}
	ecs := policy.ResolveParams{ECS: netip.MustParsePrefix("198.51.100.0/24")}
	keys := []Key{KeyOf(n, 1, 1, base, ""), KeyOf(n, 28, 1, base, ""), KeyOf(n, 1, 1, cd, ""), KeyOf(n, 1, 1, ecs, ""), KeyOf(n, 1, 1, base, "g:x")}
	if err := c.Put(Shared, keys[0], n, ansFor(n, 60, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	for i, k := range keys[1:] {
		if _, ok := c.Get(Shared, k); ok {
			t.Fatalf("key %d hit the entry of key 0", i+1)
		}
	}
}

func TestPutRefusals(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	n := nm("www.example.com")
	k := KeyOf(n, 1, 1, policy.ResolveParams{}, "")
	cases := map[string]*policy.TrueAnswer{
		"failed":   {Failed: true, RCode: policy.RCodeServFail},
		"servfail": {RCode: policy.RCodeServFail, Answer: []policy.RR{aRR(n, 60, "192.0.2.1")}},
		"refused":  {RCode: policy.RCodeRefused},
		"ttl0":     ansFor(n, 0, "192.0.2.1"),
		"empty":    {RCode: policy.RCodeNXDomain},
		"nil":      nil,
	}
	for name, a := range cases {
		if err := c.Put(Shared, k, n, a); err == nil {
			t.Errorf("%s: stored", name)
		}
	}
	if _, ok := c.Get(Shared, k); ok {
		t.Fatal("something was stored")
	}
}

// The Sanity Gate stands before every Put (T-042).
func TestSanityGate(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	pub := nm("www.example.com")
	lan := nm("nas.lan")
	cases := []struct {
		name string
		n    names.Name
		ip   string
		ok   bool
	}{
		{"injected", pub, "10.10.34.5", false},
		{"rfc1918", pub, "192.168.1.1", false},
		{"cgnat", pub, "100.64.0.9", false},
		{"loopback", pub, "127.0.0.1", false},
		{"public", pub, "192.0.2.1", true},
		{"private for a private name", lan, "192.168.1.1", true},
		{"injected for a private name", lan, "10.10.34.5", false},
		{"nat64 over loopback", pub, "64:ff9b::7f00:1", false},
	}
	for _, tc := range cases {
		k := KeyOf(tc.n, 1, 1, policy.ResolveParams{}, tc.name)
		a := ansFor(tc.n, 60, "192.0.2.1")
		addr := netip.MustParseAddr(tc.ip)
		a.Answer[0].Type = policy.TypeA
		a.Answer[0].Data = addr.AsSlice()
		if addr.Is6() {
			a.Answer[0].Type = policy.TypeAAAA
		}
		err := c.Put(Shared, k, tc.n, a)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err=%v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrSanityGate) {
			t.Errorf("%s: want ErrSanityGate, got %v", tc.name, err)
		}
	}
	if c.Stats(Shared).Rejected == 0 {
		t.Fatal("rejections not counted")
	}
}

func TestGateAllowEntryAndHints(t *testing.T) {
	n := nm("www.example.com")
	g := Gate{Allow: []netip.Prefix{netip.MustParsePrefix("192.168.5.0/24")}}
	a := ansFor(n, 60, "192.168.5.7")
	if !g.Check(n, a).OK {
		t.Fatal("allow entry ignored")
	}
	a = ansFor(n, 60, "192.168.6.7")
	if g.Check(n, a).OK {
		t.Fatal("address outside the allow entry passed")
	}
	// An HTTPS record whose ipv4hint is injected.
	d := []byte{0, 1, 0}                     // priority 1, target root
	d = append(d, 0, 4, 0, 4, 10, 10, 34, 1) // ipv4hint 10.10.34.1
	h := &policy.TrueAnswer{Answer: []policy.RR{{Name: n, Type: policy.TypeHTTPS, Class: 1, TTL: 60, Data: d}}}
	if (&Gate{}).Check(n, h).OK {
		t.Fatal("injected hint passed")
	}
}

func TestEvictionKeepsBudget(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := New(Config{SharedBytes: 16 * 2048, FreeBytes: 1 << 20, Now: clk.now})
	for i := 0; i < 500; i++ {
		n := nm("h" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + ".example.com")
		k := KeyOf(n, uint16(i%7+1), 1, policy.ResolveParams{}, "")
		_ = c.Put(Shared, k, n, ansFor(n, 60, "192.0.2.1"))
	}
	st := c.Stats(Shared)
	if st.Bytes > 16*2048 || st.Evicted == 0 {
		t.Fatalf("bytes=%d evicted=%d", st.Bytes, st.Evicted)
	}
}

func TestDoCoalescesInsideASegmentOnly(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	n := nm("www.example.com")
	k := KeyOf(n, 1, 1, policy.ResolveParams{}, "")
	var calls atomic.Int32
	release := make(chan struct{})
	fetch := func() (*policy.TrueAnswer, error) {
		calls.Add(1)
		<-release
		return ansFor(n, 60, "192.0.2.1"), nil
	}
	var wg sync.WaitGroup
	run := func(seg Segment) {
		defer wg.Done()
		if _, err := c.Do(seg, k, nil, fetch); err != nil {
			t.Error(err)
		}
	}
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go run(Shared)
		go run(Free)
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("fetch ran %d times, want one per segment", calls.Load())
	}
}

func TestDoWaiterCanLeaveAndPanicIsContained(t *testing.T) {
	c := newCache(&clock{t: time.Unix(1000, 0)})
	k := KeyOf(nm("a.example.com"), 1, 1, policy.ResolveParams{}, "")
	cancel := make(chan struct{})
	close(cancel)
	block := make(chan struct{})
	if _, err := c.Do(Shared, k, cancel, func() (*policy.TrueAnswer, error) { <-block; return nil, nil }); err == nil {
		t.Fatal("cancelled waiter got an answer")
	}
	close(block)
	k2 := KeyOf(nm("b.example.com"), 1, 1, policy.ResolveParams{}, "")
	if _, err := c.Do(Shared, k2, nil, func() (*policy.TrueAnswer, error) { panic("x") }); err == nil {
		t.Fatal("panic not turned into an error")
	}
	// The key is free again.
	if _, err := c.Do(Shared, k2, nil, func() (*policy.TrueAnswer, error) { return ansFor(nm("b.example.com"), 5, "192.0.2.1"), nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPurge(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	n := nm("www.example.com")
	k := KeyOf(n, 1, 1, policy.ResolveParams{}, "")
	_ = c.Put(Shared, k, n, ansFor(n, 60, "192.0.2.1"))
	c.Purge(Shared)
	if _, ok := c.Get(Shared, k); ok {
		t.Fatal("purge left an entry")
	}
}

// The byte budget is charged what an entry really holds. Many small records under
// short names used to be charged about a fifth of their heap, so the 512 MiB
// budget held several times that (p4n-W7-r1-10).
func TestCostTracksRealHeap(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := New(Config{SharedBytes: 1 << 30, FreeBytes: 1 << 20, Now: clk.now})
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	build := func(i int) (names.Name, *policy.TrueAnswer) {
		n := nm("n" + strconv.Itoa(i) + ".example.com")
		a := &policy.TrueAnswer{Chain: []names.Name{n}}
		for j := 0; j < 40; j++ { // a large RRset of short records
			a.Answer = append(a.Answer, aRR(n, 60, "198.51.100."+strconv.Itoa(j+1)))
		}
		return n, a
	}
	const entries = 400
	answers := make([]*policy.TrueAnswer, entries)
	qn := make([]names.Name, entries)
	for i := range answers { // built before the baseline, so only the cache's copies are measured
		qn[i], answers[i] = build(i)
	}
	before := heap()
	for i := range answers {
		k := KeyOf(qn[i], 1, 1, policy.ResolveParams{}, "")
		if err := c.Put(Shared, k, qn[i], answers[i]); err != nil {
			t.Fatal(err)
		}
	}
	grown := int64(heap() - before)
	charged := c.Stats(Shared).Bytes
	runtime.KeepAlive(answers)
	runtime.KeepAlive(c)
	// The cache copies the record slices, and the shared Data slices are not copied,
	// so the measured growth is the struct copies. The charge must cover it.
	if charged < grown*9/10 {
		t.Fatalf("charged %d bytes for %d bytes of heap growth", charged, grown)
	}
}

// A Purge ends the old resolve configuration: a fetch that began before it does
// not store its answer, and a query made after it does not join that fetch
// (p4n-W7-r2-3).
func TestPurgeIsNotUndoneByAnInFlightFetch(t *testing.T) {
	c := newCache(&clock{t: time.Unix(1000, 0)})
	n := nm("www.example.com")
	k := KeyOf(n, 1, 1, policy.ResolveParams{}, "")

	gen := c.Generation(Shared)
	release := make(chan struct{})
	started := make(chan struct{})
	var oldRes atomic.Pointer[policy.TrueAnswer]
	done := make(chan struct{})
	go func() {
		defer close(done)
		a, err := c.Do(Shared, k, nil, func() (*policy.TrueAnswer, error) {
			close(started)
			<-release
			a := ansFor(n, 60, "192.0.2.1")
			if err := c.PutGen(Shared, k, n, a, gen); !errors.Is(err, ErrStale) {
				t.Errorf("a fetch from before the purge stored its answer: %v", err)
			}
			return a, nil
		})
		if err != nil {
			t.Error(err)
		}
		oldRes.Store(a)
	}()
	<-started
	c.Purge(Shared)

	// A new-configuration query starts its own fetch.
	var fresh atomic.Int32
	a, err := c.Do(Shared, k, nil, func() (*policy.TrueAnswer, error) {
		fresh.Add(1)
		return ansFor(n, 60, "192.0.2.2"), nil
	})
	if err != nil || fresh.Load() != 1 || a.Answer[0].Data[3] != 2 {
		t.Fatalf("the new query joined the old flight: fresh=%d err=%v", fresh.Load(), err)
	}
	close(release)
	<-done
	if oldRes.Load() == nil {
		t.Fatal("the old fetch's own caller got no answer")
	}
	if c.Stats(Shared).Entries != 0 {
		t.Fatal("the old route's answer is in the cache")
	}
	// A fetch that begins after the purge stores normally.
	if err := c.PutGen(Shared, k, n, ansFor(n, 60, "192.0.2.3"), c.Generation(Shared)); err != nil {
		t.Fatal(err)
	}
}

// p4n-W7-r9-1: a read the node makes for itself (Grant safety) is not a client
// lookup and moves no hit or miss counter.
func TestPeekCountsNothing(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	c := newCache(clk)
	n := nm("www.example.com")
	k := KeyOf(n, 1, 1, policy.ResolveParams{}, "")
	if _, ok := c.Peek(Shared, k); ok {
		t.Fatal("peek found an entry in an empty cache")
	}
	if err := c.Put(Shared, k, n, ansFor(n, 60, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	clk.add(10 * time.Second)
	got, ok := c.Peek(Shared, k)
	if !ok || got.Answer[0].TTL != 50 {
		t.Fatalf("peek: ok=%v %v", ok, got)
	}
	if st := c.Stats(Shared); st.Hits != 0 || st.Misses != 0 {
		t.Fatalf("peek counted: %+v", st)
	}
	if _, ok := c.Get(Shared, k); !ok {
		t.Fatal("get")
	}
	if st := c.Stats(Shared); st.Hits != 1 || st.Misses != 0 {
		t.Fatalf("get counted wrongly: %+v", st)
	}
}
