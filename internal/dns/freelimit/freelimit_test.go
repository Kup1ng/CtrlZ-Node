package freelimit

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }

func TestPrefixAndHost(t *testing.T) {
	for _, c := range []struct{ in, prefix, host string }{
		{"192.0.2.77", "192.0.2.0/24", "192.0.2.77/32"},
		{"::ffff:192.0.2.77", "192.0.2.0/24", "192.0.2.77/32"}, // an IPv4-mapped source is IPv4
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1::/56", "2001:db8:1:2::/64"},
	} {
		a := netip.MustParseAddr(c.in)
		if got := Prefix(a).String(); got != c.prefix {
			t.Errorf("Prefix(%s) = %s, want %s", c.in, got, c.prefix)
		}
		if got := Host(a).String(); got != c.host {
			t.Errorf("Host(%s) = %s, want %s", c.in, got, c.host)
		}
	}
}

// The response limit of 7.9: 64 KiB a second, a burst of 256 KiB, over it the
// prefix is Over until time pays the debt back.
func TestResponseLimitRateAndBurst(t *testing.T) {
	c := newClock()
	r := NewResponseLimit(0, 0, c.now)
	p := Prefix(netip.MustParseAddr("192.0.2.1"))
	if r.Over(p) {
		t.Fatal("a prefix nobody charged is over")
	}
	// The whole burst goes out in 1200-byte replies: the prefix stays under until the
	// burst is gone, and not one reply longer.
	sent := 0
	for !r.Over(p) {
		r.Charge(p, 1200)
		sent += 1200
		if sent > 2*DefaultBurstBytes {
			t.Fatal("never over")
		}
	}
	if sent < DefaultBurstBytes || sent > DefaultBurstBytes+1200 {
		t.Fatalf("over after %d bytes, burst is %d", sent, DefaultBurstBytes)
	}
	// 100 ms pays back 6.5 KB, not the debt of a reply or two of a drained bucket:
	// still over until the tokens are positive, then under.
	c.add(10 * time.Millisecond)
	if !r.Over(p) {
		t.Fatal("over prefix recovered in 10 ms")
	}
	c.add(time.Second)
	if r.Over(p) {
		t.Fatal("prefix still over after a second at 64 KiB/s")
	}
	// Another prefix is untouched.
	if r.Over(Prefix(netip.MustParseAddr("198.51.100.1"))) {
		t.Fatal("one prefix's debt reached another")
	}
	// Sustained: a prefix that sends 2x the rate for 20 seconds gets burst + rate*t.
	c = newClock()
	r = NewResponseLimit(0, 0, c.now)
	total := 0
	for i := 0; i < 20*100; i++ { // 100 ticks a second of 10 ms, each tries 1200 bytes x 11 (about 2x the rate)
		c.add(10 * time.Millisecond)
		for k := 0; k < 11 && !r.Over(p); k++ {
			r.Charge(p, 1200)
			total += 1200
		}
	}
	bound := DefaultBurstBytes + 20*DefaultRateBytes + 12*1200
	if total > bound {
		t.Fatalf("sent %d bytes in 20 s, the limit allows about %d", total, bound)
	}
	if total < 20*DefaultRateBytes {
		t.Fatalf("sent only %d bytes in 20 s: the limit starves a prefix below its rate", total)
	}
}

// A spoofed flood names as many victim prefixes as it likes: the table of buckets
// is bounded.
func TestResponseLimitTableIsBounded(t *testing.T) {
	c := newClock()
	r := NewResponseLimit(0, 0, c.now)
	for i := 0; i < 3*responseShards*prefixesPerShard; i++ {
		a := netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 1})
		r.Charge(Prefix(a), 100)
	}
	n := 0
	for i := range r.sh {
		r.sh[i].mu.Lock()
		n += r.sh[i].m.Len()
		r.sh[i].mu.Unlock()
	}
	if n > responseShards*prefixesPerShard {
		t.Fatalf("%d buckets held, the bound is %d", n, responseShards*prefixesPerShard)
	}
}

func TestUnvalidatedShares(t *testing.T) {
	c := newClock()
	m := NewMeter()
	const qps = 1000 // a prefix takes 100, all of them 500
	a := netip.MustParseAddr("192.0.2.5")
	for i := 0; i < 100; i++ {
		if got := m.Unvalidated(c.now(), qps, a); got != ShareOK {
			t.Fatalf("query %d: %v", i, got)
		}
	}
	// The prefix is at its tenth; another host of the same /24 shares it.
	if got := m.Unvalidated(c.now(), qps, netip.MustParseAddr("192.0.2.99")); got != ShareUnvalidatedPrefix {
		t.Fatalf("a /24 over its tenth: %v", got)
	}
	// Other prefixes fill the half: four more prefixes make 500 in all.
	for p := 1; p <= 4; p++ {
		for i := 0; i < 100; i++ {
			if got := m.Unvalidated(c.now(), qps, netip.AddrFrom4([4]byte{198, 51, byte(p), 1})); got != ShareOK {
				t.Fatalf("prefix %d query %d: %v", p, i, got)
			}
		}
	}
	if got := m.Unvalidated(c.now(), qps, netip.MustParseAddr("203.0.113.1")); got != ShareUnvalidatedAll {
		t.Fatalf("all unvalidated over half: %v", got)
	}
	// A validated query is not stopped by the unvalidated half.
	if got := m.Validated(c.now(), qps, netip.MustParseAddr("203.0.113.1")); got != ShareOK {
		t.Fatalf("a proven source stopped by the spoofable half: %v", got)
	}
	// A new second is a new window.
	c.add(time.Second)
	if got := m.Unvalidated(c.now(), qps, a); got != ShareOK {
		t.Fatalf("new second: %v", got)
	}
}

func TestValidatedShares(t *testing.T) {
	c := newClock()
	m := NewMeter()
	const qps = 1000
	a := netip.MustParseAddr("192.0.2.5")
	for i := 0; i < 100; i++ {
		if got := m.Validated(c.now(), qps, a); got != ShareOK {
			t.Fatalf("query %d: %v", i, got)
		}
	}
	if got := m.Validated(c.now(), qps, a); got != ShareSource {
		t.Fatalf("one address over its tenth: %v", got)
	}
	// Another address of the /24 is another source but the same prefix: its own
	// tenth is untouched, the prefix is already at its tenth.
	if got := m.Validated(c.now(), qps, netip.MustParseAddr("192.0.2.6")); got != ShareValidatedPrefix {
		t.Fatalf("prefix over its tenth: %v", got)
	}
	// Five prefixes at a tenth each fill the half, and the sixth host is stopped.
	for p := 1; p <= 4; p++ {
		for i := 0; i < 100; i++ {
			if got := m.Validated(c.now(), qps, netip.AddrFrom4([4]byte{198, 51, byte(p), 1})); got != ShareOK {
				t.Fatalf("prefix %d query %d: %v", p, i, got)
			}
		}
	}
	if got := m.Validated(c.now(), qps, netip.MustParseAddr("203.0.113.1")); got != ShareValidatedAll {
		t.Fatalf("all validated over half: %v", got)
	}
	// Unvalidated queries have their own half.
	if got := m.Unvalidated(c.now(), qps, netip.MustParseAddr("203.0.113.1")); got != ShareOK {
		t.Fatalf("a spoofable source stopped by the validated half: %v", got)
	}
}

// IPv6 sources share a /56 prefix and a /64 address.
func TestIPv6Keys(t *testing.T) {
	c := newClock()
	m := NewMeter()
	const qps = 100 // a tenth is 10
	for i := 0; i < 10; i++ {
		if got := m.Unvalidated(c.now(), qps, netip.MustParseAddr(fmt.Sprintf("2001:db8:0:1::%x", i+1))); got != ShareOK {
			t.Fatalf("%d: %v", i, got)
		}
	}
	// Same /56, another /64: still the same prefix share.
	if got := m.Unvalidated(c.now(), qps, netip.MustParseAddr("2001:db8:0:2::1")); got != ShareUnvalidatedPrefix {
		t.Fatalf("a /56 shares its tenth: %v", got)
	}
	// A different /56.
	if got := m.Unvalidated(c.now(), qps, netip.MustParseAddr("2001:db8:0:100::1")); got != ShareOK {
		t.Fatalf("another /56: %v", got)
	}
}

func TestBudget(t *testing.T) {
	c := newClock()
	m := NewMeter()
	for i := 0; i < 50; i++ {
		if !m.Budget(c.now(), 50) {
			t.Fatalf("query %d refused inside the budget", i)
		}
	}
	if m.Budget(c.now(), 50) {
		t.Fatal("the 51st query of a second of 50 qps passed")
	}
	c.add(time.Second)
	if !m.Budget(c.now(), 50) {
		t.Fatal("a new second did not start a new budget")
	}
}

// Window state is bounded by what the aggregates admit, not by how many addresses
// a flood uses.
func TestMeterStateIsBounded(t *testing.T) {
	c := newClock()
	m := NewMeter()
	const qps = 2000
	for i := 0; i < 200_000; i++ {
		m.Unvalidated(c.now(), qps, netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 7}))
		m.Validated(c.now(), qps, netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 8}))
	}
	if n := len(m.unvPrefix); n > qps/2 {
		t.Fatalf("%d unvalidated prefixes held, the half of qps is %d", n, qps/2)
	}
	if n := len(m.valHost); n > qps/2 {
		t.Fatalf("%d validated hosts held, the half of qps is %d", n, qps/2)
	}
}

func addr(i int, host int) netip.Addr {
	return netip.MustParseAddr(fmt.Sprintf("100.%d.%d.%d", 64+i/256, i%256, host))
}

func TestMissCapBoundsAndReleases(t *testing.T) {
	c := NewMissCap(20) // half 10, tenth 2
	var rel []func()
	for i := 0; i < 10; i++ {
		r, ok := c.TryAcquire(true, addr(i, 1))
		if !ok {
			t.Fatalf("validated slot %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok := c.TryAcquire(true, addr(99, 1)); ok {
		t.Fatal("validated misses took more than half of the slots")
	}
	if c.InFlight() != 10 {
		t.Fatalf("in flight %d after a refused acquire", c.InFlight())
	}
	rel[0]()
	rel[0]() // idempotent
	if c.InFlight() != 9 {
		t.Fatalf("in flight %d after a double release", c.InFlight())
	}
	if _, ok := c.TryAcquire(true, addr(99, 1)); !ok {
		t.Fatal("released slot not reusable")
	}
}

// A spoofed flood (UDP with no cookie, any source address) holds half the slots at
// most and a prefix a tenth, so a real client's TCP miss still gets one.
func TestMissCapSpoofedFloodLeavesSlotsForTCP(t *testing.T) {
	c := NewMissCap(256) // half 128, tenth 25
	taken := 0
	for i := 0; i < 5000; i++ {
		if _, ok := c.TryAcquire(false, addr(i, 1)); ok {
			taken++
		}
	}
	if taken != 128 {
		t.Fatalf("%d unvalidated misses held, want half of 256", taken)
	}
	if _, ok := c.TryAcquire(true, netip.MustParseAddr("203.0.113.9")); !ok {
		t.Fatal("a validated miss was refused while spoofed ones hold half the cap")
	}
	// One prefix: a tenth.
	c = NewMissCap(256)
	taken = 0
	for h := 1; h < 200; h++ {
		if _, ok := c.TryAcquire(false, addr(7, h)); ok {
			taken++
		}
	}
	if taken != 25 {
		t.Fatalf("one prefix held %d unvalidated slots, want a tenth (25)", taken)
	}
}

// A proven source is held to a tenth by address and by prefix.
func TestMissCapValidatedShares(t *testing.T) {
	c := NewMissCap(256)
	taken := 0
	for i := 0; i < 100; i++ {
		if _, ok := c.TryAcquire(true, addr(1, 5)); ok {
			taken++
		}
	}
	if taken != 25 {
		t.Fatalf("one address held %d slots, want 25", taken)
	}
	taken = 0
	for h := 1; h < 100; h++ {
		if _, ok := c.TryAcquire(true, addr(2, h)); ok {
			taken++
		}
	}
	if taken != 25 {
		t.Fatalf("one prefix held %d slots, want 25", taken)
	}
}

// Slots of a released miss give back their share, and no key outlives its misses.
func TestMissCapReleaseClearsKeys(t *testing.T) {
	c := NewMissCap(20)
	var rel []func()
	for i := 0; i < 8; i++ {
		r, ok := c.TryAcquire(i%2 == 0, addr(i, 1))
		if !ok {
			t.Fatalf("slot %d refused", i)
		}
		rel = append(rel, r)
	}
	for _, r := range rel {
		r()
	}
	if c.InFlight() != 0 || len(c.unvPrefix)+len(c.valPrefix)+len(c.valHost) != 0 || c.unvAll != 0 || c.valAll != 0 {
		t.Fatalf("state left after every release: %+v", c)
	}
}

// A reading older than the current second must not clear the counters of the
// second in force (p4n-W9-r1-2); a clock that stepped far back starts a new window.
func TestMeterDoesNotRollBackOnAnOlderReading(t *testing.T) {
	m := NewMeter()
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 5; i++ {
		if !m.Budget(t0.Add(time.Second), 5) {
			t.Fatalf("query %d refused", i)
		}
	}
	// A goroutine that read its clock in the second before takes the lock.
	if m.Budget(t0, 5) {
		t.Fatal("an older reading cleared the budget of the second in force")
	}
	if m.Budget(t0.Add(time.Second), 5) {
		t.Fatal("the budget was cleared by the older reading")
	}
	// A step back of an hour: a new window, not an hour of refusals.
	if !m.Budget(t0.Add(-time.Hour), 5) {
		t.Fatal("a clock stepped back kept the old window")
	}
}
