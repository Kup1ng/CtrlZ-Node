package limits

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// fakeClock is a clock the test moves by hand, in nanoseconds.
type fakeClock struct{ ns atomic.Int64 }

func (c *fakeClock) now() int64 { return c.ns.Load() }
func (c *fakeClock) advance(sec float64) {
	c.ns.Add(int64(sec * 1e9))
}

func mustSet(t *testing.T, r Registry) (*Set, *fakeClock) {
	t.Helper()
	c := &fakeClock{}
	c.ns.Store(1e9)
	s, err := newSet(r, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDefaultRegistryIsValidAndCheckedClean(t *testing.T) {
	r := Default()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if bad := CheckRegistry(r); len(bad) != 0 {
		t.Fatalf("registry breaches: %v", bad)
	}
	if bad := CheckListeners(Listeners()); len(bad) != 0 {
		t.Fatalf("listener breaches: %v", bad)
	}
}

// The numbers of 7.5 are asserted by name so a change of the table is a
// decision someone makes on purpose.
func TestDefaultRegistryNumbers(t *testing.T) {
	want := map[string]struct {
		rate  float64
		burst int
		count int
	}{
		"udp-query-addr":      {100, 200, 0},
		"udp-query-prefix":    {1000, 2000, 0},
		"tcp-conn-open":       {0, 0, 20000},
		"tcp-conn-new":        {2000, 4000, 0},
		"enc-conn-open-src":   {0, 0, 64},
		"enc-conn-open-v6-56": {0, 0, 256},
		"enc-conn-open-v6-48": {0, 0, 1024},
		"enc-conn-open-v6-32": {0, 0, 4096},
		"enc-conn-new-src":    {10, 40, 0},
		"enc-conn-new-v6-56":  {40, 160, 0},
		"enc-query-src":       {100, 200, 0},
		"enc-query-v6-32":     {6400, 12800, 0},
		"enc-conn-open-node":  {0, 0, 50000},
	}
	got := map[string]Entry{}
	for _, e := range Default() {
		got[e.Name] = e
	}
	for name, w := range want {
		e, ok := got[name]
		if !ok {
			t.Errorf("missing entry %s", name)
			continue
		}
		if e.Rate != w.rate || e.Burst != w.burst || e.Count != w.count {
			t.Errorf("%s = %v/%v/%v, want %v/%v/%v", name, e.Rate, e.Burst, e.Count, w.rate, w.burst, w.count)
		}
	}
	for _, name := range []string{"enc-conn-open-node", "enc-query-src"} {
		if len(got[name].Transports) != 4 {
			t.Errorf("%s must list the four encrypted transports", name)
		}
	}
}

func TestQueryBucketPerAddress(t *testing.T) {
	r := Registry{{Name: "q", Acts: ActsQuery, Transports: []Transport{UDP},
		Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 128}, Rate: 10, Burst: 5, Answer: AnswerTC}}
	s, clk := mustSet(t, r)
	a, b := addr("192.0.2.1"), addr("192.0.2.2")
	for i := 0; i < 5; i++ {
		if got := s.Query(UDP, a); got != AnswerNone {
			t.Fatalf("burst query %d stopped", i)
		}
	}
	if got := s.Query(UDP, a); got != AnswerTC {
		t.Fatalf("query over the burst got %v", got)
	}
	// Another address has its own bucket.
	if got := s.Query(UDP, b); got != AnswerNone {
		t.Fatalf("other address stopped: %v", got)
	}
	// The bucket refills at the rate: 0.2 s gives two tokens.
	clk.advance(0.2)
	for i := 0; i < 2; i++ {
		if got := s.Query(UDP, a); got != AnswerNone {
			t.Fatalf("refilled query %d stopped", i)
		}
	}
	if got := s.Query(UDP, a); got != AnswerTC {
		t.Fatalf("third query after refill got %v", got)
	}
	// Limits are per transport: the same entry does not count TCP.
	if got := s.Query(TCP, a); got != AnswerNone {
		t.Fatalf("TCP counted by a UDP entry: %v", got)
	}
}

func TestPrefixKeyGroupsSources(t *testing.T) {
	r := Registry{{Name: "p", Acts: ActsQuery, Transports: []Transport{UDP},
		Key: Key{Kind: KeySource, V4Bits: 24, V6Bits: 56}, Rate: 1, Burst: 3, Answer: AnswerTC}}
	s, _ := mustSet(t, r)
	for i := 1; i <= 3; i++ {
		if s.Query(UDP, addr("198.51.100."+string(rune('0'+i)))) != AnswerNone {
			t.Fatal("within burst stopped")
		}
	}
	if s.Query(UDP, addr("198.51.100.99")) != AnswerTC {
		t.Fatal("fourth source of one /24 not stopped")
	}
	if s.Query(UDP, addr("198.51.101.1")) != AnswerNone {
		t.Fatal("other /24 stopped")
	}
	// IPv6 /56: two addresses of one /56 share a bucket, a third /56 does not.
	for i := 0; i < 3; i++ {
		if s.Query(UDP, addr("2001:db8:0:100::"+string(rune('1'+i)))) != AnswerNone {
			t.Fatal("v6 within burst stopped")
		}
	}
	if s.Query(UDP, addr("2001:db8:0:1ff::1")) != AnswerTC {
		t.Fatal("v6 same /56 not stopped")
	}
	if s.Query(UDP, addr("2001:db8:0:200::1")) != AnswerNone {
		t.Fatal("v6 other /56 stopped")
	}
}

func TestIPv4MappedIsIPv4(t *testing.T) {
	r := Registry{{Name: "q", Acts: ActsQuery, Transports: []Transport{UDP},
		Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 128}, Rate: 1, Burst: 1, Answer: AnswerTC}}
	s, _ := mustSet(t, r)
	if s.Query(UDP, addr("192.0.2.9")) != AnswerNone {
		t.Fatal("first stopped")
	}
	if s.Query(UDP, addr("::ffff:192.0.2.9")) != AnswerTC {
		t.Fatal("the mapped form must share the IPv4 bucket")
	}
}

func TestConnectionCountAndRelease(t *testing.T) {
	r := Registry{{Name: "open", Acts: ActsConnection, Transports: []Transport{DoT},
		Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Count: 2}}
	s, _ := mustSet(t, r)
	a := addr("192.0.2.1")
	c1, ok1 := s.Admit(DoT, a)
	c2, ok2 := s.Admit(DoT, a)
	if !ok1 || !ok2 {
		t.Fatal("two connections must be admitted")
	}
	if _, ok := s.Admit(DoT, a); ok {
		t.Fatal("third connection admitted")
	}
	if _, ok := s.Admit(DoT, addr("192.0.2.2")); !ok {
		t.Fatal("other source refused")
	}
	c1.Release()
	c1.Release() // idempotent
	if _, ok := s.Admit(DoT, a); !ok {
		t.Fatal("slot not given back")
	}
	c2.Release()
	// DoH is another transport: not listed, so not limited.
	for i := 0; i < 5; i++ {
		if _, ok := s.Admit(DoH, a); !ok {
			t.Fatal("unlisted transport limited")
		}
	}
}

// A refused connection must leave nothing counted: when the second limit
// refuses, the first one's slot is given back.
func TestAdmitRollsBack(t *testing.T) {
	r := Registry{
		{Name: "a", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeyNone}, Count: 10},
		{Name: "b", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Count: 1},
	}
	s, _ := mustSet(t, r)
	a := addr("192.0.2.1")
	if _, ok := s.Admit(DoQ, a); !ok {
		t.Fatal("first refused")
	}
	for i := 0; i < 5; i++ {
		if _, ok := s.Admit(DoQ, a); ok {
			t.Fatal("second admitted")
		}
	}
	if n := s.Open(DoQ, "a"); n != 1 {
		t.Fatalf("refused connections leaked into the node-wide count: %d", n)
	}
}

func TestConnectionRateAndIPv6Aggregates(t *testing.T) {
	r := Registry{
		{Name: "new64", Acts: ActsConnection, Transports: []Transport{DoH}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Rate: 1, Burst: 2},
		{Name: "new56", Acts: ActsConnection, Transports: []Transport{DoH}, Key: Key{Kind: KeySource, V6Bits: 56}, Rate: 1, Burst: 8},
	}
	s, _ := mustSet(t, r)
	// Two hosts of one /64 share the /64 bucket (burst 2).
	if _, ok := s.Admit(DoH, addr("2001:db8:0:1::1")); !ok {
		t.Fatal("refused")
	}
	if _, ok := s.Admit(DoH, addr("2001:db8:0:1::2")); !ok {
		t.Fatal("refused")
	}
	if _, ok := s.Admit(DoH, addr("2001:db8:0:1::3")); ok {
		t.Fatal("third host of the /64 admitted")
	}
	// Other /64s of the same /56 each have 2, but the /56 allows 8 in all
	// (2 are used, so six more /64s pass and no more).
	n := 0
	for i := 2; i < 12; i++ {
		for j := 0; j < 2; j++ {
			if _, ok := s.Admit(DoH, addr("2001:db8:0:"+string(rune('0'+i%10))+"::"+string(rune('1'+j)))); ok {
				n++
			}
		}
	}
	if n >= 20 || n < 5 {
		t.Fatalf("the /56 aggregate did not bound the sources: %d admitted", n)
	}
	// IPv4 is untouched by the IPv6-only aggregate.
	for i := 0; i < 2; i++ {
		if _, ok := s.Admit(DoH, addr("192.0.2.1")); !ok {
			t.Fatal("IPv4 refused within its burst")
		}
	}
}

func TestEvictionBoundsTable(t *testing.T) {
	r := Registry{{Name: "q", Acts: ActsQuery, Transports: []Transport{UDP},
		Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 128}, Rate: 1, Burst: 2, Answer: AnswerTC}}
	s, _ := mustSet(t, r)
	for i := 0; i < nShards*maxKeysPerShard*2; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.Query(UDP, a)
	}
	total := 0
	tb := s.queries[UDP][0]
	for i := range tb.shards {
		total += len(tb.shards[i].m)
	}
	if total > nShards*maxKeysPerShard {
		t.Fatalf("table grew to %d slots", total)
	}
}

func TestHookSeesQueriesAndStops(t *testing.T) {
	r := Registry{{Name: "q", Acts: ActsQuery, Transports: []Transport{UDP},
		Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 128}, Rate: 1, Burst: 1, Answer: AnswerTC}}
	s, _ := mustSet(t, r)
	var given, stopped int
	s.SetHook(func(e Event) {
		switch e.Kind {
		case EventQuery:
			given++
		case EventStopped:
			stopped++
		}
	})
	s.Query(UDP, addr("192.0.2.1"))
	s.Query(UDP, addr("192.0.2.1"))
	if given != 2 || stopped != 1 {
		t.Fatalf("given %d stopped %d", given, stopped)
	}
}

func TestValidateRefusals(t *testing.T) {
	base := Entry{Name: "x", Acts: ActsQuery, Transports: []Transport{UDP}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 128}, Rate: 1, Burst: 1, Answer: AnswerTC}
	cases := map[string]func(e *Entry){
		"no name":                func(e *Entry) { e.Name = "" },
		"rate without burst":     func(e *Entry) { e.Burst = 0 },
		"no rate and no count":   func(e *Entry) { e.Rate, e.Burst = 0, 0 },
		"query with a count":     func(e *Entry) { e.Count = 5 },
		"query with no answer":   func(e *Entry) { e.Answer = AnswerNone },
		"connection with answer": func(e *Entry) { e.Acts = ActsConnection },
		"bad transport":          func(e *Entry) { e.Transports = []Transport{99} },
		"keyless with bits":      func(e *Entry) { e.Key = Key{Kind: KeyNone, V4Bits: 24} },
		"source with no bits":    func(e *Entry) { e.Key = Key{Kind: KeySource} },
	}
	for name, mut := range cases {
		e := base
		mut(&e)
		if err := (Registry{e}).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (Registry{base, base}).Validate(); err == nil {
		t.Error("repeated name accepted")
	}
}

func TestExemption(t *testing.T) {
	x := NewExemption()
	rid := "abcdefghijklmnopqrstuvwxyz"[:0] + strings.Repeat("a", 26)
	if x.Exempt(rid+".dns.example.ir.", 1) {
		t.Fatal("exempt with no zone set")
	}
	x.SetZones([]names.Name{names.MustString("dns.example.ir")})
	yes := []struct {
		name string
		qt   uint16
	}{
		{rid + ".dns.example.ir.", 1},
		{rid + ".DNS.example.ir.", 28},
		{rid + "-laptop.dns.example.ir.", 1},
		{strings.Repeat("b", 26) + ".dns.example.ir.", 65}, // an unknown rid is the same form
		{"dns.example.ir.", typeNS},
		{"ns1.dns.example.ir.", 1},
		{"ns4.dns.example.ir.", typeNS},
	}
	for _, c := range yes {
		if !x.Exempt(c.name, c.qt) {
			t.Errorf("%s/%d must be exempt", c.name, c.qt)
		}
	}
	no := []struct {
		name string
		qt   uint16
	}{
		{"dns.example.ir.", 1},  // apex A is not exempt
		{"dns.example.ir.", 16}, // nor TXT
		{"example.com.", 1},
		{"www.example.ir.", typeNS},
		{"abc.dns.example.ir.", 1},           // malformed resolver label
		{"ns5.dns.example.ir.", 1},           // not one of ns1 to ns4
		{"myip.dns.example.ir.", 1},          // reserved, but not ns
		{"x." + rid + ".dns.example.ir.", 1}, // two labels: malformed
		{strings.Repeat("a", 300) + ".dns.example.ir.", 1},
	}
	for _, c := range no {
		if x.Exempt(c.name, c.qt) {
			t.Errorf("%s/%d must not be exempt", c.name, c.qt)
		}
	}
	var nilx *Exemption
	if nilx.Exempt(rid+".dns.example.ir.", 1) {
		t.Error("nil exemption exempts")
	}
}

// Walk mutants: each planted breach of L13 or 7.5 must be found by the walk,
// so the walk cannot pass by checking nothing (N5's mutant list).
func TestRegistryWalkFindsMutants(t *testing.T) {
	mutants := map[string]func(r Registry) Registry{
		"a per-source TCP 53 limit": func(r Registry) Registry {
			return append(r, Entry{Name: "tcp-src", Acts: ActsConnection, Transports: []Transport{TCP},
				Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Count: 100})
		},
		"a TCP 53 query limit": func(r Registry) Registry {
			return append(r, Entry{Name: "tcp-q", Acts: ActsQuery, Transports: []Transport{TCP},
				Key: Key{Kind: KeyNone}, Rate: 10, Burst: 10, Answer: AnswerRefused})
		},
		"a TCP 53 limit with a name in its key": func(r Registry) Registry {
			r = r.Clone()
			for i := range r {
				if r[i].Name == "tcp-conn-new" {
					r[i].Key.Extra = []string{"qname"}
				}
			}
			return r
		},
		"a UDP source limit that drops": func(r Registry) Registry {
			r = r.Clone()
			r[0].Answer = AnswerRefused
			return r
		},
		"an encrypted limit keyed per IPv6 address": func(r Registry) Registry {
			r = r.Clone()
			for i := range r {
				if r[i].Name == "enc-query-src" {
					r[i].Key.V6Bits = 128
				}
			}
			return r
		},
		"no /48 aggregate": func(r Registry) Registry {
			var out Registry
			for _, e := range r {
				if strings.HasSuffix(e.Name, "v6-48") {
					continue
				}
				out = append(out, e)
			}
			return out
		},
		"an encrypted stop that drops": func(r Registry) Registry {
			r = r.Clone()
			for i := range r {
				if r[i].Name == "enc-query-src" {
					r[i].Answer = AnswerTC
				}
			}
			return r
		},
	}
	for name, mut := range mutants {
		if bad := CheckRegistry(mut(Default())); len(bad) == 0 {
			t.Errorf("mutant %q passed the registry walk", name)
		}
	}
}

func TestListenerWalkFindsMutants(t *testing.T) {
	set := func(t Transport, f func(s *ListenerSettings)) []ListenerSettings {
		ls := CloneSettings(Listeners())
		for i := range ls {
			if ls[i].Transport == t {
				f(&ls[i])
			}
		}
		return ls
	}
	mutants := map[string][]ListenerSettings{
		"a listener with a query cap per connection":    set(TCP, func(s *ListenerSettings) { s.MaxQueriesPerConn = 128 }),
		"a maximum connection age":                      set(DoT, func(s *ListenerSettings) { s.MaxConnAge = 5 * 60e9 }),
		"a plain 30 s write deadline":                   set(DoQ, func(s *ListenerSettings) { s.WriteStallOnlyWhenQuiet = false }),
		"an idle deadline that fires with a query due":  set(TCP, func(s *ListenerSettings) { s.IdleOnlyWhenQuiet = false }),
		"DoH with no handshake deadline":                set(DoH, func(s *ListenerSettings) { s.HandshakeTimeout = 0 }),
		"DoH with no idle deadline":                     set(DoH, func(s *ListenerSettings) { s.IdleTimeout = 0 }),
		"a DoH body read with no cap":                   set(DoH, func(s *ListenerSettings) { s.MaxBodyBytes = 0 }),
		"the default MaxHeaderBytes":                    set(DoH, func(s *ListenerSettings) { s.MaxHeaderBytes = 1 << 20 }),
		"DoH3 with no header deadline":                  set(DoH3, func(s *ListenerSettings) { s.ReadHeaderTimeout = 0 }),
		"no stream cap on DoQ":                          set(DoQ, func(s *ListenerSettings) { s.MaxStreams = 0 }),
		"no body deadline":                              set(TCP, func(s *ListenerSettings) { s.BodyTimeout = 0 }),
		"a missing listener":                            Listeners()[:5],
		"TCP with no reply-queue bound":                 set(TCP, func(s *ListenerSettings) { s.MaxQueuedReplies = 0 }),
		"DoT with a reply-queue bound below pipelining": set(DoT, func(s *ListenerSettings) { s.MaxQueuedReplies = 8 }),
		"TCP with no byte bound on queued replies":      set(TCP, func(s *ListenerSettings) { s.MaxQueuedBytes = 0 }),
		"DoT with a listener bound under the conn one":  set(DoT, func(s *ListenerSettings) { s.MaxQueuedBytesNode = s.MaxQueuedBytes - 1 }),
		"a QUIC idle timer under our idle deadline":     set(DoQ, func(s *ListenerSettings) { s.QUICMaxIdle = s.IdleTimeout }),
		"a QUIC connection with no keep-alive":          set(DoH3, func(s *ListenerSettings) { s.QUICKeepAlive = 0 }),
		"unpinned QUIC windows":                         set(DoQ, func(s *ListenerSettings) { s.QUICStreamWindow = 0 }),
		"unpinned HTTP/2 receive buffers":               set(DoH, func(s *ListenerSettings) { s.H2StreamWindow = 0 }),
		"DoQ with no byte bound on held replies":        set(DoQ, func(s *ListenerSettings) { s.MaxQueuedBytes = 0 }),
		"DoH with no byte bound on held replies":        set(DoH, func(s *ListenerSettings) { s.MaxQueuedBytes = 0 }),
		"DoH3 with a listener bound under the conn one": set(DoH3, func(s *ListenerSettings) { s.MaxQueuedBytesNode = s.MaxQueuedBytes - 1 }),
	}
	for name, ls := range mutants {
		if bad := CheckListeners(ls); len(bad) == 0 {
			t.Errorf("mutant %q passed the listener walk", name)
		}
	}
}

// A stopped query spends nothing: the tokens of the entries checked before the
// one that stops it go back (p4n-W6-r2-8).
func TestStoppedQueryRefundsEarlierTokens(t *testing.T) {
	r := Registry{
		{Name: "a", Acts: ActsQuery, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Rate: 0.001, Burst: 5, Answer: AnswerRefused},
		{Name: "b", Acts: ActsQuery, Transports: []Transport{DoQ}, Key: Key{Kind: KeyNone}, Rate: 0.001, Burst: 1, Answer: AnswerRefused},
	}
	s, _ := mustSet(t, r)
	a := addr("192.0.2.1")
	if s.Query(DoQ, a) != AnswerNone {
		t.Fatal("first query stopped")
	}
	for i := 0; i < 20; i++ {
		if s.Query(DoQ, a) == AnswerNone {
			t.Fatal("b should have stopped it")
		}
	}
	// a started with 5 and spent one on the query that passed; the 20 stopped
	// ones must have spent none.
	var tb *table
	for _, x := range s.queries[DoQ] {
		if x.e.Name == "a" {
			tb = x
		}
	}
	sh := tb.shardOf(tb.keyOf(a))
	sh.mu.Lock()
	got := sh.m[tb.keyOf(a)].tokens
	sh.mu.Unlock()
	if got < 3.999 || got > 4.001 {
		t.Fatalf("bucket a holds %v tokens, want 4: the stopped queries spent some", got)
	}
}

// A refused connection gives back the tokens of the entries that let it
// through (p4n-W6-r2-8).
func TestRefusedConnectionRefundsTokens(t *testing.T) {
	r := Registry{
		{Name: "new", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Rate: 0.001, Burst: 3},
		{Name: "open", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeyNone}, Count: 1},
	}
	s, _ := mustSet(t, r)
	a := addr("192.0.2.1")
	c, ok := s.Admit(DoQ, a)
	if !ok {
		t.Fatal("first refused")
	}
	for i := 0; i < 20; i++ {
		if _, ok := s.Admit(DoQ, a); ok {
			t.Fatal("admitted beyond the count")
		}
	}
	c.Release()
	// 3 tokens, one spent by the first; the refused 20 must not have drained the
	// other two.
	for i := 0; i < 2; i++ {
		c2, ok := s.Admit(DoQ, a)
		if !ok {
			t.Fatalf("admit %d refused: the refused attempts spent the bucket", i)
		}
		c2.Release()
	}
}

// The clock of a Set is not the wall clock: it starts near zero and only goes
// forward (p4n-W6-r2-7).
func TestSetClockIsMonotonic(t *testing.T) {
	s, err := NewSet(Default())
	if err != nil {
		t.Fatal(err)
	}
	first := s.clock()
	if first <= 0 || first > 60e9 {
		t.Fatalf("clock reads %d ns, want a small positive reading since the Set was built, not the wall clock", first)
	}
	if next := s.clock(); next < first {
		t.Fatalf("clock went back: %d then %d", first, next)
	}
}

// WouldRefuse agrees with Admit and counts nothing: asked about a source that
// has never connected it makes no slot, and asked about one at its limit it
// spends no token and takes no open slot (p4n-W6-r4-4).
func TestWouldRefuseCountsNothing(t *testing.T) {
	r := Registry{
		{Name: "new", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Rate: 0.001, Burst: 2},
		{Name: "open", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Count: 5},
	}
	s, _ := mustSet(t, r)
	a := addr("192.0.2.1")
	for i := 0; i < 1000; i++ {
		if s.WouldRefuse(DoQ, a) {
			t.Fatal("refused before anything was used")
		}
	}
	if s.Open(DoQ, "open") != 0 {
		t.Fatal("WouldRefuse took an open slot")
	}
	// Two tokens in the bucket: WouldRefuse, however often asked, must leave both.
	c1, ok1 := s.Admit(DoQ, a)
	if !ok1 || s.WouldRefuse(DoQ, a) {
		t.Fatal("one token is left")
	}
	for i := 0; i < 100; i++ {
		s.WouldRefuse(DoQ, a)
	}
	c2, ok2 := s.Admit(DoQ, a)
	if !ok2 {
		t.Fatal("WouldRefuse spent a token")
	}
	if !s.WouldRefuse(DoQ, a) {
		t.Fatal("no refusal with an empty bucket")
	}
	if _, ok := s.Admit(DoQ, a); ok {
		t.Fatal("Admit and WouldRefuse disagree")
	}
	if s.WouldRefuse(DoQ, addr("192.0.2.2")) {
		t.Fatal("another source refused")
	}
	// The mapped form is the same source.
	if !s.WouldRefuse(DoQ, addr("::ffff:192.0.2.1")) {
		t.Fatal("the mapped form is not the same source")
	}
	c1.Release()
	c2.Release()

	// The open count.
	r2 := Registry{{Name: "open", Acts: ActsConnection, Transports: []Transport{DoT}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Count: 1}}
	s2, _ := mustSet(t, r2)
	c, _ := s2.Admit(DoT, a)
	if !s2.WouldRefuse(DoT, a) {
		t.Fatal("no refusal at the open count")
	}
	c.Release()
	if s2.WouldRefuse(DoT, a) {
		t.Fatal("refusal after the release")
	}
	// An unlisted transport is never refused for a limit it does not have.
	if s2.WouldRefuse(DoH, a) {
		t.Fatal("unlisted transport refused")
	}
}

// Handshakes in progress count for the Retry decision at every level of the
// aggregates, and for nothing else: they spend no token, take no open slot and
// refuse nothing (p4n-W6-r5-4).
func TestPendingCountsForTheRetryDecision(t *testing.T) {
	r := Registry{
		{Name: "new-64", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V6Bits: 64}, Rate: 0.001, Burst: 100},
		{Name: "new-56", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V6Bits: 56}, Rate: 0.001, Burst: 3},
		{Name: "open-48", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V6Bits: 48}, Count: 5},
	}
	s, _ := mustSet(t, r)
	// Many /64s of one /56: each is far inside its own bucket, the /56 holds 3.
	a := func(i int) netip.Addr { return addr(fmt.Sprintf("2001:db8:0:%x::1", i)) }
	var ps []*Pending
	for i := 0; i < 3; i++ {
		if s.WouldRefuse(DoQ, a(i)) {
			t.Fatalf("Retry asked with %d handshakes in progress under a /56 that holds 3", i)
		}
		ps = append(ps, s.BeginPending(DoQ, a(i)))
	}
	if !s.WouldRefuse(DoQ, a(200)) {
		t.Fatal("no Retry for a new /64 of a /56 whose tokens are all spoken for")
	}
	// A source in another /56 (and /48) is not asked: nothing under its keys is
	// spoken for.
	if s.WouldRefuse(DoQ, addr("2001:db8:100::1")) {
		t.Fatal("another /56 was asked for a Retry")
	}
	// Pending takes no token and no open slot: ending the handshakes restores
	// every answer, and the whole bucket is still there to Admit.
	for _, p := range ps {
		p.End()
		p.End() // idempotent
	}
	if s.WouldRefuse(DoQ, a(200)) {
		t.Fatal("a finished handshake still counts")
	}
	if n := s.Open(DoQ, "open-48"); n != 0 {
		t.Fatalf("pending took %d open slots", n)
	}
	for i := 0; i < 3; i++ {
		c, ok := s.Admit(DoQ, a(i))
		if !ok {
			t.Fatalf("admit %d refused: pending spent a token", i)
		}
		defer c.Release()
	}
	var nilP *Pending
	nilP.End()
}

// A source with open connections and handshakes in progress together is held at
// the open count.
func TestPendingAddsToOpenCount(t *testing.T) {
	r := Registry{{Name: "open", Acts: ActsConnection, Transports: []Transport{DoQ}, Key: Key{Kind: KeySource, V4Bits: 32, V6Bits: 64}, Count: 3}}
	s, _ := mustSet(t, r)
	a := addr("192.0.2.1")
	c, _ := s.Admit(DoQ, a)
	defer c.Release()
	p1 := s.BeginPending(DoQ, a)
	if s.WouldRefuse(DoQ, a) {
		t.Fatal("one open and one pending leave room for a third")
	}
	p2 := s.BeginPending(DoQ, a)
	if !s.WouldRefuse(DoQ, a) {
		t.Fatal("one open and two pending fill the count of 3")
	}
	// Pending never refuses: Admit is decided by the open count alone.
	c2, ok := s.Admit(DoQ, a)
	if !ok {
		t.Fatal("pending refused a connection")
	}
	c2.Release()
	p1.End()
	p2.End()
}
