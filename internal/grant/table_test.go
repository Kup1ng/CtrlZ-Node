package grant

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Unix(1_800_000_000, 0)} }

func ep(b byte) [16]byte {
	var e [16]byte
	for i := range e {
		e[i] = b
	}
	return e
}

var (
	nameX = []byte("\x01x\x04test\x00")
	srcA  = netip.MustParseAddr("192.0.2.10")
	outL1 = Outcome{Kind: KindRedirect, Location: 1}
	outL2 = Outcome{Kind: KindRedirect, Location: 2}
)

func yes(Outcome) bool { return true }

// put writes a validated holder of Endpoint e (account is its own) with the given
// outcome, and joins any live outcome when join is set.
func put(t *Table, e byte, out Outcome, join bool) PutResult {
	r := &PutReq{Name: nameX, Source: srcA, ASN: 64500, Out: out, Validated: true,
		Holder: Holder{Endpoint: ep(e), Account: ep(e), Ident: ep(e), Widenable: true, Open: true}, Privileged: true}
	if join {
		r.Joins = yes
	}
	return t.Put(r)
}

func tbl(c *clock) *Table { return NewTable(DefaultLimits(), c.now) }

// Two tenants, one source address: the second to decide a different outcome is
// refused and the live Grant stands; one that joins is added; the end of one leaves
// the other (15.1).
func TestPutTwoTenants(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	if r := put(tb, 1, outL1, false); r.Verdict != Ok {
		t.Fatalf("first: %+v", r)
	}
	r := put(tb, 2, outL2, false)
	if r.Verdict != Refused || r.Reason != ReasonCollision {
		t.Fatalf("a second location must collide: %+v", r)
	}
	if h, ok := tb.Lookup(srcA, 64500, nameX, WidthExact); !ok || h.Out != outL1 || len(h.Holders) != 1 {
		t.Fatalf("the live Grant must stand for tenant 1: %+v %v", h, ok)
	}
	if r := put(tb, 2, outL1, false); r.Verdict != Refused {
		t.Fatalf("a holder whose decision does not allow the live outcome joined: %+v", r)
	}
	if r := put(tb, 2, outL1, true); r.Verdict != Ok {
		t.Fatalf("a holder that allows the live outcome must join: %+v", r)
	}
	h, _ := tb.Lookup(srcA, 64500, nameX, WidthExact)
	if len(h.Holders) != 2 || h.Accounts != 2 {
		t.Fatalf("two accounts hold the entry: %+v", h)
	}
	// Tenant 1 ends: tenant 2's holder and the outcome stay.
	tb.Sweep(func(_ []byte, _ netip.Addr, _ Outcome, h *Holder) bool { return h.Endpoint == ep(1) })
	h, ok := tb.Lookup(srcA, 64500, nameX, WidthExact)
	if !ok || len(h.Holders) != 1 || h.Holders[0].Endpoint != ep(2) {
		t.Fatalf("the end of A's holder must leave B's: %+v %v", h, ok)
	}
}

// A policy edit: the first device to decide the new outcome leaves the entry and
// gets a collision when another holder remains; its next query joins. Holders of
// another account never leave by it.
func TestEditLeavesAndOthersStay(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	put(tb, 1, outL1, false)
	put(tb, 2, outL1, true)
	// Tenant 1 edits to location 2: it leaves, tenant 2 remains, so it is refused.
	if r := put(tb, 1, outL2, false); r.Verdict != Refused || r.Reason != ReasonCollision {
		t.Fatalf("%+v", r)
	}
	h, _ := tb.Lookup(srcA, 64500, nameX, WidthExact)
	if len(h.Holders) != 1 || h.Holders[0].Endpoint != ep(2) || h.Out != outL1 {
		t.Fatalf("tenant 2 must be untouched: %+v", h)
	}
	// Tenant 2 edits as well: now it is alone, so the new outcome is written.
	if r := put(tb, 2, outL2, false); r.Verdict != Ok {
		t.Fatalf("%+v", r)
	}
	// Tenant 1's next query joins the new outcome.
	if r := put(tb, 1, outL2, true); r.Verdict != Ok {
		t.Fatalf("%+v", r)
	}
	// An account's own newer decision replaces the outcome when every holder is its own.
	tb2 := tbl(c)
	put(tb2, 1, outL1, false)
	if r := put(tb2, 1, outL2, false); r.Verdict != Ok {
		t.Fatalf("own newer decision: %+v", r)
	}
	if h, _ := tb2.Lookup(srcA, 64500, nameX, WidthExact); h.Out != outL2 {
		t.Fatalf("%+v", h)
	}
}

// A silent holder of the same account leaves with the editor (no cache holds its
// answer), a silent holder of another account never does.
func TestSilentHolderLeavesOnlyOfSameAccount(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	put(tb, 1, outL1, false)
	r := &PutReq{Name: nameX, Source: srcA, Out: outL1, Validated: true, Joins: yes,
		Holder: Holder{Endpoint: ep(3), Account: ep(1), Ident: ep(3)}} // a second Endpoint of account 1
	if tb.Put(r).Verdict != Ok {
		t.Fatal("join")
	}
	put(tb, 2, outL1, true) // another account
	c.advance((MaxProxyTTL + 1) * time.Second)
	// Endpoint 1 edits; Endpoint 3 (same account) was silent for more than the TTL and
	// leaves; Endpoint 2 (another account) stays, so the edit is refused.
	if r := put(tb, 1, outL2, false); r.Verdict != Refused {
		t.Fatalf("%+v", r)
	}
	h, _ := tb.Lookup(srcA, 64500, nameX, WidthExact)
	if len(h.Holders) != 1 || h.Holders[0].Endpoint != ep(2) {
		t.Fatalf("only the other account's holder must stay: %+v", h.Holders)
	}
}

// A source that is not validated writes nothing and refreshes nothing; a live holder
// with an equal outcome and more than the TTL of life is answered ok (4.2 step 2).
func TestUnvalidatedWritesNothing(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	r := &PutReq{Name: nameX, Source: srcA, Out: outL1, Holder: Holder{Endpoint: ep(1), Account: ep(1)}}
	if got := tb.Put(r); got.Verdict != Validate {
		t.Fatalf("%+v", got)
	}
	if tb.Holders() != 0 {
		t.Fatal("written")
	}
	put(tb, 1, outL1, false)
	exp := func() int64 { h, _ := tb.Lookup(srcA, 0, nameX, WidthExact); return h.Holders[0].Expires }
	before := exp()
	c.advance(time.Minute)
	r2 := &PutReq{Name: nameX, Source: srcA, Out: outL1, Holder: Holder{Endpoint: ep(1), Account: ep(1), Ident: ep(1)}}
	if got := tb.Put(r2); got.Verdict != Ok {
		t.Fatalf("a live holder with an equal outcome: %+v", got)
	}
	if exp() != before {
		t.Fatal("an unvalidated query refreshed the expiry")
	}
	r2.Out = outL2
	if got := tb.Put(r2); got.Verdict != Validate {
		t.Fatalf("a different outcome must not replace: %+v", got)
	}
	// Near the end of its life even an equal outcome needs a validated query.
	c.advance(HolderLife - 30*time.Minute)
	if got := tb.Put(&PutReq{Name: nameX, Source: srcA, Out: outL1, Holder: Holder{Endpoint: ep(1), Account: ep(1), Ident: ep(1)}}); got.Verdict != Validate {
		t.Fatalf("%+v", got)
	}
}

func TestExpiry(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	put(tb, 1, outL1, false)
	c.advance(HolderLife + time.Second)
	if _, ok := tb.Lookup(srcA, 0, nameX, WidthExact); ok {
		t.Fatal("an expired holder was found")
	}
	if tb.Holders() != 0 || tb.Known(srcA, 0, WidthExact) {
		t.Fatal("expiry left counters behind")
	}
}

// The caps of 4.2 step 4: the Endpoint's, the (Endpoint, source) quarter, the last
// quarter for claims and prefixes, and the node's under the share rule.
func TestCaps(t *testing.T) {
	c := newClock()
	lim := DefaultLimits()
	lim.NodeHolders = 1000
	tb := NewTable(lim, c.now)
	mk := func(e byte, i int, priv bool) PutResult {
		src := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		return tb.Put(&PutReq{Name: nameX, Source: src, Out: outL1, Validated: true, EndpointCap: 40, Privileged: priv,
			Holder: Holder{Endpoint: ep(e), Account: ep(e)}})
	}
	for i := 0; i < 30; i++ { // three quarters of 40
		if r := mk(1, i, false); r.Verdict != Ok {
			t.Fatalf("holder %d: %+v", i, r)
		}
	}
	if r := mk(1, 30, false); r.Reason != ReasonEndpointCap {
		t.Fatalf("the last quarter is for claims and prefixes: %+v", r)
	}
	if r := mk(1, 31, true); r.Verdict != Ok {
		t.Fatalf("a claimed source may use it: %+v", r)
	}
	// One source holds at most a quarter of the cap with names; same source, many names.
	src := netip.MustParseAddr("198.51.100.1")
	n := 0
	for i := 0; i < 20; i++ {
		r := tb.Put(&PutReq{Name: []byte{1, byte('a' + i), 0}, Source: src, Out: outL1, Validated: true, EndpointCap: 40, Privileged: true,
			Holder: Holder{Endpoint: ep(2), Account: ep(2)}})
		if r.Verdict == Ok {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("one source may hold a quarter of the Endpoint's room, got %d", n)
	}
}

// Share rule: one account cannot take more than a ninth of the node's room.
func TestShareRule(t *testing.T) {
	c := newClock()
	lim := DefaultLimits()
	lim.NodeHolders = 900
	lim.DefaultEndpointCap = 100000
	tb := NewTable(lim, c.now)
	n := 0
	for i := 0; i < 2000; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		r := tb.Put(&PutReq{Name: nameX, Source: src, Out: outL1, Validated: true, Privileged: true,
			EndpointCap: 100000, Holder: Holder{Endpoint: ep(1), Account: ep(1)}})
		if r.Verdict == Ok {
			n++
		} else if r.Reason != ReasonNodeCap {
			t.Fatalf("%+v", r)
		}
	}
	if n > 900/9+1 || n < 900/9-2 {
		t.Fatalf("one account holds %d of 900, want about a ninth", n)
	}
	if !tb.Full() {
		t.Fatal("a node_cap refusal must set full")
	}
	// Another account is still served.
	if r := tb.Put(&PutReq{Name: nameX, Source: srcA, Out: outL1, Validated: true, EndpointCap: 100000,
		Holder: Holder{Endpoint: ep(2), Account: ep(2)}}); r.Verdict != Ok {
		t.Fatalf("the second account is not served: %+v", r)
	}
}

// Widths (4.3): one Endpoint in the /24 matches, two match neither, a wildcard rule
// never widens, an ASN of 0 never matches; the counters say what each would have said.
func TestWidths(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	other := netip.MustParseAddr("192.0.2.77")
	if _, ok := tb.Lookup(other, 64500, nameX, WidthPrefix24); ok {
		t.Fatal("nothing written yet")
	}
	put(tb, 1, outL1, false)
	if h, ok := tb.Lookup(other, 64500, nameX, WidthPrefix24); !ok || h.Via != WidthPrefix24 || h.Holders[0].Endpoint != ep(1) {
		t.Fatalf("/24: %+v %v", h, ok)
	}
	if _, ok := tb.Lookup(other, 64500, nameX, WidthExact); ok {
		t.Fatal("exact must not widen")
	}
	if h, ok := tb.Lookup(netip.MustParseAddr("203.0.113.5"), 64500, nameX, WidthCarrier); !ok || h.Via != WidthCarrier {
		t.Fatalf("carrier: %+v %v", h, ok)
	}
	if _, ok := tb.Lookup(netip.MustParseAddr("203.0.113.5"), 0, nameX, WidthCarrier); ok {
		t.Fatal("an ASN of 0 matched")
	}
	// A second Endpoint of another outcome in the same /24 makes it shared: neither matches.
	srcB := netip.MustParseAddr("192.0.2.11")
	tb.Put(&PutReq{Name: nameX, Source: srcB, ASN: 64500, Out: outL2, Validated: true, Holder: Holder{Endpoint: ep(2), Account: ep(2), Widenable: true}})
	if _, ok := tb.Lookup(other, 64500, nameX, WidthPrefix24); ok {
		t.Fatal("two outcomes in the /24 must match neither")
	}
	if _, ok := tb.Lookup(netip.MustParseAddr("203.0.113.5"), 64500, nameX, WidthCarrier); ok {
		t.Fatal("two outcomes of the ASN must match neither")
	}
	// A wildcard rule is never widenable.
	nameW := []byte("\x01w\x04test\x00")
	tb.Put(&PutReq{Name: nameW, Source: srcA, ASN: 64500, Out: outL1, Validated: true, Holder: Holder{Endpoint: ep(1), Account: ep(1)}})
	if _, ok := tb.Lookup(other, 64500, nameW, WidthPrefix24); ok {
		t.Fatal("a wildcard rule widened")
	}
	tb.Lookup(srcA, 64500, nameX, WidthExact)
	st, _ := tb.Stats()
	if st["a64500_prefix24_shared"] == 0 || st["a64500_prefix24_unique"] == 0 || st["a64500_exact"] == 0 {
		t.Fatalf("width counters: %v", st)
	}
	for k := range st {
		if len(k) > 32 {
			t.Fatalf("counter name %q too long for the link", k)
		}
	}
}

// A Put wakes the wait of its exact key; a source has at most 16 waits.
func TestWait(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	done := make(chan bool, 1)
	go func() { done <- tb.Wait(context.Background(), nameX, srcA, 2*time.Second, nil) }()
	time.Sleep(50 * time.Millisecond)
	put(tb, 1, outL1, false)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("the wait did not see the Put")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hung")
	}
	start := time.Now()
	if tb.Wait(context.Background(), []byte("\x01z\x00"), srcA, 30*time.Millisecond, nil) || time.Since(start) < 25*time.Millisecond {
		t.Fatal("a wait with no Put must time out")
	}
	tb.lim.WaitPerSource = 0
	if tb.Wait(context.Background(), nameX, srcA, time.Second, nil) {
		t.Fatal("over the per-source waits it must return at once")
	}
}

// alone: a refused forward sets it and the answer leaves the peer out; accepted
// clears it, and the offer is due again only after the waits of 4.5.
func TestAloneAndOffer(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	r := put(tb, 1, outL1, false)
	if !r.Offer || r.Alone {
		t.Fatalf("a new holder is offered and not alone yet: %+v", r)
	}
	if r = put(tb, 1, outL1, false); r.Offer {
		t.Fatalf("an offer in flight is not repeated: %+v", r)
	}
	tb.Sent(nameX, srcA, ep(1), [16]byte{}, "refused")
	c.advance(time.Minute)
	if r = put(tb, 1, outL1, false); !r.Alone || r.Offer {
		t.Fatalf("after a refusal: alone, offered again only after 10 min: %+v", r)
	}
	c.advance(RefusedRetry)
	if r = put(tb, 1, outL1, false); !r.Offer {
		t.Fatalf("%+v", r)
	}
	tb.Sent(nameX, srcA, ep(1), [16]byte{}, "accepted")
	if r = put(tb, 1, outL1, false); r.Alone || r.Offer {
		t.Fatalf("accepted clears alone: %+v", r)
	}
	c.advance(HolderLife/2 + time.Minute)
	if r = put(tb, 1, outL1, false); !r.Offer {
		t.Fatalf("a peer copy past half its life is offered again: %+v", r)
	}
}

func TestForwardedHolderUsesItsOwnRoom(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	peer := ep(0xee)
	n := 0
	for i := 0; i < 20; i++ {
		src := netip.AddrFrom4([4]byte{10, 1, 0, byte(i)})
		r := tb.Put(&PutReq{Name: nameX, Source: src, Out: outL1, Validated: true, EndpointCap: 20, Privileged: true,
			Holder: Holder{Endpoint: ep(1), Account: ep(1), Origin: peer}})
		if r.Verdict == Ok {
			n++
			if r.Offer {
				t.Fatal("a forwarded holder is never offered back")
			}
		}
	}
	if n != 10 {
		t.Fatalf("forwarded holders take at most half of the Endpoint's cap, got %d", n)
	}
	// Local holders still have the other half.
	if r := tb.Put(&PutReq{Name: nameX, Source: srcA, Out: outL1, Validated: true, EndpointCap: 20, Privileged: true,
		Holder: Holder{Endpoint: ep(1), Account: ep(1)}}); r.Verdict != Ok {
		t.Fatalf("%+v", r)
	}
}

// A Put that lands between the caller's miss and the registration of its wait is
// found by the ready probe the wait runs after registering (4.3 step 3), so the
// connection is not closed for a Grant that exists.
func TestWaitReadyClosesTheGap(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	start := time.Now()
	ok := tb.Wait(context.Background(), nameX, srcA, 5*time.Second, func() bool {
		put(tb, 1, outL1, false) // lands after the registration but signals before the select
		_, found := tb.Lookup(srcA, 0, nameX, WidthExact)
		return found
	})
	if !ok || time.Since(start) > time.Second {
		t.Fatal("the probe after the registration must end the wait")
	}
	// And the signal path still wakes a waiter whose probe finds nothing.
	done := make(chan bool, 1)
	n2 := []byte("\x01q\x00")
	go func() {
		done <- tb.Wait(context.Background(), n2, srcA, 2*time.Second, func() bool { return false })
	}()
	time.Sleep(50 * time.Millisecond)
	tb.Put(&PutReq{Name: n2, Source: srcA, Out: outL1, Validated: true,
		Holder: Holder{Endpoint: ep(1), Account: ep(1)}})
	if !<-done {
		t.Fatal("the Put must wake the waiter")
	}
}

// A connection that waits counts once, as what it finally found (Probe + Record).
func TestProbeCountsOnce(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	_, y, ok := tb.Probe(srcA, 64500, nameX, WidthExact)
	if ok {
		t.Fatal("empty table")
	}
	put(tb, 1, outL1, false)
	_, y2, ok := tb.Probe(srcA, 64500, nameX, WidthExact)
	if !ok {
		t.Fatal("must hit")
	}
	_ = y
	tb.Record(64500, y2)
	named, _ := tb.Stats()
	if named["a64500_exact"] != 1 || named["a64500_miss"] != 0 {
		t.Fatalf("counted twice or wrong: %v", named)
	}
}

// 4.1: an entry holds 64 Endpoints with 8 holders each; the 65th Endpoint and the
// 9th holder of one Endpoint are `collision`.
func TestEntryHoldsSixtyFourEndpointsOfEight(t *testing.T) {
	c := newClock()
	lim := DefaultLimits()
	lim.DefaultEndpointCap = 100000
	tb := NewTable(lim, c.now)
	mk := func(e, client byte) PutResult {
		return tb.Put(&PutReq{Name: nameX, Source: srcA, Out: outL1, Validated: true, Privileged: true, Joins: yes,
			Holder: Holder{Endpoint: ep(e), Client: ep(client), Account: ep(e)}})
	}
	for e := byte(1); e <= 64; e++ {
		for cl := byte(1); cl <= 8; cl++ {
			if r := mk(e, cl); r.Verdict != Ok {
				t.Fatalf("endpoint %d client %d: %+v", e, cl, r)
			}
		}
	}
	if r := mk(65, 1); r.Reason != ReasonCollision {
		t.Fatalf("the 65th Endpoint must collide: %+v", r)
	}
	if r := mk(1, 9); r.Reason != ReasonCollision {
		t.Fatalf("the 9th holder of one Endpoint must collide: %+v", r)
	}
}

// Two tenants, one carrier-NAT source, one Branded page hash: the second account
// does not join the first one's entry, so the connection of the entry never carries
// the other tenant's Endpoint and key (SC 10.3). The same account still joins.
func TestBlockPageEntryIsOfOneAccount(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	page := Outcome{Kind: KindBlockPage}
	mk := func(e, acct byte) PutResult {
		return tb.Put(&PutReq{Name: nameX, Source: srcA, Out: page, Validated: true, Privileged: true, Joins: yes,
			Holder: Holder{Endpoint: ep(e), Account: ep(acct)}})
	}
	if r := mk(1, 1); r.Verdict != Ok {
		t.Fatalf("A decides: %+v", r)
	}
	if r := mk(2, 2); r.Verdict != Refused || r.Reason != ReasonCollision {
		t.Fatalf("another account must not join a kind 2 entry: %+v", r)
	}
	if r := mk(3, 1); r.Verdict != Ok {
		t.Fatalf("a second Endpoint of the same account joins: %+v", r)
	}
	h, _ := tb.Lookup(srcA, 0, nameX, WidthExact)
	if h.Accounts != 1 || len(h.Holders) != 2 {
		t.Fatalf("the entry must hold one account: %+v", h)
	}
	// A kind 1 entry is still shared across accounts.
	n2 := []byte("\x01r\x00")
	for _, a := range []byte{1, 2} {
		r := tb.Put(&PutReq{Name: n2, Source: srcA, Out: outL1, Validated: true, Privileged: true, Joins: yes,
			Holder: Holder{Endpoint: ep(a), Account: ep(a)}})
		if r.Verdict != Ok {
			t.Fatalf("kind 1 joins across accounts: %+v", r)
		}
	}
}

// A holder that joins gets the live outcome back, which is what a forward carries.
func TestPutResultCarriesTheStoredOutcome(t *testing.T) {
	c := newClock()
	tb := tbl(c)
	put(tb, 1, outL1, false)
	if r := put(tb, 2, outL2, true); r.Verdict != Ok || r.Out != outL1 {
		t.Fatalf("a joiner must see the live outcome: %+v", r)
	}
}

// Past 600 ASNs a new one folds into row 0 and is counted without the table lock.
func TestWidthCountOverflowFoldsIntoRowZero(t *testing.T) {
	tb := tbl(newClock())
	for asn := uint32(1); asn <= 700; asn++ {
		tb.widthCount(asn, 4)
	}
	if tb.overRow.Load() == nil {
		t.Fatal("the overflow row was never published")
	}
	before := tb.overRow.Load()[4].Load()
	for i := 0; i < 5; i++ {
		tb.widthCount(9999, 4)
	}
	if got := tb.overRow.Load()[4].Load(); got != before+5 {
		t.Fatalf("overflow row %d, want %d", got, before+5)
	}
	if _, ok := tb.widths.Load(uint32(9999)); ok {
		t.Fatal("an ASN past the cap got a row of its own")
	}
	var n int
	tb.widths.Range(func(_, _ any) bool { n++; return true })
	if n > 601 {
		t.Fatalf("%d rows", n)
	}
}
