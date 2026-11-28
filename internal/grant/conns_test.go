package grant

import (
	"net/netip"
	"testing"
	"time"
)

func hit(name []byte, src netip.Addr, out Outcome, hs ...Holder) Hit {
	eps, accts := map[[16]byte]bool{}, map[[16]byte]bool{}
	for _, h := range hs {
		eps[h.Endpoint], accts[h.Account] = true, true
	}
	return Hit{Name: string(name), Out: out, Holders: hs, EntrySrc: src, Endpoints: len(eps), Accounts: len(accts)}
}

func holder(e byte, decided int64) Holder {
	return Holder{Endpoint: ep(e), Account: ep(e), Ident: ep(e), LastDecide: decided}
}

func newConns(c *clock, mod func(*Limits)) (*Conns, map[string]int) {
	lim := DefaultLimits()
	if mod != nil {
		mod(&lim)
	}
	counts := map[string]int{}
	return NewConns(lim, c.now, func(s string) { counts[s]++ }), counts
}

// An entry whose holders are all of one account charges the Endpoint of the newest
// deciding query; an entry of several accounts is shared and charges neither (4.3).
func TestChargeSingleAndShared(t *testing.T) {
	c := newClock()
	cs, _ := newConns(c, func(l *Limits) { l.EndpointOpen = 2 })
	single := hit(nameX, srcA, outL1, holder(1, 10), holder(1, 5))
	for i := uint64(1); i <= 2; i++ {
		if _, _, why := cs.Admit(i, srcA, single, []string{"e1"}, "127.0.0.20:20001"); why != "" {
			t.Fatalf("%d: %s", i, why)
		}
	}
	if _, _, why := cs.Admit(3, srcA, single, []string{"e1"}, "127.0.0.20:20001"); why != "endpoint_open" {
		t.Fatalf("the third connection of an Endpoint at its cap: %q", why)
	}
	// A shared entry of A and B is charged to neither Endpoint, so A at its cap does
	// not stop B's device and B's does not use A's room.
	shared := hit(nameX, srcA, outL1, holder(1, 10), holder(2, 9))
	if shared.Accounts != 2 {
		t.Fatal("test setup")
	}
	for i := uint64(10); i < 14; i++ {
		if _, _, why := cs.Admit(i, srcA, shared, []string{"e1"}, "127.0.0.20:20001"); why != "" {
			t.Fatalf("shared %d: %s", i, why)
		}
	}
	if cs.epOpen[ep(1)] != 2 || cs.epOpen[ep(2)] != 0 {
		t.Fatalf("a shared connection was charged to an Endpoint: %v", cs.epOpen)
	}
	// Closing releases.
	cs.Closed([]uint64{1, 2}, nil)
	if _, _, why := cs.Admit(20, srcA, single, []string{"e1"}, "127.0.0.20:20001"); why != "" {
		t.Fatal(why)
	}
}

func TestEntryCapAndExitRoom(t *testing.T) {
	c := newClock()
	cs, counts := newConns(c, func(l *Limits) { l.EntryPerEndpoint = 2; l.ExitOpen = 30 })
	h := hit(nameX, srcA, outL1, holder(1, 1))
	cs.Admit(1, srcA, h, []string{"e1"}, "s")
	cs.Admit(2, srcA, h, []string{"e1"}, "s")
	if _, _, why := cs.Admit(3, srcA, h, []string{"e1"}, "s"); why != "entry_open" {
		t.Fatalf("%q", why)
	}
	// Another name is another entry; the exit's share rule (a ninth of 30) now bites.
	n := 0
	for i := 0; i < 20; i++ {
		nm := []byte{1, byte('a' + i), 0}
		if _, _, why := cs.Admit(uint64(100+i), srcA, hit(nm, srcA, outL1, holder(1, 1)), []string{"e1"}, "s"); why == "" {
			n++
		}
	}
	if n > 3 {
		t.Fatalf("one account took %d places of an exit of 30", n)
	}
	if counts["exit_open"] == 0 {
		t.Fatalf("the refusals are counted by reason: %v", counts)
	}
	// An exit with no room is skipped in the target list, the next one is charged.
	cn, rooms, why := cs.Admit(900, srcA, hit([]byte{1, 'z', 0}, srcA, outL1, holder(1, 1)), []string{"e1", "e2"}, "s")
	if why != "" || len(rooms) != 1 || rooms[0] != 1 || cn.pl.exit != "e2" {
		t.Fatalf("%v %v %q", rooms, cn, why)
	}
}

// A close with no byte from the target keeps the place counted until dial_hold after
// the dial began; a move on silence keeps the left dial's place and charges the new
// exit (5.5).
func TestDialHold(t *testing.T) {
	c := newClock()
	cs, _ := newConns(c, nil)
	cs.SetExits(map[string]string{"s1": "e1", "s2": "e2"})
	h := hit(nameX, srcA, outL1, holder(1, 1))
	cs.Admit(1, srcA, h, []string{"e1", "e2"}, "s1")
	cs.Moved(1, "s2", true, 0) // after 5 s of silence; the dial of s1 started at 0
	if cs.Held() != 1 {
		t.Fatalf("the left dial must be held: %d", cs.Held())
	}
	if cs.ExitOpen("e1") != 1 || cs.ExitOpen("e2") != 1 {
		t.Fatalf("the old exit keeps the place of the dial that goes on, the new one is charged: %d %d", cs.ExitOpen("e1"), cs.ExitOpen("e2"))
	}
	// The connection closes with no byte from s2, whose dial began 5 s after the open.
	cs.Closed(nil, []Pending{{ID: 1, StartMS: 5000}})
	c.advance(DefaultLimits().DialHold - time.Second)
	cs.Tick()
	if cs.ExitOpen("e1") != 1 || cs.Held() != 2 {
		t.Fatalf("both dials are held until their own 90 s: e1=%d held=%d", cs.ExitOpen("e1"), cs.Held())
	}
	c.advance(time.Second)
	cs.Tick()
	if cs.ExitOpen("e2") != 1 || cs.ExitOpen("e1") != 0 {
		t.Fatalf("the first dial (start 0) is released at 90 s, the second (start 5 s) at 95 s: e1=%d e2=%d", cs.ExitOpen("e1"), cs.ExitOpen("e2"))
	}
	c.advance(5 * time.Second)
	cs.Tick()
	if cs.ExitOpen("e1") != 0 || cs.ExitOpen("e2") != 0 || cs.Held() != 0 || cs.NodeOpen() != 0 {
		t.Fatalf("holds must end: e1=%d e2=%d held=%d node=%d", cs.ExitOpen("e1"), cs.ExitOpen("e2"), cs.Held(), cs.NodeOpen())
	}
	// A close after a byte frees at once.
	cs.Admit(2, srcA, h, []string{"e1"}, "s1")
	cs.Closed([]uint64{2}, nil)
	if cs.NodeOpen() != 0 || cs.Held() != 0 {
		t.Fatal("a closed connection kept a place")
	}
	// A move after a reset holds nothing: only the exit's pool changes.
	cs.Admit(3, srcA, h, []string{"e1", "e2"}, "s1")
	cs.Moved(3, "s2", false, 0)
	if cs.Held() != 0 || cs.ExitOpen("e1") != 0 || cs.ExitOpen("e2") != 1 {
		t.Fatalf("held=%d e1=%d e2=%d", cs.Held(), cs.ExitOpen("e1"), cs.ExitOpen("e2"))
	}
}

// 4.6: a connection ends when every holder recorded with it has ended, and with
// `more` only when its (name, source) has no live holder of its outcome either; one
// restored from a tag judges the same.
func TestJudgeConnsAndTag(t *testing.T) {
	c := newClock()
	cs, _ := newConns(c, nil)
	tb := tbl(c)
	put(tb, 1, outL1, false)
	hs := []Holder{holder(1, 3), holder(2, 2)}
	h := hit(nameX, srcA, outL1, hs...)
	h.More = true
	cs.Admit(1, srcA, h, []string{"e1"}, "s1")
	endAll := func(_ []byte, _ netip.Addr, _ Outcome, _ *Holder) bool { return true }
	if got := cs.JudgeConns(endAll, tb.Live); len(got) != 0 {
		t.Fatalf("with `more` a live holder of its outcome keeps it: %v", got)
	}
	tb.Sweep(endAll)
	if got := cs.JudgeConns(endAll, tb.Live); len(got) != 1 || got[0] != 1 {
		t.Fatalf("%v", got)
	}
	only1 := func(_ []byte, _ netip.Addr, _ Outcome, h *Holder) bool { return h.Endpoint == ep(1) }
	if got := cs.JudgeConns(only1, tb.Live); len(got) != 0 {
		t.Fatal("one holder is still alive: nine Endpoints, eight end, B stays")
	}

	// A restart of dns: the table is rebuilt from the proxy's list and the tags.
	cn, _ := cs.Get(1)
	tag := cn.Tag(1024)
	if len(tag) > 1024 {
		t.Fatalf("tag %d bytes", len(tag))
	}
	cs2, _ := newConns(c, nil)
	cs2.Rebuild([]OpenItem{{ID: 7, Source: srcA, Socks: "s1", Tag: tag}, {ID: 8, Source: srcA, Socks: "s1", Tag: []byte("junk")}})
	none := func([]byte, netip.Addr) (Outcome, bool) { return Outcome{}, false }
	if got := cs2.JudgeConns(endAll, none); len(got) != 2 {
		t.Fatalf("a rebuilt connection and one with an unreadable tag both end with their holders: %v", got)
	}
	if got := cs2.JudgeConns(only1, none); len(got) != 1 || got[0] != 8 {
		t.Fatalf("holder 2 is alive in the rebuilt record: %v", got)
	}
	if cs2.NodeOpen() != 1 {
		t.Fatalf("the rebuilt connection keeps its charge: %d", cs2.NodeOpen())
	}
}

func TestTagFitsAndTrims(t *testing.T) {
	var hs []Holder
	for i := 0; i < 8; i++ {
		h := holder(byte(i+1), int64(i))
		h.Client, h.Origin, h.Claim = ep(0xc1), ep(0xc2), ep(0xc3)
		hs = append(hs, h)
	}
	long := make([]byte, 0, 255)
	for len(long) < 200 {
		long = append(long, 60)
		for i := 0; i < 60; i++ {
			long = append(long, 'a')
		}
	}
	long = append(long, 0)
	cn := &Conn{Name: string(long), EntrySrc: srcA, Out: Outcome{Kind: KindRedirect, Dial: string(long)}, Holders: hs}
	tag := cn.Tag(1024)
	if len(tag) > 1024 {
		t.Fatalf("%d", len(tag))
	}
	back := decodeTag(tag)
	if back == nil || len(back.Holders) == 0 {
		t.Fatalf("%+v", back)
	}
	if len(back.Holders) < 8 && !back.More {
		t.Fatal("holders left out must set more")
	}
}

func TestFwdQueueServesAccountsInTurn(t *testing.T) {
	q := NewFwdQueue(DefaultLimits())
	now := time.Now()
	mk := func(a byte, i byte, isNew bool) *FwdItem {
		return &FwdItem{ID: [16]byte{a, i}, Account: ep(a), New: isNew}
	}
	for i := byte(0); i < 5; i++ {
		q.Offer(mk(1, i, false)) // a flood from account 1
	}
	q.Offer(mk(2, 0, true))
	q.Offer(mk(1, 9, true))
	var order []byte
	for len(order) < 4 {
		it, ok := q.Next(now)
		if !ok {
			break
		}
		order = append(order, it.Account[0])
	}
	has2 := false
	for _, a := range order[:2] {
		has2 = has2 || a == 2
	}
	if !has2 {
		t.Fatalf("account 2's first Grant must not wait behind account 1's flood: %v", order)
	}
	if it, _ := q.Answer([16]byte{2, 0}); it == nil {
		t.Fatal("answer")
	}
	// The unanswered limit stops the sender.
	lim := DefaultLimits()
	lim.ForwardUnanswered = 2
	q2 := NewFwdQueue(lim)
	for i := byte(0); i < 4; i++ {
		q2.Offer(mk(3, i, false))
	}
	q2.Next(now)
	q2.Next(now)
	if _, ok := q2.Next(now); ok {
		t.Fatal("over the unanswered limit")
	}
	if got := q2.Expire(now.Add(time.Minute), 15*time.Second); len(got) != 2 {
		t.Fatalf("%d expired", len(got))
	}
}

// A shared kind 1 connection counts in the shared part of the opened-lately window
// (5.4) and ages out of it with the others.
func TestSharedConnectionsCountInOpenedWindow(t *testing.T) {
	c := newClock()
	cs, counts := newConns(c, func(l *Limits) { l.OpenedLast30s = 16 })
	shared := hit(nameX, srcA, outL1, holder(1, 10), holder(2, 9))
	n := 0
	for i := uint64(1); i <= 40; i++ {
		if _, _, why := cs.Admit(i, srcA, shared, []string{"e1"}, "127.0.0.20:20001"); why == "" {
			n++
		}
	}
	if n == 40 || counts["opened_rate"] == 0 {
		t.Fatalf("the window never limited shared connections: %d admitted, %v", n, counts)
	}
	c.advance(31 * time.Second)
	cs.Tick()
	if _, _, why := cs.Admit(100, srcA, shared, []string{"e1"}, "127.0.0.20:20001"); why != "" {
		t.Fatalf("the window must age: %s", why)
	}
}

// A connection rebuilt before the agent's list reached dns moves to its real exit
// when the list comes.
func TestSetExitsRekeysRebuiltConnections(t *testing.T) {
	c := newClock()
	cs, _ := newConns(c, nil)
	cn := &Conn{Name: string(nameX), EntrySrc: srcA, Out: outL1, Holders: []Holder{holder(1, 1)}}
	cn.Holders = append([]Holder(nil), cn.Holders...)
	tag := (&Conn{Name: string(nameX), EntrySrc: srcA, Out: outL1, Holders: cn.Holders, pl: place{ep: ep(1), acct: ep(1), kind: KindRedirect}}).Tag(1024)
	cs.Rebuild([]OpenItem{{ID: 1, Source: srcA, Socks: "127.0.0.20:20001", Tag: tag}})
	if cs.ExitOpen("x:127.0.0.20:20001") != 1 {
		t.Fatal("setup: the rebuilt connection must be charged to its own address key")
	}
	cs.SetExits(map[string]string{"127.0.0.20:20001": "e1"})
	if cs.ExitOpen("e1") != 1 || cs.ExitOpen("x:127.0.0.20:20001") != 0 {
		t.Fatalf("the connection must count in the real exit: e1=%d x=%d", cs.ExitOpen("e1"), cs.ExitOpen("x:127.0.0.20:20001"))
	}
	cs.Closed([]uint64{1}, nil)
	if cs.ExitOpen("e1") != 0 || cs.NodeOpen() != 0 {
		t.Fatal("close must give the place back from the new exit")
	}
}

// A verdict that began before a rebuild charges nothing and replaces nothing.
func TestAdmitAtRefusesAStaleGeneration(t *testing.T) {
	c := newClock()
	cs, _ := newConns(c, nil)
	gen := cs.Gen()
	live := hit(nameX, srcA, outL1, holder(1, 10))
	if _, _, why := cs.AdmitAt(gen, 7, srcA, live, []string{"e1"}, "127.0.0.20:20001"); why != "" {
		t.Fatal(why)
	}
	tag := (&Conn{Name: string(nameX), EntrySrc: srcA, Out: outL1, Holders: live.Holders, pl: place{ep: ep(1), acct: ep(1), kind: KindRedirect}}).Tag(1024)
	cs.Rebuild([]OpenItem{{ID: 7, Source: srcA, Socks: "127.0.0.20:20001", Tag: tag}})
	before := cs.NodeOpen()
	if _, _, why := cs.AdmitAt(gen, 7, srcA, live, []string{"e1"}, "127.0.0.20:20001"); why != StaleGen {
		t.Fatalf("a lookup of the old session must be refused: %q", why)
	}
	if cs.NodeOpen() != before {
		t.Fatal("a stale verdict charged the rebuilt table")
	}
	if _, _, why := cs.AdmitAt(cs.Gen(), 8, srcA, live, []string{"e1"}, "127.0.0.20:20001"); why != "" {
		t.Fatalf("a lookup of the new session must admit: %s", why)
	}
}
