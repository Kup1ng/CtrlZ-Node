package listen

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// closedAny counts the closes of one transport whatever the reason: net/http, not
// this package, decides how a drained DoH connection is reported.
func (o *observed) closedAny(t Transport) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for k, v := range o.closed {
		if len(k) > len(t.String()) && k[:len(t.String())+1] == t.String()+"/" {
			n += v
		}
	}
	return n
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var encrypted = []Transport{DoT, DoH, DoH3, DoQ}

// SC 8a.6: from the start of the window every DoT, DoH, DoH3 and DoQ connection is
// closed, none before it, and Plain DNS is never touched.
func TestDrainClosesEveryEncryptedTransportAndSparesPlain(t *testing.T) {
	f := newFixture(t)
	clients := map[Transport]qclient{}
	for _, tr := range append([]Transport{TCP, UDP}, encrypted...) {
		c := f.mustDial(tr)
		r, err := ask(c, rid(1), dns.TypeA)
		if err != nil || !answered(r) {
			t.Fatalf("%s before the drain: %v %v", tr, r, err)
		}
		clients[tr] = c
	}
	start := time.Now()
	f.srv.Drain(DrainPlan{Start: 300 * time.Millisecond, Window: 300 * time.Millisecond, Wait: 3 * time.Second})
	if !f.srv.Draining() {
		t.Fatal("not draining after Drain")
	}
	time.Sleep(200 * time.Millisecond)
	for _, tr := range encrypted {
		if n := f.obs.closedAny(tr); n != 0 {
			t.Fatalf("%s closed %d connections %v into a window that opens at 300 ms", tr, n, time.Since(start))
		}
	}
	for _, tr := range encrypted {
		tr := tr
		waitFor(t, 10*time.Second, tr.String()+" connection closed", func() bool { return f.obs.closedAny(tr) >= 1 })
	}
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("a connection was closed after %v, before the window", el)
	}
	// DoT: the client sees the end of the connection with the close_notify.
	if fc := clients[DoT].(*frameClient); !fc.waitClosed(3 * time.Second) {
		t.Fatal("the DoT client was not told the connection ended")
	}
	if n := f.obs.closedCount(DoT, CloseDrain); n != 1 {
		t.Fatalf("DoT drain closes = %d", n)
	}
	for _, tr := range []Transport{DoH3, DoQ} {
		if n := f.obs.closedCount(tr, CloseDrain); n != 1 {
			t.Fatalf("%s drain closes = %d", tr, n)
		}
	}
	// Plain DNS: the TCP connection stays open and both answer.
	for _, tr := range []Transport{TCP, UDP} {
		if r, err := ask(clients[tr], rid(2), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%s after the drain: %v %v", tr, r, err)
		}
	}
	if n := f.obs.closedAny(TCP) + f.obs.closedAny(UDP); n != 0 {
		t.Fatalf("Plain DNS closed %d connections", n)
	}
	waitFor(t, 2*time.Second, "the window to end", func() bool { return !f.srv.Draining() })
	// The node serves new connections after the drain, with the same answers: a
	// client that uses it by address is served as before.
	for _, tr := range encrypted {
		c := f.mustDial(tr)
		if r, err := ask(c, rid(3), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%s new connection after the drain: %v %v", tr, r, err)
		}
	}
}

// A query in flight is answered before its connection goes: the drain waits for it.
func TestDrainWaitsForAQueryInFlight(t *testing.T) {
	for _, tr := range encrypted {
		t.Run(tr.String(), func(t *testing.T) {
			f := newFixture(t)
			f.stub.SlowFor = 600 * time.Millisecond
			c := f.mustDial(tr)
			if r, err := ask(c, rid(1), dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("warm-up: %v %v", r, err)
			}
			type res struct {
				r   *dns.Msg
				err error
				at  time.Time
			}
			ch := make(chan res, 1)
			go func() {
				r, err := ask(c, "slow-"+rid(2), dns.TypeA)
				ch <- res{r, err, time.Now()}
			}()
			waitFor(t, 10*time.Second, "the slow query to reach the handler", func() bool {
				for _, q := range f.stub.Requests() {
					if len(q.Msg.Question) == 1 && len(q.Msg.Question[0].Name) > 5 && q.Msg.Question[0].Name[:5] == "slow-" {
						return true
					}
				}
				return false
			})
			began := time.Now()
			f.srv.Drain(DrainPlan{Window: time.Millisecond, Wait: 5 * time.Second})
			got := <-ch
			if got.err != nil || !answered(got.r) {
				t.Fatalf("the query in flight when the drain began was not answered: %v %v", got.r, got.err)
			}
			if got.at.Sub(began) < 300*time.Millisecond {
				t.Fatalf("the reply came after %v: the handler cannot have been waited for", got.at.Sub(began))
			}
			waitFor(t, 10*time.Second, "the connection to close after the reply", func() bool { return f.obs.closedAny(tr) >= 1 })
		})
	}
}

// A re-advertisement before the window cancels the drain; so does Still saying
// the node is advertised again, and a connection is then never closed.
func TestDrainCancel(t *testing.T) {
	f := newFixture(t)
	for _, tr := range encrypted {
		c := f.mustDial(tr)
		if r, err := ask(c, rid(1), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%s: %v %v", tr, r, err)
		}
	}
	f.srv.Drain(DrainPlan{Start: 300 * time.Millisecond, Window: 200 * time.Millisecond, Wait: time.Second})
	time.Sleep(100 * time.Millisecond)
	f.srv.CancelDrain()
	if f.srv.Draining() {
		t.Fatal("still draining after CancelDrain")
	}
	time.Sleep(900 * time.Millisecond)
	for _, tr := range encrypted {
		if n := f.obs.closedAny(tr); n != 0 {
			t.Fatalf("%s closed %d connections after the cancel", tr, n)
		}
	}
	// Still false: the node is advertised again by the time a close is due.
	var asked atomic.Int32
	f.srv.Drain(DrainPlan{Window: 100 * time.Millisecond, Wait: time.Second, Still: func() bool { asked.Add(1); return false }})
	time.Sleep(700 * time.Millisecond)
	if asked.Load() == 0 {
		t.Fatal("Still was never asked before a close")
	}
	if f.srv.Draining() {
		t.Fatal("a plan whose Still said false is still in force")
	}
	for _, tr := range encrypted {
		if n := f.obs.closedAny(tr); n != 0 {
			t.Fatalf("%s closed %d connections although Still said the node is advertised", tr, n)
		}
	}
}

// A connection opened during the window is closed within it; one opened after it
// is a client that uses the node by address and stays.
func TestDrainConnectionsOpenedDuringAndAfterTheWindow(t *testing.T) {
	f := newFixture(t)
	// A first handshake on a cold process can take a second; the connections of this
	// test must be opened inside the window, so every transport is warmed up first.
	for _, tr := range encrypted {
		c, err := f.dial(tr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = ask(c, rid(9), dns.TypeA)
		c.close()
	}
	waitFor(t, 5*time.Second, "the warm-up connections to end", func() bool {
		for _, tr := range encrypted {
			if f.obs.closedAny(tr) == 0 {
				return false
			}
		}
		return true
	})
	base := map[Transport]int{}
	for _, tr := range encrypted {
		base[tr] = f.obs.closedAny(tr)
	}
	began := time.Now()
	f.srv.Drain(DrainPlan{Window: 2 * time.Second, Wait: time.Second})
	time.Sleep(100 * time.Millisecond)
	for _, tr := range encrypted {
		c := f.mustDial(tr)
		if r, err := ask(c, rid(1), dns.TypeA); err != nil || !answered(r) {
			// The drain may close this connection before its first query, which is its
			// right (it is quiet): a client opens another, as the steady client does.
			c = f.mustDial(tr)
			if r, err = ask(c, rid(1), dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("%s: %v %v", tr, r, err)
			}
		}
	}
	// The close must come from the drain, inside the window, and not from the idle
	// timeout 10 s later, which would let a connection that the drain missed pass.
	for _, tr := range encrypted {
		tr := tr
		waitFor(t, 5*time.Second, tr.String()+" opened during the window is closed by the drain", func() bool { return f.obs.closedAny(tr) > base[tr] })
		if el := time.Since(began); el > 4*time.Second {
			t.Fatalf("%s: the close came %v after the plan began, outside its window of 2 s", tr, el)
		}
	}
	for _, tr := range []Transport{DoT, DoQ, DoH3} {
		if f.obs.closedCount(tr, CloseDrain) < 1 {
			t.Fatalf("%s: the connection was not closed for the drain", tr)
		}
		if n := f.obs.closedCount(tr, CloseIdle); n != 0 {
			t.Fatalf("%s: %d idle closes", tr, n)
		}
	}
	waitFor(t, 4*time.Second, "the window to end", func() bool { return !f.srv.Draining() })
	time.Sleep(100 * time.Millisecond)
	after := map[Transport]int{}
	for _, tr := range encrypted {
		after[tr] = f.obs.closedAny(tr)
		c := f.mustDial(tr)
		if r, err := ask(c, rid(2), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%s: %v %v", tr, r, err)
		}
	}
	time.Sleep(700 * time.Millisecond)
	for _, tr := range encrypted {
		if n := f.obs.closedAny(tr); n != after[tr] {
			t.Fatalf("%s: a connection opened after the window was closed", tr)
		}
	}
}

// A client that retries once on a closed connection loses no query through a drain
// that runs while it asks steadily: the node closes only between queries.
func TestDrainLosesNoQueryOfASteadyClient(t *testing.T) {
	for _, tr := range []Transport{DoT, DoH, DoH3, DoQ} {
		t.Run(tr.String(), func(t *testing.T) {
			f := newFixture(t)
			c := f.mustDial(tr)
			f.srv.Drain(DrainPlan{Start: 100 * time.Millisecond, Window: 500 * time.Millisecond, Wait: time.Second})
			end := time.Now().Add(900 * time.Millisecond)
			var failed, sent, redials int
			for time.Now().Before(end) {
				sent++
				r, err := ask(c, rid(sent), dns.TypeA)
				if err != nil || !answered(r) {
					// The close came between this client's queries or crossed one: the
					// connection is gone, and a client opens another (RFC 7766 6.2.4).
					// A connection that opens in the window is itself drained at a random
					// moment, so the retry can cross that close too (the one crossing
					// that cannot be avoided, p4-nodes 7.8). A client retries again;
					// a query that fails on three fresh connections in a row is lost.
					ok := false
					for try := 0; try < 3 && !ok; try++ {
						c.close()
						c = f.mustDial(tr)
						redials++
						r, err = ask(c, rid(sent), dns.TypeA)
						ok = err == nil && answered(r)
					}
					if !ok {
						failed++
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if failed != 0 {
				t.Fatalf("%d of %d queries failed even on a new connection", failed, sent)
			}
			if f.obs.closedAny(tr) == 0 {
				t.Fatal("the drain closed nothing")
			}
			t.Logf("%s: %d queries, %d reconnects", tr, sent, redials)
		})
	}
}

// The closes of the DoH shards are spread: the connections of one listener do not
// all end at one moment.
func TestDrainSpreadsTheDoHConnections(t *testing.T) {
	f := newFixture(t, withTransports(DoH))
	// One connection on each of the 32 shards, and the moments of the 32 shards an even
	// grid over the window, so the result does not depend on a random draw: with random
	// ones, about one run in a hundred put no connection in the first quarter.
	const n = 32
	var pick, grid atomic.Int64
	f.srv.doh.rng = func(m int) int { return int(pick.Add(1)-1) % m }
	f.srv.dr.rnd = func(w int64) int64 { return (grid.Add(1) - 1) % n * w / n }
	var cs []qclient
	for i := 0; i < n; i++ {
		// A separate client each: one connection each.
		c := f.dohClient(true, "")
		if r, err := ask(c, rid(i), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%v %v", r, err)
		}
		cs = append(cs, c)
		defer c.close()
	}
	f.srv.Drain(DrainPlan{Window: 800 * time.Millisecond, Wait: time.Second})
	time.Sleep(200 * time.Millisecond)
	early := f.obs.closedAny(DoH)
	waitFor(t, 10*time.Second, "every connection closed", func() bool { return f.obs.closedAny(DoH) >= n })
	if early == 0 || early >= n {
		t.Fatalf("after 200 ms of an 800 ms window %d of %d connections were closed: no spread", early, n)
	}
}

// ---- the plan itself, on fake connections and a fixed random draw

type fakeConn struct {
	mu     sync.Mutex
	closed time.Time
	quiet  atomic.Bool
}

func (c *fakeConn) item() *drainItem {
	return &drainItem{
		quiet: c.quiet.Load,
		close: func() { c.mu.Lock(); c.closed = time.Now(); c.mu.Unlock() },
	}
}

func (c *fakeConn) closedAt() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }

func TestDrainerSchedulesInsideTheWindowAndNotAfterIt(t *testing.T) {
	d := newDrainer()
	d.rnd = func(n int64) int64 { return n / 2 } // the middle of the window
	a, b := &fakeConn{}, &fakeConn{}
	a.quiet.Store(true)
	b.quiet.Store(true)
	d.attach(a.item())
	began := time.Now()
	d.begin(DrainPlan{Start: 100 * time.Millisecond, Window: 200 * time.Millisecond, Wait: time.Second})
	d.attach(b.item()) // a replacement made while the plan runs: scheduled in what is left
	time.Sleep(350 * time.Millisecond)
	if at := a.closedAt(); at.IsZero() || at.Sub(began) < 190*time.Millisecond || at.Sub(began) > 330*time.Millisecond {
		t.Fatalf("closed at %v, want about 200 ms (the middle of 100..300 ms)", at.Sub(began))
	}
	// b joined at once, 0 ms into the window; its moment is the middle of what was left.
	if at := b.closedAt(); at.IsZero() || at.Sub(began) > 330*time.Millisecond {
		t.Fatalf("an item that joined during the window was not closed inside it: %v", at.Sub(began))
	}
	// After the window nothing is scheduled.
	c := &fakeConn{}
	c.quiet.Store(true)
	d.attach(c.item())
	time.Sleep(50 * time.Millisecond)
	if !c.closedAt().IsZero() {
		t.Fatal("an item attached after the window was closed")
	}
}

func TestDrainerNotQuietWaitsThenClosesAtTheBound(t *testing.T) {
	d := newDrainer()
	c := &fakeConn{} // never quiet
	d.attach(c.item())
	began := time.Now()
	d.begin(DrainPlan{Window: time.Millisecond, Wait: 200 * time.Millisecond})
	time.Sleep(100 * time.Millisecond)
	if !c.closedAt().IsZero() {
		t.Fatal("closed while a query was in flight")
	}
	time.Sleep(250 * time.Millisecond)
	if at := c.closedAt(); at.IsZero() || at.Sub(began) < 190*time.Millisecond {
		t.Fatalf("closed at %v, want after the wait of 200 ms", at.Sub(began))
	}
}

func TestDrainerDetachAndCancelStopTheClose(t *testing.T) {
	d := newDrainer()
	a, b := &fakeConn{}, &fakeConn{}
	a.quiet.Store(true)
	b.quiet.Store(true)
	detachA := d.attach(a.item())
	d.attach(b.item())
	d.begin(DrainPlan{Start: 100 * time.Millisecond, Window: time.Millisecond, Wait: time.Second})
	detachA()
	time.Sleep(50 * time.Millisecond)
	d.cancel()
	time.Sleep(150 * time.Millisecond)
	if !a.closedAt().IsZero() || !b.closedAt().IsZero() {
		t.Fatal("a detached or cancelled connection was closed")
	}
	// A new plan replaces the old one and works again.
	d.begin(DrainPlan{Window: time.Millisecond, Wait: time.Second})
	time.Sleep(100 * time.Millisecond)
	if b.closedAt().IsZero() {
		t.Fatal("the new plan did not close the connection")
	}
}

// A replacement shard that an earlier drain put in place holds the connections of
// the next one: a second drain closes them too.
func TestASecondDrainClosesTheConnectionsOfTheReplacementShards(t *testing.T) {
	f := newFixture(t, withTransports(DoH))
	c1 := f.dohClient(true, "")
	if r, err := ask(c1, rid(1), dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("%v %v", r, err)
	}
	defer c1.close()
	f.srv.Drain(DrainPlan{Window: 200 * time.Millisecond, Wait: time.Second})
	waitFor(t, 10*time.Second, "the first drain", func() bool { return f.obs.closedAny(DoH) >= 1 })
	waitFor(t, 2*time.Second, "the first window to end", func() bool { return !f.srv.Draining() })
	// Enough connections that some sit in a replacement shard.
	var cs []qclient
	for i := 0; i < 16; i++ {
		c := f.dohClient(true, "")
		if r, err := ask(c, rid(i), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%v %v", r, err)
		}
		cs = append(cs, c)
		defer c.close()
	}
	before := f.obs.closedAny(DoH)
	f.srv.Drain(DrainPlan{Window: 300 * time.Millisecond, Wait: time.Second})
	waitFor(t, 10*time.Second, "the second drain to close every connection", func() bool { return f.obs.closedAny(DoH) >= before+len(cs) })
}

// A plan whose window is already over by the time it reaches a connection still
// closes the connections that were open when it began: a node that learns of a drain
// 340 s after the apply has a window of a millisecond, and must be done by 360 s.
func TestDrainerAnEmptyWindowStillClosesTheOpenConnections(t *testing.T) {
	d := newDrainer()
	var cs []*fakeConn
	for i := 0; i < 20; i++ {
		c := &fakeConn{}
		c.quiet.Store(true)
		d.attach(c.item())
		cs = append(cs, c)
	}
	time.Sleep(5 * time.Millisecond)
	d.begin(DrainPlan{Window: time.Nanosecond, Wait: time.Second})
	time.Sleep(200 * time.Millisecond)
	for i, c := range cs {
		if c.closedAt().IsZero() {
			t.Fatalf("connection %d was not closed", i)
		}
	}
}

// A connection that always has queries in flight (a home router sending a
// household's lookups over one connection) is not cut at the wait with every reply
// lost: at its moment it takes no new query, the ones it holds are answered, and only
// then does it close. Every query the handler received gets its reply (p4n-W8-r1-6).
func TestDrainOfABusyConnectionLosesNoQueryTheHandlerHas(t *testing.T) {
	for _, tr := range encrypted {
		t.Run(tr.String(), func(t *testing.T) {
			f := newFixture(t)
			f.stub.SlowFor = 150 * time.Millisecond
			c := f.mustDial(tr)
			if r, err := ask(c, rid(1), dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("warm-up: %v %v", r, err)
			}
			const workers = 6
			var answeredN, failedN, lastEnd atomic.Int64
			var stop atomic.Bool
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Go(func() {
					for !stop.Load() {
						r, err := ask(c, "slow-"+rid(w), dns.TypeA)
						if err != nil || !answered(r) {
							failedN.Add(1)
							lastEnd.Store(time.Now().UnixNano())
							return // the connection is gone; a real client opens another
						}
						answeredN.Add(1)
					}
				})
			}
			time.Sleep(400 * time.Millisecond) // traffic is steady: some query is always open
			// The workers keep asking past the wait, so a close that came only at the wait
			// would find queries in flight and cut their replies.
			wait := 2 * time.Second
			began := time.Now()
			f.srv.Drain(DrainPlan{Window: time.Millisecond, Wait: wait})
			done := make(chan struct{})
			go func() {
				// DoH clients move to a new connection on their own and never fail, so the
				// workers also end a little after the wait.
				time.Sleep(wait + 1500*time.Millisecond)
				stop.Store(true)
				wg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(wait + 8*time.Second):
				t.Fatal("the workers did not end")
			}
			if tr == DoT || tr == DoQ {
				// HTTP clients (DoH, DoH3) retry a refused request on a new connection and
				// never fail; the stream clients see the connection end.
				if el := time.Duration(lastEnd.Load() - began.UnixNano()); el <= 0 || el > wait {
					t.Fatalf("the connection ended %v after the drain began: it was not closed at its moment, before the wait of %v", el, wait)
				}
			}
			if tr != DoH {
				waitFor(t, 3*time.Second, "the drain close", func() bool { return f.obs.closedCount(tr, CloseDrain) >= 1 })
			}
			got := int64(0)
			for _, q := range f.stub.Requests() {
				if n := q.Msg.Question[0].Name; len(n) > 5 && n[:5] == "slow-" {
					got++
				}
			}
			if got != answeredN.Load() {
				t.Fatalf("the handler received %d queries and %d were answered: %d replies lost", got, answeredN.Load(), got-answeredN.Load())
			}
			t.Logf("%s: %d answered, %d refused or retried", tr, answeredN.Load(), failedN.Load())
		})
	}
}

// A DoH connection that opens during the window and lands on a shard that an earlier
// close of the same window replaced is closed in the window too (p4n-W8-r1-1).
func TestDrainClosesADoHConnectionOnAReplacementShard(t *testing.T) {
	f := newFixture(t, withTransports(DoH))
	s := f.srv.doh
	s.rng = func(int) int { return 0 } // every client goes to shard 0
	f.srv.dr.rnd = func(n int64) int64 { return n / 4 }
	s.mu.Lock()
	first := s.shards[0]
	s.mu.Unlock()
	began := time.Now()
	f.srv.Drain(DrainPlan{Window: 1500 * time.Millisecond, Wait: time.Second})
	waitFor(t, 3*time.Second, "shard 0 to be replaced", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.shards[0] != first
	})
	c := f.dohClient(true, "")
	defer c.close()
	if r, err := ask(c, rid(1), dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("%v %v", r, err)
	}
	waitFor(t, 3*time.Second, "the connection on the replacement shard to be closed", func() bool { return f.obs.closedAny(DoH) >= 1 })
	if el := time.Since(began); el > 2500*time.Millisecond {
		t.Fatalf("closed %v after the plan began: not by the drain (the window is 1.5 s, the idle timeout is longer)", el)
	}
}

// A connection that is told to take no new query is told to take queries again when
// the plan ends before its close; one whose close is decided stays refusing.
func TestDrainerRefusesAtTheMomentAndLiftsItOnCancel(t *testing.T) {
	d := newDrainer()
	d.rnd = func(n int64) int64 { return 0 }
	var refusing atomic.Bool
	var quiet atomic.Bool
	closed := make(chan struct{})
	it := &drainItem{
		quiet:  quiet.Load,
		refuse: func(on bool) bool { refusing.Store(on); return true },
		close:  func() { close(closed) },
	}
	d.attach(it)
	d.begin(DrainPlan{Window: time.Millisecond, Wait: 5 * time.Second})
	waitFor(t, time.Second, "the connection to refuse", refusing.Load)
	select {
	case <-closed:
		t.Fatal("closed while not quiet")
	case <-time.After(60 * time.Millisecond):
	}
	d.cancel()
	if refusing.Load() {
		t.Fatal("the connection still refuses after the plan was cancelled")
	}
	// A new plan, and this time the connection becomes quiet once it refuses.
	d.begin(DrainPlan{Window: time.Millisecond, Wait: 5 * time.Second})
	waitFor(t, time.Second, "the connection to refuse again", refusing.Load)
	quiet.Store(true)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("not closed once quiet")
	}
	if !refusing.Load() {
		t.Fatal("a connection whose close was decided stopped refusing")
	}
	d.cancel()
	if !refusing.Load() {
		t.Fatal("a cancel after the close lifted the refusal of a closing connection")
	}
}

// A plan that ends while a DoT connection is refusing must not leave the queries it
// dropped unanswered on a connection that goes on: once a frame was dropped, the
// close is decided and the client is told to retry (p4n-W8-r2-2).
func TestDrainCancelledAfterADoTConnectionDroppedAQueryStillClosesIt(t *testing.T) {
	f := newFixture(t)
	gate := make(chan struct{})
	f.stub.Gate = gate
	c := f.mustDial(DoT).(*frameClient)
	if r, err := ask(c, rid(1), dns.TypeA); err != nil || !answered(r) {
		t.Fatalf("warm-up: %v %v", r, err)
	}
	slow := make(chan error, 1)
	go func() {
		r, err := ask(c, "slow-"+rid(2), dns.TypeA)
		if err == nil && !answered(r) {
			err = errUnanswered
		}
		slow <- err
	}()
	waitFor(t, 10*time.Second, "the slow query to reach the handler", func() bool {
		for _, q := range f.stub.Requests() {
			if len(q.Msg.Question) == 1 && strings.HasPrefix(q.Msg.Question[0].Name, "slow-") {
				return true
			}
		}
		return false
	})
	f.srv.Drain(DrainPlan{Window: time.Millisecond, Wait: 10 * time.Second})
	time.Sleep(150 * time.Millisecond)               // the moment has come and the connection refuses
	go func() { _, _ = ask(c, rid(3), dns.TypeA) }() // read and dropped, never answered
	time.Sleep(150 * time.Millisecond)
	f.srv.CancelDrain() // the node is advertised again
	close(gate)
	if err := <-slow; err != nil {
		t.Fatalf("the query in flight was not answered: %v", err)
	}
	if !c.waitClosed(5 * time.Second) {
		t.Fatal("the connection that dropped a query stayed open after the drain was cancelled: the client waits for an answer that never comes")
	}
}

// The drainer closes a refusing connection once quiet when the plan ends after it
// dropped something, and puts one back to normal when it dropped nothing.
func TestDrainerClosesAConnectionThatCannotGoBackToNormal(t *testing.T) {
	d := newDrainer()
	d.rnd = func(n int64) int64 { return 0 }
	var quiet atomic.Bool
	var dirty atomic.Bool
	closed := make(chan struct{})
	it := &drainItem{
		quiet:  quiet.Load,
		refuse: func(on bool) bool { return on || !dirty.Load() },
		close:  func() { close(closed) },
	}
	d.attach(it)
	d.begin(DrainPlan{Window: time.Millisecond, Wait: 5 * time.Second})
	waitFor(t, time.Second, "the connection to refuse", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return it.refusing
	})
	dirty.Store(true)
	d.cancel()
	select {
	case <-closed:
		t.Fatal("closed while not quiet")
	case <-time.After(60 * time.Millisecond):
	}
	quiet.Store(true)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("not closed once quiet")
	}
}

var errUnanswered = errors.New("not answered")

// A DoH shard waits for the requests it holds only for the plan's Wait, not for the
// 30 s handler timeout: a late plan's Wait is short so that the last close is done by
// 360 s (p4n-W8-r3-1). The request here would take 4 s; the plan's Wait is 300 ms.
func TestDrainDoHShardCloseWaitsOnlyForThePlansWait(t *testing.T) {
	f := newFixture(t, withTransports(DoH))
	f.stub.SlowFor = 4 * time.Second
	c := f.dohClient(true, "")
	defer c.close()
	go func() { _, _ = ask(c, "slow-"+rid(1), dns.TypeA) }()
	waitFor(t, 10*time.Second, "the slow query to reach the handler", func() bool {
		for _, q := range f.stub.Requests() {
			if len(q.Msg.Question) == 1 && len(q.Msg.Question[0].Name) > 5 && q.Msg.Question[0].Name[:5] == "slow-" {
				return true
			}
		}
		return false
	})
	began := time.Now()
	f.srv.Drain(DrainPlan{Window: time.Millisecond, Wait: 300 * time.Millisecond})
	waitFor(t, 3*time.Second, "the connection to be closed at the plan's Wait", func() bool { return f.obs.closedAny(DoH) >= 1 })
	if el := time.Since(began); el > 2*time.Second {
		t.Fatalf("closed %v after the plan began, Wait was 300 ms", el)
	}
}

// A DoH connection ended by the drain is reported as such (p4n-W8-r3-2).
func TestDrainDoHClosesAreReportedAsDrain(t *testing.T) {
	f := newFixture(t, withTransports(DoH))
	var cs []qclient
	for i := 0; i < 8; i++ {
		c := f.dohClient(true, "")
		if r, err := ask(c, rid(i), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%v %v", r, err)
		}
		cs = append(cs, c)
		defer c.close()
	}
	f.srv.Drain(DrainPlan{Window: 200 * time.Millisecond, Wait: time.Second})
	waitFor(t, 10*time.Second, "every connection closed as drained", func() bool { return f.obs.closedCount(DoH, CloseDrain) >= len(cs) })
}

// A connection that opens after the window is never closed by the drain, even when
// the last moments of the replacement shards' cascade run late (p4n-W8-r3-3). The
// window is short and the rounds many, so a moment that lands after the end is likely.
func TestDrainDoHConnectionOpenedAfterTheWindowIsNeverClosed(t *testing.T) {
	for round := 0; round < 6; round++ {
		f := newFixture(t, withTransports(DoH))
		c1 := f.dohClient(true, "")
		if r, err := ask(c1, rid(1), dns.TypeA); err != nil || !answered(r) {
			t.Fatalf("%v %v", r, err)
		}
		f.srv.Drain(DrainPlan{Window: 100 * time.Millisecond, Wait: time.Second})
		waitFor(t, 10*time.Second, "the drain to close the first connection", func() bool { return f.obs.closedAny(DoH) >= 1 })
		waitFor(t, 2*time.Second, "the window to end", func() bool { return !f.srv.Draining() })
		before := f.obs.closedAny(DoH)
		var cs []qclient
		for i := 0; i < 16; i++ {
			c := f.dohClient(true, "")
			if r, err := ask(c, rid(i), dns.TypeA); err != nil || !answered(r) {
				t.Fatalf("%v %v", r, err)
			}
			cs = append(cs, c)
		}
		time.Sleep(400 * time.Millisecond)
		if n := f.obs.closedAny(DoH); n != before {
			t.Fatalf("round %d: %d connections opened after the window were closed", round, n-before)
		}
		for _, c := range cs {
			c.close()
		}
		c1.close()
	}
}

// After the window a shard with a close still to come (its timer is late) is not
// handed new connections while another shard is free, and any shard will do when all
// are pending.
func TestDohPickAvoidsAShardWhoseCloseIsStillToComeAfterTheWindow(t *testing.T) {
	f := newFixture(t, withTransports(DoH))
	s := f.srv.doh
	d := f.srv.dr
	s.rng = func(int) int { return 0 }
	s.mu.Lock()
	first := s.shards[0]
	s.mu.Unlock()
	// A plan whose window is over, with shard 0's moment still to come.
	d.mu.Lock()
	d.plan = &drainRun{DrainPlan: DrainPlan{Window: time.Millisecond}, began: time.Now().Add(-time.Second)}
	first.item.run = d.plan
	first.item.timer = time.NewTimer(time.Hour)
	d.mu.Unlock()
	s.mu.Lock()
	got := s.pick()
	s.mu.Unlock()
	if got == first {
		t.Fatal("a connection after the window was given to a shard that is about to be shut down")
	}
	// A shard whose moment has come and whose close is under way (timer cleared by the
	// detach, replacement not yet in place) is just as unfit.
	d.mu.Lock()
	first.item.timer.Stop()
	first.item.timer = nil
	first.item.done = true
	d.mu.Unlock()
	s.mu.Lock()
	got = s.pick()
	s.mu.Unlock()
	if got == first {
		t.Fatal("a connection after the window was given to a shard whose close is under way")
	}
	d.mu.Lock()
	first.item.timer = time.NewTimer(time.Hour)
	first.item.done = false
	d.mu.Unlock()
	d.mu.Lock()
	for _, sh := range s.shards {
		sh.item.run = d.plan
		sh.item.timer = time.NewTimer(time.Hour)
	}
	d.mu.Unlock()
	s.mu.Lock()
	got = s.pick()
	s.mu.Unlock()
	if got != first {
		t.Fatal("with every shard pending the random one should be used")
	}
	d.cancel()
}
