package push_test

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// A Heartbeat is never built behind a lock that waits on a slow step (L11). While a
// push sits in its fsynced write, Status, Flags, Member, Table and TableInUse all
// answer, and already show the accepted push (review round 2, r2-4).
func TestReportReadersDoNotWaitForTheDiskWrite(t *testing.T) {
	reached, release := make(chan struct{}, 1), make(chan struct{})
	wr := &fsx.Writer{Hook: func(string, fsx.Step) error {
		select {
		case reached <- struct{}{}:
		default:
		}
		<-release
		return nil
	}}
	f := newFixture(t, wr)
	member := storetest.Table(3, 0)
	f.w.Load(member, now)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.apply(f.signed(100, 0))
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the push never reached its disk write")
	}
	read := make(chan struct{})
	go func() {
		defer close(read)
		st := f.w.Status()
		if st.Version != 100 || !st.AcceptedSinceStart {
			t.Errorf("status before the disk write ended: %+v", st)
		}
		if len(f.w.Flags()) == 0 || f.w.Member() == nil || f.w.Table() == nil || f.w.TableInUse(now) == nil {
			t.Error("the readers do not see the swapped table")
		}
	}()
	select {
	case <-read:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("a report reader waited for the disk write")
	}
	close(release)
	<-done
}

// SC 8a.5 (Table in use): a table loaded at start is built but not in use until a
// push is accepted or 30 s have passed; a redelivery of the persisted push counts
// (review round 2, r2-6).
func TestTableInUseWaitsForAPushOrThirtySeconds(t *testing.T) {
	f := newFixture(t, nil)
	f.w.Load(storetest.Table(3, 0), now)
	if f.w.Table() == nil {
		t.Fatal("no built table")
	}
	if f.w.TableInUse(now) != nil || f.w.TableInUse(now+29) != nil {
		t.Fatal("a table loaded at start is in use before a push or 30 s")
	}
	if f.w.TableInUse(now+30) == nil {
		t.Fatal("no table in use after 30 s")
	}
	if r := f.apply(f.signed(100)); !r.Accepted {
		t.Fatalf("%+v", r)
	}
	if f.w.TableInUse(now) == nil {
		t.Fatal("no table in use after an accepted push")
	}
	// A restart is a new period, and the persisted push is not a push of this run.
	w2 := f.writer(nil)
	w2.Load(storetest.Table(3, 0), now)
	if w2.TableInUse(now+1) != nil {
		t.Fatal("table in use right after a restart")
	}
	if r := w2.ApplyPush(f.signed(100), now); !r.Accepted || !r.Redelivery {
		t.Fatalf("%+v", r)
	}
	if w2.TableInUse(now+1) == nil {
		t.Fatal("a redelivery did not put the table in use")
	}
	// No applied membership, no table at all.
	w3 := f.writer(nil)
	w3.Load(nil, now)
	if w3.TableInUse(now+100) != nil {
		t.Fatal("a table with no membership")
	}
}
