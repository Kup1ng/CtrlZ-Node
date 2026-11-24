package alert

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// gate is a writer that blocks until released, as a journal pipe that stopped draining.
type gate struct {
	mu  sync.Mutex
	buf bytes.Buffer
	ch  chan struct{}
}

func (g *gate) Write(p []byte) (int, error) {
	<-g.ch
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.buf.Write(p)
}

// p4n-W5b-r3-7: Alert never waits for the writer, so a receive loop that raises one
// is not stopped by a journal that does not drain.
func TestLogAlertDoesNotWaitForTheWriter(t *testing.T) {
	g := &gate{ch: make(chan struct{})}
	l := &Log{W: g}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5*logQueue; i++ { // more than the queue holds, all different codes
			l.Alert(Alert{Code: fmt.Sprintf("c%d", i), Detail: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Alert blocked on a writer that does not drain")
	}
	if l.dropped.Load() == 0 {
		t.Error("nothing was dropped although the queue overflowed")
	}
	close(g.ch)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		n := strings.Count(g.buf.String(), "\n")
		g.mu.Unlock()
		if n >= logQueue {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the queued lines were never written")
}

func TestLogRateLimitsOneCode(t *testing.T) {
	g := &gate{ch: make(chan struct{})}
	close(g.ch)
	now := time.Unix(1000, 0)
	l := &Log{W: g, Now: func() time.Time { return now }}
	l.Alert(Alert{Code: "a", Detail: "1"})
	l.Alert(Alert{Code: "a", Detail: "2"})
	now = now.Add(2 * time.Minute)
	l.Alert(Alert{Code: "a", Detail: "3"})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		s := g.buf.String()
		g.mu.Unlock()
		if strings.Count(s, "\n") == 2 {
			if strings.Contains(s, `"2"`) {
				t.Fatal("a second alert of one code within a minute was written")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected two lines")
}
