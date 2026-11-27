// Package testsink takes over the process's own output for a test, so that a test
// of the no-trace rule (N7, SC 5.2a) can read everything the node printed.
//
// It is used by tests only. It lives outside a _test file so the dns and agent
// packages share one copy.
package testsink

import (
	"bytes"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Capture is the process's own output (slog's default logger, the log package,
// os.Stderr and os.Stdout) gathered in one buffer.
type Capture struct {
	mu   sync.Mutex
	b    bytes.Buffer
	stop func()
}

// Write implements io.Writer, so a test can add its own sinks (an Alerter that
// formats into it).
func (c *Capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}

// Bytes is what was written so far.
func (c *Capture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.b.Bytes()...)
}

// Reset forgets what was written.
func (c *Capture) Reset() {
	c.mu.Lock()
	c.b.Reset()
	c.mu.Unlock()
}

// Stop puts the sinks back and waits until what the pipes held is read. It is also
// registered with t.Cleanup.
func (c *Capture) Stop() { c.stop() }

// Start redirects the sinks. The test must not call t.Log between Start and Stop,
// because the testing package may write through os.Stdout.
func Start(t *testing.T) *Capture {
	t.Helper()
	c := &Capture{}
	oldSlog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(c, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(c)
	oldErr, oldOut := os.Stderr, os.Stdout
	var wg sync.WaitGroup
	var writers []*os.File
	for _, f := range []**os.File{&os.Stderr, &os.Stdout} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		*f = w
		writers = append(writers, w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(c, r)
			_ = r.Close()
		}()
	}
	var once sync.Once
	c.stop = func() {
		once.Do(func() {
			os.Stderr, os.Stdout = oldErr, oldOut
			log.SetOutput(oldErr)
			slog.SetDefault(oldSlog)
			for _, w := range writers {
				_ = w.Close()
			}
			wg.Wait()
		})
	}
	t.Cleanup(c.stop)
	return c
}

// Control writes a marker through every sink and waits until all four show up, so a
// test that captured nothing cannot pass for ever. It resets the buffer after.
func (c *Capture) Control(t *testing.T) {
	t.Helper()
	slog.Info("control", "k", "ctl-slog")
	log.Print("ctl-log")
	_, _ = io.WriteString(os.Stderr, "ctl-stderr\n")
	_, _ = io.WriteString(os.Stdout, "ctl-stdout\n")
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := string(c.Bytes())
		if strings.Contains(got, "ctl-slog") && strings.Contains(got, "ctl-log") && strings.Contains(got, "ctl-stderr") && strings.Contains(got, "ctl-stdout") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a sink is not captured: %q", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.Reset()
}
