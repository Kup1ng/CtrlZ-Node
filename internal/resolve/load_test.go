//go:build loadtest

package resolve

// The local part of T-551: DoH and DoT upstreams driven on loopback at rising
// request rates, with and without a simulated server round trip. Run it with
//
//	go test -tags loadtest -run TestUpstreamLoad -v -timeout 60m ./internal/resolve/
//
// It is behind a build tag because it takes minutes and its numbers depend on
// the machine. Server and client share one process and one CPU budget, so the
// figures are a floor for the client's own cost, not a capacity claim. The run
// on target hardware belongs to T-412.

import (
	"context"
	"errors"
	"io"
	"strings"
	"syscall"

	"fmt"
	"github.com/miekg/dns"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
)

// maxInFlight bounds the generator so a stalled upstream cannot grow the
// process without limit. A query that would exceed it is counted as dropped by
// the generator, which is itself a finding: the upstream was not keeping up.
const maxInFlight = 20000

type loadResult struct {
	target   int
	sent     int
	ok       int
	errs     int
	dropped  int
	elapsed  time.Duration
	p50, p99 time.Duration
	errKinds map[string]int
}

// drive sends queries at a fixed open-loop rate for d. Open-loop matters: a
// closed loop slows down when the upstream does, which hides exactly the
// queueing that the two-connection DoH cap would cause.
func drive(u exchanger, timeout time.Duration, rate int, d time.Duration) loadResult {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		lat      = make([]time.Duration, 0, rate*int(d/time.Second)+1)
		inflight atomic.Int64
		okN      atomic.Int64
		errN     atomic.Int64
		dropped  int
		sent     int
		errKinds = map[string]int{}
	)
	start := time.Now()
	deadline := start.Add(d)
	// A ticker per query is too coarse at 10k+/s on Windows (15 ms timer
	// granularity), so dispatch in 2 ms batches sized to hit the rate.
	const batch = 2 * time.Millisecond
	perBatch := float64(rate) * batch.Seconds()
	var carry float64
	for next := start; time.Now().Before(deadline); next = next.Add(batch) {
		carry += perBatch
		n := int(carry)
		carry -= float64(n)
		for i := 0; i < n; i++ {
			if inflight.Load() >= maxInFlight {
				dropped++
				continue
			}
			sent++
			inflight.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer inflight.Add(-1)
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				t0 := time.Now()
				resp, err := u.Exchange(ctx, query("load.example.com"))
				l := time.Since(t0)
				if err != nil || len(resp.Answer) != 1 {
					errN.Add(1)
					mu.Lock()
					errKinds[errKind(err, resp)]++
					mu.Unlock()
					return
				}
				okN.Add(1)
				mu.Lock()
				lat = append(lat, l)
				mu.Unlock()
			}()
		}
		if s := time.Until(next.Add(batch)); s > 0 {
			time.Sleep(s)
		}
	}
	wg.Wait()
	// Throughput is over the generation window: replies that arrive after it
	// (the tail) still count as ok but the window is what the rate was held for.
	res := loadResult{errKinds: errKinds, target: rate, sent: sent, ok: int(okN.Load()), errs: int(errN.Load()), dropped: dropped, elapsed: time.Since(start)}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if len(lat) > 0 {
		res.p50 = lat[len(lat)/2]
		res.p99 = lat[len(lat)*99/100]
	}
	return res
}

func TestUpstreamLoad(t *testing.T) {
	secs := 3
	if v, err := strconv.Atoi(os.Getenv("CTRLZ_LOAD_SECONDS")); err == nil && v > 0 {
		secs = v
	}
	window := time.Duration(secs) * time.Second
	rates := []int{500, 1000, 2000, 4000, 8000, 12000, 16000, 20000}
	// 0 ms is the loopback floor. 20 and 60 ms stand for a near and a far
	// upstream: with a round trip, in-flight queries = rate x delay, which is
	// what meets the two-connection DoH cap.
	delays := []time.Duration{0, 20 * time.Millisecond, 60 * time.Millisecond}
	only := os.Getenv("CTRLZ_LOAD_KIND")

	cert, pool := testCert(t)
	for _, delay := range delays {
		doh, dohSrv := startDoH(t, cert, delay)
		dot, dotHits := startDoT(t, cert, delay)
		kinds := []struct {
			name      string
			cfg       Config
			instances int
			conns     *counter
		}{
			{"doh", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: hostport(doh, testHost)}, 1, &dohSrv.hits},
			{"doh-x4", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: hostport(doh, testHost)}, 4, &dohSrv.hits},
			{"dot", Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOT, Address: hostport(dot, testHost)}, 1, dotHits},
		}
		for _, k := range kinds {
			if only != "" && only != k.name {
				continue
			}
			k.cfg.BootstrapIP, k.cfg.RootCAs, k.cfg.Timeout = loopback, pool, 5*time.Second
			f, err := newFanout(k.cfg, k.instances)
			if err != nil {
				t.Fatal(err)
			}
			for range f.us { // one query each so no handshake lands in the first window
				mustAnswer(t, f.us[int(f.next.Add(1))%len(f.us)], "warm.example.com")
			}
			for _, r := range rates {
				conns0 := k.conns.conns.Load()
				res := drive(f, k.cfg.Timeout, r, window)
				// Greppable, one line per run.
				fmt.Printf("LOAD kind=%s delay=%s target=%d sent=%d ok=%d err=%d dropped=%d throughput=%.0f/s p50=%s p99=%s handshakes=%d errs=%v\n",
					k.name, delay, res.target, res.sent, res.ok, res.errs, res.dropped,
					float64(res.ok)/window.Seconds(), res.p50.Round(10*time.Microsecond), res.p99.Round(10*time.Microsecond), k.conns.conns.Load()-conns0, res.errKinds)
				if res.errs > res.sent/2 {
					break // saturated; higher rates only add noise
				}
			}
			f.Close()
		}
	}
}

// errKind reduces an error to a short class so a run's error counts can be
// read: addresses and ports vary per query, so they are cut.
func errKind(err error, resp *dns.Msg) string {
	if err == nil {
		return fmt.Sprintf("bad reply (%d answers)", len(resp.Answer))
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, io.EOF):
		return "eof"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

type exchanger interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// fanout round-robins over several Upstreams built from one Config. It is the
// no-patch way past dnsproxy's two connections per DoH upstream: each instance
// has its own pair. The load test measures whether it helps.
type fanout struct {
	us   []*Upstream
	next atomic.Uint64
}

func newFanout(cfg Config, n int) (*fanout, error) {
	f := &fanout{}
	for i := 0; i < n; i++ {
		u, err := NewUpstream(cfg)
		if err != nil {
			return nil, err
		}
		f.us = append(f.us, u)
	}
	return f, nil
}

func (f *fanout) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return f.us[f.next.Add(1)%uint64(len(f.us))].Exchange(ctx, req)
}

func (f *fanout) Close() {
	for _, u := range f.us {
		_ = u.Close()
	}
}
