package resolve

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
)

// doqFake is a DoQ server whose answer to a name a test chooses: handle returns the
// reply, or nil to never answer that stream.
type doqFake struct {
	port  int
	conns atomic.Int64
}

func startDoQFake(t *testing.T, handle func(*dns.Msg) *dns.Msg) (*doqFake, *tls.Config) {
	t.Helper()
	cert, roots := testCert(t)
	ln, port := freeListen(t, func(a string) (*quic.Listener, error) {
		return quic.ListenAddr(a, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13},
			&quic.Config{MaxIdleTimeout: 30 * time.Second})
	})
	f := &doqFake{port: port}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			f.conns.Add(1)
			go func() {
				for {
					st, err := c.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						var l [2]byte
						if _, err := io.ReadFull(st, l[:]); err != nil {
							return
						}
						buf := make([]byte, binary.BigEndian.Uint16(l[:]))
						if _, err := io.ReadFull(st, buf); err != nil {
							return
						}
						req := new(dns.Msg)
						if req.Unpack(buf) != nil {
							return
						}
						resp := handle(req)
						if resp == nil {
							<-ctx.Done()
							return
						}
						out, _ := resp.Pack()
						_, _ = st.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
						_ = st.Close()
					}()
				}
			}()
		}
	}()
	return f, &tls.Config{RootCAs: roots}
}

func newDoQPool(t *testing.T, f *doqFake, roots *tls.Config, timeout time.Duration) *FreePool {
	t.Helper()
	p, err := NewFreePool(Config{Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOQ, Address: fmt.Sprintf("%s:%d", testHost, f.port),
		BootstrapIP: netip.MustParseAddr("127.0.0.1"), RootCAs: roots.RootCAs, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// p4n-W9-r1-1 and p4n-W9-r1-5: a name whose upstream never answers costs only its
// own query. The names that follow it are answered, on the same connection, and no
// connection is dialled for any of them.
func TestFreePoolDoQTimeoutOfOneNameDoesNotHoldBackOthers(t *testing.T) {
	f, roots := startDoQFake(t, func(req *dns.Msg) *dns.Msg {
		if req.Question[0].Name == "slow.example.com." {
			return nil
		}
		return answerA(req)
	})
	p := newDoQPool(t, f, roots, 1500*time.Millisecond) // the first query pays for the handshake too
	// Warm both slots with a long timeout of their own (p4n-W9-r2-2): the first TLS and
	// QUIC handshake of a fresh test process can take seconds on a loaded machine,
	// and that is no part of what this test checks. The 1.5 s timeout comes back
	// before the slow names start.
	warm := func(d time.Duration) {
		p.timeout = d
		for _, s := range p.slots {
			s.(*doqSlot).timeout = d
		}
	}
	warm(30 * time.Second)
	for i := 0; i < 8; i++ {
		if _, err := p.Exchange(context.Background(), qn(i)); err != nil {
			t.Fatalf("warm-up %d: %v", i, err)
		}
	}
	for _, s := range p.slots {
		ds := s.(*doqSlot)
		ds.mu.Lock()
		connected := ds.conn != nil
		ds.mu.Unlock()
		if !connected {
			t.Fatal("a slot is still cold after the warm-up")
		}
	}
	warm(1500 * time.Millisecond)
	dialled := f.conns.Load()

	// Names that time out, over and over, in between the queries of everyone else.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = p.Exchange(context.Background(), query("slow.example.com"))
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 30; i++ {
		resp, err := p.Exchange(context.Background(), qn(100+i))
		if err != nil || len(resp.Answer) != 1 {
			t.Fatalf("query %d beside the slow names: %v %v", i, resp, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if c := f.conns.Load(); c != dialled {
		t.Fatalf("%d connections after the slow names, %d before: a timeout closed or redialled a connection", c, dialled)
	}
}

// A connection that is really gone is replaced, and no oftener than the redial
// rate.
func TestFreePoolDoQRedialsOnlyAtTheRedialRate(t *testing.T) {
	f, roots := startDoQFake(t, func(req *dns.Msg) *dns.Msg { return answerA(req) })
	p := newDoQPool(t, f, roots, 2*time.Second)
	for i := 0; i < 8; i++ {
		if _, err := p.Exchange(context.Background(), qn(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Close every connection of the pool from our side, as a server restart would.
	for _, s := range p.slots {
		ds := s.(*doqSlot)
		ds.mu.Lock()
		if ds.conn != nil {
			_ = ds.conn.CloseWithError(0, "")
		}
		ds.mu.Unlock()
	}
	before := f.conns.Load()
	started := time.Now()
	ok := 0
	for i := 0; i < 200; i++ {
		if _, err := p.Exchange(context.Background(), qn(i)); err == nil {
			ok++
		}
		time.Sleep(time.Millisecond)
	}
	dials := f.conns.Load() - before
	bound := int64(FreeTLSConns) * (1 + int64(FreeRedialRate*(time.Since(started).Seconds()+1)))
	if dials < 1 || dials > bound {
		t.Fatalf("%d dials after the connections were gone, bound %d", dials, bound)
	}
	if ok == 0 {
		t.Fatal("no query was answered after the redial")
	}
}

// A dead upstream gets no more than one dial per slot per gap, whatever the number
// of queries that find it dead.
func TestFreePoolDoQDeadUpstreamIsDialledAtTheRedialRate(t *testing.T) {
	f, roots := startDoQFake(t, func(req *dns.Msg) *dns.Msg { return answerA(req) })
	p := newDoQPool(t, f, roots, 50*time.Millisecond)
	for _, s := range p.slots {
		s.(*doqSlot).addr = fmt.Sprintf("127.0.0.1:%d", f.port+1000) // nobody listens there
	}
	var dials atomic.Int64
	for _, s := range p.slots {
		ds := s.(*doqSlot)
		ds.dialHook = func() { dials.Add(1) }
	}
	started := time.Now()
	for i := 0; i < 60; i++ {
		if _, err := p.Exchange(context.Background(), qn(i)); err == nil {
			t.Fatal("answered by a dead upstream")
		}
		time.Sleep(time.Millisecond)
	}
	bound := int64(FreeTLSConns) * (1 + int64(FreeRedialRate*(time.Since(started).Seconds()+1)))
	if d := dials.Load(); d < 1 || d > bound {
		t.Fatalf("%d dials of a dead upstream by 60 queries, bound %d", d, bound)
	}
}
