package querypath_test

// The seams of the Join that make the free path, taken apart from the real agent
// (p4n-MD-r1-1): a fake agent on the real socket hands the dns role the NodeConfig,
// an image and the facts, and a real Join answers free queries over Plain TCP. What
// each test shows fails when its seam is cut:
//
//   - Count: dropping Count from newFree leaves the free counters at zero;
//   - Refusal and the full mark of freeBackend.Exchange: without either, a free query
//     turned away by a full pool is SERVFAIL, not REFUSED (SC 5.2a point 7);
//   - syncFree: a NodeConfig change that does not swap the free Router and purge the
//     Free segment keeps answering from the old route.
//
// Linux only (the agent socket is a unix socket with chmod). Host ports 5380 to 5391, kept apart from the ranges other packages scan.

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/querypath"
	"github.com/Kup1ng/CtrlZ-Node/internal/resolve"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

type freeCountKey struct {
	proto   commonv1.Protocol
	outcome telemetryv1.FreeOutcome
	rcode   uint32
}

// joinLab is a Join behind a real dns role and a fake agent.
type joinLab struct {
	t      *testing.T
	srv    *sock.Server
	ports  listen.Ports
	mu     sync.Mutex
	counts map[freeCountKey]uint64
}

func (l *joinLab) counted(k freeCountKey) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[k]
}

// freeFacts is what the agent says while the free path is on at applied seq seq.
func freeFacts(seq uint64) *sock.Facts {
	return &sock.Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: true, FreeSet: true, FreeEnabled: true,
		FreeQPS: 100000, FreeVersion: 1, AppliedSeq: seq}
}

// startJoinLab starts the role with the query path joined. base is the first
// NodeConfig; free carries the free Unbound and the miss cap.
func startJoinLab(t *testing.T, firstPort int, localUnbound string, free querypath.FreeOptions, base *hubv1.NodeConfig) *joinLab {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the agent socket needs chmod on a unix socket, which is Linux")
	}
	root := t.TempDir()
	conf := filepath.Join(root, "agent.conf")
	_ = os.WriteFile(conf, []byte("hub=127.0.0.1\ndns_bind_ip=127.0.0.1\n"), 0o600)
	if err := os.MkdirAll(filepath.Join(root, store.DirConfig), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := nodecfg.New(filepath.Join(root, store.DirConfig), nil).Save(base); err != nil {
		t.Fatal(err)
	}
	// An image with no Endpoint: every Plain source is a stranger (identity case 3).
	imgDir := filepath.Join(root, store.DirImage)
	_ = os.MkdirAll(imgDir, 0o755)
	name, err := image.Build(&fsx.Writer{}, imgDir, image.Input{Seq: 1, Head: [32]byte{1}, Endpoints: map[[16]byte]*policyv1.EndpointRecord{},
		Claims: map[[16]byte]*policyv1.ClaimRecord{}, Degraded: map[[16]byte]bool{}, Profiles: map[[32]byte]bool{}, BlockPages: map[[32]byte]bool{}})
	if err != nil {
		t.Fatal(err)
	}

	l := &joinLab{t: t, counts: map[freeCountKey]uint64{}, ports: listen.Ports{DNS: uint16(firstPort), TLS: uint16(firstPort + 1), HTTPS: uint16(firstPort + 2)}}
	sockPath := filepath.Join(t.TempDir(), "a.sock")
	l.srv, err = sock.Listen(sock.ServerConfig{Path: sockPath, Check: func(net.Conn) error { return nil }, H: sock.Handlers{
		FreeCounts: func(items []sock.FreeCount) {
			l.mu.Lock()
			defer l.mu.Unlock()
			for _, it := range items {
				l.counts[freeCountKey{commonv1.Protocol(it.Proto), telemetryv1.FreeOutcome(it.Outcome), it.Rcode}] += it.Count
			}
		},
	}})
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go l.srv.Serve(ctx)
	l.publishConfig(base)
	_ = l.srv.Publish(&sock.Msg{Type: sock.TypeImage, Image: &sock.Image{Name: name}})
	_ = l.srv.Publish(&sock.Msg{Type: sock.TypeFacts, Facts: freeFacts(1)})

	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- dnsrole.Run(ctx, dnsrole.Config{Root: root, AgentConf: conf, SockPath: sockPath, Ports: l.ports,
			Build:   querypath.Factory(querypath.Options{LocalUnbound: netip.MustParseAddrPort(localUnbound), IntervalUnit: 200 * time.Millisecond, Free: free}),
			OnReady: func(*listen.Server) { close(ready) }})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("dnsrole.Run: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("the dns role did not come up")
	}
	t.Cleanup(func() { cancel(); <-done; l.srv.Close() })
	return l
}

func (l *joinLab) publishConfig(c *hubv1.NodeConfig) {
	l.t.Helper()
	b, err := proto.Marshal(c)
	if err != nil {
		l.t.Fatal(err)
	}
	_ = l.srv.Publish(&sock.Msg{Type: sock.TypeConfig, Config: &sock.Config{NodeConfig: b}})
}

// ask is a free query over Plain TCP from the source 127.0.0.9, which no claim and no
// node address covers.
func (l *joinLab) ask(name string, rd bool) (*dns.Msg, error) {
	d := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.9")}}
	cn, err := d.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(l.ports.DNS))))
	if err != nil {
		return nil, err
	}
	defer cn.Close()
	m := q(name, dns.TypeA)
	m.RecursionDesired = rd
	return framedAsk(cn, m)
}

// upstreamPair is one upstream that answers over UDP (the identified path and the
// health checks) and over TCP (the free pool dials TCP for a udp row). dark makes
// the TCP side read every query and answer none.
type upstreamPair struct {
	addr   string
	frames atomic.Int64 // queries the dark TCP side read
}

func startUpstreamPair(t *testing.T, ip string, dark bool) *upstreamPair {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.5:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &upstreamPair{addr: ln.Addr().String()}
	_, port := splitHostPort(t, p.addr)
	newFakeUnbound(t, "127.0.0.5", port, ip) // the UDP side, shut down by its cleanup
	if !dark {
		started := make(chan struct{})
		srv := &dns.Server{Listener: ln, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(ip).To4()})
			_ = w.WriteMsg(m)
		})}
		go func() { _ = srv.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = srv.Shutdown() })
		return p
	}
	var conns sync.Map
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(c, struct{}{})
			go func() {
				var lb [2]byte
				for {
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(lb[:]))); err != nil {
						return
					}
					p.frames.Add(1)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		conns.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
	})
	return p
}

func upstreamRow(id byte, addr string, timeoutMs uint32) *hubv1.Upstream {
	return &hubv1.Upstream{Id: []byte(strings.Repeat(string(rune(id)), 16)), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: addr, TimeoutMs: timeoutMs, HealthIntervalS: 30}
}

func labConfig(t *testing.T, version uint64, mode commonv1.ResolveMode, ups ...*hubv1.Upstream) *hubv1.NodeConfig {
	return nodeConfig(version, storetest.RandomSecret(t, 32), mode, ups...)
}

// The Count seam: a free query through the Join reaches the sink with its protocol,
// outcome and rcode, and the agent receives it.
func TestFreeJoinCountsEveryOutcome(t *testing.T) {
	local := newFakeUnbound(t, "127.0.0.1", 0, ipV1)
	free := newFakeUnbound(t, "127.0.0.1", 0, ipFree)
	l := startJoinLab(t, 5380, local.addr, querypath.FreeOptions{Unbound: netip.MustParseAddrPort(free.addr)}, labConfig(t, 1, commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE))

	eventually(t, 30*time.Second, "a free answer", func() bool {
		r, err := l.ask("count-one.example.net", true)
		return err == nil && hasA(r, ipFree)
	})
	if r, err := l.ask("count-two.example.net", false); err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("rd0: %v %v", r, err)
	}
	eventually(t, 10*time.Second, "the free counts at the agent", func() bool {
		return l.counted(freeCountKey{commonv1.Protocol_PROTOCOL_TCP, telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, 0}) >= 1 &&
			l.counted(freeCountKey{commonv1.Protocol_PROTOCOL_TCP, telemetryv1.FreeOutcome_FREE_OUTCOME_RD0, uint32(dns.RcodeRefused)}) >= 1
	})
	// The free Unbound answered, never the identified one.
	if local.asked("count-one.example.net") != 0 {
		t.Fatal("a free query reached the identified Unbound")
	}

	// The facts say the free path is off: REFUSED, counted as off.
	off := freeFacts(1)
	off.FreeEnabled = false
	_ = l.srv.Publish(&sock.Msg{Type: sock.TypeFacts, Facts: off})
	eventually(t, 10*time.Second, "REFUSED and counted off", func() bool {
		r, err := l.ask("count-three.example.net", true)
		return err == nil && r.Rcode == dns.RcodeRefused &&
			l.counted(freeCountKey{commonv1.Protocol_PROTOCOL_TCP, telemetryv1.FreeOutcome_FREE_OUTCOME_OFF, uint32(dns.RcodeRefused)}) >= 1
	})
}

// p4n-MD-r1-4 at the join: the agent's facts say applied seq 2 while dns serves the
// image of seq 1 (the swap or the open failed), and the free path stays REFUSED,
// counted as not caught up, instead of answering a tenant's device as a stranger.
func TestFreeJoinWaitsForTheImageOfTheAppliedSeq(t *testing.T) {
	local := newFakeUnbound(t, "127.0.0.1", 0, ipV1)
	free := newFakeUnbound(t, "127.0.0.1", 0, ipFree)
	l := startJoinLab(t, 5383, local.addr, querypath.FreeOptions{Unbound: netip.MustParseAddrPort(free.addr)}, labConfig(t, 1, commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE))
	eventually(t, 30*time.Second, "a free answer at seq 1", func() bool {
		r, err := l.ask("seq-one.example.net", true)
		return err == nil && hasA(r, ipFree)
	})
	_ = l.srv.Publish(&sock.Msg{Type: sock.TypeFacts, Facts: freeFacts(2)})
	notCaught := freeCountKey{commonv1.Protocol_PROTOCOL_TCP, telemetryv1.FreeOutcome_FREE_OUTCOME_NOT_CAUGHT_UP, uint32(dns.RcodeRefused)}
	eventually(t, 10*time.Second, "REFUSED while the image is behind", func() bool {
		r, err := l.ask("seq-two.example.net", true)
		return err == nil && r.Rcode == dns.RcodeRefused && l.counted(notCaught) >= 1
	})
	if free.asked("seq-two.example.net") != 0 {
		t.Fatal("a free query was looked up while dns served an image behind the applied seq")
	}
}

// The swap and purge seam: a NodeConfig that changes the resolve part swaps the free
// Router and purges the Free segment, so a name answered before is answered again by
// the new route; a config whose only upstream points at this node leaves the free
// path with no Router (the looping upstream is left out), and the segment is purged
// again.
// the new route; an upstream-only config with no upstream leaves no free path.
func TestFreeJoinSwapsItsRouterAndPurgesOnAConfigChange(t *testing.T) {
	local := newFakeUnbound(t, "127.0.0.1", 0, ipV1)
	free := newFakeUnbound(t, "127.0.0.1", 0, ipFree)
	l := startJoinLab(t, 5386, local.addr, querypath.FreeOptions{Unbound: netip.MustParseAddrPort(free.addr)}, labConfig(t, 1, commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE))

	const name = "swap.example.net"
	eventually(t, 30*time.Second, "the free answer of the recursive route", func() bool {
		r, err := l.ask(name, true)
		return err == nil && hasA(r, ipFree)
	})
	asked := free.asked(name)
	if r, err := l.ask(name, true); err != nil || !hasA(r, ipFree) || free.asked(name) != asked {
		t.Fatalf("a second ask must be a cache hit: %v %v (asked %d)", r, err, free.asked(name))
	}

	// 1. Upstream mode with one upstream: the free pool goes there over TCP, and the
	// name cached from the old route is not served again.
	up := startUpstreamPair(t, ipV2, false)
	l.publishConfig(labConfig(t, 2, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, upstreamRow('U', up.addr, 2000)))
	eventually(t, 30*time.Second, "the same name from the upstream (swapped and purged)", func() bool {
		r, err := l.ask(name, true)
		return err == nil && hasA(r, ipV2)
	})
	if free.asked(name) != asked {
		t.Fatal("the old free Unbound was asked again after the swap")
	}

	// 2. The only upstream points at this node (its own bind address), so it is left
	// out and no Router is built: nothing is answered from the old route or the old
	// cache.
	l.publishConfig(labConfig(t, 3, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, upstreamRow('L', "127.0.0.1:5353", 2000)))
	eventually(t, 30*time.Second, "no answer once no route is left", func() bool {
		r, err := l.ask(name, true)
		return err == nil && !hasA(r, ipV2) && !hasA(r, ipFree)
	})
}

// The full-pool seam (SC 5.2a point 7): when every free connection of the upstream is
// at its in-flight limit, a miss that finds no answer is REFUSED and counted
// over_miss_cap, not SERVFAIL. The upstream reads every query and answers none, so
// the pool of one udp row (4 connections of 64 streams) fills with 256 misses.
func TestFreeJoinRefusesWhenTheUpstreamPoolIsFull(t *testing.T) {
	local := newFakeUnbound(t, "127.0.0.1", 0, ipV1)
	free := newFakeUnbound(t, "127.0.0.1", 0, ipFree)
	up := startUpstreamPair(t, ipV2, true)
	cfg := labConfig(t, 1, commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, upstreamRow('D', up.addr, 20000))
	l := startJoinLab(t, 5389, local.addr, querypath.FreeOptions{Unbound: netip.MustParseAddrPort(free.addr), MissCap: 10000}, cfg)

	const fill = resolve.FreeTCPConns * resolve.FreeStreamCap
	var wg sync.WaitGroup
	for i := 0; i < fill; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = l.ask("fill"+strconv.Itoa(i)+".example.net", true) // waits for the upstream, which never answers
		}(i)
	}
	t.Cleanup(wg.Wait)
	eventually(t, 30*time.Second, "every connection full", func() bool { return up.frames.Load() >= fill })

	r, err := l.ask("one-too-many.example.net", true)
	if err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("a full pool answered %v %v, want REFUSED", r, err)
	}
	eventually(t, 10*time.Second, "the refusal counted over_miss_cap", func() bool {
		return l.counted(freeCountKey{commonv1.Protocol_PROTOCOL_TCP, telemetryv1.FreeOutcome_FREE_OUTCOME_OVER_MISS_CAP, uint32(dns.RcodeRefused)}) >= 1
	})
}
