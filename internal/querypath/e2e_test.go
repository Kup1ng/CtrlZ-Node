package querypath_test

// End to end, merge B: a real agent against the in-process fake hub, a real dns
// role on loopback with the query path joined (querypath.Factory), and real clients
// for every transport. Nothing here fakes a step of the node: the hub's entries
// become a serving image through the agent's Applier, the image, the NodeConfig,
// the zone certificate, the revocations and the table reach dns over the agent
// socket, and a query is answered by the real path. The only stand-ins are the
// hub (shared proto, as the plan says) and the identified Unbound (a loopback UDP
// server that gives a fixed address).
//
// Linux only (the agent swaps the image by renaming a symlink); the container run
// of the plan covers it. Host ports 5300 to 5349.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/fakehub"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/zonekeys"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/querypath"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const (
	zoneName = "dns.example.net"
	// The proxy address differs from the DNS address (8.8.8.8) so that an answer carrying the
	// node's proxy address (Block) cannot be taken for one carrying its DNS address.
	proxyIPText = "8.8.4.4"
)

func rid(c byte) string { return strings.Repeat(string(rune('a'+c)), 26) }
func tok(c byte) string { return strings.Repeat(string(rune('a'+c)), 32) }

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- the identified Unbound's stand-in

type fakeUnbound struct {
	srv   *dns.Server
	addr  string
	ip    atomic.Value // string
	count atomic.Int64
	mu    sync.Mutex
	named map[string]int // queries by lower-case name: the health probes of the router also arrive here
}

func newFakeUnbound(t *testing.T, host string, port int, ip string) *fakeUnbound {
	t.Helper()
	pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUnbound{addr: pc.LocalAddr().String(), named: map[string]int{}}
	f.ip.Store(ip)
	started := make(chan struct{})
	f.srv = &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		f.count.Add(1)
		if len(r.Question) == 1 {
			f.mu.Lock()
			f.named[strings.ToLower(r.Question[0].Name)]++
			f.mu.Unlock()
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A: net.ParseIP(f.ip.Load().(string)).To4()})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = f.srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = f.srv.Shutdown() })
	return f
}

// asked is how many queries for name reached the stand-in.
func (f *fakeUnbound) asked(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.named[strings.ToLower(dns.Fqdn(name))]
}

// ---- the node under test

type node struct {
	t       *testing.T
	dir     string
	hub     *fakehub.Hub
	keys    *storetest.Keys
	chain   storetest.Chain
	runner  *fake.Runner
	files   *fake.Files
	alerts  *alert.Memory
	cfg     agent.Config
	ag      *agent.Agent
	cancel  context.CancelFunc
	done    chan struct{}
	nodeKey *ecdsa.PrivateKey
	pool    *x509.CertPool
	units   fake.Units

	dnsCancel context.CancelFunc
	dnsDone   chan struct{}
	ports     listen.Ports
	join      *querypath.Join

	// W8: the node's clock, which a test moves; the slot of the node in
	// storetest.Table; and where its listeners bind.
	clock    *testClock
	idx      int
	portBase int
}

func newNode(t *testing.T) *node { return newNodeAt(t, 0) }

// newNodeAt is the node of table slot idx (0 to 3): its certificate names that node of
// storetest.Table, so the agent knows which node of the pair it is.
func newNodeAt(t *testing.T, idx int) *node {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the image swap is a symlink rename, which is Linux")
	}
	n := &node{t: t, dir: t.TempDir(), hub: fakehub.New(), keys: storetest.NewKeys(t), runner: &fake.Runner{}, alerts: &alert.Memory{},
		clock: &testClock{}, idx: idx, portBase: 5320}
	n.files = fake.NewFiles(map[string]string{
		"/proc/sys/net/ipv4/ip_local_port_range":   "32768 39999\n",
		"/proc/self/limits":                        "Max core file size 0 0 bytes\n",
		"/proc/sys/kernel/core_pattern":            "|/lib/systemd/systemd-coredump %P\n",
		"/etc/systemd/coredump.conf.d/ctrlz.conf":  "[Coredump]\nStorage=none\nProcessSizeMax=0\n",
		"/proc/sys/net/netfilter/nf_conntrack_max": "999999\n",
		"/etc/resolv.conf":                         "nameserver 9.9.9.9\n",
	})
	n.runner.Reply = func(c fake.Call) ([]byte, error) {
		if out, err, ok := n.units.Handle(c); ok {
			return out, err
		}
		if c.Name == "unbound" {
			return []byte("Version 1.20.0\n"), nil
		}
		return nil, nil
	}
	n.hub.Start()
	t.Cleanup(n.hub.Stop)

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cder, _ := x509.CreateCertificate(rand.Reader, ctmpl, ctmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(cder)
	n.nodeKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ntmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hex.EncodeToString(storetest.NodeID(idx))}, NotBefore: time.Now().Add(-3 * time.Hour),
		NotAfter: time.Now().Add(10 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	nder, _ := x509.CreateCertificate(rand.Reader, ntmpl, ca, &n.nodeKey.PublicKey, caKey)
	kder, _ := x509.MarshalPKCS8PrivateKey(n.nodeKey)
	id, err := hubconn.NewIdentity(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nder}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder}), [32]byte{1}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(n.dir, "agent.conf")
	if err := os.WriteFile(confPath, []byte("hub=127.0.0.1\ndns_bind_ip=127.0.0.1\ndns_advertised_ip=8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.cfg = agent.Config{
		Root: filepath.Join(n.dir, "ctrlz"), ConfPath: confPath,
		Conf:     conf.Agent{Hub: "127.0.0.1", DNSBindIP: netip.MustParseAddr("127.0.0.1"), DNSAdvertisedIP: netip.MustParseAddr("8.8.8.8")},
		SockPath: filepath.Join(t.TempDir(), "a.sock"), PeerCheck: func(net.Conn) error { return nil }, Version: "vtest",
		Identity: id, Now: n.clock.Now,
		Dial:      func(hubconn.Role) (*grpc.ClientConn, error) { return n.hub.Dial() },
		TrustRoot: func() (*signv1.Root, error) { return n.keys.Root, nil },
		Runner:    n.runner, Files: n.files, Alert: n.alerts,
		NoSystem: true, SkipHostChecks: true,
		HeartbeatEvery: 100 * time.Millisecond, ServerTimeTimeout: time.Hour, TableEvery: 50 * time.Millisecond,
		CountersPoll: 20 * time.Millisecond, ActivityEvery: 200 * time.Millisecond, TransferIdle: 20 * time.Second,
		RetryEvery: time.Hour, LogPoll: time.Hour, ProbeEvery: time.Hour,
	}
	return n
}

func (n *node) startAgent() {
	n.t.Helper()
	ag, err := agent.New(n.cfg)
	if err != nil {
		n.t.Fatal(err)
	}
	n.ag = ag
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel, n.done = cancel, make(chan struct{})
	go func() {
		defer close(n.done)
		if err := ag.Run(ctx); err != nil {
			n.t.Errorf("agent.Run: %v", err)
		}
	}()
	n.t.Cleanup(n.stopAgent)
}

func (n *node) stopAgent() {
	if n.cancel != nil {
		n.cancel()
		<-n.done
		n.cancel = nil
	}
}

func (n *node) startDNS(local string) { n.startDNSWith(local, nil) }

// startDNSWith starts dns with the config a test adjusts (W8: the drain times, an observer).
func (n *node) startDNSWith(local string, adjust func(*dnsrole.Config)) {
	n.t.Helper()
	n.ports = allocPortsAt(n.t, n.portBase)
	ctx, cancel := context.WithCancel(context.Background())
	n.dnsCancel, n.dnsDone = cancel, make(chan struct{})
	ready := make(chan struct{})
	ap := netip.MustParseAddrPort(local)
	go func() {
		defer close(n.dnsDone)
		dc := dnsrole.Config{
			Root: n.cfg.Root, AgentConf: n.cfg.ConfPath, SockPath: n.cfg.SockPath, Ports: n.ports,
			Build:   querypath.Factory(querypath.Options{LocalUnbound: ap, IntervalUnit: 200 * time.Millisecond, OnBuilt: func(j *querypath.Join) { n.join = j }}),
			OnReady: func(*listen.Server) { close(ready) },
		}
		if adjust != nil {
			adjust(&dc)
		}
		if err := dnsrole.Run(ctx, dc); err != nil {
			n.t.Errorf("dnsrole.Run: %v", err)
		}
	}()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		n.t.Fatal("the dns role did not come up")
	}
	n.t.Cleanup(func() { cancel(); <-n.dnsDone })
}

var e2ePort atomic.Int32

func allocPorts(t testing.TB) listen.Ports { return allocPortsAt(t, 5320) }

func allocPortsAt(t testing.TB, first int) listen.Ports {
	t.Helper()
	for try := 0; try < 32; try++ {
		base := first + (int(e2ePort.Add(1)-1)%8)*3
		ok := true
		var cl []io.Closer
		for p := base; p < base+3 && ok; p++ {
			ap := fmt.Sprintf("127.0.0.1:%d", p)
			if l, err := net.Listen("tcp", ap); err != nil {
				ok = false
			} else {
				cl = append(cl, l)
			}
			if u, err := net.ListenPacket("udp", ap); err != nil {
				ok = false
			} else {
				cl = append(cl, u)
			}
		}
		for _, c := range cl {
			_ = c.Close()
		}
		if ok {
			return listen.Ports{DNS: uint16(base), TLS: uint16(base + 1), HTTPS: uint16(base + 2)}
		}
	}
	t.Fatal("no free ports in 5320-5349")
	return listen.Ports{}
}

// ---- what the hub sends

func serverTime() *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: time.Now().Unix()}}}
}

func headNotice(seq uint64) *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_HeadNotice{HeadNotice: &hubv1.HeadNotice{Seq: seq, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY}}}
}

func nodeConfig(version uint64, key []byte, mode commonv1.ResolveMode, ups ...*hubv1.Upstream) *hubv1.NodeConfig {
	return &hubv1.NodeConfig{
		Version: version, DnsBindIp: []byte{127, 0, 0, 1}, DnsAdvertisedIp: []byte{8, 8, 8, 8}, ProxyBindIp: []byte{127, 0, 0, 1}, ProxyAdvertisedIp: []byte{8, 8, 4, 4},
		Zones: []string{zoneName}, PanelHostnames: []string{"panel.example.net"}, Mode: mode, ProofKey: key, Upstreams: ups,
	}
}

func nodeConfigMsg(c *hubv1.NodeConfig) *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: c}}
}

// certBundleMsg is the CertBundle of the zone, sealed to the node's key, and the
// pool that trusts its chain.
func (n *node) certBundleMsg() *hubv1.HubMessage {
	n.t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "zone ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cder, err := x509.CreateCertificate(rand.Reader, ctmpl, ctmpl, &caKey.PublicKey, caKey)
	if err != nil {
		n.t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(cder)
	n.pool = x509.NewCertPool()
	n.pool.AddCert(ca)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notAfter := time.Now().Add(2 * time.Hour)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: zoneName},
		DNSNames:  []string{zoneName, "*." + zoneName, "*.verify." + zoneName},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &lk.PublicKey, caKey)
	if err != nil {
		n.t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(lk)
	wrapped, err := zonekeys.Seal(&n.nodeKey.PublicKey, kder)
	if err != nil {
		n.t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder})...)
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_CertBundle{CertBundle: &hubv1.CertBundle{
		Kind: signv1.Kind_KIND_CERTS, WrappedKey: wrapped, ChainPem: chain, NotAfter: notAfter.Unix()}}}
}

func (n *node) keyFiles() int {
	ents, _ := os.ReadDir(filepath.Join(n.cfg.Root, "keys"))
	c := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "zone-") {
			c++
		}
	}
	return c
}

// ---- entries

func profile(t *testing.T, tokens ...string) ([]byte, [32]byte) {
	t.Helper()
	// Branded blocks answer with the node's proxy address (SC 7), which is what shows
	// that the Handler was given the node's own addresses.
	spec := &blob.Spec{Default: blob.ActBypass, Options: blob.Options{Present: blob.OptBlockResponse, BlockResponse: blob.BlockBranded}}
	for i, tk := range tokens {
		p, err := rules.Parse(tk)
		if err != nil {
			t.Fatal(err)
		}
		spec.Rules = append(spec.Rules, blob.RuleSpec{ID: [16]byte{byte(i + 1)}, Pattern: p, Action: blob.ActBlock})
	}
	d, err := blob.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	return d, storetest.Hash(d)
}

// endpoint is an Endpoint record with its real rid hash and token hash, and a
// Plain DNS claim for 127.0.0.<id>.
func endpoint(id byte, h [32]byte) (*policyv1.EndpointRecord, *policyv1.ClaimRecord) {
	rh := identity.RIDHash(rid(id))
	th := identity.TokenHash(tok(id))
	ep := &policyv1.EndpointRecord{
		EndpointId: bytes.Repeat([]byte{id}, 16), RidHash: rh[:], DohTokenHash: th[:],
		PairId: bytes.Repeat([]byte{0xb0}, 16), AdminState: commonv1.AdminState_ADMIN_STATE_ENABLED,
		LegacyDns: true, AnalyticsLevel: commonv1.AnalyticsLevel_ANALYTICS_LEVEL_SOME, ClientCap: 4,
		Base: &policyv1.StackRecord{Profile1Hash: h[:]},
	}
	cl := &policyv1.ClaimRecord{
		ClaimId: bytes.Repeat([]byte{id + 0x40}, 16), EndpointId: ep.EndpointId,
		Prefix: &commonv1.Prefix{Addr: []byte{127, 0, 0, id}, Bits: 32},
	}
	return ep, cl
}

func (n *node) addEntry(blobs [][]byte, ent *policyv1.ConfigEntry) uint64 {
	n.t.Helper()
	for _, b := range blobs {
		n.hub.SetBlob(storetest.Hash(b), b)
		ent.PutBlobs = append(ent.PutBlobs, storetest.Ref(b))
	}
	stored := n.chain.Next(n.t, ent)
	n.hub.Script(func(h *fakehub.Hub) {
		h.Entries = append(h.Entries, &hubv1.StoredEntry{Seq: n.chain.Seq, EntryHash: n.chain.Head[:], EntryBytes: stored})
	})
	head := n.keys.SignPayload("ctrlz/head", mustMarshal(n.t, &signv1.SignedHead{Seq: n.chain.Seq, EntryHash: n.chain.Head[:], CreatedAt: time.Now().Unix()}))
	n.hub.Script(func(h *fakehub.Hub) { h.Head = head })
	return n.chain.Seq
}

// ---- clients

type clients struct {
	n    *node
	zone string
}

func (c *clients) tlsConf(sni string, alpn ...string) *tls.Config {
	return &tls.Config{RootCAs: c.n.pool, ServerName: sni, NextProtos: alpn, MinVersion: tls.VersionTLS12}
}

func (c *clients) addr(t listen.Transport) string {
	p := c.n.ports.DNS
	switch t {
	case listen.DoT, listen.DoQ:
		p = c.n.ports.TLS
	case listen.DoH, listen.DoH3:
		p = c.n.ports.HTTPS
	}
	return fmt.Sprintf("127.0.0.1:%d", p)
}

func framedAsk(cn net.Conn, m *dns.Msg) (*dns.Msg, error) {
	b, err := m.Pack()
	if err != nil {
		return nil, err
	}
	_ = cn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := cn.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(cn, lb[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, int(lb[0])<<8|int(lb[1]))
	if _, err := io.ReadFull(cn, buf); err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	return r, r.Unpack(buf)
}

func q(name string, qt uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.RecursionDesired = true
	return m
}

func (c *clients) udp(src string, m *dns.Msg) (*dns.Msg, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if src != "" {
		d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(src)}
	}
	cn, err := d.Dial("udp", c.addr(listen.UDP))
	if err != nil {
		return nil, err
	}
	defer cn.Close()
	b, _ := m.Pack()
	_, _ = cn.Write(b)
	_ = cn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	k, err := cn.Read(buf)
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	return r, r.Unpack(buf[:k])
}

// udpCookie validates the source with a server cookie, as a Plain DNS client does.
func (c *clients) udpCookie(src string, m *dns.Msg) (*dns.Msg, error) {
	first := m.Copy()
	first.SetEdns0(1232, false)
	first.IsEdns0().Option = append(first.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
	r, err := c.udp(src, first)
	if err != nil {
		return nil, err
	}
	server := ""
	if opt := r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ck, ok := o.(*dns.EDNS0_COOKIE); ok {
				server = ck.Cookie
			}
		}
	}
	if server == "" {
		return nil, errors.New("no server cookie")
	}
	second := m.Copy()
	second.SetEdns0(1232, false)
	second.IsEdns0().Option = append(second.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: server})
	return c.udp(src, second)
}

func (c *clients) tcp(src string, m *dns.Msg) (*dns.Msg, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if src != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}
	cn, err := d.Dial("tcp", c.addr(listen.TCP))
	if err != nil {
		return nil, err
	}
	defer cn.Close()
	return framedAsk(cn, m)
}

func (c *clients) dot(sni string, m *dns.Msg) (*dns.Msg, error) {
	cn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", c.addr(listen.DoT), c.tlsConf(sni))
	if err != nil {
		return nil, err
	}
	defer cn.Close()
	return framedAsk(cn, m)
}

func (c *clients) doq(sni string, m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, c.addr(listen.DoQ), c.tlsConf(sni, "doq"), &quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	m = m.Copy()
	m.Id = 0
	b, _ := m.Pack()
	_ = str.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := str.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
		return nil, err
	}
	_ = str.Close()
	all, err := io.ReadAll(str)
	if err != nil || len(all) < 2 {
		return nil, fmt.Errorf("doq: %v", err)
	}
	r := new(dns.Msg)
	return r, r.Unpack(all[2:])
}

// doh returns the HTTP status and the reply (nil unless 200).
func (c *clients) doh(t listen.Transport, h2 bool, sni, path, authority string, m *dns.Msg) (int, *dns.Msg, error) {
	var cl *http.Client
	if t == listen.DoH3 {
		tr := &http3.Transport{TLSClientConfig: c.tlsConf(sni, "h3"), QUICConfig: &quic.Config{}}
		defer tr.Close()
		cl = &http.Client{Transport: tr, Timeout: 8 * time.Second}
	} else {
		tr := &http.Transport{DisableKeepAlives: true}
		if h2 {
			tr.TLSClientConfig, tr.ForceAttemptHTTP2 = c.tlsConf(sni, "h2", "http/1.1"), true
		} else {
			tr.TLSClientConfig = c.tlsConf(sni, "http/1.1")
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		defer tr.CloseIdleConnections()
		cl = &http.Client{Transport: tr, Timeout: 8 * time.Second}
	}
	b, _ := m.Pack()
	req, err := http.NewRequest("POST", "https://"+c.addr(t)+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Host = authority
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil, nil
	}
	r := new(dns.Msg)
	return resp.StatusCode, r, r.Unpack(body)
}

type asker struct {
	name string
	ask  func(c *clients, ep byte, m *dns.Msg) (*dns.Msg, error)
}

func askers() []asker {
	h := func(t listen.Transport, h2 bool, formB bool) func(c *clients, ep byte, m *dns.Msg) (*dns.Msg, error) {
		return func(c *clients, ep byte, m *dns.Msg) (*dns.Msg, error) {
			path, authority := "/"+tok(ep), rid(ep)+"."+zoneName
			if formB {
				path, authority = "/"+rid(ep)+"/"+tok(ep), zoneName
			}
			st, r, err := c.doh(t, h2, "x."+zoneName, path, authority, m)
			if err == nil && st != 200 {
				err = fmt.Errorf("http %d", st)
			}
			return r, err
		}
	}
	src := func(ep byte) string { return fmt.Sprintf("127.0.0.%d", ep) }
	return []asker{
		{"plain-tcp", func(c *clients, ep byte, m *dns.Msg) (*dns.Msg, error) { return c.tcp(src(ep), m) }},
		{"plain-udp", func(c *clients, ep byte, m *dns.Msg) (*dns.Msg, error) { return c.udpCookie(src(ep), m) }},
		{"dot", func(c *clients, ep byte, m *dns.Msg) (*dns.Msg, error) { return c.dot(rid(ep)+"."+zoneName, m) }},
		{"doq", func(c *clients, ep byte, m *dns.Msg) (*dns.Msg, error) { return c.doq(rid(ep)+"."+zoneName, m) }},
		{"doh-h2", h(listen.DoH, true, false)},
		{"doh-http1", h(listen.DoH, false, true)},
		{"doh3", h(listen.DoH3, true, false)},
	}
}

func hasA(r *dns.Msg, ip string) bool {
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == ip {
			return true
		}
	}
	return false
}

func lastHeartbeat(s *fakehub.Session) *hubv1.Heartbeat {
	msgs := s.Messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if hb := msgs[i].GetHeartbeat(); hb != nil && len(hb.Upstreams) > 0 {
			return hb
		}
	}
	return &hubv1.Heartbeat{}
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stop ends the stand-in, so the path to it is down; a new one on the same address
// brings it back.
func (f *fakeUnbound) stop() { _ = f.srv.Shutdown() }

func splitHostPort(t *testing.T, ap string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(ap)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return h, port
}
