package dnsrole

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func nodeConfig(t *testing.T, bind string, key []byte) *hubv1.NodeConfig {
	t.Helper()
	ip := net.ParseIP(bind).To4()
	return &hubv1.NodeConfig{Version: 1, DnsBindIp: ip, DnsAdvertisedIp: []byte{8, 8, 8, 8}, ProxyBindIp: ip, ProxyAdvertisedIp: []byte{8, 8, 8, 8},
		Zones: []string{"dns.example.net"}, PanelHostnames: []string{"panel.example.net"}, Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, ProofKey: key}
}

// buildImage makes an image with n Endpoints whose resolver ids are rid0, rid1, ...
func buildImage(t *testing.T, root string, seq uint64, n int) string {
	t.Helper()
	dir := filepath.Join(root, store.DirImage)
	_ = os.MkdirAll(dir, 0o755)
	in := image.Input{Seq: seq, Head: [32]byte{byte(seq)}, Endpoints: map[[16]byte]*policyv1.EndpointRecord{}, Claims: map[[16]byte]*policyv1.ClaimRecord{},
		Degraded: map[[16]byte]bool{}, Profiles: map[[32]byte]bool{}, BlockPages: map[[32]byte]bool{}}
	for i := 0; i < n; i++ {
		ep := storetest.Endpoint(byte(i+1), storetest.Blob(t, fmt.Sprintf("n%d.example.com", i)))
		rid := identity.RIDHash(rid(i))
		ep.RidHash = rid[:]
		in.Endpoints[[16]byte(ep.EndpointId)] = ep
		in.Degraded[[16]byte(ep.EndpointId)] = true
	}
	name, err := image.Build(&fsx.Writer{}, dir, in)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

// rid returns the i-th resolver id of buildImage (26 characters).
func rid(i int) string { return strings.Repeat("a", 25) + string(rune('a'+i)) }

func zoneKey(t *testing.T, sans ...string) *sock.ZoneKey {
	t.Helper()
	ca, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cder, _ := x509.CreateCertificate(rand.Reader, ctmpl, ctmpl, &ca.PublicKey, ca)
	cc, _ := x509.ParseCertificate(cder)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: sans[0]}, DNSNames: sans, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, cc, &k.PublicKey, ca)
	kder, _ := x509.MarshalPKCS8PrivateKey(k)
	return &sock.ZoneKey{SANs: sans, ChainPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: kder, NotAfter: time.Now().Add(time.Hour).Unix()}
}

func TestFreePathIsOffWhileTheLinkIsDown(t *testing.T) {
	e := newEnv()
	if e.FreeOK(0) {
		t.Fatal("free path on with no facts")
	}
	good := sock.Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: true, FreeSet: true, FreeEnabled: true, FreeQPS: 40, FreeVersion: 3}
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &good}, "", func(string) {}, nil)
	if e.FreeOK(0) {
		t.Fatal("facts without a link")
	}
	e.linkUp.Store(true)
	if !e.FreeOK(0) || e.FreeQPS() != 40 {
		t.Fatal("link up and facts good")
	}
	e.linkUp.Store(false)
	if e.FreeOK(0) {
		t.Fatal("a dns cut off from the agent must not serve on facts nothing refreshes")
	}
	// the image is kept while the link is down: nothing here clears it
	e.linkUp.Store(true)
	bad := good
	bad.OffFloor = 9
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &bad}, "", func(string) {}, nil)
	if e.FreeOK(0) {
		t.Fatal("the off floor is above the value in force")
	}
}

func TestTableInUseFromTheAgentsData(t *testing.T) {
	e := newEnv()
	pt := storetest.Table(3, 0)
	mem, _ := proto.Marshal(pt)
	self := storetest.NodeID(1)
	m := &sock.Table{Member: mem, Version: 77, InUse: true, PanelStale: true, Self: self,
		Flags: []sock.Flag{{Node: storetest.NodeID(0), Withdrawn: true}}, PeerDown: [][]byte{storetest.NodeID(2)}, DrainSince: 123}
	e.apply(&sock.Msg{Type: sock.TypeTable, Table: m}, "", nil, nil)
	st := e.Tables()
	if st.Table == nil || st.Table.Version != 77 || !st.Local.PanelStale || st.DrainSince != 123 {
		t.Fatalf("%+v", st)
	}
	var n0, n2 zone.NodeID
	copy(n0[:], storetest.NodeID(0))
	copy(n2[:], storetest.NodeID(2))
	if !st.Table.Nodes[n0].Withdrawn || !st.Local.PeerDown[n2] {
		t.Error("flags or peer view lost")
	}
	// the node's own address answers from the pair's fallback while the primary is withdrawn
	var pairID zone.PairID
	copy(pairID[:], pt.Pairs[0].PairId)
	if n, ok := zone.Target(st.Table, pairID, st.Local); !ok || n.ID == n0 {
		t.Errorf("target %v %v", n, ok)
	}
	// not in use: no table
	m2 := *m
	m2.InUse = false
	e.apply(&sock.Msg{Type: sock.TypeTable, Table: &m2}, "", nil, nil)
	if e.Tables().Table != nil {
		t.Error("a table that is not in use was handed to the query path")
	}
	// a member that does not parse keeps the table that was in use
	e.apply(&sock.Msg{Type: sock.TypeTable, Table: m}, "", nil, nil)
	bad := *m
	bad.Member = []byte("garbage that is not a PairTable \xff\xff\xff")
	e.apply(&sock.Msg{Type: sock.TypeTable, Table: &bad}, "", nil, nil)
	if e.Tables().Table == nil || e.Tables().Table.Version != 77 {
		t.Error("a table that did not build replaced the one in use")
	}
}

// R7 and SC 3.3: unrecognized_name only for a HostResolver SNI with an unknown
// RIDHash; every other name completes the handshake.
func TestCertificateProvider(t *testing.T) {
	root := t.TempDir()
	name := buildImage(t, root, 5, 2)
	e := newEnv()
	e.setConfig(mustMarshal(nodeConfig(t, "10.0.0.5", make([]byte, 16))))
	im, err := image.Open(filepath.Join(root, store.DirImage, name))
	if err != nil {
		t.Fatal(err)
	}
	e.image.Store(im)
	hello := func(sni string) *tls.ClientHelloInfo { return &tls.ClientHelloInfo{ServerName: sni} }
	if _, err := e.GetCertificate(hello("dns.example.net")); err != ErrNoCertificate {
		t.Fatalf("no key yet: %v", err)
	}
	k := zoneKey(t, "dns.example.net", "*.dns.example.net", "*.verify.dns.example.net")
	e.apply(&sock.Msg{Type: sock.TypeZoneKey, ZoneKey: k}, "", nil, nil)
	for _, sni := range []string{
		rid(0) + ".dns.example.net", rid(1) + "-laptop.dns.example.net", // known rid
		"dns.example.net", "ns1.dns.example.net", "x.verify.dns.example.net", // apex, reserved, verify
		"bad name.dns.example.net", "other.example.org", "", // malformed, out of zone, missing
	} {
		c, err := e.GetCertificate(hello(sni))
		if err != nil || c == nil {
			t.Errorf("%q: the handshake must complete (%v)", sni, err)
		}
	}
	for _, sni := range []string{rid(7) + ".dns.example.net", rid(9) + "-phone.dns.example.net", "RID" + ".dns.example.net"} {
		c, err := e.GetCertificate(hello(sni))
		host := identity.ParseHost(sni, e.Zones())
		if host.Kind == identity.HostResolver && (c != nil || err != nil) {
			t.Errorf("%q: an unknown rid must be (nil, nil) for unrecognized_name, got %v %v", sni, c, err)
		}
	}
	// no image: a resolver name is refused rather than answered from nothing
	e.image.Store(nil)
	if c, err := e.GetCertificate(hello(rid(0) + ".dns.example.net")); c != nil || err != nil {
		t.Error("a resolver name with no image")
	}
	// a replaced key for the same names replaces the old
	e.apply(&sock.Msg{Type: sock.TypeZoneKey, ZoneKey: zoneKey(t, "dns.example.net", "*.dns.example.net", "*.verify.dns.example.net")}, "", nil, nil)
	if n := len(*e.keys.Load()); n != 1 {
		t.Errorf("keys = %d", n)
	}
	if err := e.setZoneKey(&sock.ZoneKey{SANs: []string{"x"}, ChainPEM: []byte("junk"), Key: []byte("junk")}); err == nil {
		t.Error("a junk key was accepted")
	}
}

func mustMarshal(m proto.Message) []byte { b, _ := proto.Marshal(m); return b }

func freePorts(t *testing.T) (a, b, c int) {
	t.Helper()
	var got []int
	for p := 5640; p < 5699 && len(got) < 3; p++ {
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue
		}
		u, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(p))
		l.Close()
		if err != nil {
			continue
		}
		u.Close()
		got = append(got, p)
	}
	if len(got) < 3 {
		t.Skip("no free ports in the lane's range")
	}
	return got[0], got[1], got[2]
}

func ask(t *testing.T, port int, name string) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	c := &dns.Client{Timeout: 2 * time.Second}
	r, _, err := c.Exchange(q, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPlainOnlyFallbackAndTheRefusingHandler(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "agent.conf")
	_ = os.WriteFile(conf, []byte("hub=127.0.0.1\ndns_bind_ip=127.0.0.1\n"), 0o600)
	p1, _, _ := freePorts(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan *listen.Server, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Root: root, AgentConf: conf, SockPath: filepath.Join(root, "none.sock"),
			Ports: listen.Ports{DNS: uint16(p1), TLS: 1, HTTPS: 1}, OnReady: func(s *listen.Server) { ready <- s }})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("not ready")
	}
	r := ask(t, p1, "anything.example.com.")
	if r.Rcode != dns.RcodeRefused || len(r.Answer) != 0 {
		t.Fatalf("the unjoined node answered %v", r)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

// Run with a NodeConfig on disk and a fake agent on the socket: all six listeners
// start, the image and facts arrive from the socket, and dns reports back.
func TestRunWithTheAgentSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent socket needs chmod on a unix socket, which is Linux")
	}
	root := t.TempDir()
	conf := filepath.Join(root, "agent.conf")
	_ = os.WriteFile(conf, []byte("hub=127.0.0.1\ndns_bind_ip=127.0.0.1\n"), 0o600)
	if err := os.MkdirAll(filepath.Join(root, store.DirConfig), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := nodecfg.New(filepath.Join(root, store.DirConfig), nil).Save(nodeConfig(t, "127.0.0.1", storetest.RandomSecret(t, 32))); err != nil {
		t.Fatal(err)
	}
	name := buildImage(t, root, 3, 1)
	p1, p2, p3 := freePorts(t)

	sockPath := filepath.Join(t.TempDir(), "a.sock")
	got := make(chan *sock.Msg, 64)
	srv, err := sock.Listen(sock.ServerConfig{Path: sockPath, Check: func(net.Conn) error { return nil }, H: sock.Handlers{
		ImageAck: func(n string) { got <- &sock.Msg{Type: sock.TypeImageAck, ImageAck: &sock.ImageAck{Name: n}} },
		FreeCounts: func(i []sock.FreeCount) {
			got <- &sock.Msg{Type: sock.TypeFreeCounts, FreeCounts: &sock.FreeCounts{Items: i}}
		},
		Outbound: func(b []byte) { got <- &sock.Msg{Type: sock.TypeOutbound, Outbound: &sock.Outbound{NodeMessage: b}} },
	}})
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()
	realKey := storetest.RandomSecret(t, 32)
	_ = srv.Publish(&sock.Msg{Type: sock.TypeConfig, Config: &sock.Config{NodeConfig: mustMarshal(nodeConfig(t, "127.0.0.1", realKey))}})
	_ = srv.Publish(&sock.Msg{Type: sock.TypeImage, Image: &sock.Image{Name: name}})
	_ = srv.Publish(&sock.Msg{Type: sock.TypeFacts, Facts: &sock.Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: true, FreeSet: true, FreeEnabled: true, FreeQPS: 9, FreeVersion: 1}})

	var env *Env
	var sink *Sink
	ready := make(chan *listen.Server, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Root: root, AgentConf: conf, SockPath: sockPath, Ports: listen.Ports{DNS: uint16(p1), TLS: uint16(p2), HTTPS: uint16(p3)},
			Build: func(e *Env, s *Sink) (listen.Handler, listen.VerifyHandler, error) {
				env, sink = e, s
				return RefuseHandler(e, s)
			},
			OnReady: func(s *listen.Server) { ready <- s }})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("not ready")
	}
	eventually(t, "the image acknowledged", func() bool {
		select {
		case m := <-got:
			return m.Type == sock.TypeImageAck && m.ImageAck.Name == name
		default:
			return false
		}
	})
	eventually(t, "the free path on", func() bool { return env.FreeOK(0) })
	if c := env.Config(); c == nil || !bytesEqual(c.ProofKey, realKey) {
		t.Error("the real proof_key did not arrive from the agent")
	}
	if im := env.Image(); im == nil || im.Seq() != 3 {
		t.Error("image")
	}
	// the sink reports, best effort
	sink.FreeCount(commonv1.Protocol_PROTOCOL_UDP, telemetryv1.FreeOutcome_FREE_OUTCOME_RD0, 5)
	sink.FreeCount(commonv1.Protocol_PROTOCOL_UDP, telemetryv1.FreeOutcome_FREE_OUTCOME_RD0, 5)
	eventually(t, "free counts at the agent", func() bool {
		select {
		case m := <-got:
			return m.Type == sock.TypeFreeCounts && len(m.FreeCounts.Items) == 1 && m.FreeCounts.Items[0].Count == 2
		default:
			return false
		}
	})
	sink.Outbound(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_RevocationAck{RevocationAck: &hubv1.RevocationAck{RevSeq: 1}}})
	eventually(t, "outbound at the agent", func() bool {
		select {
		case m := <-got:
			return m.Type == sock.TypeOutbound
		default:
			return false
		}
	})
	// TCP 53 refuses too, and DoT answers a handshake with the certificate once the key is there
	if r := ask(t, p1, "x.example.com."); r.Rcode != dns.RcodeRefused {
		t.Errorf("rcode %d", r.Rcode)
	}
	_ = srv.Publish(&sock.Msg{Type: sock.TypeZoneKey, ZoneKey: zoneKey(t, "dns.example.net", "*.dns.example.net", "*.verify.dns.example.net")})
	eventually(t, "a DoT handshake", func() bool {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p2)),
			&tls.Config{ServerName: "dns.example.net", InsecureSkipVerify: true})
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	// the link going down: the free path is off, the image stays
	srv.Close()
	eventually(t, "free path off", func() bool { return !env.FreeOK(0) })
	if env.Image() == nil {
		t.Error("the image was dropped with the link")
	}
	cancel()
	<-done
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// p4n-W5b-r1-6: the facts a dns holds are the last agent run's. A reconnect (and a
// drop) clears them, so the free path stays off until the new run has sent its own.
func TestReconnectClearsTheAgentsFacts(t *testing.T) {
	e := newEnv()
	good := sock.Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: true, FreeSet: true, FreeEnabled: true, FreeQPS: 40, FreeVersion: 3}
	e.setLink(true)
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &good}, "", func(string) {}, nil)
	if !e.FreeOK(0) {
		t.Fatal("link up and facts good")
	}
	e.setLink(false)
	e.setLink(true) // the agent came back; its facts message has not arrived yet
	if e.FreeOK(0) {
		t.Fatal("free queries answered on the previous run's facts")
	}
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &good}, "", func(string) {}, nil)
	if !e.FreeOK(0) {
		t.Fatal("the new facts must turn it on")
	}
}

// p4n-W5b-r1-15: a NodeConfig that retires a zone also retires its certificate in
// dns, which would otherwise keep offering it as the fallback.
func TestConfigRetiresTheKeyOfAGoneZone(t *testing.T) {
	e := newEnv()
	two := nodeConfig(t, "10.0.0.5", make([]byte, 16))
	two.Zones = []string{"dns.example.net", "dns.old.example"}
	e.setConfig(mustMarshal(two))
	e.apply(&sock.Msg{Type: sock.TypeZoneKey, ZoneKey: zoneKey(t, "dns.example.net", "*.dns.example.net", "*.verify.dns.example.net")}, "", nil, nil)
	e.apply(&sock.Msg{Type: sock.TypeZoneKey, ZoneKey: zoneKey(t, "dns.old.example", "*.dns.old.example", "*.verify.dns.old.example")}, "", nil, nil)
	if n := len(*e.keys.Load()); n != 2 {
		t.Fatalf("keys = %d", n)
	}
	one := nodeConfig(t, "10.0.0.5", make([]byte, 16))
	one.Version = 2
	e.setConfig(mustMarshal(one))
	ks := *e.keys.Load()
	if len(ks) != 1 || !coversZone(ks[0].sans, "dns.example.net") {
		t.Fatalf("keys after the zone left: %d", len(ks))
	}
	c, err := e.GetCertificate(&tls.ClientHelloInfo{ServerName: "nothing.example.org"})
	if err != nil || c == nil || c.Leaf.Subject.CommonName != "dns.example.net" {
		t.Errorf("the fallback certificate is not the live zone's: %v", err)
	}
}

// dns holds no more challenges than the agent does, drops expired ones, and takes
// an already-expired message as a removal: the agent has no other way to tell it
// that it dropped a challenge to hold its bound (p4n-W5b-r2-11).
func TestAcmeChallengesAreBoundedExpiredAndRemoved(t *testing.T) {
	e := newEnv()
	now := time.Now().Unix()
	for i := 0; i < 200; i++ {
		e.setAcme(&sock.Acme{TokenID: []byte{byte(i), 1}, FQDN: "_acme-challenge.dns.example.net", Value: fmt.Sprintf("v%03d", i), ExpiresAt: now + 3600 + int64(i)})
	}
	e.mu.Lock()
	n := len(e.acme)
	e.mu.Unlock()
	if n != 64 {
		t.Fatalf("challenges held = %d, want 64", n)
	}
	// the earliest expiries went, the latest are kept
	got := e.AcmeChallenges(now)
	if len(got) != 64 || got[0].Value != "v136" {
		t.Errorf("kept %d, first %q", len(got), got[0].Value)
	}
	// a removal
	e.setAcme(&sock.Acme{TokenID: []byte{199, 1}, ExpiresAt: 1})
	if len(e.AcmeChallenges(now)) != 63 {
		t.Error("a removal did not remove")
	}
	// an expired one is dropped when the next arrives, not kept for ever
	e.setFacts(sock.Facts{}) // the hub offset is known, so an expired entry may be purged
	e.setAcme(&sock.Acme{TokenID: []byte{250, 2}, FQDN: "x", Value: "old", ExpiresAt: now + 1})
	e.mu.Lock()
	e.acme[string([]byte{250, 2})] = sock.Acme{TokenID: []byte{250, 2}, FQDN: "x", Value: "old", ExpiresAt: now - 10}
	e.mu.Unlock()
	e.setAcme(&sock.Acme{TokenID: []byte{251, 2}, FQDN: "x", Value: "new", ExpiresAt: now + 100})
	e.mu.Lock()
	_, kept := e.acme[string([]byte{250, 2})]
	e.mu.Unlock()
	if kept {
		t.Error("an expired entry is still held")
	}
}

// p4n-W5b-r3-1: the bound never takes the challenge just given, even when it is the
// one that expires first, and a tie goes to the oldest arrival.
func TestAcmeBoundKeepsTheChallengeJustGiven(t *testing.T) {
	e := newEnv()
	now := time.Now().Unix()
	for i := 0; i < 64; i++ {
		e.setAcme(&sock.Acme{TokenID: []byte{byte(i), 1}, FQDN: "x", Value: fmt.Sprintf("v%03d", i), ExpiresAt: now + 3600 + int64(i)})
	}
	e.setAcme(&sock.Acme{TokenID: []byte{64, 1}, FQDN: "x", Value: "new", ExpiresAt: now + 60})
	e.mu.Lock()
	_, has := e.acme[string([]byte{64, 1})]
	_, oldest := e.acme[string([]byte{0, 1})]
	n := len(e.acme)
	e.mu.Unlock()
	if !has || oldest || n != 64 {
		t.Errorf("new kept %v, earliest-expiring of the others kept %v, held %d", has, oldest, n)
	}
	// every challenge with the same expiry (the agent gives one to those with none):
	// the oldest arrival goes, never the newest
	e = newEnv()
	for i := 0; i < 200; i++ {
		e.setAcme(&sock.Acme{TokenID: []byte{byte(i), 1}, FQDN: "x", Value: "v", ExpiresAt: now + 3600})
		e.mu.Lock()
		_, newest := e.acme[string([]byte{byte(i), 1})]
		e.mu.Unlock()
		if !newest {
			t.Fatalf("challenge %d was evicted as it arrived", i)
		}
	}
	for i := 0; i < 136; i++ {
		e.mu.Lock()
		_, kept := e.acme[string([]byte{byte(i), 1})]
		e.mu.Unlock()
		if kept {
			t.Fatalf("challenge %d should have gone before newer ones", i)
		}
	}
}

// p4n-W5b-r4-5: with the agent gone dns has no Control stream behind it, so the
// PanelStale the agent last sent must not outlive 30 s of a down link.
func TestPanelIsStaleOnceTheAgentIsGoneFor30Seconds(t *testing.T) {
	e := newEnv()
	clock := time.Now()
	e.now = func() time.Time { return clock }
	e.downSince.Store(clock.UnixNano())
	mem, _ := proto.Marshal(storetest.Table(3, 0))
	m := &sock.Table{Member: mem, Version: 5, InUse: true, PanelStale: false, Self: storetest.NodeID(1), PeerDown: [][]byte{storetest.NodeID(2)}}
	e.setLink(true)
	e.apply(&sock.Msg{Type: sock.TypeTable, Table: m}, "", nil, nil)
	if e.Tables().Local.PanelStale {
		t.Fatal("stale with the agent connected and saying it is not")
	}
	e.setLink(false)
	clock = clock.Add(29 * time.Second)
	if e.Tables().Local.PanelStale {
		t.Fatal("stale before 30 s of a down link")
	}
	clock = clock.Add(2 * time.Second)
	st := e.Tables()
	if !st.Local.PanelStale || st.Table == nil || !st.Local.PeerDown[zone.NodeID(storetest.NodeID(2))] {
		t.Fatalf("after 30 s down: stale %v, table kept %v, peer down kept %v", st.Local.PanelStale, st.Table != nil, st.Local.PeerDown)
	}
	e.setLink(true)
	if e.Tables().Local.PanelStale {
		t.Fatal("still stale after the agent came back with a table that says it is not")
	}
	// a dns that never reached the agent counts from its own start
	e2 := newEnv()
	c2 := time.Now()
	e2.now = func() time.Time { return c2 }
	e2.downSince.Store(c2.UnixNano())
	c2 = c2.Add(31 * time.Second)
	if !e2.Tables().Local.PanelStale {
		t.Fatal("a dns that never saw the agent is not stale after 30 s")
	}
}

// p4n-W5b-r7-1: expiries from the agent are hub time. A node whose clock is ahead of
// the hub by more than a challenge's lifetime still answers it, whichever of the
// snapshot's messages (the challenge, or the facts that carry the offset) comes
// first.
func TestAcmeChallengeIsJudgedInHubTime(t *testing.T) {
	for _, factsFirst := range []bool{false, true} {
		e := newEnv()
		e.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
		hubNow := time.Now().Unix()
		facts := sock.Facts{ServerTimeSeen: true, HubOffset: -7200}
		if factsFirst {
			e.setFacts(facts)
		}
		e.setAcme(&sock.Acme{TokenID: []byte{1}, FQDN: "_acme-challenge.dns.example.net", Value: "v", ExpiresAt: hubNow + 3600})
		if !factsFirst {
			e.setFacts(facts)
		}
		if got := e.AcmeChallenges(e.HubNow()); len(got) != 1 {
			t.Errorf("factsFirst=%v: %d challenges at hub time, want 1", factsFirst, len(got))
		}
		if got := e.AcmeChallenges(hubNow + 3601); len(got) != 0 {
			t.Errorf("factsFirst=%v: a challenge past its expiry in hub time is still answered", factsFirst)
		}
	}
}

// p4n-W5b-r7-2: the stand-in proof_key of a stored config is no key.
func TestProofKeyIsNilForTheStandIn(t *testing.T) {
	e := newEnv()
	if e.ProofKey() != nil {
		t.Fatal("a key before any config")
	}
	e.config.Store(&hubv1.NodeConfig{ProofKey: make([]byte, 16)})
	if e.ProofKey() != nil {
		t.Fatal("the all-zero stand-in is returned as a key")
	}
	real := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
	e.config.Store(&hubv1.NodeConfig{ProofKey: real})
	if string(e.ProofKey()) != string(real) {
		t.Fatal("the real key is not returned")
	}
}

// Merge B: the query path swaps to a new image before dns confirms it. The agent
// ends a revocation on the confirmation, so a confirmation sent first would leave a
// window in which the revocation is gone and the old image still serves.
func TestTheQueryPathSeesAnImageBeforeItIsConfirmed(t *testing.T) {
	root := t.TempDir()
	name := buildImage(t, root, 3, 1)
	e := newEnv()
	var order []string
	e.OnApply(func(typ string) {
		if typ == sock.TypeImage && e.Image() != nil {
			order = append(order, "hook")
		}
	})
	e.apply(&sock.Msg{Type: sock.TypeImage, Image: &sock.Image{Name: name}}, filepath.Join(root, store.DirImage), func(string) { order = append(order, "ack") }, nil)
	if len(order) != 2 || order[0] != "hook" || order[1] != "ack" {
		t.Fatalf("order of hook and ack: %v", order)
	}
	// An image that does not open reaches neither.
	order = nil
	e.apply(&sock.Msg{Type: sock.TypeImage, Image: &sock.Image{Name: "missing"}}, filepath.Join(root, store.DirImage), func(string) { order = append(order, "ack") }, nil)
	if len(order) != 0 {
		t.Fatalf("an image that does not open was reported: %v", order)
	}
}

// FreeGate splits FreeOK in (a) and (c) for the counters, and is false in both
// while the agent cannot be read.
func TestFreeGateSplitsTheFactsAndIsOffWhileTheLinkIsDown(t *testing.T) {
	e := newEnv()
	if on, caught := e.FreeGate(0); on || caught {
		t.Fatal("a gate open with no facts")
	}
	facts := sock.Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: false, FreeSet: true, FreeEnabled: true, FreeQPS: 40, FreeVersion: 3}
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &facts}, "", func(string) {}, nil)
	if on, caught := e.FreeGate(0); on || caught {
		t.Fatal("facts with no link")
	}
	e.linkUp.Store(true)
	if on, caught := e.FreeGate(0); !on || caught {
		t.Fatalf("a lagging node: on %v caught up %v", on, caught)
	}
	facts.LagOK, facts.FreeEnabled = true, false
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &facts}, "", func(string) {}, nil)
	if on, caught := e.FreeGate(0); on || !caught {
		t.Fatalf("free off: on %v caught up %v", on, caught)
	}
	e.linkUp.Store(false)
	if on, caught := e.FreeGate(0); on || caught {
		t.Fatal("a gate open with the agent gone")
	}
}

// p4n-MD-r1-4, p4n-MD-r3-1: the agent's applied seq moves at the state commit, before
// the image swap, and the swap can fail. The free gate must not call dns caught up
// while the image that identifies sources is older than the seq the facts were
// judged at: a tenant's device whose claim is only in the newer entry would be
// answered as a free stranger, unfiltered. The seq is the query path's own, handed
// in by the caller: the Env stores a new image before the query path has swapped to
// it, and must not open the gate on that.
func TestFreeGateJudgesTheSeqOfTheImageThatIdentifiedTheQuery(t *testing.T) {
	root := t.TempDir()
	imgs := filepath.Join(root, store.DirImage)
	e := newEnv()
	e.linkUp.Store(true)
	facts := sock.Facts{ServerTimeSeen: true, CaughtUpOnce: true, LagOK: true, FreeSet: true, FreeEnabled: true, FreeQPS: 40, FreeVersion: 3, AppliedSeq: 2}
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &facts}, "", func(string) {}, nil)
	if on, caught := e.FreeGate(1); !on || caught || e.FreeOK(1) {
		t.Fatalf("a query identified at seq 1 under applied seq 2: on %v caught up %v", on, caught)
	}
	// The Env now holds the image of seq 2 (stored before the query path swaps to
	// it). A query still identified by seq 1 must stay refused: this is the window,
	// and the whole of it if the swap fails.
	e.apply(&sock.Msg{Type: sock.TypeImage, Image: &sock.Image{Name: buildImage(t, root, 2, 1)}}, imgs, func(string) {}, nil)
	if e.Image() == nil || e.Image().Seq() != 2 {
		t.Fatal("the test needs the Env to hold the image of seq 2")
	}
	if _, caught := e.FreeGate(1); caught || e.FreeOK(1) {
		t.Fatal("the Env's own image opened the gate for a query the old claims identified")
	}
	if on, caught := e.FreeGate(2); !on || !caught || !e.FreeOK(2) {
		t.Fatalf("a query identified at seq 2: on %v caught up %v", on, caught)
	}
	// An image from a lost state has a higher seq and passes.
	facts.AppliedSeq = 1
	e.apply(&sock.Msg{Type: sock.TypeFacts, Facts: &facts}, "", func(string) {}, nil)
	if !e.FreeOK(2) {
		t.Fatal("an image above the applied seq must pass")
	}
}
