package sock

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func goodLocations() *Locations {
	return &Locations{Guard: true, Direct: "127.0.0.20:20000", Draining: []string{"127.0.0.21:20001"}, Configs: []LocationConfig{
		{ID: bytes.Repeat([]byte{1}, 16), Location: 3, Socks: "127.0.0.20:20001", Exit: bytes.Repeat([]byte{2}, 8), Priority: 1, Healthy: true, LatencyMS: 40},
	}}
}

// locations is a state slot: a dns that connects later gets the latest list, and
// one that is connected gets each change.
func TestLocationsIsAStateSlot(t *testing.T) {
	s := startServer(t, ServerConfig{})
	if err := s.Publish(&Msg{Type: TypeLocations, Locations: goodLocations()}); err != nil {
		t.Fatal(err)
	}
	l2 := goodLocations()
	l2.Configs[0].Healthy = false
	if err := s.Publish(&Msg{Type: TypeLocations, Locations: l2}); err != nil {
		t.Fatal(err)
	}
	c := dial(t, s.cfg.Path)
	readMsg(t, c) // hello
	m := readMsg(t, c)
	if m.Type != TypeLocations || m.Locations.Configs[0].Healthy {
		t.Fatalf("the snapshot holds the old list: %+v", m)
	}
	l3 := goodLocations()
	l3.Configs = nil
	_ = s.Publish(&Msg{Type: TypeLocations, Locations: l3})
	if m := readMsg(t, c); m.Type != TypeLocations || len(m.Locations.Configs) != 0 {
		t.Fatalf("the update: %+v", m)
	}
	// A list that fails its check is not stored and not sent.
	bad := goodLocations()
	bad.Configs[0].Exit = []byte{1}
	if err := s.Publish(&Msg{Type: TypeLocations, Locations: bad}); err == nil {
		t.Fatal("a bad list was published")
	}
	dup := goodLocations()
	dup.Configs = append(dup.Configs, dup.Configs[0])
	if err := s.Publish(&Msg{Type: TypeLocations, Locations: dup}); err == nil {
		t.Fatal("two configs with one id were published")
	}
}

// grant_in and grant_sent are events: nothing is kept for a dns that connects later.
func TestGrantEventsAreNotKept(t *testing.T) {
	s := startServer(t, ServerConfig{})
	in := &Msg{Type: TypeGrantIn, GrantIn: &GrantIn{Sender: bytes.Repeat([]byte{1}, 16), Forward: []byte("fwd")}}
	if s.Send(in) {
		t.Fatal("an event was queued with no dns connected")
	}
	if err := s.Publish(in); err == nil {
		t.Fatal("an event was published as state")
	}
	c := dial(t, s.cfg.Path)
	readMsg(t, c) // hello
	eventually(t, "dns connected", s.Connected)
	if !s.Send(in) {
		t.Fatal("event not queued")
	}
	if m := readMsg(t, c); m.Type != TypeGrantIn || string(m.GrantIn.Forward) != "fwd" {
		t.Fatalf("%+v", m)
	}
	if s.Send(&Msg{Type: TypeGrantSent, GrantSent: &GrantSent{GrantID: bytes.Repeat([]byte{1}, 16), Result: "maybe"}}) {
		t.Fatal("a bad result was sent")
	}
	if !s.Send(&Msg{Type: TypeGrantSent, GrantSent: &GrantSent{GrantID: bytes.Repeat([]byte{1}, 16), Result: GrantUnsent}}) {
		t.Fatal("grant_sent not queued")
	}
	if m := readMsg(t, c); m.Type != TypeGrantSent || m.GrantSent.Result != GrantUnsent {
		t.Fatalf("%+v", m)
	}
	// Other types cannot go this way.
	if s.Send(&Msg{Type: TypeImage, Image: &Image{Name: "1"}}) {
		t.Fatal("Send took a state type")
	}
}

// dns sends grant_res, grant_out and proxy_state; anything else of the new types
// from dns ends its connection.
func TestDNSSendsTheP4bTypesItMay(t *testing.T) {
	var mu sync.Mutex
	var got []*Msg
	s := startServer(t, ServerConfig{H: Handlers{Message: func(m *Msg) { mu.Lock(); got = append(got, m); mu.Unlock() }}})
	c := dial(t, s.cfg.Path)
	readMsg(t, c)
	gid := bytes.Repeat([]byte{4}, 16)
	for _, m := range []*Msg{
		{Type: TypeGrantRes, GrantRes: &GrantRes{GrantID: gid, Accepted: true}},
		{Type: TypeGrantOut, GrantOut: &GrantOut{Forward: []byte("f")}},
		{Type: TypeProxyState, ProxyState: &ProxyState{DNSBind: "203.0.113.5", Listening: true, Open: 4}},
	} {
		if err := Write(c, m, MaxFrameFromDNS); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "three messages", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 3 })
	// A frame that fails the check is a decode error on the agent: the connection ends.
	var bad bytes.Buffer
	body := `{"t":"grant_res","grant_res":{"gid":"AA==","ok":true}}`
	bad.Write([]byte{0, 0, 0, byte(len(body))})
	bad.WriteString(body)
	_, _ = c.Write(bad.Bytes())
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the connection stayed up after a bad grant_res")
	}
	// dns may not send what is the agent's.
	c2 := dial(t, s.cfg.Path)
	readMsg(t, c2)
	_ = Write(c2, &Msg{Type: TypeLocations, Locations: goodLocations()}, MaxFrameFromDNS)
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("dns sent locations and stayed connected")
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 3 {
		t.Fatalf("%d messages reached the handler", n)
	}
}

func TestP4bTypeNeedsExactlyItsField(t *testing.T) {
	var buf bytes.Buffer
	m := &Msg{Type: TypeGrantRes, ProxyState: &ProxyState{Listening: true}}
	if err := Write(&buf, m, MaxFrameFromDNS); err == nil {
		t.Fatal("a grant_res frame with a proxy_state body was written")
	}
	two := &Msg{Type: TypeProxyState, ProxyState: &ProxyState{}, GrantRes: &GrantRes{GrantID: bytes.Repeat([]byte{1}, 16)}}
	if err := Write(&buf, two, MaxFrameFromDNS); err == nil {
		t.Fatal("two bodies in one frame")
	}
	if err := Write(&buf, &Msg{Type: TypeProxyState, ProxyState: &ProxyState{DNSBind: "dns.example:53"}}, MaxFrameFromDNS); err == nil {
		t.Fatal("a name where an address belongs")
	}
}

// B1n-r1-1: dns_bind is the bare IP of dns_bind_ip, not ip:port.
func TestProxyStateDNSBindIsABareIP(t *testing.T) {
	var buf bytes.Buffer
	for _, ok := range []string{"", "203.0.113.5", "2001:db8::5"} {
		if err := Write(&buf, &Msg{Type: TypeProxyState, ProxyState: &ProxyState{DNSBind: ok, Listening: true}}, MaxFrameFromDNS); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"203.0.113.5:53", "[2001:db8::5]:53", "dns.example"} {
		if err := Write(&buf, &Msg{Type: TypeProxyState, ProxyState: &ProxyState{DNSBind: bad}}, MaxFrameFromDNS); err == nil {
			t.Errorf("%q was written", bad)
		}
	}
}

// B1n-r1-13: a frame carries the field of its own generation alone.
func TestEnvelopeKeepsTheGenerationsApart(t *testing.T) {
	var buf bytes.Buffer
	gid := bytes.Repeat([]byte{1}, 16)
	p4bWithP4 := &Msg{Type: TypeGrantOut, GrantOut: &GrantOut{Forward: []byte("f")}, Outbound: &Outbound{NodeMessage: []byte("x")}}
	if err := Write(&buf, p4bWithP4, MaxFrameFromDNS); err == nil {
		t.Fatal("a grant_out frame with an outbound was written")
	}
	p4withP4b := &Msg{Type: TypeOutbound, Outbound: &Outbound{NodeMessage: []byte("x")}, GrantRes: &GrantRes{GrantID: gid}}
	if err := Write(&buf, p4withP4b, MaxFrameFromDNS); err == nil {
		t.Fatal("an outbound frame with a grant_res was written")
	}
	// The reader refuses the same two frames.
	for _, body := range []string{
		`{"t":"grant_out","grant_out":{"fwd":"Zg=="},"outbound":{"nm":"eA=="}}`,
		`{"t":"outbound","outbound":{"nm":"eA=="},"grant_res":{"gid":"AAAAAAAAAAAAAAAAAAAAAA==","ok":true}}`,
	} {
		var f bytes.Buffer
		f.Write([]byte{0, 0, 0, byte(len(body))})
		f.WriteString(body)
		if _, err := Read(&f, MaxFrameFromDNS); err == nil {
			t.Errorf("read %s", body[:20])
		}
	}
	s := startServer(t, ServerConfig{})
	if err := s.Publish(p4bWithP4); err == nil {
		t.Fatal("Publish took a mixed frame")
	}
}

// B1n-r1-4 and 10: nothing but white space follows a P4b frame's message, also on
// agent.sock, and a decode error does not carry the peer's text.
func TestAgentSockReadTrailingAndDecodeText(t *testing.T) {
	gid := `"AAAAAAAAAAAAAAAAAAAAAA=="`
	good := `{"t":"grant_res","grant_res":{"gid":` + gid + `,"ok":true}}`
	frame := func(body string) *bytes.Reader {
		var f bytes.Buffer
		f.Write([]byte{0, 0, 0, byte(len(body))})
		f.WriteString(body)
		return bytes.NewReader(f.Bytes())
	}
	if _, err := Read(frame(good+" \n"), MaxFrameFromDNS); err != nil {
		t.Fatalf("white space after the message: %v", err)
	}
	for _, tail := range []string{"}", "]", " } junk", "{}"} {
		if _, err := Read(frame(good+tail), MaxFrameFromDNS); err == nil {
			t.Errorf("tail %q accepted", tail)
		}
	}
	key := strings.Repeat("K", 100)
	_, err := Read(frame(`{"t":"grant_res","`+key+`":1}`), MaxFrameFromDNS)
	if err == nil || strings.Contains(err.Error(), key[:10]) {
		t.Fatalf("the error is missing or quotes the peer's key: %v", err)
	}
}

// B1n-r1-8: dns's Client refuses a bad P4b message before it is queued, so the
// writer never fails on it and the link stays up.
func TestClientSendRefusesABadP4bMessage(t *testing.T) {
	p := sockPath(t)
	cfg := ServerConfig{Path: p, Check: allow}
	s, err := Listen(cfg)
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx)
	defer s.Close()
	cl := NewClient(p, ClientHandlers{})
	go cl.Run(ctx)
	eventually(t, "client up", cl.Up)
	if cl.Send(&Msg{Type: TypeGrantRes, GrantRes: &GrantRes{GrantID: bytes.Repeat([]byte{1}, 15)}}) {
		t.Fatal("a grant_res with a 15 byte id was queued")
	}
	if !cl.Send(&Msg{Type: TypeGrantRes, GrantRes: &GrantRes{GrantID: bytes.Repeat([]byte{1}, 16), Accepted: true}}) {
		t.Fatal("a good grant_res was refused")
	}
	if !cl.Up() {
		t.Fatal("the link went down")
	}
}
