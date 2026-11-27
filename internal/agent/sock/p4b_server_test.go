package sock

import (
	"bytes"
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
		{Type: TypeProxyState, ProxyState: &ProxyState{DNSBind: "203.0.113.5:53", Listening: true, Open: 4}},
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
