package cookie

import (
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var (
	src    = netip.MustParseAddr("192.0.2.7")
	other  = netip.MustParseAddr("192.0.2.8")
	client = []byte{1, 2, 3, 4, 5, 6, 7, 8}
)

func TestMakeVerify(t *testing.T) {
	j, err := New()
	if err != nil {
		t.Fatal(err)
	}
	sc := j.Make(client, src)
	if len(sc) != 16 || sc[0] != 1 {
		t.Fatalf("layout: %x", sc)
	}
	if !j.Verify(client, sc, src) {
		t.Fatal("own cookie does not verify")
	}
	if !j.Verify(client, sc, netip.MustParseAddr("::ffff:192.0.2.7")) {
		t.Fatal("the IPv4-mapped form of the source must verify")
	}
	if j.Verify(client, sc, other) {
		t.Fatal("cookie verified for another address")
	}
	if j.Verify([]byte{9, 9, 9, 9, 9, 9, 9, 9}, sc, src) {
		t.Fatal("cookie verified for another client cookie")
	}
	bad := append([]byte(nil), sc...)
	bad[15] ^= 1
	if j.Verify(client, bad, src) {
		t.Fatal("tampered hash verified")
	}
	if j.Verify(client, sc[:8], src) || j.Verify(client, nil, src) {
		t.Fatal("short server cookie verified")
	}
}

func TestWindowAndRotation(t *testing.T) {
	j, _ := New()
	base := time.Unix(1_800_000_000, 0)
	j.now = func() time.Time { return base }
	sc := j.Make(client, src)
	j.now = func() time.Time { return base.Add(59 * time.Minute) }
	if !j.Verify(client, sc, src) {
		t.Fatal("cookie inside the hour rejected")
	}
	j.now = func() time.Time { return base.Add(61 * time.Minute) }
	if j.Verify(client, sc, src) {
		t.Fatal("cookie older than an hour accepted")
	}
	j.now = func() time.Time { return base.Add(-10 * time.Minute) }
	if j.Verify(client, sc, src) {
		t.Fatal("cookie from the future accepted")
	}
	j.now = func() time.Time { return base }
	if err := j.Rotate(); err != nil {
		t.Fatal(err)
	}
	if !j.Verify(client, sc, src) {
		t.Fatal("a cookie made before one rotation must still verify")
	}
	if err := j.Rotate(); err != nil {
		t.Fatal(err)
	}
	if j.Verify(client, sc, src) {
		t.Fatal("a cookie two rotations old verified")
	}
}

func TestWipeInvalidates(t *testing.T) {
	j, _ := New()
	sc := j.Make(client, src)
	if err := j.Wipe(); err != nil {
		t.Fatal(err)
	}
	if j.Verify(client, sc, src) {
		t.Fatal("cookie verified after the secret was wiped")
	}
}

func msgWith(cookie string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	if cookie != "-" {
		o := m.SetEdns0(1232, false)
		_ = o
		m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie})
	}
	return m
}

func TestParse(t *testing.T) {
	c := hex.EncodeToString(client)
	srv := hex.EncodeToString(make([]byte, 16))
	cases := []struct {
		name    string
		cookie  string
		present bool
		server  int
	}{
		{"no option", "-", false, 0},
		{"client only", c, true, 0},
		{"client and server", c + srv, true, 16},
		{"short", c[:10], false, 0},
		{"server of 4 bytes", c + "01020304", false, 0},
		{"server of 33 bytes", c + hex.EncodeToString(make([]byte, 33)), false, 0},
		{"not hex", "zz", false, 0},
	}
	for _, tc := range cases {
		p := Parse(msgWith(tc.cookie))
		if p.Present != tc.present || len(p.Server) != tc.server {
			t.Errorf("%s: %+v", tc.name, p)
		}
	}
}

func TestAttach(t *testing.T) {
	j, _ := New()
	req := msgWith(hex.EncodeToString(client))
	p := Parse(req)
	reply := new(dns.Msg)
	reply.SetReply(req)
	j.Attach(reply, p, src)
	got := Parse(reply)
	if !got.Present || string(got.Client) != string(client) || len(got.Server) != 16 {
		t.Fatalf("reply cookie: %+v", got)
	}
	if !j.Verify(got.Client, got.Server, src) {
		t.Fatal("the cookie in the reply does not verify")
	}
	// An existing COOKIE option is replaced, not doubled.
	j.Attach(reply, p, src)
	n := 0
	for _, o := range reply.IsEdns0().Option {
		if _, ok := o.(*dns.EDNS0_COOKIE); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d COOKIE options", n)
	}
	// A query without a cookie gets none.
	plain := new(dns.Msg)
	plain.SetReply(msgWith("-"))
	j.Attach(plain, Parse(msgWith("-")), src)
	if plain.IsEdns0() != nil {
		t.Fatal("a cookie was added to a query that had none")
	}
}

// The previous secret is zeroed once the cookies it made have expired, not
// kept until the next rotation (p4n-W6-r1-10).
func TestPreviousSecretIsWiped(t *testing.T) {
	j, _ := New()
	j.prevKeep = 50 * time.Millisecond
	if err := j.Rotate(); err != nil {
		t.Fatal(err)
	}
	j.mu.RLock()
	zero := j.prev == [32]byte{}
	j.mu.RUnlock()
	if zero {
		t.Fatal("the previous secret was zeroed at once")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		j.mu.RLock()
		zero, have := j.prev == [32]byte{}, j.have
		j.mu.RUnlock()
		if zero && !have {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the previous secret was not wiped")
}

// A timer from an earlier rotation does not wipe the previous secret of a
// later one.
func TestStaleWipeTimerDoesNothing(t *testing.T) {
	j, _ := New()
	j.prevKeep = time.Hour
	_ = j.Rotate()
	old := j.gen
	_ = j.Rotate()
	j.wipePrev(old)
	j.mu.RLock()
	defer j.mu.RUnlock()
	if !j.have {
		t.Fatal("a stale timer wiped the current previous secret")
	}
}
