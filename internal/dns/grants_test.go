package dns

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/grant"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// The proxy world: the test world with Endpoints that Redirect to a location. P1, P2
// and P4 belong to three tenants (accounts 1, 2 and 4); P1 and P4 go to location 5,
// P2 to location 6. The pair's bitmap holds both, the first node is this node and the
// second its peer.
const (
	epP1 byte = 11
	epP2 byte = 12
	epP4 byte = 14
	// Branded block pages: B1 and B3 show page 1, B2 page 2.
	epB1 byte = 15
	epB2 byte = 16
	epB3 byte = 17
)

func brandedProfile(t testing.TB, page byte) ([]byte, [32]byte) {
	p, err := rules.Parse("brand.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var ph [32]byte
	ph[0] = page
	d, err := blob.Build(&blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: p, Action: blob.ActBlock}},
		Options: blob.Options{Present: blob.OptBlockResponse, BlockResponse: blob.BlockBranded, BlockPageHash: ph}})
	if err != nil {
		t.Fatal(err)
	}
	return d, storetest.Hash(d)
}

type fakeGeo struct{}

func (fakeGeo) Country(a netip.Addr) [2]byte {
	if a.Is4() && a.As4()[0] == 5 && a.As4()[1] == 200 {
		return [2]byte{'I', 'R'}
	}
	return [2]byte{}
}
func (fakeGeo) ASN(netip.Addr) uint32 { return 64500 }

type agentRec struct {
	mu   sync.Mutex
	msgs []*sock.Msg
	ends []sock.LinkEnd
}

func (r *agentRec) send(m *sock.Msg) bool {
	r.mu.Lock()
	r.msgs = append(r.msgs, m)
	r.mu.Unlock()
	return true
}

func (r *agentRec) end(ids []uint64, socks []string) bool {
	r.mu.Lock()
	r.ends = append(r.ends, sock.LinkEnd{IDs: ids, Socks: socks})
	r.mu.Unlock()
	return true
}

func (r *agentRec) of(typ string) (out []*sock.Msg) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.msgs {
		if m.Type == typ {
			out = append(out, m)
		}
	}
	return
}

func (r *agentRec) endedIDs() (out []uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.ends {
		out = append(out, e.IDs...)
	}
	return
}

func redirectProfile(t testing.TB, loc uint16) ([]byte, [32]byte) {
	mk := func(tok string, id byte) blob.RuleSpec {
		p, err := rules.Parse(tok)
		if err != nil {
			t.Fatal(err)
		}
		return blob.RuleSpec{ID: [16]byte{id}, Pattern: p, Action: blob.ActRedirect, Target: &blob.TargetSpec{Kind: blob.TargetLocation, Location: loc}}
	}
	d, err := blob.Build(&blob.Spec{Default: blob.ActBypass, Rules: []blob.RuleSpec{
		mk("pub.example.com", 1), mk("pub2.example.com", 2), mk("ir.example.com", 3), mk("pub3.example.com", 4),
		mk("private.example.com", 5), mk("inject.example.com", 6), mk("loop.example.com", 7)}})
	if err != nil {
		t.Fatal(err)
	}
	return d, storetest.Hash(d)
}

func newProxyWorld(t *testing.T) (*world, *Grants, *agentRec) {
	t.Helper()
	w := newWorldTuned(t, func(in *image.Input, put func(string, []byte, [32]byte)) {
		for _, e := range []struct {
			id  byte
			loc uint16
		}{{epP1, 5}, {epP2, 6}, {epP4, 5}} {
			d, h := redirectProfile(t, e.loc)
			put("P"+itoa(int(e.id)), d, h)
			rec := record(e.id, h)
			rec.AccountHash = bytes.Repeat([]byte{e.id}, 16)
			addEndpoint(in, rec)
		}
		for _, e := range []struct{ id, page byte }{{epB1, 1}, {epB2, 2}, {epB3, 1}} {
			d, h := brandedProfile(t, e.page)
			put("B"+itoa(int(e.id)), d, h)
			rec := record(e.id, h)
			rec.AccountHash = bytes.Repeat([]byte{e.id}, 16)
			addEndpoint(in, rec)
		}
		in.Member.Pairs[0].LocationBitmap = []byte{0x60} // locations 5 and 6
	})
	w.h.cfg.Self = func() sharedpolicy.SelfAddrs {
		return sharedpolicy.SelfAddrs{DNSIP: netip.MustParseAddr(selfDNSIP), ProxyIP: netip.MustParseAddr(selfDNSIP)}
	}
	w.h.cfg.Geo = fakeGeo{}
	w.h.cfg.CachedA = w.res.CachedA
	rec := &agentRec{}
	g := newGrants(w.h, ProxyOptions{Send: rec.send, End: rec.end, Facts: func() ProxyFacts {
		return ProxyFacts{Self: [16]byte(storetest.NodeID(0)), ProxyBind: netip.MustParseAddr("127.0.0.1"), DNSBind: netip.MustParseAddr("127.0.0.2")}
	}})
	w.h.grants = g
	g.linkUp.Store(true)
	g.listening.Store(true)
	g.OnLocations(locs(true, "127.0.0.20:20001"))
	return w, g, rec
}

func cfgL(id byte, loc uint32, socks string, exit string, prio, ms uint32) sock.LocationConfig {
	return sock.LocationConfig{ID: bytes.Repeat([]byte{id}, 16), Location: loc, Socks: socks, Exit: []byte(exit), Priority: prio, Healthy: true, LatencyMS: ms}
}

func locs(guard bool, socks5 string) *sock.Locations {
	return &sock.Locations{Guard: guard, Direct: "127.0.0.20:20000", Configs: []sock.LocationConfig{
		cfgL(0x51, 5, socks5, "exit0005", 1, 40),
		cfgL(0x52, 5, "127.0.0.20:20002", "exit005b", 1, 90),
		cfgL(0x53, 5, "127.0.0.20:20004", "exit005c", 2, 10),
		cfgL(0x61, 6, "127.0.0.20:20003", "exit0006", 1, 50),
	}}
}

var srcLocal = netip.MustParseAddr("127.0.0.1")

func wn(s string) []byte { n := names.MustString(s); return append([]byte(nil), n.Wire()...) }

func (g *Grants) look(id uint64, name string) *sock.LinkVerdict {
	return g.Lookup(context.Background(), id, srcLocal, wn(name), 443)
}

// Two tenants, one source address (15.1): A redirects, B asks the same name for
// another location. A's connection goes to A's location, B gets the true answer, and
// B's device never reaches A's outcome by a Grant of its own.
func TestGrantsTwoTenantsOneSource(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	if got := w.dot(epP1, "pub.example.com", dns.TypeA); aAddrs(got.Msg)[0] != selfDNSIP || len(aAddrs(got.Msg)) != 2 {
		t.Fatalf("A must get own, then the peer: %v", aAddrs(got.Msg))
	}
	// B decides another location for the same name from the same address.
	wantA(t, "B refused: the true answer, never A's location", w.dot(epP2, "pub.example.com", dns.TypeA), "93.184.216.34")
	if n := g.Table().Holders(); n != 1 {
		t.Fatalf("B wrote a holder: %d", n)
	}
	v := g.look(1, "pub.example.com")
	if v.Kind != sock.VerdictProxy || len(v.Targets) != 3 {
		t.Fatalf("the verdict of A's Grant: %+v", v)
	}
	// Location 5: the priority-1 configs by latency, then the later one (6.4).
	want := []string{"127.0.0.20:20001", "127.0.0.20:20002", "127.0.0.20:20004"}
	for i, tg := range v.Targets {
		if tg.Socks != want[i] || tg.Host != "pub.example.com" || tg.Port != 443 {
			t.Fatalf("target %d: %+v", i, tg)
		}
	}
	if len(v.Tag) == 0 || len(v.Tag) > sock.MaxTag {
		t.Fatalf("tag %d", len(v.Tag))
	}
	// Another source has no Grant: none, after the wait of 4.3 step 3.
	other := g.Lookup(context.Background(), 2, netip.MustParseAddr("127.0.0.9"), wn("pub.example.com"), 443)
	if other.Kind != sock.VerdictNone {
		t.Fatalf("another source: %+v", other)
	}
	// Another name has none either.
	if v := g.look(3, "pub2.example.com"); v.Kind != sock.VerdictNone {
		t.Fatalf("another name: %+v", v)
	}
}

// Both tenants redirect to one location: both work, and the end of A's Grant leaves
// B's; a shared connection lives while B's right stands and ends with it (15.1).
func TestGrantsJoinAndEndOfOne(t *testing.T) {
	w, g, rec := newProxyWorld(t)
	w.dot(epP1, "pub.example.com", dns.TypeA)
	if got := aAddrs(w.dot(epP4, "pub.example.com", dns.TypeA).Msg); len(got) != 2 {
		t.Fatalf("a holder whose decision allows the live outcome joins: %v", got)
	}
	if g.Table().Holders() != 2 {
		t.Fatalf("%d holders", g.Table().Holders())
	}
	v := g.look(1, "pub.example.com")
	if v.Kind != sock.VerdictProxy {
		t.Fatal("no verdict")
	}
	if cn, _ := g.Conns().Get(1); len(cn.Holders) != 2 {
		t.Fatalf("a shared connection records both holders: %+v", cn.Holders)
	}
	var revoked []Revocation // a revocation stays in force until the entry that applies it
	revoke := func(id byte) {
		revoked = append(revoked, Revocation{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT,
			IDs: [][16]byte{[16]byte(bytes.Repeat([]byte{id}, 16))}, RevSeq: 100, ExpiresAt: time.Now().Add(time.Hour)})
		w.h.Revocations().Set(revoked)
		g.pass()
	}
	revoke(epP1)
	if g.Table().Holders() != 1 || len(rec.endedIDs()) != 0 {
		t.Fatalf("A's end must leave B's holder and the connection: %d holders, ended %v", g.Table().Holders(), rec.endedIDs())
	}
	if v := g.look(2, "pub.example.com"); v.Kind != sock.VerdictProxy {
		t.Fatal("B still works")
	}
	// A's end does not charge B and B's device was never at A's: now B ends too.
	revoke(epP4)
	if g.Table().Holders() != 0 {
		t.Fatal("B's holder stays after its own end")
	}
	if got := rec.endedIDs(); len(got) != 2 {
		t.Fatalf("both connections end when every holder recorded with them has: %v", got)
	}
}

// 4.2 verdicts in the handler: a source that is not validated gets TC=1 and no
// Grant; with the proxy down own is left out while the peer is usable; with neither,
// the answer is the true one.
func TestGrantsHandlerVerdicts(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	r := w.call(qopt{t: listen.DoT, sni: rid(epP1) + "." + testZone, validated: vptr(false)}, "pub2.example.com", dns.TypeA)
	if r.Msg == nil || !r.Msg.Truncated || len(r.Msg.Answer) != 0 || g.Table().Holders() != 0 {
		t.Fatalf("validate: %+v holders %d", r.Msg, g.Table().Holders())
	}
	g.listening.Store(false) // the proxy is down: own is left out while the peer is usable
	wantA(t, "proxy down", w.dot(epP1, "pub3.example.com", dns.TypeA), "8.8.4.4")
	g.linkUp.Store(true)
	g.listening.Store(true)
	// With no location left the whole name is Bypass and no Grant is written.
	g.OnLocations(&sock.Locations{Guard: false})
	wantA(t, "guard off", w.dot(epP1, "ir.example.com", dns.TypeA), "5.200.1.1")
	if g.Table().Holders() != 1 {
		t.Fatalf("holders %d", g.Table().Holders())
	}
}

// 5.3: an address in the IR range goes out of the direct inbound with that numeric
// address; R9 and never-proxied are judged again at the verdict.
func TestGrantsVerdictDestinations(t *testing.T) {
	w, g, rec := newProxyWorld(t)
	w.dot(epP1, "ir.example.com", dns.TypeA)
	v := g.look(1, "ir.example.com")
	if v.Kind != sock.VerdictProxy || len(v.Targets) != 1 || v.Targets[0].Socks != "127.0.0.20:20000" || v.Targets[0].Host != "5.200.1.1" {
		t.Fatalf("direct: %+v", v)
	}
	// A name that became never-proxied after the Grant: none (T-526), and the holder ends.
	w.dot(epP1, "pub.example.com", dns.TypeA)
	w.h.cfg.NeverProxied = func(n names.Name) bool { return n.String() == "pub.example.com" || neverIR(n) }
	if v := g.look(2, "pub.example.com"); v.Kind != sock.VerdictNone {
		t.Fatalf("never proxied: %+v", v)
	}
	g.pass()
	if n := g.Table().Holders(); n != 1 {
		t.Fatalf("the holder of a never-proxied name must end with the catalog change: %d", n)
	}
	// A Grant planted for a name under a private suffix is never dialled.
	g.Table().Put(&grant.PutReq{Name: wn("printer.lan"), Source: srcLocal, Validated: true,
		Out:    grant.Outcome{Kind: grant.KindRedirect, Location: 5},
		Holder: grant.Holder{Endpoint: [16]byte(bytes.Repeat([]byte{epP1}, 16)), Account: [16]byte(bytes.Repeat([]byte{epP1}, 16))}})
	if v := g.look(3, "printer.lan"); v.Kind != sock.VerdictNone {
		t.Fatalf("R9 at the verdict: %+v", v)
	}
	// Open connections on a SOCKS address the list no longer holds are ended (4.6).
	w.h.cfg.NeverProxied = neverIR
	w.dot(epP1, "pub2.example.com", dns.TypeA)
	if v := g.look(4, "pub2.example.com"); v.Kind != sock.VerdictProxy {
		t.Fatal("verdict")
	}
	g.OnLocations(locs(true, "127.0.0.20:20009"))
	found := false
	for _, e := range rec.ends {
		for _, s := range e.Socks {
			found = found || s == "127.0.0.20:20001"
		}
	}
	if !found {
		t.Fatalf("a deleted config must close its connections at once: %+v", rec.ends)
	}
}

// 4.5: a holder decided here is offered to the peer, the answer of the agent clears
// alone; a forward from the pair peer is accepted when the receiver would have
// granted it itself, and never from another node, for another client, or for a name
// that is never proxied.
func TestGrantsForwards(t *testing.T) {
	w, g, rec := newProxyWorld(t)
	w.dot(epP1, "pub.example.com", dns.TypeA)
	g.sendForwards()
	outs := rec.of(sock.TypeGrantOut)
	if len(outs) != 1 {
		t.Fatalf("one forward is queued for the new holder: %d", len(outs))
	}
	var f peerv1.GrantForward
	if err := proto.Unmarshal(outs[0].GrantOut.Forward, &f); err != nil || f.Location != 5 || f.GrantKind != 1 || !bytes.Equal(f.EndpointId, bytes.Repeat([]byte{epP1}, 16)) || f.SenderConfigSeq != 7 {
		t.Fatalf("%+v %v", &f, err)
	}
	g.OnAgent(&sock.Msg{Type: sock.TypeGrantSent, GrantSent: &sock.GrantSent{GrantID: f.GrantId, Result: sock.GrantRefused}})
	// A refusal sets alone: the answer leaves the peer out until the retry.
	wantA(t, "alone", w.dot(epP1, "pub.example.com", dns.TypeA), selfDNSIP)

	mk := func(ep byte, name string, loc uint32, mod func(*peerv1.GrantForward)) []byte {
		fw := &peerv1.GrantForward{GrantId: bytes.Repeat([]byte{9}, 16), EndpointId: bytes.Repeat([]byte{ep}, 16),
			SourcePrefix: append(netip.MustParseAddr("127.0.0.77").AsSlice(), 32), NameWire: wn(name), Location: loc, GrantKind: 1,
			ExpiresAt: time.Now().Add(time.Hour).Unix(), SenderConfigSeq: 7}
		if mod != nil {
			mod(fw)
		}
		b, _ := proto.Marshal(fw)
		return b
	}
	peer, stranger := [16]byte(storetest.NodeID(1)), [16]byte(storetest.NodeID(2))
	if !g.acceptForward(mk(epP2, "pub.example.com", 6, nil), peer) {
		t.Fatal("a forward the receiver would have granted itself")
	}
	if v := g.Lookup(context.Background(), 5, netip.MustParseAddr("127.0.0.77"), wn("pub.example.com"), 443); v.Kind != sock.VerdictProxy || v.Targets[0].Socks != "127.0.0.20:20003" {
		t.Fatalf("the forwarded location is B's: %+v", v)
	}
	for label, c := range map[string]struct {
		b      []byte
		sender [16]byte
	}{
		"a node outside the pair": {mk(epP2, "pub2.example.com", 6, nil), stranger},
		"another location":        {mk(epP2, "pub2.example.com", 5, nil), peer},
		"another dial host":       {mk(epP2, "pub2.example.com", 6, func(f *peerv1.GrantForward) { f.DialHostWire = wn("other.example.com") }), peer},
		"a client of another one": {mk(epP2, "pub2.example.com", 6, func(f *peerv1.GrantForward) { f.ClientHash = bytes.Repeat([]byte{3}, 16) }), peer},
		"a never-proxied name":    {mk(epP2, "x.example.ir", 6, nil), peer},
		"an unknown Endpoint":     {mk(0x66, "pub2.example.com", 6, nil), peer},
		"an expired forward":      {mk(epP2, "pub2.example.com", 6, func(f *peerv1.GrantForward) { f.ExpiresAt = 1 }), peer},
	} {
		if g.acceptForward(c.b, c.sender) {
			t.Errorf("%s was accepted", label)
		}
	}
	before := g.Table().Holders()
	g.OnAgent(&sock.Msg{Type: sock.TypeGrantIn, GrantIn: &sock.GrantIn{Sender: stranger[:], Forward: mk(epP2, "pub3.example.com", 6, nil)}})
	deadline := time.Now().Add(2 * time.Second)
	for len(rec.of(sock.TypeGrantRes)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if res := rec.of(sock.TypeGrantRes); len(res) != 1 || res[0].GrantRes.Accepted || g.Table().Holders() != before {
		t.Fatalf("grant_res: %+v", res)
	}
	// The peer's holder ends with the entry that takes it out of the pair (4.6).
	w.h.srv.Load().img.PairTable().Nodes[1].SpkiSha256 = nil
	g.pass()
	if g.Table().Holders() != before-1 {
		t.Fatalf("a forwarded holder must end when its origin is revoked: %d", g.Table().Holders())
	}
}

// A restart of dns: the table is rebuilt from the proxy's list and the connection is
// judged against the image, so one whose Grants ended while dns was away is closed
// (G1), and `config` waits for that.
func TestGrantsLinkUpJudgesTheOpenList(t *testing.T) {
	w, g, rec := newProxyWorld(t)
	w.dot(epP1, "pub.example.com", dns.TypeA)
	g.look(1, "pub.example.com")
	cn, _ := g.Conns().Get(1)
	tag := cn.Tag(sock.MaxTag)

	// A fresh dns: no Grants, and A is hard_disabled now.
	w2, g2, rec2 := newProxyWorld(t)
	_ = w2
	g2.LinkUp(1, []grant.OpenItem{{ID: 9, Source: srcLocal, Socks: "127.0.0.20:20001", Tag: tag}, {ID: 10, Source: srcLocal, Socks: "127.0.0.20:20001", Tag: []byte("junk")}})
	ids := rec2.endedIDs()
	if len(ids) != 1 || ids[0] != 10 {
		// holder A is alive in the image (it is enabled), only the unreadable one ends
		t.Fatalf("ended %v", ids)
	}
	w2.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT,
		IDs: [][16]byte{[16]byte(bytes.Repeat([]byte{epP1}, 16))}, RevSeq: 100, ExpiresAt: time.Now().Add(time.Hour)}})
	g2.pass()
	if got := rec2.endedIDs(); len(got) < 2 {
		t.Fatalf("a revoked Endpoint's connection must end after the restart too: %v", got)
	}
	_ = rec
	_ = g
}

// Branded blocks (kind 2): two tenants with different pages for one name from one
// address: the second gets 0.0.0.0, never the true answer; one with the same page
// joins. The page of the verdict is empty for MaxProxyTTL after the start of dns, so
// ctrlz-block shows our default page, and the real hash after it (4.1).
func TestGrantsBrandedBlocks(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	if got := aAddrs(w.dot(epB1, "brand.example.com", dns.TypeA).Msg); len(got) != 2 || got[0] != selfDNSIP {
		t.Fatalf("a Branded block answers with the proxy addresses: %v", got)
	}
	wantA(t, "another page", w.dot(epB2, "brand.example.com", dns.TypeA), "0.0.0.0")
	w.advance(time.Second)
	// The same page hash but another account: a Branded page is of one account (SC
	// 10.3), so B3 does not join B1's entry. It is refused and stays blocked, and the
	// connection of the entry never carries B3's Endpoint or key.
	wantA(t, "another account, same page", w.dot(epB3, "brand.example.com", dns.TypeA), "0.0.0.0")
	v := g.look(1, "brand.example.com")
	if v.Kind != sock.VerdictBlock || !bytes.Equal(v.Endpoint, bytes.Repeat([]byte{epB1}, 16)) || !bytes.Equal(v.Account, bytes.Repeat([]byte{epB1}, 16)) || len(v.PageHash) != 0 {
		t.Fatalf("right after the start the page is ours: %+v", v)
	}
	w.advance(time.Hour + time.Minute)
	w.dot(epB1, "brand.example.com", dns.TypeA) // a deciding query keeps the Grant alive
	v = g.look(2, "brand.example.com")
	if v.Kind != sock.VerdictBlock || len(v.PageHash) != 32 || v.PageHash[0] != 1 {
		t.Fatalf("later the page is the Grant's: %+v", v)
	}
	if n, _ := g.Conns().Open(); n != 0 {
		t.Fatalf("a block-page connection has no SOCKS leg: %d", n)
	}
}

// A forward that is ahead of this node's image is decided with what the node has,
// kept short, and decided again when the image reaches its seq (4.5).
func TestGrantsForwardAheadOfTheImage(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	f := &peerv1.GrantForward{GrantId: bytes.Repeat([]byte{9}, 16), EndpointId: bytes.Repeat([]byte{epP2}, 16),
		SourcePrefix: append(netip.MustParseAddr("127.0.0.88").AsSlice(), 32), NameWire: wn("pub.example.com"), Location: 6, GrantKind: 1,
		ExpiresAt: w.now().Add(2 * time.Hour).Unix(), SenderConfigSeq: 99}
	b, _ := proto.Marshal(f)
	peer := [16]byte(storetest.NodeID(1))
	if !g.acceptForward(b, peer) {
		t.Fatal("decided with the image it has")
	}
	h, ok := g.Table().Lookup(netip.MustParseAddr("127.0.0.88"), 64500, wn("pub.example.com"), grant.WidthExact)
	if !ok || h.Holders[0].Expires-w.now().Unix() > 60 {
		t.Fatalf("an offer ahead of the image is kept short: %+v", h.Holders)
	}
	g.mu.Lock()
	waiting := len(g.waiting)
	g.mu.Unlock()
	if waiting != 1 {
		t.Fatalf("%d waiting", waiting)
	}
	g.pass() // the image (seq 7) is still behind 99: nothing is decided again
	g.mu.Lock()
	waiting = len(g.waiting)
	g.mu.Unlock()
	if waiting != 1 {
		t.Fatalf("an offer ahead of the image was decided again: %d", waiting)
	}
}

// 5.3: the Sanity Gate refused the A of the host to dial for a class other than
// injected (private, loopback): none, so the exit is never asked to resolve it. An
// injected answer is a filtered name and still goes to the exit by name.
func TestGrantsVerdictGateRefusal(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	w.h.cfg.GateClass = w.res.GateClass
	for i, name := range []string{"private.example.com", "loop.example.com"} {
		w.dot(epP1, name, dns.TypeA)
		if g.Table().Holders() == 0 {
			t.Fatalf("%s: no Grant was written, so the verdict cannot be tested", name)
		}
		if v := g.look(uint64(10+i), name); v.Kind != sock.VerdictNone {
			t.Fatalf("%s: a Gate refusal must give none: %+v", name, v)
		}
		// Still none for the 60 s the name is remembered, with no new lookup.
		hits := w.back.hitCount(name, dns.TypeA)
		if v := g.look(uint64(20+i), name); v.Kind != sock.VerdictNone || w.back.hitCount(name, dns.TypeA) != hits {
			t.Fatalf("%s: the refusal is remembered: %+v", name, v)
		}
	}
	w.dot(epP1, "inject.example.com", dns.TypeA)
	if v := g.look(30, "inject.example.com"); v.Kind != sock.VerdictProxy || v.Targets[0].Host != "inject.example.com" {
		t.Fatalf("an injected answer is a filtered name and goes to the exit by name: %+v", v)
	}
}

// A lookup of a replaced proxy session charges nothing into the rebuilt table, and a
// caller that went away marks no name as having no A.
func TestGrantsLookupOfAReplacedSession(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	w.dot(epP1, "pub.example.com", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if v := g.Lookup(ctx, 1, srcLocal, wn("pub.example.com"), 443); v.Kind != sock.VerdictNone {
		t.Fatalf("a cancelled lookup must answer none: %+v", v)
	}
	if g.Conns().NodeOpen() != 0 {
		t.Fatal("a cancelled lookup charged a place")
	}
	g.mu.Lock()
	marks := len(g.noA)
	g.mu.Unlock()
	if marks != 0 {
		t.Fatal("a cancelled lookup marked a name as having no A")
	}
	// The generation changes under a lookup that began before the rebuild.
	gen := g.Conns().Gen()
	g.LinkUp(2, nil)
	hit, ok := g.Table().Lookup(srcLocal, 64500, wn("pub.example.com"), grant.WidthExact)
	if !ok {
		t.Fatal("setup")
	}
	if _, _, why := g.Conns().AdmitAt(gen, 3, srcLocal, hit, []string{"exit0005"}, "127.0.0.20:20001"); why != grant.StaleGen {
		t.Fatalf("an old generation must not admit: %q", why)
	}
}

// A refusal list that changes names with each frame does not grow the map.
func TestGrantsStateReplacesRefusals(t *testing.T) {
	_, g, _ := newProxyWorld(t)
	for i := 0; i < 50; i++ {
		g.State(&sock.LinkState{Refused: []sock.Refusal{{Reason: "r" + itoa(i), Count: 1}}})
	}
	g.mu.Lock()
	n := len(g.refused)
	g.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d refusal names kept", n)
	}
}

// A grants_by_endpoint revocation in force refuses a Put and a forward, and a Grant
// the Endpoint holds ends with the next pass (4.6).
func TestGrantsByEndpointRevocationRefusesNewHolders(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	id := [16]byte(bytes.Repeat([]byte{epP1}, 16))
	w.h.Revocations().Set([]Revocation{{Kind: policyv1.RevocationKind_REVOCATION_KIND_GRANTS_BY_ENDPOINT, RevSeq: 99,
		ExpiresAt: w.now().Add(time.Hour), IDs: [][16]byte{id}}})
	w.dot(epP1, "pub.example.com", dns.TypeA)
	if n := g.Table().Holders(); n != 0 {
		t.Fatalf("a holder was written while grants_by_endpoint was in force: %d", n)
	}
	w.dot(epP2, "pub.example.com", dns.TypeA)
	if n := g.Table().Holders(); n != 1 {
		t.Fatalf("another Endpoint is not affected: %d", n)
	}
}

// 4.6: a served image is judged at most once in 5 s, a revocation at once.
func TestGrantsPassIsThrottledExceptForRevocations(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	g.pass()
	first := g.lastPass.Load()
	waitFor := func(what string, cond func() bool) bool {
		for i := 0; i < 100; i++ {
			if cond() {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	w.advance(time.Second)
	for i := 0; i < 5; i++ {
		g.Revalidate() // a burst of images
	}
	time.Sleep(200 * time.Millisecond)
	if g.lastPass.Load() != first {
		t.Fatal("an image within 5 s of the last pass was judged again")
	}
	g.RevalidateNow()
	if !waitFor("a revocation", func() bool { return g.lastPass.Load() != first }) {
		t.Fatal("a revocation must be judged at once")
	}
	second := g.lastPass.Load()
	w.advance(6 * time.Second)
	g.Revalidate()
	if !waitFor("an image after 5 s", func() bool { return g.lastPass.Load() != second }) {
		t.Fatal("an image more than 5 s after the last pass must be judged")
	}
}

// 5.3: the Gate's refusal decides the verdict on every path of dialAddrs, also when
// the 300 ms lookup had given up before the refusal came (a noA mark written with
// gated false) and when the Endpoint already has 64 lookups waiting.
func TestGrantsVerdictGateRefusalOnSkippedPaths(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	w.h.cfg.GateClass = w.res.GateClass
	const name = "private.example.com"
	w.dot(epP1, name, dns.TypeA)
	hit, ok := g.Table().Lookup(srcLocal, 64500, wn(name), grant.WidthExact)
	if !ok {
		t.Fatal("setup: no Grant")
	}
	nm := names.MustString(name)
	key := string(nm.Wire())
	if v := g.look(1, name); v.Kind != sock.VerdictNone {
		t.Fatalf("setup: %+v", v)
	}
	// A noA mark written before the refusal was known.
	g.mu.Lock()
	g.noA = map[string]noAMark{key: {at: g.h.now(), gated: false}}
	g.mu.Unlock()
	if v := g.look(2, name); v.Kind != sock.VerdictNone {
		t.Fatalf("a not-gated mark hid the Gate refusal: %+v", v)
	}
	g.mu.Lock()
	remembered := g.noA[key].gated
	g.mu.Unlock()
	if !remembered {
		t.Fatal("the mark must learn the refusal")
	}
	// The wait cap.
	g.mu.Lock()
	g.noA = map[string]noAMark{}
	g.aWaits[hit.Holders[0].Endpoint] = aWaitsEp
	g.mu.Unlock()
	if v := g.look(3, name); v.Kind != sock.VerdictNone {
		t.Fatalf("the wait cap hid the Gate refusal: %+v", v)
	}
}

// The first placement of a verdict is tied to the generation it was admitted under.
func TestGrantsPlacedAtRefusesAStaleGeneration(t *testing.T) {
	w, g, _ := newProxyWorld(t)
	w.dot(epP1, "pub.example.com", dns.TypeA)
	hit, ok := g.Table().Lookup(srcLocal, 64500, wn("pub.example.com"), grant.WidthExact)
	if !ok {
		t.Fatal("setup")
	}
	gen := g.Conns().Gen()
	if _, _, why := g.Conns().AdmitAt(gen, 5, srcLocal, hit, []string{"exit0005", "exit005b"}, "127.0.0.20:20001"); why != "" {
		t.Fatal(why)
	}
	g.LinkUp(2, nil) // the rebuild bumps the generation
	if _, _, why := g.Conns().AdmitAt(g.Conns().Gen(), 5, srcLocal, hit, []string{"exit0005", "exit005b"}, "127.0.0.20:20001"); why != "" {
		t.Fatal(why)
	}
	g.Conns().PlacedAt(gen, 5, "127.0.0.20:20002")
	cn, _ := g.Conns().Get(5)
	if cn.Socks != "127.0.0.20:20001" {
		t.Fatalf("a stale placement moved the new session's connection: %q", cn.Socks)
	}
	g.Conns().PlacedAt(g.Conns().Gen(), 5, "127.0.0.20:20002")
	if cn, _ = g.Conns().Get(5); cn.Socks != "127.0.0.20:20002" {
		t.Fatalf("a current placement must apply: %q", cn.Socks)
	}
}
