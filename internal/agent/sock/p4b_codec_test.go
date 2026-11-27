package sock_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os/user"
	"reflect"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock/sockfake"
)

func b(n int, v byte) []byte { return bytes.Repeat([]byte{v}, n) }

// raw frames a JSON body the way the codec does, so a test can hand a reader a
// body that no Write would produce.
func raw(body string) []byte {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(body)))
	return append(h[:], body...)
}

func validLink() map[string]*sock.LinkMsg {
	src := []byte{10, 1, 2, 3}
	return map[string]*sock.LinkMsg{
		"hello":        {Type: sock.TLinkHello, Hello: &sock.LinkHello{Run: 1<<63 + 5}},
		"open":         {Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: []sock.OpenItem{{ID: 1<<64 - 1, Source: src, Socks: "127.0.0.20:20001", Tag: []byte("t")}}, Last: true}},
		"config":       {Type: sock.TLinkConfig, Config: &sock.ProxyConfig{BindIP: "203.0.113.5", MainPerSource: 512, MainNode: 8192, MainSniffMS: 5000, OtherPerSource: 64, OtherNode: 2048, OtherFirstMS: 1000, NewRate: 200, NewBurst: 1000, LookupPerSource: 64, LookupNode: 8192, MemUnit: 1 << 30, MemSlots: 3 << 29, DialFirstByteMS: 5000, MaxAgeS: 86400, IdleS: 600}},
		"source":       {Type: sock.TLinkSource, Source: &sock.LinkSource{ID: 2, Source: b(16, 1)}},
		"source_known": {Type: sock.TLinkSourceKnown, SourceKnown: &sock.LinkSourceKnown{ID: 2, Known: true}},
		"lookup":       {Type: sock.TLinkLookup, Lookup: &sock.LinkLookup{ID: 3, Source: src, Name: []byte("\x03www\x07example\x03com\x00"), Port: 443}},
		"verdict1": {Type: sock.TLinkVerdict, Verdict: &sock.LinkVerdict{ID: 3, Kind: sock.VerdictProxy, Tag: b(1024, 7),
			Targets: []sock.Target{{Socks: "127.0.0.20:20001", Host: "www.example.com", Port: 443}, {Socks: "127.0.0.20:20002", Host: "93.184.216.34", Port: 80}}}},
		"verdict2":  {Type: sock.TLinkVerdict, Verdict: &sock.LinkVerdict{ID: 3, Kind: sock.VerdictBlock, Endpoint: b(16, 1), Account: b(16, 2), PageHash: b(32, 3)}},
		"verdict0":  {Type: sock.TLinkVerdict, Verdict: &sock.LinkVerdict{ID: 3}},
		"moved":     {Type: sock.TLinkMoved, Moved: &sock.LinkMoved{ID: 3, Socks: "127.0.0.20:20002", Left: &sock.Left{Socks: "127.0.0.20:20001", StartMS: 5000}}},
		"end_ids":   {Type: sock.TLinkEnd, End: &sock.LinkEnd{IDs: []uint64{1, 2}}},
		"end_sock":  {Type: sock.TLinkEnd, End: &sock.LinkEnd{Socks: []string{"127.0.0.20:20001"}}},
		"closed":    {Type: sock.TLinkClosed, Closed: &sock.LinkClosed{IDs: []uint64{1}, Pending: []sock.Pending{{ID: 2, StartMS: 100}}}},
		"state":     {Type: sock.TLinkState, State: &sock.LinkState{Listening: true, Open: 9, Refused: []sock.Refusal{{Reason: "node_cap", Count: 3}}}},
		"stats":     {Type: sock.TLinkStats, Stats: &sock.LinkStats{}},
		"stats_res": {Type: sock.TLinkStatsRes, StatsRes: &sock.LinkStatsRes{Counters: []sock.Counter{{Name: "prefix24_unique", Value: 7}}, LastRefused: "node_cap"}},
	}
}

func TestLinkMessagesRoundTrip(t *testing.T) {
	for name, m := range validLink() {
		var buf bytes.Buffer
		if err := sock.LinkCodec.Write(&buf, m); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		got, err := sock.LinkCodec.Read(&buf)
		if err != nil {
			t.Fatalf("%s: read: %v", name, err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("%s: got %+v want %+v", name, got, m)
		}
	}
}

func TestLinkRefusesWhatItMust(t *testing.T) {
	bad := map[string]string{
		"unknown type":         `{"t":"nope","hello":{"run":1}}`,
		"no type":              `{"hello":{"run":1}}`,
		"type and field apart": `{"t":"hello","stats":{}}`,
		"two fields":           `{"t":"hello","hello":{"run":1},"stats":{}}`,
		"no field":             `{"t":"hello"}`,
		"unknown field":        `{"t":"hello","hello":{"run":1,"extra":1}}`,
		"trailing bytes":       `{"t":"hello","hello":{"run":1}} {}`,
		"source of 5 bytes":    `{"t":"source","source":{"id":1,"src":"AQIDBAU="}}`,
		"lookup port 8080":     `{"t":"lookup","lookup":{"id":1,"src":"CgECAw==","name":"AQ==","port":8080}}`,
		"lookup empty name":    `{"t":"lookup","lookup":{"id":1,"src":"CgECAw==","port":80}}`,
		"verdict kind 3":       `{"t":"verdict","verdict":{"id":1,"kind":3}}`,
		"verdict 1 no target":  `{"t":"verdict","verdict":{"id":1,"kind":1}}`,
		"verdict 1 four":       `{"t":"verdict","verdict":{"id":1,"kind":1,"targets":[` + strings.Repeat(`{"socks":"127.0.0.20:20001","host":"a.com","port":80},`, 3) + `{"socks":"127.0.0.20:20001","host":"a.com","port":80}]}}`,
		"verdict 1 host":       `{"t":"verdict","verdict":{"id":1,"kind":1,"targets":[{"socks":"127.0.0.20:20001","host":"a b","port":80}]}}`,
		"verdict 1 socks name": `{"t":"verdict","verdict":{"id":1,"kind":1,"targets":[{"socks":"localhost:20001","host":"a.com","port":80}]}}`,
		"verdict 2 no account": `{"t":"verdict","verdict":{"id":1,"kind":2,"endpoint":"AAAAAAAAAAAAAAAAAAAAAA=="}}`,
		"verdict 0 with page":  `{"t":"verdict","verdict":{"id":1,"kind":0,"page_hash":"AA=="}}`,
		"end both":             `{"t":"end","end":{"ids":[1],"socks":["127.0.0.20:20001"]}}`,
		"end neither":          `{"t":"end","end":{}}`,
		"closed nothing":       `{"t":"closed","closed":{}}`,
		"moved start too old":  `{"t":"moved","moved":{"id":1,"socks":"127.0.0.20:20001","left":{"socks":"127.0.0.20:20002","start_ms":90000000}}}`,
		"state reason":         `{"t":"state","state":{"listening":true,"open":1,"refused":[{"reason":"Has Space","n":1}]}}`,
		"config zero":          `{"t":"config","config":{"bind_ip":"203.0.113.5"}}`,
		"config bind name":     `{"t":"config","config":{"bind_ip":"example.com"}}`,
	}
	for name, body := range bad {
		if _, err := sock.LinkCodec.Read(bytes.NewReader(raw(body))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A frame of length 0, and one over the cap, are refused before anything is read.
	if _, err := sock.LinkCodec.Read(bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, sock.ErrFrame) {
		t.Fatalf("empty frame: %v", err)
	}
	if _, err := sock.LinkCodec.Read(bytes.NewReader([]byte{0, 0x10, 0, 1})); !errors.Is(err, sock.ErrFrame) {
		t.Fatalf("frame over the cap: %v", err)
	}
	// The sending side refuses a bad message too.
	if err := sock.LinkCodec.Write(&bytes.Buffer{}, &sock.LinkMsg{Type: sock.TLinkVerdict, Verdict: &sock.LinkVerdict{Kind: 9}}); err == nil {
		t.Fatal("wrote a bad verdict")
	}
}

func TestWhoMaySendWhat(t *testing.T) {
	proxy := []string{sock.TLinkHello, sock.TLinkOpen, sock.TLinkSource, sock.TLinkLookup, sock.TLinkMoved, sock.TLinkClosed, sock.TLinkState}
	dns := []string{sock.TLinkConfig, sock.TLinkSourceKnown, sock.TLinkVerdict, sock.TLinkEnd, sock.TLinkStatsRes}
	all := append(append([]string{sock.TLinkStats}, proxy...), dns...)
	for _, ty := range all {
		inProxy, inDNS, inRoot := sock.WhoProxy.May(ty), sock.MayDNSSend(ty), sock.WhoRoot.May(ty)
		n := 0
		for _, v := range []bool{inProxy, inDNS, inRoot} {
			if v {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s is sent by %d sides", ty, n)
		}
	}
	if !sock.WhoRoot.May(sock.TLinkStats) || sock.WhoRoot.May(sock.TLinkLookup) || sock.WhoRoot.May(sock.TLinkHello) {
		t.Fatal("root may send stats and nothing else")
	}
	if sock.Who(0).May(sock.TLinkStats) {
		t.Fatal("an unknown role may send nothing")
	}
}

func TestOpenPartIsHeldToItsByteCap(t *testing.T) {
	// 500 items with a full tag each: about 700 KiB, under the 1 MiB frame cap and
	// over the 512 KiB a part may have.
	items := make([]sock.OpenItem, 500)
	for i := range items {
		items[i] = sock.OpenItem{ID: uint64(i), Source: b(4, 1), Socks: "127.0.0.20:20001", Tag: b(sock.MaxTag, 9)}
	}
	m := &sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: items}}
	if err := sock.LinkCodec.Write(&bytes.Buffer{}, m); !errors.Is(err, sock.ErrFrame) {
		t.Fatalf("a part over 512 KiB was written: %v", err)
	}
	// And a reader refuses one that a peer wrote anyway.
	body := mustJSON(t, m)
	if _, err := sock.LinkCodec.Read(bytes.NewReader(raw(body))); !errors.Is(err, sock.ErrFrame) {
		t.Fatalf("a part over 512 KiB was read: %v", err)
	}
	// 5001 small items are over the item cap.
	small := make([]sock.OpenItem, sock.MaxPartItems+1)
	for i := range small {
		small[i] = sock.OpenItem{ID: uint64(i), Source: b(4, 1), Socks: "127.0.0.20:20001"}
	}
	if err := sock.LinkCodec.Write(&bytes.Buffer{}, &sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: small}}); err == nil {
		t.Fatal("5001 items in a part")
	}
}

func TestSplitAndAssembleAList(t *testing.T) {
	// 12,001 small items: three parts by count, each of which Write accepts.
	items := make([]sock.OpenItem, 12001)
	for i := range items {
		items[i] = sock.OpenItem{ID: uint64(i), Source: b(16, 1), Socks: "127.0.0.20:20001", Tag: []byte("x")}
	}
	parts, err := sock.SplitList(items)
	if err != nil || len(parts) != 3 {
		t.Fatalf("%d parts, %v", len(parts), err)
	}
	var asm sock.ListAssembler[sock.OpenItem]
	var whole []sock.OpenItem
	for i, p := range parts {
		var buf bytes.Buffer
		n, err := sock.LinkCodec.WriteSized(&buf, &sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: p, Last: i == len(parts)-1}})
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		got, size, err := sock.LinkCodec.ReadSized(&buf)
		if err != nil || size != n {
			t.Fatalf("part %d: %v (%d of %d)", i, err, size, n)
		}
		out, done, err := asm.Add(got.Open.Items, size, got.Open.Last)
		if err != nil || done != (i == len(parts)-1) {
			t.Fatalf("part %d: done=%v %v", i, done, err)
		}
		whole = out
	}
	if !reflect.DeepEqual(whole, items) {
		t.Fatal("the list that came out is not the list that went in")
	}

	// By bytes: 1,000 items with a full tag are cut by the 512 KiB, not by the count.
	big := make([]sock.OpenItem, 1000)
	for i := range big {
		big[i] = sock.OpenItem{ID: uint64(i), Source: b(4, 1), Socks: "127.0.0.20:20001", Tag: b(sock.MaxTag, 9)}
	}
	parts, err = sock.SplitList(big)
	if err != nil || len(parts) < 2 {
		t.Fatalf("%d parts, %v", len(parts), err)
	}
	for i, p := range parts {
		if err := sock.LinkCodec.Write(&bytes.Buffer{}, &sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: p, Last: i == len(parts)-1}}); err != nil {
			t.Fatalf("part %d does not fit: %v", i, err)
		}
	}

	// An empty list is one empty last part.
	parts, err = sock.SplitList([]sock.OpenItem(nil))
	if err != nil || len(parts) != 1 || len(parts[0]) != 0 {
		t.Fatalf("empty: %d parts, %v", len(parts), err)
	}
}

func TestAListOverItsCapIsRefused(t *testing.T) {
	var asm sock.ListAssembler[int]
	var err error
	// 128 parts of 512 KiB are exactly 64 MiB; the next byte is over.
	for i := 0; i < 128; i++ {
		if _, _, err = asm.Add(nil, sock.MaxPartBytes, false); err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
	}
	if _, _, err = asm.Add(nil, 1, false); err == nil {
		t.Fatal("a list over 64 MiB was taken")
	}
	// After the error the assembler is empty again.
	if out, done, err := asm.Add([]int{1}, 10, true); err != nil || !done || len(out) != 1 {
		t.Fatalf("%v %v %v", out, done, err)
	}
	// A part over its own caps is refused.
	if _, _, err := asm.Add(make([]int, sock.MaxPartItems+1), 10, false); err == nil {
		t.Fatal("a part over the item cap")
	}
	// The sender refuses to make one: 70 MiB of items cannot be split.
	huge := make([]sock.OpenItem, 52000)
	for i := range huge {
		huge[i] = sock.OpenItem{ID: uint64(i), Source: b(4, 1), Socks: "127.0.0.20:20001", Tag: b(sock.MaxTag, 9)}
	}
	if _, err := sock.SplitList(huge); err == nil {
		t.Fatal("a list of over 64 MiB was split")
	}
}

func TestServeFrameThenRawBytes(t *testing.T) {
	proxy, block := sockfake.Pair(0, 0)
	f := &sock.ServeFrame{Name: "blocked.example.com", Port: 443, Endpoint: b(16, 1), Account: b(16, 2), Source: []byte{10, 0, 0, 9}, PageHash: b(32, 3)}
	go func() {
		defer proxy.Close()
		_ = sock.ServeCodec.Write(proxy, f)
		_, _ = proxy.Write([]byte("\x16\x03\x01 client hello bytes"))
	}()
	got, err := sock.ServeCodec.Read(block)
	if err != nil || !reflect.DeepEqual(got, f) {
		t.Fatalf("%+v %v", got, err)
	}
	// The frame took its own bytes and not one more: the raw bytes are the client's.
	rest := make([]byte, 64)
	n, _ := block.Read(rest)
	if !strings.HasPrefix(string(rest[:n]), "\x16\x03\x01 client") {
		t.Fatalf("the raw bytes after the frame were eaten: %q", rest[:n])
	}
	for name, body := range map[string]string{
		"port 8443":  `{"name":"a.com","port":8443,"endpoint":"AAAAAAAAAAAAAAAAAAAAAA==","account":"AAAAAAAAAAAAAAAAAAAAAA==","src":"CgAACQ=="}`,
		"name space": `{"name":"a b","port":80,"endpoint":"AAAAAAAAAAAAAAAAAAAAAA==","account":"AAAAAAAAAAAAAAAAAAAAAA==","src":"CgAACQ=="}`,
		"no source":  `{"name":"a.com","port":80,"endpoint":"AAAAAAAAAAAAAAAAAAAAAA==","account":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
		"page hash":  `{"name":"a.com","port":80,"endpoint":"AAAAAAAAAAAAAAAAAAAAAA==","account":"AAAAAAAAAAAAAAAAAAAAAA==","src":"CgAACQ==","page_hash":"AA=="}`,
	} {
		if _, err := sock.ServeCodec.Read(bytes.NewReader(raw(body))); err == nil {
			t.Errorf("serve %s: accepted", name)
		}
	}
}

func TestBlockMessagesRoundTripAndRefuse(t *testing.T) {
	ok := []*sock.BlockMsg{
		{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: b(32, 1)}},
		{Type: sock.BlockNeedKey, NeedKey: &sock.NeedKey{Endpoint: b(16, 1), Account: b(16, 2)}},
		{Type: sock.BlockPage, Page: &sock.PageMsg{Hash: b(32, 1), Blob: b(sock.MaxPageBlob, 5)}},
		{Type: sock.BlockPage, Page: &sock.PageMsg{Hash: b(32, 1)}},
		{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: b(8, 4)}},
		{Type: sock.BlockIntermediate, Intermediate: &sock.Intermediate{Account: b(16, 2), Epoch: b(8, 4), Chain: [][]byte{b(900, 1), b(800, 2)}, Key: b(138, 3), NotAfter: 1 << 40}},
		{Type: sock.BlockUnblock, Unblock: &sock.UnblockMsg{Endpoint: b(16, 1), Profile: b(16, 2), Name: "a.example.com", Message: "please", At: 1700000000}},
	}
	for _, m := range ok {
		var buf bytes.Buffer
		if err := sock.BlockCodec.Write(&buf, m); err != nil {
			t.Fatalf("%s: %v", m.Type, err)
		}
		got, err := sock.BlockCodec.Read(&buf)
		if err != nil || !reflect.DeepEqual(got, m) {
			t.Fatalf("%s: %+v %v", m.Type, got, err)
		}
	}
	bad := []*sock.BlockMsg{
		{Type: sock.BlockNeedPage, NeedPage: &sock.NeedPage{Hash: b(31, 1)}},
		{Type: sock.BlockPage, Page: &sock.PageMsg{Hash: b(32, 1), Blob: b(sock.MaxPageBlob+1, 5)}},
		{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: b(16, 4)}},
		{Type: sock.BlockIntermediate, Intermediate: &sock.Intermediate{Account: b(16, 2), Epoch: b(8, 4), Key: b(138, 3), NotAfter: 1}},
		{Type: sock.BlockIntermediate, Intermediate: &sock.Intermediate{Account: b(16, 2), Epoch: b(8, 4), Chain: [][]byte{b(1, 1)}, NotAfter: 1}},
		{Type: sock.BlockUnblock, Unblock: &sock.UnblockMsg{Endpoint: b(16, 1), Profile: b(15, 2), Name: "a.com"}},
		{Type: sock.BlockUnblock, Unblock: &sock.UnblockMsg{Endpoint: b(16, 1), Profile: b(16, 2)}},
		{Type: sock.BlockNeedPage, NeedKey: &sock.NeedKey{Endpoint: b(16, 1), Account: b(16, 2)}},
	}
	for i, m := range bad {
		if err := sock.BlockCodec.Write(&bytes.Buffer{}, m); err == nil {
			t.Errorf("bad %d: written", i)
		}
	}
	if !sock.MayBlockSend(sock.BlockUnblock) || sock.MayBlockSend(sock.BlockPage) || !sock.MayAgentSend(sock.BlockEpoch) || sock.MayAgentSend(sock.BlockNeedKey) {
		t.Fatal("directions of the block socket")
	}
}

func TestCtlRunFormsAreClosed(t *testing.T) {
	id := strings.Repeat("ab", 16)
	good := []sock.CtlRun{
		{ID: 1, Version: "v26.11.9", Op: sock.OpTest, Stdin: []byte("{}")},
		{ID: 2, Version: "v26.11.9", Op: sock.OpAddOut, Slot: "a", Stdin: []byte("{}")},
		{ID: 3, Version: "v26.11.9", Op: sock.OpRmIn, Slot: "b", Tags: []string{"in:" + id + ".3"}},
		{ID: 4, Version: "v26.11.9", Op: sock.OpRmOut, Slot: "a", Tags: []string{"L" + id + ".3.0", "L" + id + ".3.12"}},
		{ID: 5, Version: "v26.11.9", Op: sock.OpRmRules, Slot: "a", Tags: []string{"L" + id + ".3"}},
	}
	for _, r := range good {
		r := r
		var buf bytes.Buffer
		m := &sock.CtlMsg{Type: sock.CtlTypeRun, Run: &r}
		if err := sock.CtlCodec.Write(&buf, m); err != nil {
			t.Fatalf("%d: %v", r.ID, err)
		}
		if got, err := sock.CtlCodec.Read(&buf); err != nil || !reflect.DeepEqual(got, m) {
			t.Fatalf("%d: %v", r.ID, err)
		}
	}
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = "L" + id + ".1.0"
	}
	bad := map[string]sock.CtlRun{
		"version":              {Version: "26.11.9", Op: sock.OpTest, Stdin: []byte("{}")},
		"version with path":    {Version: "v1.2.3/../x", Op: sock.OpTest, Stdin: []byte("{}")},
		"unknown op":           {Version: "v1.2.3", Op: "run", Slot: "a", Stdin: []byte("{}")},
		"test with slot":       {Version: "v1.2.3", Op: sock.OpTest, Slot: "a", Stdin: []byte("{}")},
		"ado with no slot":     {Version: "v1.2.3", Op: sock.OpAddOut, Stdin: []byte("{}")},
		"slot c":               {Version: "v1.2.3", Op: sock.OpAddOut, Slot: "c", Stdin: []byte("{}")},
		"ado with a tag":       {Version: "v1.2.3", Op: sock.OpAddOut, Slot: "a", Stdin: []byte("{}"), Tags: []string{"L" + id + ".1.0"}},
		"ado with no stdin":    {Version: "v1.2.3", Op: sock.OpAddOut, Slot: "a"},
		"rmo with stdin":       {Version: "v1.2.3", Op: sock.OpRmOut, Slot: "a", Tags: []string{"L" + id + ".1.0"}, Stdin: []byte("x")},
		"rmo without a tag":    {Version: "v1.2.3", Op: sock.OpRmOut, Slot: "a"},
		"a file name as a tag": {Version: "v1.2.3", Op: sock.OpRmOut, Slot: "a", Tags: []string{"config.json"}},
		"a URL as a tag":       {Version: "v1.2.3", Op: sock.OpRmIn, Slot: "a", Tags: []string{"http://example.com/x"}},
		"a path as a tag":      {Version: "v1.2.3", Op: sock.OpRmIn, Slot: "a", Tags: []string{"in:../../etc/passwd"}},
		"rmi with an out tag":  {Version: "v1.2.3", Op: sock.OpRmIn, Slot: "a", Tags: []string{"L" + id + ".1.0"}},
		"rmrules with a hop":   {Version: "v1.2.3", Op: sock.OpRmRules, Slot: "a", Tags: []string{"L" + id + ".1.0"}},
		"upper-case id":        {Version: "v1.2.3", Op: sock.OpRmRules, Slot: "a", Tags: []string{"L" + strings.ToUpper(id) + ".1"}},
		"17 tags":              {Version: "v1.2.3", Op: sock.OpRmOut, Slot: "a", Tags: tooMany},
		"stdin over 256 KiB":   {Version: "v1.2.3", Op: sock.OpAddOut, Slot: "a", Stdin: b(sock.MaxCtlStdin+1, 1)},
	}
	for name, r := range bad {
		r := r
		if err := sock.CtlCodec.Write(&bytes.Buffer{}, &sock.CtlMsg{Type: sock.CtlTypeRun, Run: &r}); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	// A result carries at most 4 KiB of error.
	if err := sock.CtlCodec.Write(&bytes.Buffer{}, &sock.CtlMsg{Type: sock.CtlTypeResult, Result: &sock.CtlResult{ID: 1, Exit: 23, Error: strings.Repeat("e", 4096)}}); err != nil {
		t.Fatal(err)
	}
	if err := sock.CtlCodec.Write(&bytes.Buffer{}, &sock.CtlMsg{Type: sock.CtlTypeResult, Result: &sock.CtlResult{ID: 1, Error: strings.Repeat("e", 4097)}}); err == nil {
		t.Fatal("an error text over 4 KiB")
	}
	// The largest legal stdin fits the frame cap once it is base64.
	if err := sock.CtlCodec.Write(&bytes.Buffer{}, &sock.CtlMsg{Type: sock.CtlTypeRun, Run: &sock.CtlRun{ID: 1, Version: "v1.2.3", Op: sock.OpTest, Stdin: b(sock.MaxCtlStdin, 1)}}); err != nil {
		t.Fatal(err)
	}
}

func TestPeerChecks(t *testing.T) {
	srv, _ := sockfake.Pair(42, 0) // the server reads its peer's uid as 42
	allow := sock.UIDsCheckWith(sockfake.GetUID, 7, 42)
	if err := allow(srv); err != nil {
		t.Fatal(err)
	}
	if err := sock.UIDsCheckWith(sockfake.GetUID, 7)(srv); err == nil {
		t.Fatal("a uid that is not named passed")
	}
	if err := sock.UIDsCheckWith(sockfake.GetUID)(srv); err == nil {
		t.Fatal("a check that names nobody must let nobody in")
	}
	// A connection that is not the fake kind is refused by the getter, not passed.
	c1, c2 := newPipe()
	defer c1.Close()
	defer c2.Close()
	if err := allow(c1); err == nil {
		t.Fatal("a connection with no readable uid passed")
	}

	root, _ := sockfake.Pair(0, 0)
	proxy, _ := sockfake.Pair(7, 0)
	other, _ := sockfake.Pair(9, 0)
	if w, err := sock.PeerRole(sockfake.GetUID, root, 7); err != nil || w != sock.WhoRoot {
		t.Fatalf("%v %v", w, err)
	}
	if w, err := sock.PeerRole(sockfake.GetUID, proxy, 7); err != nil || w != sock.WhoProxy {
		t.Fatalf("%v %v", w, err)
	}
	if _, err := sock.PeerRole(sockfake.GetUID, other, 7); err == nil {
		t.Fatal("a third uid has a role")
	}
}

func TestLookupUIDs(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		switch name {
		case "ctrlz-proxy":
			return &user.User{Uid: "991"}, nil
		case "odd":
			return &user.User{Uid: "S-1-5"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	got, err := sock.LookupUIDs(lookup, "ctrlz-proxy")
	if err != nil || len(got) != 1 || got[0] != 991 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := sock.LookupUIDs(lookup, "ctrlz-proxy", "ctrlz-nobody"); err == nil {
		t.Fatal("an unknown account must stop the socket from starting")
	}
	if _, err := sock.LookupUIDs(lookup, "odd"); err == nil {
		t.Fatal("a non-numeric uid")
	}
}

func TestFakeEndpointsCarryFrames(t *testing.T) {
	dns, proxy := sockfake.LinkPair()
	defer dns.Close()
	defer proxy.Close()
	go func() { _ = proxy.Send(validLink()["hello"]) }()
	m, err := dns.Recv()
	if err != nil || m.Type != sock.TLinkHello {
		t.Fatalf("%+v %v", m, err)
	}
	// Garbage ends the read with an error: the owner closes the connection.
	go func() { _ = proxy.SendRaw(raw(`{"t":"lookup"}`)) }()
	if _, err := dns.Recv(); err == nil {
		t.Fatal("a lookup with no body was taken")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	j, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(j)
}

func newPipe() (net.Conn, net.Conn) { return net.Pipe() }

// B1n-r1-4 and 10: a closing bracket after the message is a byte after the
// message, though json.Decoder.More says there is nothing more.
func TestLinkRefusesAClosingBracketAfterTheMessage(t *testing.T) {
	base := `{"t":"hello","hello":{"run":1}}`
	if _, err := sock.LinkCodec.Read(bytes.NewReader(raw(base + " \n"))); err != nil {
		t.Fatalf("white space after the message: %v", err)
	}
	for _, tail := range []string{"}", "]", "}}", " ]junk", "{}"} {
		if _, err := sock.LinkCodec.Read(bytes.NewReader(raw(base + tail))); err == nil {
			t.Errorf("tail %q accepted", tail)
		}
	}
}

// B1n-r1-12: the error of a decode does not carry text the peer chose.
func TestDecodeErrorsDoNotQuoteThePeer(t *testing.T) {
	key := strings.Repeat("Z", 5000)
	for _, body := range []string{
		`{"t":"hello","` + key + `":1}`,
		`{"t":"hello","hello":{"run":"` + key + `"}}`,
		`{"t":"hello","hello":{"run":1.5e999999}}`,
	} {
		_, err := sock.LinkCodec.Read(bytes.NewReader(raw(body)))
		if err == nil {
			t.Fatal("accepted")
		}
		if len(err.Error()) > 100 || strings.Contains(err.Error(), "ZZZZ") {
			t.Fatalf("the error carries the peer's text: %.120s", err.Error())
		}
	}
}

// B1n-r1-2: a node that has seen many operators can still answer stats.
func TestStatsResHoldsTheCountersOfManyASNs(t *testing.T) {
	mk := func(n int) *sock.LinkMsg {
		c := make([]sock.Counter, n)
		for i := range c {
			c[i] = sock.Counter{Name: "prefix24_unique", Value: uint64(i)}
		}
		return &sock.LinkMsg{Type: sock.TLinkStatsRes, StatsRes: &sock.LinkStatsRes{Counters: c}}
	}
	var buf bytes.Buffer
	if err := sock.LinkCodec.Write(&buf, mk(600)); err != nil { // about 100 ASNs at six names
		t.Fatalf("600 counters: %v", err)
	}
	if _, err := sock.LinkCodec.Read(&buf); err != nil {
		t.Fatal(err)
	}
	if err := sock.LinkCodec.Write(&bytes.Buffer{}, mk(sock.MaxCounters)); err != nil {
		t.Fatalf("the cap itself: %v", err)
	}
	if err := sock.LinkCodec.Write(&bytes.Buffer{}, mk(sock.MaxCounters+1)); err == nil {
		t.Fatal("over the cap")
	}
}

// B1n-r1-5: a block-page connection has no SOCKS leg; the open list may name it
// with an empty socks, and a socks that is there must still be ip:port.
func TestOpenItemOfABlockPageHasNoSocks(t *testing.T) {
	src := []byte{10, 1, 2, 3}
	ok := &sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: []sock.OpenItem{{ID: 1, Source: src, Tag: []byte("t")}}, Last: true}}
	var buf bytes.Buffer
	if err := sock.LinkCodec.Write(&buf, ok); err != nil {
		t.Fatal(err)
	}
	got, err := sock.LinkCodec.Read(&buf)
	if err != nil || got.Open.Items[0].Socks != "" {
		t.Fatalf("%+v %v", got, err)
	}
	bad := &sock.LinkMsg{Type: sock.TLinkOpen, Open: &sock.LinkOpen{Items: []sock.OpenItem{{ID: 1, Source: src, Socks: "localhost:1"}}}}
	if err := sock.LinkCodec.Write(&bytes.Buffer{}, bad); err == nil {
		t.Fatal("a socks that is not ip:port")
	}
}

// B1n-r1-11: a lookup name is held to the wire form `names` makes.
func TestLookupNameIsHeldToItsWireForm(t *testing.T) {
	src := []byte{10, 1, 2, 3}
	try := func(name string) error {
		return sock.LinkCodec.Write(&bytes.Buffer{}, &sock.LinkMsg{Type: sock.TLinkLookup, Lookup: &sock.LinkLookup{ID: 1, Source: src, Name: []byte(name), Port: 443}})
	}
	for _, ok := range []string{"\x03www\x07example\x03com\x00", "\x01a\x00", "\x05a-b_1\x00", "\x0b" + strings.Repeat("a", 11) + "\x00"} {
		if err := try(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	long := strings.Repeat("\x3f"+strings.Repeat("a", 63), 4) + "\x00" // 257 bytes
	for name, bad := range map[string]string{
		"label past the end": "\x3fA\x00",
		"upper case":         "\x03WWW\x00",
		"not rooted":         "\x03www",
		"root only":          "\x00",
		"bytes after root":   "\x01a\x00\x01b\x00",
		"label of 64":        "\x40" + strings.Repeat("a", 64) + "\x00",
		"compression":        "\xc0\x0c",
		"dot in a label":     "\x03a.b\x00",
		"space":              "\x03a b\x00",
		"too long":           long,
		"zero label inside":  "\x01a\x00\x00",
	} {
		if try(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// B1n-r1-15: the fake pairs give each end its own uid, and the proxy is not root.
func TestFakePairsDoNotMakeTheProxyRoot(t *testing.T) {
	dns, proxy := sockfake.LinkPair()
	defer dns.Close()
	defer proxy.Close()
	w, err := sock.PeerRole(sockfake.GetUID, dns.Conn, sockfake.UIDProxy)
	if err != nil || w != sock.WhoProxy || !w.May(sock.TLinkHello) {
		t.Fatalf("the proxy end: %v %v", w, err)
	}
	rdns, rclient := sockfake.LinkPairAs(sockfake.UIDRoot)
	defer rdns.Close()
	defer rclient.Close()
	w, err = sock.PeerRole(sockfake.GetUID, rdns.Conn, sockfake.UIDProxy)
	if err != nil || w != sock.WhoRoot || w.May(sock.TLinkHello) || !w.May(sock.TLinkStats) {
		t.Fatalf("the root client: %v %v", w, err)
	}
	if u, _ := sockfake.GetUID(proxy.Conn); u != sockfake.UIDDNS {
		t.Fatalf("the proxy reads dns as uid %d", u)
	}
}
