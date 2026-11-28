package dns

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// The UDP size rule (SC 7, T-555): over UDP an answer that does not fit the limit
// is TC=1 with no records. The limit is the client's EDNS payload size raised to
// 512 and capped at 1232, and 512 without EDNS, for an identified source and a free
// one alike. big.example.com is about 1 KB (over 512, under 1232) and
// huge.example.com about 1.9 KB (over the cap), so every edge shows: size 0 and 100
// are raised to 512 and both answers are cut, 512 itself cuts both, 1232 lets the 1 KB
// answer through and cuts the huge one, and 4096 is capped at 1232 and cuts the huge
// one. Over TCP both are whole.
//
// Without the floor (a limit of the raw EDNS size) 0 and 100 would cut the small
// answer too; without `limit = 512` for a missing OPT the no-EDNS case would pass
// nothing; without the cap 4096 would let the huge answer out in one datagram.
func TestUDPSizeRuleAtEveryEdnsSize(t *testing.T) {
	type src struct {
		name string
		opt  qopt
		free bool
	}
	srcs := []src{
		{"identified", qopt{t: listen.UDP, src: "127.0.0.2", validated: vptr(true)}, false},
		{"free", freeUDPCookie(stranger), true},
	}
	cases := []struct {
		name         string
		size         int // -1: no OPT record at all
		bigCut, huge bool
	}{
		{"no EDNS", -1, true, true},
		{"EDNS 0", 0, true, true},
		{"EDNS 100", 100, true, true},
		{"EDNS 512", 512, true, true},
		{"EDNS 1232", 1232, false, true},
		{"EDNS 4096", 4096, false, true},
	}
	for _, s := range srcs {
		t.Run(s.name, func(t *testing.T) {
			w := newWorld(t)
			if s.free {
				newRig(t, w)
			}
			ask := func(name string, size int) *dns.Msg {
				m := mkq(name, dns.TypeA, qopt{})
				if size >= 0 {
					m.SetEdns0(uint16(size), false)
				}
				r := w.callMsg(s.opt, m)
				if r.Msg == nil {
					t.Fatalf("%s: no message (drop=%v)", name, r.Drop)
				}
				return r.Msg
			}
			for _, c := range cases {
				check := func(name string, want bool, answers int) {
					m := ask(name, c.size)
					if m.Truncated != want || (want && len(m.Answer) != 0) || (!want && len(m.Answer) != answers) {
						t.Errorf("%s, %s: truncated=%v with %d records, want truncated=%v with %d", c.name, name, m.Truncated, len(m.Answer), want, answers)
					}
				}
				check("big.example.com", c.bigCut, 60)
				check("huge.example.com", c.huge, 120)
				// A small answer fits every limit, so a size of 0 is not "nothing fits".
				if m := ask("allow.example.com", c.size); m.Truncated || len(aAddrs(m)) != 1 {
					t.Errorf("%s: a one-record answer was cut", c.name)
				}
			}
			// Over TCP the same answers are whole.
			tcp := qopt{t: listen.TCP, src: s.opt.src}
			if r := w.call(tcp, "huge.example.com", dns.TypeA); r.Msg == nil || r.Msg.Truncated || len(r.Msg.Answer) != 120 {
				t.Errorf("TCP: the huge answer was cut or lost")
			}
		})
	}
}
