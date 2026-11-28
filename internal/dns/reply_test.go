package dns

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
)

func ecsOf(m *dns.Msg) *dns.EDNS0_SUBNET {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*dns.EDNS0_SUBNET); ok {
				return s
			}
		}
	}
	return nil
}

// RFC 7871 7.2.2 (p4n-W7-r4-3): an upstream ECS from the profile never shows in
// a reply to a client that sent none, and a client that sent ECS gets its own
// family, prefix and address back with the answer's scope.
func TestReplyECSEchoFollowsTheClient(t *testing.T) {
	ans := sharedpolicy.Answer{ECS: &sharedpolicy.ECSEcho{Source: netip.MustParsePrefix("198.51.100.0/24"), Scope: 20}}
	qn := names.MustString("www.example.com")

	plain := new(dns.Msg)
	plain.SetQuestion("www.example.com.", dns.TypeA)
	plain.SetEdns0(1232, false)
	if s := ecsOf(fromAnswer(plain, qn, ans)); s != nil {
		t.Fatalf("an ECS option reached a client that sent none: %+v", s)
	}

	withECS := new(dns.Msg)
	withECS.SetQuestion("www.example.com.", dns.TypeA)
	withECS.SetEdns0(1232, false)
	withECS.IsEdns0().Option = append(withECS.IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 2, SourceNetmask: 56, Address: netip.MustParseAddr("2001:db8:1:2::").AsSlice()})
	s := ecsOf(fromAnswer(withECS, qn, ans))
	if s == nil || s.Family != 2 || s.SourceNetmask != 56 || s.SourceScope != 20 || s.Address.String() != "2001:db8:1:2::" {
		t.Fatalf("echo is not the client's option with our scope: %+v", s)
	}
}
