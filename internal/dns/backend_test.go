package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
)

// recorder is a Reporter that keeps what it is told.
type recorder struct {
	mu      sync.Mutex
	proofs  []*hubv1.ProofObservation
	learned []*hubv1.LearnedIP
	acts    []*telemetryv1.ActivityEntry
}

func (r *recorder) Proof(p *hubv1.ProofObservation) {
	r.mu.Lock()
	r.proofs = append(r.proofs, p)
	r.mu.Unlock()
}

func (r *recorder) LearnedIP(l *hubv1.LearnedIP) {
	r.mu.Lock()
	r.learned = append(r.learned, l)
	r.mu.Unlock()
}

func (r *recorder) Activity(a *telemetryv1.ActivityEntry) {
	r.mu.Lock()
	r.acts = append(r.acts, a)
	r.mu.Unlock()
}

func (r *recorder) counts() (proofs, learned, acts int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.proofs), len(r.learned), len(r.acts)
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.proofs, r.learned, r.acts = nil, nil, nil
	r.mu.Unlock()
}

// fakeBackend stands in for the identified Unbound (and for an upstream): it
// answers from a fixed table of names, counts what it is asked, and can be made
// to fail or stall.
type fakeBackend struct {
	mu    sync.Mutex
	hits  map[string]int
	total atomic.Int64
	fail  atomic.Bool
	stall atomic.Bool
	delay atomic.Int64 // nanoseconds
	last  *dns.Msg     // the latest query, as the resolver sent it
}

func newFakeBackend() *fakeBackend { return &fakeBackend{hits: map[string]int{}} }

func (b *fakeBackend) Route(*names.Name, uint16) string { return "" }

func (b *fakeBackend) hitCount(name string, qt uint16) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hits[strings.ToLower(dns.Fqdn(name))+"/"+dns.TypeToString[qt]]
}

func (b *fakeBackend) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	q := req.Question[0]
	b.mu.Lock()
	b.hits[strings.ToLower(q.Name)+"/"+dns.TypeToString[q.Qtype]]++
	b.mu.Unlock()
	b.total.Add(1)
	b.mu.Lock()
	b.last = req.Copy()
	b.mu.Unlock()
	if d := time.Duration(b.delay.Load()); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	if b.stall.Load() {
		<-ctx.Done()
		return nil, "", ctx.Err()
	}
	if b.fail.Load() {
		return nil, "", errors.New("backend down")
	}
	return answerFor(req), "", nil
}

func rrA(name string, ip string) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(ip).To4()}
}

func soaFor(zone string) dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
		Ns: "ns." + zone, Mbox: "h." + zone, Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minttl: 120}
}

// answerFor is the data of the world: every name has an address unless this
// table says otherwise.
func answerFor(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	addr := map[string]string{
		"www.example.com": "192.0.2.20", "allow.example.com": "192.0.2.30", "ads.example.com": "192.0.2.66",
		"shared.example.com": "192.0.2.40", "panel.example.org": "192.0.2.77", "admin.example.org": "192.0.2.78",
		"www.example.ir": "192.0.2.88", "captive.apple.com": "17.253.1.1", "inject.example.com": "10.10.34.5",
		"private.example.com": "192.168.1.5", "loop.example.com": "127.0.0.1", "secure.example.com": "192.0.2.55",
		"connectivitycheck.gstatic.com": "142.250.1.1",
		"pub.example.com":               "93.184.216.34", "pub2.example.com": "93.184.216.35", "pub3.example.com": "93.184.216.36", "ir.example.com": "5.200.1.1",
	}
	switch {
	case name == "nx.example.com.":
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{soaFor("example.com.")}
		return m
	case name == "alias.example.com." && q.Qtype == dns.TypeA:
		m.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "www.example.com."},
			rrA("www.example.com.", "192.0.2.20"),
		}
		return m
	case name == "cloak.example.com." && q.Qtype == dns.TypeA:
		m.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "ads.example.com."},
			rrA("ads.example.com.", "192.0.2.66"),
		}
		return m
	case name == "big.example.com." && q.Qtype == dns.TypeA:
		for i := 0; i < 60; i++ {
			m.Answer = append(m.Answer, rrA(q.Name, "192.0.2."+itoa(i+1)))
		}
		return m
	case name == "huge.example.com." && q.Qtype == dns.TypeA:
		// about 1.9 KB on the wire: over 1232, the most a UDP answer may be
		for i := 0; i < 120; i++ {
			m.Answer = append(m.Answer, rrA(q.Name, "192.0.2."+itoa(i+1)))
		}
		return m
	case name == "stray.example.com." && q.Qtype == dns.TypeA:
		// a hostile upstream adds a record for another name
		m.Answer = []dns.RR{rrA(q.Name, "192.0.2.61"), rrA("www.example.com.", "6.6.6.6")}
		return m
	case name == "servfail.example.com.":
		m.Rcode = dns.RcodeServerFailure
		return m
	case q.Qtype == dns.TypeAAAA && name == "v6.example.com.":
		m.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")}}
		return m
	case q.Qtype == dns.TypeA:
		ip, ok := addr[strings.TrimSuffix(name, ".")]
		if !ok {
			ip = "192.0.2.99"
		}
		m.Answer = []dns.RR{rrA(q.Name, ip)}
		if strings.TrimSuffix(name, ".") == "secure.example.com" {
			m.AuthenticatedData = true
		}
		return m
	}
	// every other type: NODATA with an SOA
	m.Ns = []dns.RR{soaFor("example.com.")}
	return m
}

// ---- reading replies

func msgOf(r listen.Reply) *dns.Msg { return r.Msg }

func aAddrs(m *dns.Msg) []string {
	var out []string
	if m == nil {
		return out
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}

func rcodeOf(r listen.Reply) string {
	if r.Msg == nil {
		return "none"
	}
	return dns.RcodeToString[r.Msg.Rcode]
}
