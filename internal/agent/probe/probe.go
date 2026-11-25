// Package probe is the node's probe of every other node of its table (SC 8a.4,
// Plan T-541 and T-545): each round, every 5 s, runs a DoT part and a DoH part
// against the target's advertised address, each with a 2 s timeout, and the node
// reports the result as PeerView and uses it for its own local mode.
//
// The probes check the certificate chain against the configured CA and the exact
// SNI name, as a client would: no probe sets InsecureSkipVerify or a verifier
// that skips either check, so an on-path party that lacks the zone's key cannot
// answer them. They never check which node answers (every node holds the zone
// certificate), which is the recorded risk of a relay in SC 8a.9.
package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// Timing of SC 8a.4.
const (
	Every   = 5 * time.Second
	Timeout = 2 * time.Second
	// LabelLen is the length of a DoH probe label: 26 characters of [a-z2-7] are 130 bits.
	LabelLen = 26
	maxBody  = 4096
)

// Target is a node to probe: its id and its advertised address (dns_advertised_ip,
// the address clients are given).
type Target struct {
	ID   zone.NodeID
	Addr netip.Addr
}

// SOANames are the MNAME and RNAME the zone's SOA must carry. The zone answerer of
// the dns role builds its SOA from the same constants (DefaultSOA), so the probe
// and the answers agree by construction.
type SOANames struct{ MName, RName string }

// DefaultSOA is the SOA owner names of a zone: the first name server and the
// hostmaster mailbox.
func DefaultSOA(zoneName string) SOANames {
	z := dns.Fqdn(strings.ToLower(zoneName))
	return SOANames{MName: "ns1." + z, RName: "hostmaster." + z}
}

// Config is what a Prober needs.
type Config struct {
	// Zone is the live zone to probe through. It may change (a domain change), so it
	// is a function.
	Zone func() string
	// SOA overrides DefaultSOA.
	SOA func(zone string) SOANames
	// Roots returns the CA pool the zone certificate must chain to, or nil for the
	// system's public roots (public-CA mode).
	Roots func() *x509.CertPool

	DoTPort, DoHPort int // 853 and 443

	// Dial replaces the network dial, for tests: network and address are those the
	// probe would use.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time
	// Timeout and Every replace the SC 8a.4 values, for tests.
	Timeout, Every time.Duration
}

// Prober keeps the probe states.
type Prober struct {
	cfg Config

	mu      sync.Mutex
	targets []Target
	state   map[zone.NodeID]*zone.Probe
	down    zone.PeerDownSet
}

// New returns a Prober.
func New(cfg Config) *Prober {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.DoTPort == 0 {
		cfg.DoTPort = 853
	}
	if cfg.DoHPort == 0 {
		cfg.DoHPort = 443
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = Timeout
	}
	if cfg.Every == 0 {
		cfg.Every = Every
	}
	return &Prober{cfg: cfg, state: map[zone.NodeID]*zone.Probe{}}
}

// SetTargets replaces the nodes to probe (every other node of the table). A node
// that left is forgotten; one that enters starts unknown, as the contract says.
func (p *Prober) SetTargets(ts []Target) {
	p.mu.Lock()
	defer p.mu.Unlock()
	keep := map[zone.NodeID]bool{}
	for _, t := range ts {
		keep[t.ID] = true
		if p.state[t.ID] == nil {
			p.state[t.ID] = &zone.Probe{}
		}
	}
	for id := range p.state {
		if !keep[id] {
			delete(p.state, id)
			p.down.Forget(id)
		}
	}
	p.targets = append([]Target(nil), ts...)
}

// Run probes every Every until ctx ends.
func (p *Prober) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.Every)
	defer t.Stop()
	for {
		p.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round probes every target once, in parallel, and records the results.
func (p *Prober) Round(ctx context.Context) {
	p.mu.Lock()
	targets := append([]Target(nil), p.targets...)
	p.mu.Unlock()
	if p.cfg.Zone() == "" {
		// No live zone is known yet (a new node, or the Plain-only fallback): nothing was
		// probed, so nothing is recorded. A failure here would report every peer known and
		// down, where 8a.4 says the state stays unknown.
		return
	}
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pass := p.Probe(ctx, t.Addr)
			now := p.cfg.Now()
			p.mu.Lock()
			if s := p.state[t.ID]; s != nil {
				s.Round(now, pass)
				p.down.Round(now, t.ID, pass)
			}
			p.mu.Unlock()
		}()
	}
	wg.Wait()
}

// Probe is one round against one address: DoT and DoH in parallel, both must pass.
func (p *Prober) Probe(ctx context.Context, addr netip.Addr) bool {
	z := p.cfg.Zone()
	if z == "" {
		return false
	}
	var dotOK, dohOK bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); dotOK = p.dot(ctx, addr, z) == nil }()
	go func() { defer wg.Done(); dohOK = p.doh(ctx, addr, z) == nil }()
	wg.Wait()
	return dotOK && dohOK
}

// PeerView is the probe state of every target, for Heartbeat.peer_view: an entry
// in the unknown state has known false.
func (p *Prober) PeerView() []*hubv1.PeerProbe {
	now := p.cfg.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*hubv1.PeerProbe, 0, len(p.targets))
	for _, t := range p.targets {
		st := zone.ProbeUnknown
		if s := p.state[t.ID]; s != nil {
			st = s.State(now)
		}
		id := t.ID
		out = append(out, &hubv1.PeerProbe{NodeId: id[:], Known: st != zone.ProbeUnknown, Down: st == zone.ProbeDown})
	}
	return out
}

// PeerDown is the node's own view for local mode (8a.5): the nodes that are down
// after 90 s of failed rounds without a break.
func (p *Prober) PeerDown() map[zone.NodeID]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down.Snapshot()
}

// ---- the two parts

func (p *Prober) dial(ctx context.Context, addr netip.Addr, port int) (net.Conn, error) {
	ap := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	if p.cfg.Dial != nil {
		return p.cfg.Dial(ctx, "tcp", ap)
	}
	d := net.Dialer{}
	return d.DialContext(ctx, "tcp", ap)
}

func (p *Prober) tlsConfig(name string, protos ...string) *tls.Config {
	var roots *x509.CertPool
	if p.cfg.Roots != nil {
		roots = p.cfg.Roots()
	}
	// ServerName makes crypto/tls check the exact name; RootCAs nil is the system
	// pool. Nothing here relaxes either check.
	return &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: protos}
}

func (p *Prober) soa(z string) SOANames {
	if p.cfg.SOA != nil {
		return p.cfg.SOA(z)
	}
	return DefaultSOA(z)
}

// dot is the DoT part: TLS to 853 with SNI ns1.<zone>, query <zone> SOA.
func (p *Prober) dot(ctx context.Context, addr netip.Addr, zoneName string) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	z := dns.Fqdn(strings.ToLower(zoneName))
	raw, err := p.dial(ctx, addr, p.cfg.DoTPort)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, p.tlsConfig("ns1."+strings.TrimSuffix(z, "."), "dot"))
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	q := new(dns.Msg)
	q.SetQuestion(z, dns.TypeSOA)
	q.RecursionDesired = false
	wireQ, err := q.Pack()
	if err != nil {
		return err
	}
	frame := append([]byte{byte(len(wireQ) >> 8), byte(len(wireQ))}, wireQ...)
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return err
	}
	n := int(lenb[0])<<8 | int(lenb[1])
	if n < 12 || n > 4096 {
		return errors.New("probe: bad DoT frame length")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	return p.checkSOA(wireQ, resp, z)
}

// checkSOA is the pass rule of the DoT part: NOERROR, AA=1, the query ID, the
// question echoed byte for byte, and one SOA at the zone apex with the configured
// MNAME and RNAME. The serial is not compared.
func (p *Prober) checkSOA(query, resp []byte, z string) error {
	var m dns.Msg
	if err := m.Unpack(resp); err != nil {
		return err
	}
	if !m.Response || m.Rcode != dns.RcodeSuccess || !m.Authoritative {
		return errors.New("probe: not an authoritative NOERROR")
	}
	if m.Id != uint16(query[0])<<8|uint16(query[1]) {
		return errors.New("probe: wrong ID")
	}
	// The question section of the response starts at byte 12 and must be the
	// query's, byte for byte: a different case or a different name is a
	// different server or a relay that rewrote it.
	ql := len(query) - 12
	if len(resp) < 12+ql || string(resp[12:12+ql]) != string(query[12:]) || int(resp[4])<<8|int(resp[5]) != 1 {
		return errors.New("probe: question not echoed")
	}
	if len(m.Answer) != 1 {
		return errors.New("probe: not exactly one answer")
	}
	soa, ok := m.Answer[0].(*dns.SOA)
	if !ok || !strings.EqualFold(soa.Hdr.Name, z) {
		return errors.New("probe: the answer is not the apex SOA")
	}
	want := p.soa(z)
	if !strings.EqualFold(soa.Ns, want.MName) || !strings.EqualFold(soa.Mbox, want.RName) {
		return errors.New("probe: SOA MNAME or RNAME differ")
	}
	return nil
}

// Label returns a fresh probe label of 26 characters of [a-z2-7] from the system
// CSPRNG. It is used as a DoH name only and never sent in a DNS query.
func Label() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var b [LabelLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[b[i]&31]
	}
	return string(b[:]), nil
}

// verifyBody is the /v JSON of p4-nodes 7.6.
type verifyBody struct {
	Seen      *bool   `json:"seen"`
	N         *string `json:"n"`
	RidTag    *string `json:"rid_tag"`
	ClientTag *string `json:"client_tag"`
	ProtoTag  *string `json:"proto_tag"`
}

func hex32(s *string) bool {
	if s == nil || len(*s) != 32 {
		return false
	}
	_, err := hex.DecodeString(*s)
	return err == nil
}

// ParseVerify reports whether a body is the /v JSON, whatever `seen` says: a
// query for a guessed label over spoofed UDP could set it, so a probe never
// reads it (Plan T-046).
func ParseVerify(b []byte) error {
	var v verifyBody
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if v.Seen == nil || !hex32(v.N) || !hex32(v.RidTag) || !hex32(v.ClientTag) || !hex32(v.ProtoTag) {
		return errors.New("probe: not the /v body")
	}
	return nil
}

// doh is the DoH part: TLS to 443 with SNI <label>.verify.<zone>, GET /v.
func (p *Prober) doh(ctx context.Context, addr netip.Addr, zoneName string) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	label, err := Label()
	if err != nil {
		return err
	}
	host := label + ".verify." + strings.TrimSuffix(strings.ToLower(zoneName), ".")
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   p.tlsConfig(host, "h2", "http/1.1"),
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return p.dial(ctx, addr, p.cfg.DoHPort)
		},
		TLSHandshakeTimeout: p.cfg.Timeout,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/v", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return errors.New("probe: body too long")
	}
	return ParseVerify(body)
}
