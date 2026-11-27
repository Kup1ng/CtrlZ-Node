package sock

import (
	"errors"
	"fmt"
)

// proxy.sock (p4b-proxy 2.1, 5.1): /run/ctrlz-link/proxy.sock, served by dns,
// connected to by proxy. These are the messages of both directions, as Go types;
// internal/link (B3 and B4) holds the server and client around them.
//
// Who may send what is part of the type and is checked by MayProxySend,
// MayDNSSend and MayRootSend: the one rule the socket has is that a peer of uid 0
// (the reader of `ctrlz-node grants-stats`) may send nothing but `stats`, and that
// the proxy may not send what dns sends.
const (
	TLinkHello       = "hello"
	TLinkOpen        = "open"
	TLinkConfig      = "config"
	TLinkSource      = "source"
	TLinkSourceKnown = "source_known"
	TLinkLookup      = "lookup"
	TLinkVerdict     = "verdict"
	TLinkMoved       = "moved"
	TLinkEnd         = "end"
	TLinkClosed      = "closed"
	TLinkState       = "state"
	TLinkStats       = "stats"
	TLinkStatsRes    = "stats_res"
)

// Verdict kinds: 0 none (close with no byte), 1 Redirect through SOCKS, 2 the block
// page.
const (
	VerdictNone  = 0
	VerdictProxy = 1
	VerdictBlock = 2
)

// Caps of the link's fields.
const (
	MaxTag       = 1 << 10 // an opaque tag of the verdict, 1 KiB (2.1)
	MaxTargets   = 3
	MaxNameWire  = 255
	MaxCounters  = 256
	MaxRefusals  = 64
	MaxIDsPerMsg = MaxPartItems
	// maxStartMS is the age of a connection at its end (12: 24 h), so a start
	// offset beyond it is a bug and not a time.
	maxStartMS = 24 * 60 * 60 * 1000
)

// LinkMsg is one frame of proxy.sock. Exactly the field of its Type is set.
type LinkMsg struct {
	Type string `json:"t"`

	Hello       *LinkHello       `json:"hello,omitempty"`
	Open        *LinkOpen        `json:"open,omitempty"`
	Config      *ProxyConfig     `json:"config,omitempty"`
	Source      *LinkSource      `json:"source,omitempty"`
	SourceKnown *LinkSourceKnown `json:"source_known,omitempty"`
	Lookup      *LinkLookup      `json:"lookup,omitempty"`
	Verdict     *LinkVerdict     `json:"verdict,omitempty"`
	Moved       *LinkMoved       `json:"moved,omitempty"`
	End         *LinkEnd         `json:"end,omitempty"`
	Closed      *LinkClosed      `json:"closed,omitempty"`
	State       *LinkState       `json:"state,omitempty"`
	Stats       *LinkStats       `json:"stats,omitempty"`
	StatsRes    *LinkStatsRes    `json:"stats_res,omitempty"`
}

// LinkHello opens the proxy's side. Run is random per start of the proxy, so dns
// tells a restart of the proxy (whose open list is new) from a reconnect.
type LinkHello struct {
	Run uint64 `json:"run"`
}

// OpenItem is one open connection the proxy reports after it connects: its id (a
// counter of 64 bits), the client source (4 or 16 bytes), the SOCKS address of its
// target, and the tag of the verdict that opened it (the charge it keeps, 4.3).
type OpenItem struct {
	ID     uint64 `json:"id"`
	Source []byte `json:"src"`
	Socks  string `json:"socks"`
	Tag    []byte `json:"tag,omitempty"`
}

// LinkOpen is one part of the list of all open connections. The proxy sends it
// after hello; Last marks the final part, after which dns sends `config`.
type LinkOpen struct {
	Items []OpenItem `json:"items"`
	Last  bool       `json:"last,omitempty"`
}

// ProxyConfig is what dns tells the proxy to apply once it has judged the open list
// (4.6): the address to listen on and the limits of 12 that the proxy itself keeps.
// Every other cap is judged in dns at the verdict (5.4). No field may be zero: a
// zero cap would refuse everything, which dns never means.
type ProxyConfig struct {
	BindIP string `json:"bind_ip"`

	// Pre-grant pools (5.4): a source with a live entry uses Main, any other
	// source its own small pool with a short first-byte time.
	MainPerSource  uint32 `json:"main_per_source"`
	MainNode       uint32 `json:"main_node"`
	MainSniffMS    uint32 `json:"main_sniff_ms"`
	OtherPerSource uint32 `json:"other_per_source"`
	OtherNode      uint32 `json:"other_node"`
	OtherFirstMS   uint32 `json:"other_first_ms"`
	// New connections per source: a rate a second and a burst.
	NewRate  uint32 `json:"new_rate"`
	NewBurst uint32 `json:"new_burst"`
	// Lookups in flight on the link.
	LookupPerSource uint32 `json:"lookup_per_source"`
	LookupNode      uint32 `json:"lookup_node"`
	// Socket memory of the unit and of both slots, in bytes (5.4).
	MemUnit  uint64 `json:"mem_unit"`
	MemSlots uint64 `json:"mem_slots"`
	// DialFirstByteMS is the time a SOCKS target has for its first byte.
	DialFirstByteMS uint32 `json:"dial_first_byte_ms"`
	// MaxAgeS is the age at which a connection is ended (24 h), IdleS the time of an
	// idle splice (10 min).
	MaxAgeS uint32 `json:"max_age_s"`
	IdleS   uint32 `json:"idle_s"`
}

// LinkSource asks dns which pool a new connection belongs to: the proxy sends the
// source of connection ID before it sniffs anything.
type LinkSource struct {
	ID     uint64 `json:"id"`
	Source []byte `json:"src"`
}

// LinkSourceKnown answers it: Known is true when the source has a live entry.
type LinkSourceKnown struct {
	ID    uint64 `json:"id"`
	Known bool   `json:"known"`
}

// LinkLookup asks for the verdict of a connection. Name is in wire form, already
// normalised by `names`; Port is 80 or 443.
type LinkLookup struct {
	ID     uint64 `json:"id"`
	Source []byte `json:"src"`
	Name   []byte `json:"name"`
	Port   uint16 `json:"port"`
}

// Target is one SOCKS target of a kind 1 verdict: the SOCKS address of the exit's
// inbound, the host to ask it to connect to (a name or an IP), and the port.
type Target struct {
	Socks string `json:"socks"`
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
}

// LinkVerdict is the answer to a lookup. Tag is opaque to the proxy and comes back
// in `open` after a restart. Kind 1 carries Targets; kind 2 the three fields that
// the proxy hands the block process.
type LinkVerdict struct {
	ID       uint64   `json:"id"`
	Kind     uint8    `json:"kind"`
	Tag      []byte   `json:"tag,omitempty"`
	Targets  []Target `json:"targets,omitempty"`
	Endpoint []byte   `json:"endpoint,omitempty"`
	Account  []byte   `json:"account,omitempty"`
	PageHash []byte   `json:"page_hash,omitempty"`
}

// Left is the dial a move leaves behind after 5 s with no byte (5.5): the target it
// left and the start of that dial in milliseconds after the open.
type Left struct {
	Socks   string `json:"socks"`
	StartMS uint32 `json:"start_ms"`
}

// LinkMoved says connection ID went on to the later target Socks. Left is absent
// after a SOCKS error, EOF or reset, because that dial has ended.
type LinkMoved struct {
	ID    uint64 `json:"id"`
	Socks string `json:"socks"`
	Left  *Left  `json:"left,omitempty"`
}

// LinkEnd tells the proxy to close connections: by id, or all of the connections
// to these SOCKS addresses. Exactly one of the two lists is set.
type LinkEnd struct {
	IDs   []uint64 `json:"ids,omitempty"`
	Socks []string `json:"socks,omitempty"`
}

// Pending is a connection that closed with no byte from its current target, with
// the start of that dial, which dns keeps counted until `dial_hold` after it.
type Pending struct {
	ID      uint64 `json:"id"`
	StartMS uint32 `json:"start_ms"`
}

// LinkClosed reports closed connections, at most 100 ms late.
type LinkClosed struct {
	IDs     []uint64  `json:"ids,omitempty"`
	Pending []Pending `json:"pending,omitempty"`
}

// Refusal counts one reason of refusal; the reason is a short name, never a value.
type Refusal struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"n"`
}

// LinkState is the proxy's state, every 10 s and when Listening changes.
type LinkState struct {
	Listening bool      `json:"listening"`
	Open      uint32    `json:"open"`
	Refused   []Refusal `json:"refused,omitempty"`
}

// LinkStats asks dns for its counters. The message is empty: the type is the ask.
type LinkStats struct{}

// Counter is one named counter of stats_res (4.2, 4.3). The names belong to dns
// (B3), which prints them; this socket only carries them.
type Counter struct {
	Name  string `json:"name"`
	Value uint64 `json:"v"`
}

// LinkStatsRes answers stats: the counters and the last refusal reason.
type LinkStatsRes struct {
	Counters    []Counter `json:"counters"`
	LastRefused string    `json:"last_refused,omitempty"`
}

// LinkCodec is the codec of proxy.sock. An `open` frame is a part of a list and is
// held to MaxPartBytes.
var LinkCodec = Codec[LinkMsg]{
	Check:  (*LinkMsg).check,
	IsList: func(m *LinkMsg) bool { return m.Open != nil },
}

// MayProxySend, MayDNSSend and MayRootSend say which side may send a type; a frame
// of another side's type ends the connection (2.1: an unknown type or a failed
// check closes it).
func MayProxySend(t string) bool {
	switch t {
	case TLinkHello, TLinkOpen, TLinkSource, TLinkLookup, TLinkMoved, TLinkClosed, TLinkState:
		return true
	}
	return false
}

// MayDNSSend is the same for dns.
func MayDNSSend(t string) bool {
	switch t {
	case TLinkConfig, TLinkSourceKnown, TLinkVerdict, TLinkEnd, TLinkStatsRes:
		return true
	}
	return false
}

// MayRootSend is true for `stats` alone: a peer of uid 0 may send nothing else.
func MayRootSend(t string) bool { return t == TLinkStats }

func (m *LinkMsg) check() error {
	return one(m.Type,
		field{TLinkHello, m.Hello != nil, func() error { return nil }},
		field{TLinkOpen, m.Open != nil, func() error { return m.Open.check() }},
		field{TLinkConfig, m.Config != nil, func() error { return m.Config.check() }},
		field{TLinkSource, m.Source != nil, func() error { return srcIP("source", m.Source.Source) }},
		field{TLinkSourceKnown, m.SourceKnown != nil, func() error { return nil }},
		field{TLinkLookup, m.Lookup != nil, func() error { return m.Lookup.check() }},
		field{TLinkVerdict, m.Verdict != nil, func() error { return m.Verdict.check() }},
		field{TLinkMoved, m.Moved != nil, func() error { return m.Moved.check() }},
		field{TLinkEnd, m.End != nil, func() error { return m.End.check() }},
		field{TLinkClosed, m.Closed != nil, func() error { return m.Closed.check() }},
		field{TLinkState, m.State != nil, func() error { return m.State.check() }},
		field{TLinkStats, m.Stats != nil, func() error { return nil }},
		field{TLinkStatsRes, m.StatsRes != nil, func() error { return m.StatsRes.check() }},
	)
}

func (o *LinkOpen) check() error {
	if len(o.Items) > MaxPartItems {
		return errors.New("sock: open part over its item cap")
	}
	for i := range o.Items {
		it := &o.Items[i]
		if err := srcIP("open source", it.Source); err != nil {
			return err
		}
		if err := ipPort("open socks", it.Socks); err != nil {
			return err
		}
		if err := lenMax("tag", len(it.Tag), MaxTag); err != nil {
			return err
		}
	}
	return nil
}

func (c *ProxyConfig) check() error {
	if err := ipOnly("bind_ip", c.BindIP); err != nil {
		return err
	}
	for _, v := range []struct {
		name string
		v    uint64
	}{
		{"main_per_source", uint64(c.MainPerSource)}, {"main_node", uint64(c.MainNode)}, {"main_sniff_ms", uint64(c.MainSniffMS)},
		{"other_per_source", uint64(c.OtherPerSource)}, {"other_node", uint64(c.OtherNode)}, {"other_first_ms", uint64(c.OtherFirstMS)},
		{"new_rate", uint64(c.NewRate)}, {"new_burst", uint64(c.NewBurst)},
		{"lookup_per_source", uint64(c.LookupPerSource)}, {"lookup_node", uint64(c.LookupNode)},
		{"mem_unit", c.MemUnit}, {"mem_slots", c.MemSlots},
		{"dial_first_byte_ms", uint64(c.DialFirstByteMS)}, {"max_age_s", uint64(c.MaxAgeS)}, {"idle_s", uint64(c.IdleS)},
	} {
		if v.v == 0 {
			return fmt.Errorf("sock: config %s is zero", v.name)
		}
	}
	return nil
}

func (l *LinkLookup) check() error {
	if err := srcIP("lookup source", l.Source); err != nil {
		return err
	}
	if len(l.Name) == 0 || len(l.Name) > MaxNameWire {
		return errors.New("sock: lookup name has the wrong length")
	}
	if l.Port != 80 && l.Port != 443 {
		return errors.New("sock: lookup port is not 80 or 443")
	}
	return nil
}

func (v *LinkVerdict) check() error {
	if err := lenMax("tag", len(v.Tag), MaxTag); err != nil {
		return err
	}
	switch v.Kind {
	case VerdictNone:
		if len(v.Targets) != 0 || len(v.Endpoint) != 0 || len(v.Account) != 0 || len(v.PageHash) != 0 {
			return errors.New("sock: a none verdict carries more")
		}
	case VerdictProxy:
		if n := len(v.Targets); n < 1 || n > MaxTargets {
			return errors.New("sock: a proxy verdict has 1 to 3 targets")
		}
		if len(v.Endpoint) != 0 || len(v.Account) != 0 || len(v.PageHash) != 0 {
			return errors.New("sock: a proxy verdict carries block fields")
		}
		for i := range v.Targets {
			t := &v.Targets[i]
			if err := ipPort("target socks", t.Socks); err != nil {
				return err
			}
			if err := hostOrIP("target host", t.Host); err != nil {
				return err
			}
			if t.Port == 0 {
				return errors.New("sock: target port is zero")
			}
		}
	case VerdictBlock:
		if len(v.Targets) != 0 {
			return errors.New("sock: a block verdict carries targets")
		}
		if err := lenIs("endpoint", v.Endpoint, 16); err != nil {
			return err
		}
		if err := lenIs("account", v.Account, 16); err != nil {
			return err
		}
		if err := lenIs("page_hash", v.PageHash, 0, 32); err != nil {
			return err
		}
	default:
		return errors.New("sock: unknown verdict kind")
	}
	return nil
}

func (m *LinkMoved) check() error {
	if err := ipPort("moved socks", m.Socks); err != nil {
		return err
	}
	if m.Left != nil {
		if err := ipPort("left socks", m.Left.Socks); err != nil {
			return err
		}
		if m.Left.StartMS > maxStartMS {
			return errors.New("sock: left start is older than a connection can be")
		}
	}
	return nil
}

func (e *LinkEnd) check() error {
	if (len(e.IDs) == 0) == (len(e.Socks) == 0) {
		return errors.New("sock: end names ids or socks, one of them")
	}
	if len(e.IDs) > MaxIDsPerMsg || len(e.Socks) > MaxIDsPerMsg {
		return errors.New("sock: end over its item cap")
	}
	for _, s := range e.Socks {
		if err := ipPort("end socks", s); err != nil {
			return err
		}
	}
	return nil
}

func (c *LinkClosed) check() error {
	if len(c.IDs) == 0 && len(c.Pending) == 0 {
		return errors.New("sock: closed names nothing")
	}
	if len(c.IDs) > MaxIDsPerMsg || len(c.Pending) > MaxIDsPerMsg {
		return errors.New("sock: closed over its item cap")
	}
	for _, p := range c.Pending {
		if p.StartMS > maxStartMS {
			return errors.New("sock: pending start is older than a connection can be")
		}
	}
	return nil
}

func (s *LinkState) check() error {
	if len(s.Refused) > MaxRefusals {
		return errors.New("sock: too many refusal reasons")
	}
	for _, r := range s.Refused {
		if err := reasonName("refusal reason", r.Reason); err != nil {
			return err
		}
	}
	return nil
}

func (r *LinkStatsRes) check() error {
	if len(r.Counters) > MaxCounters {
		return errors.New("sock: too many counters")
	}
	for _, c := range r.Counters {
		if err := reasonName("counter name", c.Name); err != nil {
			return err
		}
	}
	if r.LastRefused != "" {
		return reasonName("last refusal", r.LastRefused)
	}
	return nil
}
