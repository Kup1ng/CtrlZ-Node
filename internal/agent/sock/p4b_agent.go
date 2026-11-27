package sock

import (
	"errors"
	"fmt"
)

// The P4b types of agent.sock (p4b-proxy 2.1). They travel in the same Msg and the
// same frames as P4's; only the sizes below are new.
//
//	agent -> dns: locations (a state slot, the whole list each time), grant_in and
//	              grant_sent (events)
//	dns -> agent: grant_res, grant_out, proxy_state
const (
	TypeLocations  = "locations"
	TypeGrantIn    = "grant_in"
	TypeGrantSent  = "grant_sent"
	TypeGrantRes   = "grant_res"
	TypeGrantOut   = "grant_out"
	TypeProxyState = "proxy_state"
)

// Caps of the P4b agent.sock messages.
const (
	// MaxLocationConfigs is the number of configs a node may have (12).
	MaxLocationConfigs = 64
	// MaxDraining is the draining addresses a list may carry: a slot's configs.
	MaxDraining = MaxLocationConfigs
	// MaxForward is a marshalled GrantForward; the real one is a few hundred bytes
	// (a 16+16+16 byte header and a wire name), so this only bounds a bad peer.
	MaxForward = 4 << 10
)

// Results of a forwarded Grant that dns reports in grant_sent.
const (
	GrantAccepted = "accepted"
	GrantRefused  = "refused"
	GrantUnsent   = "unsent"
)

// LocationConfig is one config of the list that dns gets (6.4). Exit is the first 8
// bytes of the SHA-256 of the exit's host and port, so configs of one exit share a
// room in dns's caps.
type LocationConfig struct {
	ID        []byte `json:"id"`
	Location  uint32 `json:"loc"`
	Socks     string `json:"socks"`
	Exit      []byte `json:"exit"`
	Priority  uint32 `json:"prio"`
	Healthy   bool   `json:"ok"`
	LatencyMS uint32 `json:"ms"`
}

// Locations is the port map and health of every config. Guard is the read-back of
// the nftables guard (5.5). Direct is the SOCKS address of the `direct` inbound; it
// is empty while Xray is not up. Draining are the addresses of the slot that is
// being drained (7.5), which dns still serves open connections on but gives no new
// one. The list is the whole list each time, so dns never merges.
type Locations struct {
	Guard    bool             `json:"guard"`
	Direct   string           `json:"direct,omitempty"`
	Draining []string         `json:"draining,omitempty"`
	Configs  []LocationConfig `json:"configs"`
}

// GrantIn is a GrantForward from the pair node, marshalled, with the node that sent
// it (a 16-byte node id). The agent has verified the peer; dns decides on the Grant.
type GrantIn struct {
	Sender  []byte `json:"sender"`
	Forward []byte `json:"fwd"`
}

// GrantOut is a GrantForward that dns wants sent to the pair node.
type GrantOut struct {
	Forward []byte `json:"fwd"`
}

// GrantRes is dns's answer to grant_in: the Grant's id and whether it took it.
type GrantRes struct {
	GrantID  []byte `json:"gid"`
	Accepted bool   `json:"ok"`
}

// GrantSent is the agent's answer to grant_out: what became of the forward.
type GrantSent struct {
	GrantID []byte `json:"gid"`
	Result  string `json:"res"`
}

// ProxyState is what dns knows of the proxy, every 10 s and on a change of DNSBind
// or Listening. DNSBind is a bare IP. Full is true while a node_cap refusal is less than 60 s old.
type ProxyState struct {
	DNSBind   string `json:"dns_bind,omitempty"`
	Listening bool   `json:"listening"`
	Open      uint32 `json:"open"`
	Full      bool   `json:"full"`
}

func isP4bType(t string) bool {
	switch t {
	case TypeLocations, TypeGrantIn, TypeGrantSent, TypeGrantRes, TypeGrantOut, TypeProxyState:
		return true
	}
	return false
}

// checkEnvelope is the one-field rule across both generations of Msg. A P4b type
// is checked by checkP4b and may carry no P4 field beside its own; a P4 type may
// carry no P4b field. Without it a grant_out frame could bring an unchecked
// outbound along to every subscriber that receives the whole Msg.
func checkEnvelope(m *Msg) error {
	if isP4bType(m.Type) {
		if m.hasP4Field() {
			return errors.New("sock: a P4b frame carries a P4 field")
		}
		return checkP4b(m)
	}
	if m.hasP4bField() {
		return errors.New("sock: a P4 frame carries a P4b field")
	}
	return nil
}

func (m *Msg) hasP4bField() bool {
	return m.Locations != nil || m.GrantIn != nil || m.GrantSent != nil ||
		m.GrantRes != nil || m.GrantOut != nil || m.ProxyState != nil
}

func (m *Msg) hasP4Field() bool {
	return m.Hello != nil || m.Image != nil || m.Table != nil || m.Facts != nil ||
		m.ZoneKey != nil || m.Config != nil || m.Revocations != nil || m.Acme != nil ||
		m.ImageAck != nil || m.FreeCounts != nil || m.Activity != nil ||
		m.Stats != nil || m.Outbound != nil
}

// checkP4b validates the P4b types of a Msg. The older types are left alone: their
// handlers judge their own fields, as they did in P4.
func checkP4b(m *Msg) error {
	return one(m.Type,
		field{TypeLocations, m.Locations != nil, func() error { return m.Locations.check() }},
		field{TypeGrantIn, m.GrantIn != nil, func() error {
			if err := lenIs("sender", m.GrantIn.Sender, 16); err != nil {
				return err
			}
			return forwardOK(m.GrantIn.Forward)
		}},
		field{TypeGrantOut, m.GrantOut != nil, func() error { return forwardOK(m.GrantOut.Forward) }},
		field{TypeGrantRes, m.GrantRes != nil, func() error { return lenIs("grant_id", m.GrantRes.GrantID, 16) }},
		field{TypeGrantSent, m.GrantSent != nil, func() error {
			if err := lenIs("grant_id", m.GrantSent.GrantID, 16); err != nil {
				return err
			}
			switch m.GrantSent.Result {
			case GrantAccepted, GrantRefused, GrantUnsent:
				return nil
			}
			return errors.New("sock: grant_sent result is not one of the three")
		}},
		field{TypeProxyState, m.ProxyState != nil, func() error {
			if m.ProxyState.DNSBind == "" {
				return nil
			}
			// A bare IP, the dns_bind_ip that dns serves on (2.1); the port is the one
			// of DNS and adds nothing.
			return ipOnly("dns_bind", m.ProxyState.DNSBind)
		}},
	)
}

func forwardOK(b []byte) error {
	if len(b) == 0 {
		return errors.New("sock: an empty forward")
	}
	return lenMax("forward", len(b), MaxForward)
}

func (l *Locations) check() error {
	if len(l.Configs) > MaxLocationConfigs {
		return errors.New("sock: more configs than a node may have")
	}
	if len(l.Draining) > MaxDraining {
		return errors.New("sock: too many draining addresses")
	}
	if l.Direct != "" {
		if err := ipPort("direct", l.Direct); err != nil {
			return err
		}
	}
	for _, d := range l.Draining {
		if err := ipPort("draining", d); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{}, len(l.Configs))
	for i := range l.Configs {
		c := &l.Configs[i]
		if err := lenIs("config id", c.ID, 16); err != nil {
			return err
		}
		if err := lenIs("exit", c.Exit, 8); err != nil {
			return err
		}
		if err := ipPort("socks", c.Socks); err != nil {
			return err
		}
		// An id twice would let the later row replace the earlier one in dns's map
		// without anyone having said so.
		if _, dup := seen[string(c.ID)]; dup {
			return fmt.Errorf("sock: config %d repeats an id", i)
		}
		seen[string(c.ID)] = struct{}{}
	}
	return nil
}
