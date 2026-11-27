// Package sock is the local channel between the agent and the dns process
// (p4-nodes 7.1): /run/ctrlz/agent.sock, mode 0660, group ctrlz.
//
// The agent holds the hub link and the state; dns serves queries. Over this
// socket the agent hands dns each new serving image, the zone table in use, the
// facts that decide the free path (SC 5.2a (c)), the opened zone certificate keys
// and the NodeConfig with its real proof_key, which lives in these two processes'
// memory only. In the other direction dns sends its counters, its activity, its
// resolve health and the three kinds of message an outside party can cause
// (ProofObservation, LearnedIP, BlockUnblockRequest) for the agent to relay.
//
// Why a socket of our own rather than gRPC: the peer is another process of the
// same binary, one reader and one writer, with a few kinds of message, and the
// agent must be able to check SO_PEERCRED before it hands over a key. A frame is
// a 4-byte length and a JSON body, read under a size cap before anything is
// allocated; a peer that sends garbage loses its connection and nothing else.
//
// What a dead socket means is dns's rule, not the agent's: dns keeps its last
// image and takes the free path as off while it is not connected (SC 5.2a, Which
// process).
package sock

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version, sent in the agent's hello.
const Version = 1

// Frame caps. The agent's frames carry a zone key or a table at most; dns's carry
// batches of counters and activity that dns cuts into chunks (MaxItems).
const (
	MaxFrameToDNS   = 8 << 20
	MaxFrameFromDNS = 4 << 20
	// MaxItems is the most items dns puts in one activity or counter message.
	MaxItems = 5000
)

// Message types.
const (
	TypeHello       = "hello"
	TypeImage       = "image"
	TypeTable       = "table"
	TypeFacts       = "facts"
	TypeZoneKey     = "zonekey"
	TypeConfig      = "config"
	TypeRevocations = "revocations"
	TypeAcme        = "acme"

	TypeImageAck   = "image_ack"
	TypeFreeCounts = "free_counts"
	TypeActivity   = "activity"
	TypeStats      = "stats"
	TypeOutbound   = "outbound"
)

// Msg is one frame. Exactly the field of its Type is set.
type Msg struct {
	Type string `json:"t"`

	Hello       *Hello       `json:"hello,omitempty"`
	Image       *Image       `json:"image,omitempty"`
	Table       *Table       `json:"table,omitempty"`
	Facts       *Facts       `json:"facts,omitempty"`
	ZoneKey     *ZoneKey     `json:"zonekey,omitempty"`
	Config      *Config      `json:"config,omitempty"`
	Revocations *Revocations `json:"revocations,omitempty"`
	Acme        *Acme        `json:"acme,omitempty"`

	ImageAck   *ImageAck   `json:"image_ack,omitempty"`
	FreeCounts *FreeCounts `json:"free_counts,omitempty"`
	Activity   *Activity   `json:"activity,omitempty"`
	Stats      *Stats      `json:"stats,omitempty"`
	Outbound   *Outbound   `json:"outbound,omitempty"`

	// P4b (p4b-proxy 2.1), see p4b_agent.go.
	Locations  *Locations  `json:"locations,omitempty"`
	GrantIn    *GrantIn    `json:"grant_in,omitempty"`
	GrantSent  *GrantSent  `json:"grant_sent,omitempty"`
	GrantRes   *GrantRes   `json:"grant_res,omitempty"`
	GrantOut   *GrantOut   `json:"grant_out,omitempty"`
	ProxyState *ProxyState `json:"proxy_state,omitempty"`
}

// Hello opens the agent's side. RunID changes with every start of the agent,
// so dns can tell a restart of the agent from a reconnect.
type Hello struct {
	Version int    `json:"v"`
	RunID   uint64 `json:"run"`
}

// Image names the serving image directory under image/ that dns should open.
type Image struct {
	Name string `json:"name"`
}

// ImageAck is dns's answer once it has opened the image and serves from it. The
// agent deletes blobs that only older images need after this (r1-9 of W5a).
type ImageAck struct {
	Name string `json:"name"`
}

// Flag is one withdrawal flag of the table's flag map.
type Flag struct {
	Node      []byte `json:"n"`
	Withdrawn bool   `json:"w"`
}

// Table is the zone table in use, as data. dns builds zone.Table from it with
// zone.Build under recover. InUse false means SC 8a.5 gives dns no table to
// answer Endpoint hostnames from yet (it answers REFUSED for them).
type Table struct {
	// Member is the marshalled PairTable of the membership, empty when no applied
	// entry carried one.
	Member     []byte   `json:"member,omitempty"`
	Version    uint64   `json:"version"`
	Flags      []Flag   `json:"flags,omitempty"`
	InUse      bool     `json:"in_use"`
	PanelStale bool     `json:"panel_stale"`
	PeerDown   [][]byte `json:"peer_down,omitempty"`
	Self       []byte   `json:"self,omitempty"`
	// DrainSince is the Unix second at which this node stopped being the advertised
	// node of every pair in use, 0 when it is not draining (SC 8a.6). dns starts
	// closing its encrypted connections gracefully DrainFrom after it, and a table
	// that makes the node advertised again clears it.
	DrainSince int64 `json:"drain_since,omitempty"`
}

// Facts are the facts of the agent's run and the free DNS value in force. dns
// decides the free path from them (SC 5.2a): (a) FreeSet && FreeEnabled &&
// FreeVersion >= OffFloor, and (c) ServerTimeSeen && CaughtUpOnce && LagOK.
type Facts struct {
	ServerTimeSeen bool   `json:"st"`
	CaughtUpOnce   bool   `json:"cu"`
	LagOK          bool   `json:"lag"`
	OffFloor       uint64 `json:"floor"`
	FreeSet        bool   `json:"fset"`
	FreeEnabled    bool   `json:"fon"`
	FreeQPS        uint32 `json:"fqps"`
	FreeVersion    uint64 `json:"fver"`
	// AppliedSeq is the applied seq the facts above were judged at: it moves after the
	// images of an Apply reached dns, not at each commit inside a batch, so a batch in
	// progress does not turn the free path off. The agent commits it before the image
	// swap, and the swap or dns's open of the image can fail, so
	// dns serves from an image with a seq below it until the next one arrives. dns
	// therefore counts the node as caught up only while the image it serves has at
	// least this seq (SC 5.2a (c)); an image from a lost state has a higher seq and
	// passes.
	AppliedSeq uint64 `json:"applied,omitempty"`
	// HubOffset is the seconds to add to the node's clock to get the hub's (8a.4
	// Clock). Every expires_at the agent hands dns (revocations, ACME challenges) is
	// in hub time, so dns must judge it with its own clock plus this, never with its
	// clock alone: a node clock moved by more than a lifetime would otherwise end a
	// revocation or a challenge at once.
	HubOffset int64 `json:"off,omitempty"`
}

// FreeOn is (a): a free_dns value is in force, it is enabled, and its version is
// at or above the off floor.
func (f Facts) FreeOn() bool {
	return f.FreeSet && f.FreeEnabled && f.FreeVersion >= f.OffFloor
}

// FreeCaughtUp is (c): the three facts of the agent's run.
func (f Facts) FreeCaughtUp() bool { return f.ServerTimeSeen && f.CaughtUpOnce && f.LagOK }

// FreeOK is the whole decision of (a) and (c) from one message.
func (f Facts) FreeOK() bool { return f.FreeOn() && f.FreeCaughtUp() }

// ZoneKey is one zone certificate with its private key, opened in the agent.
// Key is PKCS#8 DER. dns keeps it in memory only.
type ZoneKey struct {
	SANs     []string `json:"sans"`
	ChainPEM []byte   `json:"chain"`
	Key      []byte   `json:"key"`
	NotAfter int64    `json:"na"`
}

// Config is the latest NodeConfig, marshalled, with its real proof_key.
type Config struct {
	NodeConfig []byte `json:"nc"`
}

// RevItem is one Revocation in force.
type RevItem struct {
	Seq       uint64   `json:"seq"`
	Kind      int32    `json:"kind"`
	IDs       [][]byte `json:"ids"`
	ExpiresAt int64    `json:"exp"`
}

// Revocations is the whole list of revocations in force, replaced on every
// change (SC 5.2a case 1, 10.4: hard_disabled acts before the entry is applied).
type Revocations struct {
	Items []RevItem `json:"items"`
	// Saved is the agent's hub time when the list was written to disk, set only in
	// the file. A restart reads each expiry as a lifetime left (exp - Saved) because
	// the node clock is not trusted until the first ServerTime.
	Saved int64 `json:"saved,omitempty"`
}

// AcmeRemoved is the ExpiresAt of an Acme message that takes a challenge away. It
// is not a time anybody compares with a clock: until the facts arrive (they come
// last in the snapshot) dns does not know the hub's offset and cannot tell an
// expired challenge from a live one.
const AcmeRemoved int64 = 1

// Acme is a DNS-01 challenge dns must answer with a TXT record until it expires.
type Acme struct {
	TokenID   []byte `json:"tok"`
	FQDN      string `json:"fqdn"`
	Value     string `json:"val"`
	ExpiresAt int64  `json:"exp"`
}

// FreeCount is one counter of the free path (no name, no address).
type FreeCount struct {
	Proto   int32  `json:"p"`
	Outcome int32  `json:"o"`
	Rcode   uint32 `json:"r"`
	Count   uint64 `json:"c"`
}

// FreeCounts are counts since dns's last message; the agent adds them into the
// bucket of the time it receives them.
type FreeCounts struct {
	Items []FreeCount `json:"items"`
}

// ActivityItem is one thing dns saw (p4-nodes 7.6, Activity).
type ActivityItem struct {
	Endpoint     []byte `json:"ep"`
	Label        string `json:"l"`
	Claim        []byte `json:"c,omitempty"`
	SourceIPHash []byte `json:"h,omitempty"`
	Proto        int32  `json:"p"`
	At           int64  `json:"at"`
}

// Activity is a chunk of activity items.
type Activity struct {
	Items []ActivityItem `json:"items"`
}

// Health is one resolve path's health, for Heartbeat.upstreams.
type Health struct {
	ID        []byte `json:"id"`
	Healthy   bool   `json:"ok"`
	LatencyMS uint32 `json:"ms"`
}

// Stats are the numbers of the Heartbeat that only dns knows.
type Stats struct {
	QPS              uint32   `json:"qps"`
	CacheHitPermille uint32   `json:"hit"`
	Isolated         bool     `json:"iso"`
	Upstreams        []Health `json:"up,omitempty"`
}

// Outbound is a NodeMessage the agent relays to the hub: a ProofObservation, a
// LearnedIP or a BlockUnblockRequest, marshalled as hubv1.NodeMessage. The agent
// validates it again, so dns is not trusted to have.
type Outbound struct {
	NodeMessage []byte `json:"nm"`
}

var errFrame = errors.New("sock: frame over the size cap")

// Write sends one frame.
func Write(w io.Writer, m *Msg, max int) error {
	if err := checkEnvelope(m); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("sock: marshal: %w", err)
	}
	if len(b) > max || isP4bType(m.Type) && len(b) > MaxFrame {
		return errFrame
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, err := w.Write(append(h[:], b...)); err != nil {
		return err
	}
	return nil
}

// Read reads one frame under the cap. The length is checked before the body is
// allocated, so a peer cannot make the reader allocate more than max.
func Read(r io.Reader, max int) (*Msg, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || int64(n) > int64(max) {
		return nil, errFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	m := &Msg{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(m); err != nil {
		return nil, decodeErr(err)
	}
	if m.Type == "" {
		return nil, errors.New("sock: frame without a type")
	}
	if isP4bType(m.Type) && len(b) > MaxFrame {
		return nil, errFrame
	}
	// The P4 types keep their older reading; the P4b ones are held to the rule of
	// the other sockets: nothing after the message.
	if isP4bType(m.Type) {
		if err := noTrailing(dec); err != nil {
			return nil, err
		}
	}
	if err := checkEnvelope(m); err != nil {
		return nil, err
	}
	return m, nil
}
