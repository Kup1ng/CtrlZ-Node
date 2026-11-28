package sock

import (
	"errors"
)

// The two sockets of ctrlz-block (p4b-proxy 2.1, 10.2).
//
//	/run/ctrlz-block/serve.sock   proxy -> block: one ServeFrame, then the raw bytes
//	/run/ctrlz-block/agent.sock   block <-> agent: BlockMsg
//
// Why two sockets: the proxy parses every hostile ClientHello, so it must not be
// able to reach the agent, and the block process must not hold anything that signs
// for a name (10). serve.sock carries a connection and nothing the agent decides;
// the agent socket carries keys and pages and nothing a client sends.

// ServeFrame is the one frame the proxy writes on serve.sock before it copies the
// client's bytes both ways. It names the client source, because a unix socket has
// none. Name is the SNI or Host in the normal lower-case form; Port is 80 or 443.
// The reader must read exactly one frame (Codec.Read consumes no more) and then
// treat the connection as the client's.
type ServeFrame struct {
	Name     string `json:"name"`
	Port     uint16 `json:"port"`
	Endpoint []byte `json:"endpoint"`
	Account  []byte `json:"account"`
	Source   []byte `json:"src"`
	PageHash []byte `json:"page_hash,omitempty"`
}

func (f *ServeFrame) check() error {
	if err := hostOrIP("serve name", f.Name); err != nil {
		return err
	}
	if f.Port != 80 && f.Port != 443 {
		return errors.New("sock: serve port is not 80 or 443")
	}
	if err := lenIs("endpoint", f.Endpoint, 16); err != nil {
		return err
	}
	if err := lenIs("account", f.Account, 16); err != nil {
		return err
	}
	if err := srcIP("serve source", f.Source); err != nil {
		return err
	}
	return lenIs("page_hash", f.PageHash, 0, 32)
}

// ServeCodec is the codec of serve.sock's one frame.
var ServeCodec = Codec[ServeFrame]{Check: (*ServeFrame).check}

// Types of the block agent socket.
const (
	BlockNeedPage     = "need_page"
	BlockNeedKey      = "need_key"
	BlockPage         = "page"
	BlockEpoch        = "epoch"
	BlockIntermediate = "intermediate"
	BlockUnblock      = "unblock"
)

// Caps of the block agent socket's fields.
const (
	// MaxPageBlob is the largest stored page the agent hands over. wire allows a
	// BlockPage blob of 2 MiB, which cannot go in a 1 MiB frame; a real page is a
	// logo of at most 256 KiB and about 10 KiB of text, so this is generous. A
	// stored page over it is answered as no page, which serves ours (10.2).
	MaxPageBlob = 512 << 10
	// MaxChain and MaxCertDER bound the DER chain of an intermediate.
	MaxChain   = 4
	MaxCertDER = 16 << 10
	// MaxKeyDER bounds a PKCS#8 key (an ECDSA P-256 key is under 200 bytes).
	MaxKeyDER = 4 << 10
	// MaxUnblockName and MaxUnblockMessage follow the block page's own caps
	// (wire.MaxBlockMessageChars is 2000 characters, 4 bytes each at most).
	MaxUnblockName    = 253
	MaxUnblockMessage = 8 << 10
)

// BlockMsg is one frame of the block agent socket. Exactly the field of its Type
// is set. Directions: block -> agent: need_page, need_key, unblock. agent ->
// block: page, epoch, intermediate.
type BlockMsg struct {
	Type string `json:"t"`

	NeedPage     *NeedPage     `json:"need_page,omitempty"`
	NeedKey      *NeedKey      `json:"need_key,omitempty"`
	Page         *PageMsg      `json:"page,omitempty"`
	Epoch        *EpochMsg     `json:"epoch,omitempty"`
	Intermediate *Intermediate `json:"intermediate,omitempty"`
	Unblock      *UnblockMsg   `json:"unblock,omitempty"`
}

// NeedPage asks for the stored page with this SHA-256 hash.
type NeedPage struct {
	Hash []byte `json:"hash"`
}

// NeedKey asks for the intermediate of the account of an Endpoint.
type NeedKey struct {
	Endpoint []byte `json:"endpoint"`
	Account  []byte `json:"account"`
}

// PageMsg answers need_page. Blob is a stored BlockPage blob, or empty when the
// agent has none (or it is over MaxPageBlob): block then serves its own page.
type PageMsg struct {
	Hash []byte `json:"hash"`
	Blob []byte `json:"blob,omitempty"`
}

// EpochMsg is the root epoch (10.3), sent first and on each change. block drops
// its keys and leaves when it changes.
type EpochMsg struct {
	Epoch []byte `json:"epoch"`
}

// Intermediate is one account's signing key for leaves (10.3): the DER chain, the
// PKCS#8 key, the epoch it belongs to and its end. block keeps it in memory only.
type Intermediate struct {
	Account  []byte   `json:"account"`
	Epoch    []byte   `json:"epoch"`
	Chain    [][]byte `json:"chain"`
	Key      []byte   `json:"key"`
	NotAfter int64    `json:"not_after"`
}

// UnblockMsg is a request from the page's form, relayed by the agent as a
// BlockUnblockRequest (SC 5.2). At is Unix seconds.
type UnblockMsg struct {
	Endpoint []byte `json:"endpoint"`
	Profile  []byte `json:"profile"`
	Name     string `json:"name"`
	Message  string `json:"message"`
	At       int64  `json:"at"`
}

// BlockCodec is the codec of the block agent socket.
var BlockCodec = Codec[BlockMsg]{Check: (*BlockMsg).check}

// MayBlockSend and MayAgentSend say which end may send a type.
func MayBlockSend(t string) bool {
	return t == BlockNeedPage || t == BlockNeedKey || t == BlockUnblock
}

func MayAgentSend(t string) bool {
	return t == BlockPage || t == BlockEpoch || t == BlockIntermediate
}

func (m *BlockMsg) check() error {
	return one(m.Type,
		field{BlockNeedPage, m.NeedPage != nil, func() error { return lenIs("hash", m.NeedPage.Hash, 32) }},
		field{BlockNeedKey, m.NeedKey != nil, func() error {
			if err := lenIs("endpoint", m.NeedKey.Endpoint, 16); err != nil {
				return err
			}
			return lenIs("account", m.NeedKey.Account, 16)
		}},
		field{BlockPage, m.Page != nil, func() error {
			if err := lenIs("hash", m.Page.Hash, 32); err != nil {
				return err
			}
			return lenMax("page blob", len(m.Page.Blob), MaxPageBlob)
		}},
		field{BlockEpoch, m.Epoch != nil, func() error { return lenIs("epoch", m.Epoch.Epoch, 8) }},
		field{BlockIntermediate, m.Intermediate != nil, func() error { return m.Intermediate.check() }},
		field{BlockUnblock, m.Unblock != nil, func() error { return m.Unblock.check() }},
	)
}

func (i *Intermediate) check() error {
	if err := lenIs("account", i.Account, 16); err != nil {
		return err
	}
	if err := lenIs("epoch", i.Epoch, 8); err != nil {
		return err
	}
	if n := len(i.Chain); n < 1 || n > MaxChain {
		return errors.New("sock: intermediate chain has 1 to 4 certificates")
	}
	for _, c := range i.Chain {
		if len(c) == 0 || len(c) > MaxCertDER {
			return errors.New("sock: intermediate certificate has the wrong size")
		}
	}
	if len(i.Key) == 0 || len(i.Key) > MaxKeyDER {
		return errors.New("sock: intermediate key has the wrong size")
	}
	if i.NotAfter <= 0 {
		return errors.New("sock: intermediate has no end")
	}
	return nil
}

func (u *UnblockMsg) check() error {
	if err := lenIs("endpoint", u.Endpoint, 16); err != nil {
		return err
	}
	if err := lenIs("profile", u.Profile, 16); err != nil {
		return err
	}
	if u.Name == "" {
		return errors.New("sock: unblock without a name")
	}
	if err := lenMax("unblock name", len(u.Name), MaxUnblockName); err != nil {
		return err
	}
	return lenMax("unblock message", len(u.Message), MaxUnblockMessage)
}
