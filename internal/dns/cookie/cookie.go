// Package cookie is the server side of DNS cookies (RFC 7873, RFC 9018), the
// rule of L14 of the shared contract, and the proof that a UDP source is real.
//
// A server cookie is bound to the client cookie and the client address by a
// keyed hash, so only a host that received a reply from this node at that
// address can send a valid one. A UDP query that carries one is therefore
// from a validated source (SC 5.2a). The secret lives in memory only: it is
// made at start and never written (SC 8a.3), so a restart makes every old
// cookie unverifiable, and L14 says that must change nothing but the
// validated flag: such a query is answered as if it had no server cookie,
// never with BADCOOKIE, TC=1 or a drop.
package cookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// ClientLen is the length of a client cookie (RFC 7873 section 4).
	ClientLen = 8
	// serverLen is the length of the server cookie this node makes: version 1,
	// three reserved bytes, a 4-byte timestamp and an 8-byte hash, the
	// interoperable layout of RFC 9018 section 4.
	serverLen = 16
	version   = 1
	hashLen   = 8
	// maxAge and maxSkew are the validity window of RFC 9018 section 4.3: a
	// cookie up to one hour old, or five minutes from the future.
	maxAge  = time.Hour
	maxSkew = 5 * time.Minute
)

// Jar makes and checks server cookies under a secret held in memory.
//
// The hash is HMAC-SHA-256 cut to 8 bytes, not the SipHash-2-4 that RFC 9018
// suggests: SipHash matters only when several servers must verify one
// another's cookies under a shared secret (anycast), and this node's secret
// is its own. The layout is the RFC's, so a client cannot tell.
type Jar struct {
	mu   sync.RWMutex
	cur  [32]byte
	prev [32]byte
	have bool // prev is set
	now  func() time.Time

	// prevKeep is how long the previous secret is kept after a rotation: the
	// life of the cookies it made (SC 8a.3), after which it is zeroed. A test may
	// shorten it.
	prevKeep time.Duration
	gen      uint64 // counts rotations and wipes, so a stale timer does nothing
}

// New makes a Jar with a fresh random secret.
func New() (*Jar, error) {
	j := &Jar{now: time.Now, prevKeep: maxAge + maxSkew}
	if _, err := rand.Read(j.cur[:]); err != nil {
		return nil, err
	}
	return j, nil
}

// Rotate starts a new secret and keeps the one before it, so cookies made
// just before the change still verify. Call it about once a day.
func (j *Jar) Rotate() error {
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return err
	}
	j.mu.Lock()
	j.prev, j.cur, j.have = j.cur, n, true
	j.gen++
	gen := j.gen
	j.mu.Unlock()
	// The old secret is of no use once the cookies it made have expired, and
	// a memory disclosure must not yield one that the spec says is gone.
	time.AfterFunc(j.prevKeep, func() { j.wipePrev(gen) })
	return nil
}

// Wipe replaces both secrets with fresh ones, as a restart does. A cookie made
// before it no longer verifies.
func (j *Jar) Wipe() error {
	var a, b [32]byte
	if _, err := rand.Read(a[:]); err != nil {
		return err
	}
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	j.mu.Lock()
	j.cur, j.prev, j.have = a, b, true
	j.gen++
	j.mu.Unlock()
	return nil
}

func mac(secret *[32]byte, client []byte, ts uint32, src netip.Addr) []byte {
	h := hmac.New(sha256.New, secret[:])
	h.Write(client)
	h.Write([]byte{version, 0, 0, 0})
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], ts)
	h.Write(t[:])
	a := src.Unmap().As16()
	h.Write(a[:])
	return h.Sum(nil)[:hashLen]
}

// Make returns a fresh server cookie for a client cookie and a source.
func (j *Jar) Make(client []byte, src netip.Addr) []byte {
	ts := uint32(j.now().Unix())
	j.mu.RLock()
	sum := mac(&j.cur, client, ts, src)
	j.mu.RUnlock()
	out := make([]byte, serverLen)
	out[0] = version
	binary.BigEndian.PutUint32(out[4:8], ts)
	copy(out[8:], sum)
	return out
}

// Verify reports whether server is a server cookie this node made for client
// and src, under the current or the previous secret, inside the window.
func (j *Jar) Verify(client, server []byte, src netip.Addr) bool {
	if len(server) != serverLen || server[0] != version {
		return false
	}
	ts := binary.BigEndian.Uint32(server[4:8])
	issued := time.Unix(int64(ts), 0)
	now := j.now()
	if now.Sub(issued) > maxAge || issued.Sub(now) > maxSkew {
		return false
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if hmac.Equal(server[8:], mac(&j.cur, client, ts, src)) {
		return true
	}
	return j.have && hmac.Equal(server[8:], mac(&j.prev, client, ts, src))
}

// Parsed is the COOKIE option of a query.
type Parsed struct {
	// Present is true when the query holds a well-formed COOKIE option: a client
	// cookie of 8 bytes and a server cookie of 0 or 8 to 32 bytes.
	Present bool
	Client  []byte
	Server  []byte
}

// Parse finds the COOKIE option of a message. A malformed option is treated as
// absent: RFC 7873 would answer FORMERR, but L14 and invariant 2 say a query
// for a name the node must answer never gets a refusal for a cookie reason.
func Parse(m *dns.Msg) Parsed {
	opt := m.IsEdns0()
	if opt == nil {
		return Parsed{}
	}
	for _, o := range opt.Option {
		c, ok := o.(*dns.EDNS0_COOKIE)
		if !ok {
			continue
		}
		b, err := hex.DecodeString(c.Cookie)
		if err != nil || len(b) < ClientLen {
			return Parsed{}
		}
		sl := len(b) - ClientLen
		if sl != 0 && (sl < 8 || sl > 32) {
			return Parsed{}
		}
		return Parsed{Present: true, Client: b[:ClientLen], Server: b[ClientLen:]}
	}
	return Parsed{}
}

// Attach puts the COOKIE option of a reply into m: the client cookie back and
// a fresh server cookie (RFC 7873 section 5.2.3), replacing any COOKIE option
// the message has, and adding an OPT record if there is none. m must be a
// message nothing else holds.
func (j *Jar) Attach(m *dns.Msg, p Parsed, src netip.Addr) {
	if !p.Present {
		return
	}
	value := append(append([]byte(nil), p.Client...), j.Make(p.Client, src)...)
	ck := &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: hex.EncodeToString(value)}
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(1232, false)
		opt = m.IsEdns0()
	}
	kept := opt.Option[:0:0]
	for _, o := range opt.Option {
		if _, isCookie := o.(*dns.EDNS0_COOKIE); !isCookie {
			kept = append(kept, o)
		}
	}
	opt.Option = append(kept, ck)
}

// wipePrev zeroes the previous secret, unless another rotation or a wipe has
// happened since gen (that one has its own timer).
func (j *Jar) wipePrev(gen uint64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.gen != gen {
		return
	}
	j.prev = [32]byte{}
	j.have = false
}
