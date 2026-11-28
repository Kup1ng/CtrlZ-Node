package blockpage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// The unblock form's guards (10.4). The token ties a form to the name, the Endpoint,
// the source and the hour it was served for, with a key made at process start and
// never stored: a page fetched by one device cannot be replayed from another, and
// a cross-site page cannot get a token at all because it cannot read this one.
type unblocker struct {
	key [32]byte
	now func() time.Time

	mu     sync.Mutex
	hour   int64
	perSrc map[srcKey]int
	perEP  map[[16]byte]int
}

type srcKey struct {
	endpoint [16]byte
	source   [16]byte
}

// maxCounters bounds the rate tables. A table that is full says no, which only
// makes the page answer "received" without relaying: the safe side.
const maxCounters = 1 << 17

func newUnblocker(now func() time.Time) (*unblocker, error) {
	u := &unblocker{now: now, perSrc: map[srcKey]int{}, perEP: map[[16]byte]int{}}
	if _, err := rand.Read(u.key[:]); err != nil {
		return nil, errors.New("blockpage: no randomness")
	}
	return u, nil
}

func (u *unblocker) mac(name string, endpoint, source []byte, hour int64) []byte {
	m := hmac.New(sha256.New, u.key[:])
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], uint64(hour))
	// Every field is length-prefixed: no two tuples share an encoding.
	for _, f := range [][]byte{[]byte(name), endpoint, source, h[:]} {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(f)))
		m.Write(l[:])
		m.Write(f)
	}
	return m.Sum(nil)[:16]
}

// token is the form's hidden field for the present hour.
func (u *unblocker) token(name string, endpoint, source []byte) string {
	return base64.RawURLEncoding.EncodeToString(u.mac(name, endpoint, source, u.now().Unix()/3600))
}

// valid accepts a token of this hour or the one before.
func (u *unblocker) valid(tok, name string, endpoint, source []byte) bool {
	got, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(got) != 16 {
		return false
	}
	h := u.now().Unix() / 3600
	ok := hmac.Equal(got, u.mac(name, endpoint, source, h))
	return hmac.Equal(got, u.mac(name, endpoint, source, h-1)) || ok
}

// admit counts one request against 5 an hour for (Endpoint, source) and 60 an hour
// for the Endpoint, in windows of the clock hour. It reports whether it may be
// relayed; a refused request is still answered as received (10.4).
func (u *unblocker) admit(endpoint, source []byte) bool {
	h := u.now().Unix() / 3600
	var sk srcKey
	copy(sk.endpoint[:], endpoint)
	copy(sk.source[:], source) // an IPv4 source takes 4 bytes, the rest stays zero: still one key per address
	u.mu.Lock()
	defer u.mu.Unlock()
	if h != u.hour {
		u.hour = h
		u.perSrc = map[srcKey]int{}
		u.perEP = map[[16]byte]int{}
	}
	if len(u.perSrc) >= maxCounters || len(u.perEP) >= maxCounters {
		return false
	}
	if u.perSrc[sk] >= UnblockPerSource || u.perEP[sk.endpoint] >= UnblockPerEndpoint {
		return false
	}
	u.perSrc[sk]++
	u.perEP[sk.endpoint]++
	return true
}

// cleanMessage makes the visitor's text what the hub accepts: valid UTF-8, no
// control character but a line break and a tab, at most 500 characters. It
// reports false for text that is not UTF-8, which no browser sends.
func cleanMessage(s string) (string, bool) {
	if !utf8.ValidString(s) {
		return "", false
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == '\r' {
			r = '\n'
		}
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			continue
		}
		if n == MaxMessageChars {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String()), true
}
