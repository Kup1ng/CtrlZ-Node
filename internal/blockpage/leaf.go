package blockpage

import (
	"container/list"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"time"
)

// ErrMintLimit is returned when a leaf would be minted over the rates of 12. The
// handshake then ends (10.2): a client that floods names costs the node its
// signatures, and the limit is what keeps that bounded.
var ErrMintLimit = errors.New("blockpage: leaf mint rate")

type leafKey struct {
	account [16]byte
	name    string
}

type leafEntry struct {
	k        leafKey
	cert     *tls.Certificate
	notAfter time.Time
}

// leafCache is the LRU of (account, name) of 10.2: 4096 leaves, at most 256 of one
// account. A leaf is a few hundred bytes, so the count is the bound.
type leafCache struct {
	mu      sync.Mutex
	ll      *list.List
	m       map[leafKey]*list.Element
	perAcct map[[16]byte]int
}

func newLeafCache() *leafCache {
	return &leafCache{ll: list.New(), m: map[leafKey]*list.Element{}, perAcct: map[[16]byte]int{}}
}

func (c *leafCache) get(k leafKey, now time.Time) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		return nil
	}
	le := e.Value.(*leafEntry)
	// A leaf with under an hour left is not handed out: a handshake that starts now
	// must not outlive it.
	if le.notAfter.Sub(now) < time.Hour {
		c.removeLocked(e)
		return nil
	}
	c.ll.MoveToFront(e)
	return le.cert
}

func (c *leafCache) add(k leafKey, cert *tls.Certificate, notAfter time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.removeLocked(e)
	}
	for c.perAcct[k.account] >= MaxLeavesPerAccount {
		// Oldest of this account: scan from the cold end.
		for e := c.ll.Back(); e != nil; e = e.Prev() {
			if e.Value.(*leafEntry).k.account == k.account {
				c.removeLocked(e)
				break
			}
		}
	}
	for c.ll.Len() >= MaxLeaves {
		c.removeLocked(c.ll.Back())
	}
	c.m[k] = c.ll.PushFront(&leafEntry{k: k, cert: cert, notAfter: notAfter})
	c.perAcct[k.account]++
}

func (c *leafCache) removeLocked(e *list.Element) {
	le := e.Value.(*leafEntry)
	c.ll.Remove(e)
	delete(c.m, le.k)
	if c.perAcct[le.k.account]--; c.perAcct[le.k.account] <= 0 {
		delete(c.perAcct, le.k.account)
	}
}

// purge drops every leaf (the epoch moved).
func (c *leafCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.m = map[leafKey]*list.Element{}
	c.perAcct = map[[16]byte]int{}
}

// leafMaker mints and caches leaves. The leaf key is made once, at process start
// (10.2): every leaf carries the same public key, so a mint is one signature.
type leafMaker struct {
	key   *ecdsa.PrivateKey
	cache *leafCache
	acct  *accountBuckets
	node  *bucket
	now   func() time.Time
}

func newLeafMaker(now func() time.Time) (*leafMaker, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("blockpage: no leaf key")
	}
	t := now()
	return &leafMaker{key: key, cache: newLeafCache(), now: now,
		acct: newAccountBuckets(mintAccountRate, mintAccountBurst, MaxKeys),
		node: newBucket(mintNodeRate, mintNodeRate, t)}, nil
}

// certificate returns the leaf for (account, name), from the cache or minted
// under h's key. ctx is unused by the signature but kept so a caller that gave up
// does not start a mint.
func (m *leafMaker) certificate(ctx context.Context, account []byte, name string, h *held) (*tls.Certificate, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var k leafKey
	copy(k.account[:], account)
	k.name = name
	now := m.now()
	if c := m.cache.get(k, now); c != nil {
		return c, nil
	}
	if !m.acct.allow(k.account, now) || !m.node.allow(now) {
		return nil, ErrMintLimit
	}
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		return nil, errors.New("blockpage: no randomness")
	}
	serial[0] &= 0x7f
	notAfter := now.Add(LeafLife)
	if notAfter.After(h.notAfter) {
		notAfter = h.notAfter
	}
	// The name is in the SAN, which is what clients check. A common name is only
	// for readers of the certificate, and the field is limited to 64 characters.
	var subject pkix.Name
	if len(name) <= 64 {
		subject.CommonName = name
	}
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               subject,
		DNSNames:              []string{name},
		NotBefore:             now.Add(-LeafBackdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, h.inter, &m.key.PublicKey, h.priv)
	if err != nil {
		// The error of x509 can quote the name; the caller gets a fixed text.
		return nil, errors.New("blockpage: the leaf was not signed")
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, h.interDER}, PrivateKey: m.key}
	m.cache.add(k, cert, notAfter)
	return cert, nil
}
