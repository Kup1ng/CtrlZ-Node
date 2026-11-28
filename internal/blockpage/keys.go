package blockpage

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
)

// ErrNoKey is what a handshake gets when no usable intermediate came in time. The
// connection is then closed with internal_error (10.2); port 80 does not need it.
var ErrNoKey = errors.New("blockpage: no intermediate key for the account")

// held is one account's signing key and its chain, in memory only (10.3).
type held struct {
	epoch     [8]byte
	inter     *x509.Certificate
	interDER  []byte
	priv      *ecdsa.PrivateKey
	notBefore time.Time
	notAfter  time.Time
}

// valid reports whether the key may sign at now.
func (h *held) valid(now time.Time) bool {
	return !now.Before(h.notBefore) && now.Before(h.notAfter)
}

// ending reports that a third of the key's life or less is left, the time to ask
// for the next one while this one still works (10.2).
func (h *held) ending(now time.Time) bool {
	life := h.notAfter.Sub(h.notBefore)
	return h.notAfter.Sub(now) <= life/3
}

// keyring holds the intermediates by account. The agent owns the truth (it asks the
// hub and keeps the bundle too), so this is a cache with the epoch rule: keys and
// leaves go when the epoch changes, and no key is used before the agent has said
// which epoch is now (a fresh connection starts with none, so a root that was
// rotated while the link was down is never trusted by this process alone).
type keyring struct {
	mu        sync.Mutex
	keys      *lru.Cache[[16]byte, *held]
	epoch     [8]byte
	haveEpoch bool
	waiters   map[[16]byte]chan struct{}
	lastAsk   map[[16]byte]time.Time
	// ask sends need_key; it reports false when the agent is not connected.
	ask func(endpoint, account []byte) bool
	// onPurge runs when the epoch changes, to drop the leaves.
	onPurge func()
	now     func() time.Time
}

func newKeyring(ask func(endpoint, account []byte) bool, onPurge func(), now func() time.Time) *keyring {
	return &keyring{keys: lru.New[[16]byte, *held](MaxKeys), waiters: map[[16]byte]chan struct{}{},
		lastAsk: map[[16]byte]time.Time{}, ask: ask, onPurge: onPurge, now: now}
}

// setEpoch takes the agent's epoch. A change drops every key and leaf: all of them
// are of the old epoch.
func (k *keyring) setEpoch(e []byte) {
	if len(e) != 8 {
		return
	}
	var ne [8]byte
	copy(ne[:], e)
	k.mu.Lock()
	changed := k.epoch != ne
	k.epoch, k.haveEpoch = ne, true
	if changed {
		// Everything held is of the old epoch: a key of the new one comes only after
		// this frame, because the agent sends the epoch first.
		k.keys.Clear()
	}
	k.mu.Unlock()
	if changed && k.onPurge != nil {
		k.onPurge()
	}
}

// lost is called when the agent connection ends or is replaced: until the next
// epoch frame no key is used. The keys and leaves go too, not only the epoch flag.
// The agent holds the truth and resends every intermediate it still has after its
// epoch frame, so a reconnect costs nothing; but a key kept across the gap would
// outlive a decision the agent took meanwhile (a withdrawn root, a zone added that
// the key does not exclude), and the new connection could never tell us.
func (k *keyring) lost() {
	k.mu.Lock()
	k.haveEpoch = false
	k.keys.Clear()
	k.mu.Unlock()
	if k.onPurge != nil {
		k.onPurge()
	}
}

// put installs an intermediate the agent sent. It is checked again here, since
// this process signs with it: the key must be the certificate's, valid now, and
// of the present epoch.
func (k *keyring) put(i *sock.Intermediate) error {
	h, err := parseHeld(i)
	if err != nil {
		return err
	}
	if !h.valid(k.now()) {
		return errors.New("blockpage: intermediate is not valid now")
	}
	var acct [16]byte
	copy(acct[:], i.Account)
	k.mu.Lock()
	if !k.haveEpoch || k.epoch != h.epoch {
		k.mu.Unlock()
		return errors.New("blockpage: intermediate of another epoch")
	}
	k.keys.Add(acct, h, 1)
	if ch := k.waiters[acct]; ch != nil {
		close(ch)
		delete(k.waiters, acct)
	}
	k.mu.Unlock()
	return nil
}

func parseHeld(i *sock.Intermediate) (*held, error) {
	if len(i.Chain) == 0 {
		return nil, errors.New("blockpage: intermediate without a chain")
	}
	c, err := x509.ParseCertificate(i.Chain[0])
	if err != nil || !c.IsCA {
		return nil, errors.New("blockpage: intermediate certificate is not usable")
	}
	pk, err := x509.ParsePKCS8PrivateKey(i.Key)
	if err != nil {
		return nil, errors.New("blockpage: intermediate key is not PKCS#8")
	}
	priv, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("blockpage: intermediate key is not ECDSA")
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		return nil, errors.New("blockpage: intermediate key is not the certificate's")
	}
	h := &held{inter: c, interDER: i.Chain[0], priv: priv, notBefore: c.NotBefore, notAfter: c.NotAfter}
	copy(h.epoch[:], i.Epoch)
	return h, nil
}

// get returns a usable key for the account, asking the agent when there is none
// and waiting at most KeyWait. A key with a third of its life left is used and
// asked for again in the background of this call.
func (k *keyring) get(ctx context.Context, endpoint, account []byte) (*held, error) {
	var acct [16]byte
	copy(acct[:], account)
	timer := time.NewTimer(KeyWait)
	defer timer.Stop()
	for attempt := 0; attempt < 2; attempt++ {
		now := k.now()
		k.mu.Lock()
		if !k.haveEpoch {
			k.mu.Unlock()
			return nil, ErrNoKey
		}
		h, ok := k.keys.Get(acct)
		if ok && h.epoch == k.epoch && h.valid(now) {
			refresh := h.ending(now) && k.askDueLocked(acct, now)
			k.mu.Unlock()
			if refresh {
				_ = k.ask(endpoint, account)
			}
			return h, nil
		}
		ch := k.waiters[acct]
		if ch == nil {
			if len(k.waiters) >= MaxKeys {
				k.waiters = map[[16]byte]chan struct{}{}
			}
			ch = make(chan struct{})
			k.waiters[acct] = ch
		}
		due := k.askDueLocked(acct, now)
		k.mu.Unlock()
		if due && !k.ask(endpoint, account) {
			return nil, ErrNoKey
		}
		select {
		case <-ch:
		case <-timer.C:
			return nil, ErrNoKey
		case <-ctx.Done():
			return nil, ErrNoKey
		}
	}
	return nil, ErrNoKey
}

// askDueLocked says whether a need_key may go out now, and marks it sent.
func (k *keyring) askDueLocked(acct [16]byte, now time.Time) bool {
	if t, ok := k.lastAsk[acct]; ok && now.Sub(t) < AskEvery {
		return false
	}
	if len(k.lastAsk) >= MaxKeys {
		k.lastAsk = map[[16]byte]time.Time{}
	}
	k.lastAsk[acct] = now
	return true
}
