// Package blockside is the agent's end of the block page process (p4b-proxy 10.2,
// 10.3, 17 row B6): it answers the page and key asks of ctrlz-block on
// /run/ctrlz-block/agent.sock, asks the hub for an account's intermediate
// (BlockKeyRequest) and opens what the hub sends back (CertBundle of use
// block_intermediate), and relays a visitor's unblock request as a
// BlockUnblockRequest.
//
// It is a Part of the agent (internal/agent/parts.go) and imports nothing of the
// agent: what it needs from the agent comes in through Host, so this package can be
// tested against fakes and the agent's boot code holds one short block for it.
//
// Keys live in memory only. The agent never writes an intermediate to disk and
// never gives one to dns or proxy: ctrlz-block is the one process that signs.
package blockside

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"sync"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Tuning of 10.3, with the knobs tests turn.
const (
	// AskEvery is the least time between two BlockKeyRequests for one account.
	AskEvery = time.Minute
	// MissingAfter is how long a key asked for and not received, with Control up,
	// takes to set the fault block_key_missing.
	MissingAfter = 10 * time.Minute
	// NeedLife is how long an ask stays pending after the last need_key for it: a
	// need nobody repeats is not one the node is failing.
	NeedLife = time.Hour
	// MaxKeys bounds the intermediates and the pending asks held.
	MaxKeys = 4096
	// maxLife is the longest validity the node accepts for an intermediate: seven
	// days (10.3) and a day of slack for the clocks.
	maxLife = 8 * 24 * time.Hour
)

// ErrOtherEpoch is returned by Bundle for a bundle of another epoch than the
// NodeConfig's. It is dropped without an alert: a rotation makes it happen, and the
// key is asked for again when a connection needs it (10.3).
var ErrOtherEpoch = errors.New("blockside: bundle of another epoch")

// Host is what the agent gives the part. Every field is required but Now.
type Host struct {
	// Unseal opens a CertBundle's wrapped_key with the node's key and returns the
	// PKCS#8 key inside.
	Unseal func(wrapped []byte) ([]byte, error)
	// PageBlob returns the stored block page blob of this hash, or nil. It must
	// answer for the kind block page alone: a profile blob is never returned.
	PageBlob func(hash [32]byte) []byte
	// Outside queues a message an outside party can cause (the L10 queue); false
	// when it was dropped as a repeat or for a full queue.
	Outside func(*hubv1.NodeMessage) bool
	// ControlUp says whether the Control stream is open now.
	ControlUp func() bool
	// HubNow is the hub's clock in Unix seconds.
	HubNow func() int64
}

// FaultSetter is the agent's Faults.
type FaultSetter interface {
	Set(fault hubv1.NodeFault, on bool)
}

// Config of the part.
type Config struct {
	// Path is the block agent socket, DefaultPath when empty.
	Path   string
	Faults FaultSetter
	Now    func() time.Time
	// Tick is the period of the fault check, default 10 s. AskEvery and MissingAfter
	// can be shortened for a test through these fields.
	Tick         time.Duration
	AskEvery     time.Duration
	MissingAfter time.Duration
}

// DefaultPath is the block agent socket (2.1).
const DefaultPath = "/run/ctrlz-block/agent.sock"

type key struct {
	epoch     [8]byte
	inter     *sock.Intermediate
	notBefore time.Time
	notAfter  time.Time
}

type pending struct {
	endpoint []byte
	first    time.Time // the first ask still unanswered
	lastNeed time.Time // the last need_key for it
	lastSent time.Time // the last BlockKeyRequest, zero if none went
}

// Part is the agent's end. Make it with New, give it its Host with Attach once
// the agent exists, and add it to the agent's Parts.
type Part struct {
	cfg  Config
	mu   sync.Mutex
	host *Host
	conn net.Conn
	out  chan *sock.BlockMsg
	wake chan struct{}

	epoch   []byte // 8 bytes, or empty: the NodeConfig names no root
	hosts   []string
	keys    map[[16]byte]*key
	pend    map[[16]byte]*pending
	upSince time.Time
}

// New returns a Part with no Host: until Attach, every ask is dropped.
func New(cfg Config) *Part {
	if cfg.Path == "" {
		cfg.Path = DefaultPath
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Tick == 0 {
		cfg.Tick = 10 * time.Second
	}
	if cfg.AskEvery == 0 {
		cfg.AskEvery = AskEvery
	}
	if cfg.MissingAfter == 0 {
		cfg.MissingAfter = MissingAfter
	}
	return &Part{cfg: cfg, keys: map[[16]byte]*key{}, pend: map[[16]byte]*pending{}, wake: make(chan struct{}, 1)}
}

// Attach gives the part the agent's side. It is called once, after the agent is
// built and before it runs.
func (p *Part) Attach(h Host) {
	p.mu.Lock()
	p.host = &h
	p.mu.Unlock()
}

// Heartbeat adds nothing: the one thing this part reports is a fault, and it says
// that to the agent's Faults and never to the Heartbeat itself.
func (p *Part) Heartbeat(*hubv1.Heartbeat) {}

// Config takes the epoch of the root and the names the intermediates must exclude.
// A change of epoch drops every key held (10.3) and tells ctrlz-block.
func (p *Part) Config(nc *hubv1.NodeConfig) {
	var e []byte
	if len(nc.GetBlockRootEpoch()) == 8 {
		e = append([]byte(nil), nc.BlockRootEpoch...)
	}
	hosts := append(append([]string(nil), nc.GetZones()...), nc.GetPanelHostnames()...)
	p.mu.Lock()
	changed := string(e) != string(p.epoch)
	p.epoch, p.hosts = e, hosts
	if changed {
		var ne [8]byte
		copy(ne[:], e)
		for a, k := range p.keys {
			if len(e) != 8 || k.epoch != ne {
				delete(p.keys, a)
			}
		}
	}
	p.mu.Unlock()
	if changed {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
}

// Run connects to ctrlz-block's socket, and keeps connecting: the block process may
// start after the agent or restart. It returns when ctx ends.
func (p *Part) Run(ctx context.Context) {
	go p.watch(ctx)
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", p.cfg.Path)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 100 * time.Millisecond
		p.session(ctx, c)
	}
}

// Serve runs one session on a connection that is already made (tests give a fake
// one) and returns when it ends.
func (p *Part) Serve(ctx context.Context, c net.Conn) { p.session(ctx, c) }

func (p *Part) session(ctx context.Context, c net.Conn) {
	out := make(chan *sock.BlockMsg, 64)
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done); _ = c.Close() }) }
	defer stop()
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	p.mu.Lock()
	p.conn, p.out = c, out
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.conn == c {
			p.conn, p.out = nil, nil
		}
		p.mu.Unlock()
	}()
	// A wake that was raised before this session is covered by the epoch sent now.
	select {
	case <-p.wake:
	default:
	}
	// The epoch goes first, so that ctrlz-block knows which keys are good before
	// it asks for one.
	if !p.sendEpoch(c) {
		return
	}
	go func() {
		for {
			select {
			case m := <-out:
				_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if sock.BlockCodec.Write(c, m) != nil {
					stop()
					return
				}
			case <-p.wake:
				if !p.sendEpoch(c) {
					stop()
					return
				}
			case <-done:
				return
			}
		}
	}()
	for {
		m, err := sock.BlockCodec.Read(c)
		// A frame of a type only the agent may send closes the connection.
		if err != nil || !sock.MayBlockSend(m.Type) {
			return
		}
		switch m.Type {
		case sock.BlockNeedPage:
			p.needPage(m.NeedPage.Hash)
		case sock.BlockNeedKey:
			p.needKey(m.NeedKey.Endpoint, m.NeedKey.Account)
		case sock.BlockUnblock:
			p.unblock(m.Unblock)
		}
	}
}

// sendEpoch writes the epoch directly when the connection is ours to write: it is
// called from the session before the writer starts, and from the writer.
func (p *Part) sendEpoch(c net.Conn) bool {
	p.mu.Lock()
	e := p.epoch
	var ks []*sock.Intermediate
	for _, k := range p.keys {
		ks = append(ks, k.inter)
	}
	p.mu.Unlock()
	if len(e) != 8 {
		return true
	}
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if sock.BlockCodec.Write(c, &sock.BlockMsg{Type: sock.BlockEpoch, Epoch: &sock.EpochMsg{Epoch: e}}) != nil {
		return false
	}
	// A block process that restarted holds no key: the ones the agent has go to it
	// at once, so a restart needs no panel (10.3).
	for _, i := range ks {
		if sock.BlockCodec.Write(c, &sock.BlockMsg{Type: sock.BlockIntermediate, Intermediate: i}) != nil {
			return false
		}
	}
	return true
}

// queue puts a frame on the writer's queue; it never blocks. A frame that does not
// fit is dropped, and ctrlz-block asks again.
func (p *Part) queue(m *sock.BlockMsg) {
	p.mu.Lock()
	out := p.out
	p.mu.Unlock()
	if out == nil {
		return
	}
	select {
	case out <- m:
	default:
	}
}

func (p *Part) needPage(hash []byte) {
	p.mu.Lock()
	h := p.host
	p.mu.Unlock()
	if h == nil || len(hash) != 32 {
		return
	}
	var k [32]byte
	copy(k[:], hash)
	blob := h.PageBlob(k)
	if len(blob) > sock.MaxPageBlob {
		blob = nil // the block process serves its own page for what does not fit a frame
	}
	p.queue(&sock.BlockMsg{Type: sock.BlockPage, Page: &sock.PageMsg{Hash: hash, Blob: blob}})
}

// needKey answers from memory when the agent holds a good key, and asks the hub
// when it does not, or when a third of a key's life is left.
func (p *Part) needKey(endpoint, account []byte) {
	var acct [16]byte
	copy(acct[:], account)
	now := p.cfg.Now()
	p.mu.Lock()
	h := p.host
	if h == nil || len(p.epoch) != 8 {
		p.mu.Unlock()
		return
	}
	var ep [8]byte
	copy(ep[:], p.epoch)
	k := p.keys[acct]
	have := k != nil && k.epoch == ep && !now.Before(k.notBefore) && now.Before(k.notAfter)
	var give *sock.Intermediate
	ask := !have
	if have {
		give = k.inter
		life := k.notAfter.Sub(k.notBefore)
		ask = k.notAfter.Sub(now) <= life/3
	}
	var pd *pending
	if ask {
		pd = p.pend[acct]
		if pd == nil {
			if len(p.pend) >= MaxKeys {
				p.mu.Unlock()
				return
			}
			pd = &pending{first: now}
			p.pend[acct] = pd
		}
		pd.endpoint = append(pd.endpoint[:0], endpoint...)
		pd.lastNeed = now
		if now.Sub(pd.lastSent) < p.cfg.AskEvery {
			ask = false
		}
	}
	// A key that is still good answers the need while the next one is asked for,
	// and then it is not "missing": only an ask with no key at all can be.
	if have && pd != nil {
		pd.first = now
	}
	p.mu.Unlock()
	if give != nil {
		p.queue(&sock.BlockMsg{Type: sock.BlockIntermediate, Intermediate: give})
	}
	if !ask {
		return
	}
	m := &hubv1.NodeMessage{Body: &hubv1.NodeMessage_BlockKeyRequest{BlockKeyRequest: &hubv1.BlockKeyRequest{EndpointId: endpoint}}}
	if wire.ValidateNodeMessage(m, h.HubNow()) != nil {
		return
	}
	if h.Outside(m) {
		p.mu.Lock()
		if pd := p.pend[acct]; pd != nil {
			pd.lastSent = now
		}
		p.mu.Unlock()
	}
}

// unblock relays a visitor's request. The hub decides whether it belongs to a
// tenant of the Endpoint (10.5); the node's part is to send it well formed.
func (p *Part) unblock(u *sock.UnblockMsg) {
	p.mu.Lock()
	h := p.host
	p.mu.Unlock()
	if h == nil {
		return
	}
	n, err := names.FromString(u.Name)
	if err != nil || n.IsRoot() {
		return
	}
	m := &hubv1.NodeMessage{Body: &hubv1.NodeMessage_BlockUnblockRequest{BlockUnblockRequest: &hubv1.BlockUnblockRequest{
		EndpointId: u.Endpoint, QnameWire: append([]byte(nil), n.Wire()...), Message: u.Message, At: h.HubNow(), ProfileId: u.Profile}}}
	if wire.ValidateNodeMessage(m, h.HubNow()) != nil {
		return
	}
	h.Outside(m)
}

// Bundle takes a CertBundle of use block_intermediate (10.3). It unseals it,
// checks the chain, and keeps the key in memory. A nil error means it is held; an
// error is for the caller to alert on, but ErrOtherEpoch, which is only dropped.
func (p *Part) Bundle(cb *hubv1.CertBundle) error {
	if err := wire.ValidateCertBundle(cb); err != nil || cb.Use != hubv1.CertUse_CERT_USE_BLOCK_INTERMEDIATE {
		return errors.New("blockside: not a block intermediate bundle")
	}
	p.mu.Lock()
	h, epoch, hosts := p.host, p.epoch, p.hosts
	p.mu.Unlock()
	if h == nil {
		return errors.New("blockside: not attached")
	}
	if len(epoch) != 8 || string(epoch) != string(cb.BlockRootEpoch) {
		return ErrOtherEpoch
	}
	der, err := h.Unseal(cb.WrappedKey)
	if err != nil {
		return errors.New("blockside: the bundle does not open")
	}
	now := p.cfg.Now()
	chain, err := checkBundle(cb.ChainPem, der, now, hosts)
	if err != nil {
		return err
	}
	in := &sock.Intermediate{Account: append([]byte(nil), cb.AccountHash...), Epoch: append([]byte(nil), cb.BlockRootEpoch...),
		Key: der, NotAfter: chain[0].NotAfter.Unix()}
	for _, c := range chain {
		in.Chain = append(in.Chain, c.Raw)
	}
	if err := sock.BlockCodec.Check(&sock.BlockMsg{Type: sock.BlockIntermediate, Intermediate: in}); err != nil {
		return errors.New("blockside: the bundle does not fit the block socket")
	}
	var acct [16]byte
	copy(acct[:], cb.AccountHash)
	k := &key{inter: in, notBefore: chain[0].NotBefore, notAfter: chain[0].NotAfter}
	copy(k.epoch[:], cb.BlockRootEpoch)
	p.mu.Lock()
	// The epoch may have moved while the bundle was opened.
	if string(p.epoch) != string(cb.BlockRootEpoch) {
		p.mu.Unlock()
		return ErrOtherEpoch
	}
	if _, ok := p.keys[acct]; !ok && len(p.keys) >= MaxKeys {
		for a := range p.keys { // the cap is far above the accounts of a node; drop any one
			delete(p.keys, a)
			break
		}
	}
	p.keys[acct] = k
	delete(p.pend, acct)
	p.mu.Unlock()
	p.queue(&sock.BlockMsg{Type: sock.BlockIntermediate, Intermediate: in})
	return nil
}

// checkBundle is what the node requires of an intermediate before it holds the key
// (10.3): the key is the certificate's, the chain is consistent up to a CA root, the
// certificate is a CA with pathlen 0 and serverAuth alone, valid now for at most
// seven days, and its name constraints are critical and exclude every zone and
// panel host and all IP addresses, so that a hub that went wrong cannot hand out a
// key that signs for a bank's name.
func checkBundle(chainPEM, keyDER []byte, now time.Time, protect []string) ([]*x509.Certificate, error) {
	pk, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, errors.New("blockside: the key is not PKCS#8")
	}
	priv, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("blockside: the key is not ECDSA")
	}
	var chain []*x509.Certificate
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" || len(chain) >= sock.MaxChain {
			return nil, errors.New("blockside: the chain is not usable")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, errors.New("blockside: a certificate does not parse")
		}
		chain = append(chain, c)
	}
	if len(chain) < 2 {
		return nil, errors.New("blockside: the chain holds no root")
	}
	c := chain[0]
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&priv.PublicKey) {
		return nil, errors.New("blockside: the key is not the certificate's")
	}
	for i := 0; i+1 < len(chain); i++ {
		if chain[i].CheckSignatureFrom(chain[i+1]) != nil {
			return nil, errors.New("blockside: the chain is not consistent")
		}
	}
	if !chain[len(chain)-1].IsCA {
		return nil, errors.New("blockside: the chain does not end at a CA")
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		return nil, errors.New("blockside: the intermediate is not a CA of path length 0")
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return nil, errors.New("blockside: the intermediate is not for serverAuth alone")
	}
	if now.Before(c.NotBefore) || !now.Before(c.NotAfter) || c.NotAfter.Sub(c.NotBefore) > maxLife {
		return nil, errors.New("blockside: the intermediate is not valid now or lives too long")
	}
	if !c.PermittedDNSDomainsCritical || !excludesAllIPs(c) {
		return nil, errors.New("blockside: the name constraints are not critical or leave IP addresses open")
	}
	for _, h := range protect {
		if !excludesName(c, h) {
			return nil, errors.New("blockside: the name constraints leave a zone or panel host open")
		}
	}
	return chain, nil
}

func excludesName(c *x509.Certificate, host string) bool {
	for _, d := range c.ExcludedDNSDomains {
		if d == host || len(host) > len(d) && host[len(host)-len(d)-1] == '.' && host[len(host)-len(d):] == d {
			return true
		}
	}
	return false
}

func excludesAllIPs(c *x509.Certificate) bool {
	v4, v6 := false, false
	for _, r := range c.ExcludedIPRanges {
		if ones, _ := r.Mask.Size(); ones == 0 {
			if len(r.IP) == net.IPv4len || r.IP.To4() != nil && len(r.Mask) == net.IPv4len {
				v4 = true
			} else {
				v6 = true
			}
		}
	}
	return v4 && v6
}

// watch sets block_key_missing: a key asked for and not received for 10 minutes
// while Control is up (10.3). Time with no Control does not count, because a node
// cut off from the hub cannot be blamed for a key it could not fetch.
func (p *Part) watch(ctx context.Context) {
	t := time.NewTicker(p.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.check()
		}
	}
}

func (p *Part) check() {
	p.mu.Lock()
	h := p.host
	if h == nil {
		p.mu.Unlock()
		return
	}
	now := p.cfg.Now()
	up := h.ControlUp()
	if !up {
		p.upSince = time.Time{}
	} else if p.upSince.IsZero() {
		p.upSince = now
	}
	missing := false
	for a, pd := range p.pend {
		if now.Sub(pd.lastNeed) > NeedLife {
			delete(p.pend, a)
			continue
		}
		since := pd.first
		if p.upSince.After(since) {
			since = p.upSince
		}
		if up && now.Sub(since) >= p.cfg.MissingAfter {
			missing = true
		}
	}
	for a, k := range p.keys {
		if !now.Before(k.notAfter) {
			delete(p.keys, a)
		}
	}
	p.mu.Unlock()
	if p.cfg.Faults != nil {
		p.cfg.Faults.Set(hubv1.NodeFault_NODE_FAULT_BLOCK_KEY_MISSING, missing)
	}
}
