// Package storetest holds what the tests of the store packages share: entries,
// blobs, a signing root, a fake hub and a walk that searches a directory for a
// secret. It is imported by tests only.
package storetest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// Blob builds a valid profile blob that blocks one name. Different tokens give
// different bytes and so different hashes.
func Blob(t testing.TB, token string) []byte {
	t.Helper()
	p, err := rules.Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	d, err := blob.Build(&blob.Spec{Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: p, Action: blob.ActBlock}}})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Hash is the SHA-256 of d.
func Hash(d []byte) [32]byte { return sha256.Sum256(d) }

// Ref is the BlobRef of a profile blob.
func Ref(d []byte) *policyv1.BlobRef {
	h := sha256.Sum256(d)
	return &policyv1.BlobRef{Hash: h[:], Size: uint64(len(d)), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
}

// Endpoint is an Endpoint record bound to the blob d, with every id field
// derived from id so two Endpoints never share a rid hash.
func Endpoint(id byte, d []byte) *policyv1.EndpointRecord {
	h := sha256.Sum256(d)
	return &policyv1.EndpointRecord{
		EndpointId: bytes.Repeat([]byte{id}, 16), RidHash: bytes.Repeat([]byte{id}, 16), DohTokenHash: bytes.Repeat([]byte{id}, 32),
		PairId: bytes.Repeat([]byte{9}, 16), AdminState: commonv1.AdminState_ADMIN_STATE_ENABLED,
		AnalyticsLevel: commonv1.AnalyticsLevel_ANALYTICS_LEVEL_SOME,
		Base:           &policyv1.StackRecord{Profile1Hash: h[:]},
	}
}

// Claim is a claim for an Endpoint on 10.<id>.0.0/16 spelled as an IPv4 prefix.
func Claim(id, endpoint byte) *policyv1.ClaimRecord {
	return &policyv1.ClaimRecord{
		ClaimId: bytes.Repeat([]byte{id}, 16), EndpointId: bytes.Repeat([]byte{endpoint}, 16),
		Prefix: &commonv1.Prefix{Addr: []byte{198, 51, id, 0}, Bits: 24},
	}
}

// Chain makes the stored bytes of consecutive entries.
type Chain struct {
	Seq  uint64
	Head [32]byte
}

// Next sets the seq, the previous hash and the class of e, marshals it and
// advances the chain as the node will.
func (c *Chain) Next(t testing.TB, e *policyv1.ConfigEntry) []byte {
	t.Helper()
	b := c.Marshal(t, e)
	c.Advance(b)
	return b
}

// Marshal is Next without advancing, for an entry the node should refuse.
func (c *Chain) Marshal(t testing.TB, e *policyv1.ConfigEntry) []byte {
	t.Helper()
	e.Seq = c.Seq + 1
	e.PrevHash = c.Head[:]
	e.Class = commonv1.EntryClass_ENTRY_CLASS_POLICY
	b, err := wire.MarshalEntry(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Advance moves the chain past an entry the node applied.
func (c *Chain) Advance(stored []byte) {
	c.Head = wire.EntryHash(c.Head, stored)
	c.Seq++
}

// Four public addresses, one per node of a test table.
var nodeIPs = [][]byte{{8, 8, 8, 8}, {8, 8, 4, 4}, {1, 1, 1, 1}, {9, 9, 9, 9}}

// NodeID is the id of test node n (0 to 3).
func NodeID(n int) []byte { return bytes.Repeat([]byte{0xa0 + byte(n)}, 16) }

// Table builds a valid PairTable of n nodes (2 to 4), with the pair (node 0,
// node 1) as the global pair. Slots are 1 to n, SPKIs are 32 bytes. withdrawn
// sets dns_withdrawn for the named nodes, which only a push may do.
func Table(n int, version uint64, withdrawn ...int) *policyv1.PairTable {
	pt := &policyv1.PairTable{Version: version, GlobalPairId: bytes.Repeat([]byte{0xb0}, 16)}
	for i := 0; i < n; i++ {
		ne := &policyv1.NodeEntry{
			NodeId: NodeID(i), DnsIp: nodeIPs[i], ProxyIp: nodeIPs[i], Slot: uint32(i + 1),
			SpkiSha256: bytes.Repeat([]byte{byte(i + 1)}, 32),
		}
		for _, w := range withdrawn {
			if w == i {
				ne.DnsWithdrawn = true
			}
		}
		pt.Nodes = append(pt.Nodes, ne)
	}
	pt.Pairs = []*policyv1.Pair{{PairId: bytes.Repeat([]byte{0xb0}, 16), Primary: NodeID(0), Fallback: NodeID(1)}}
	return pt
}

// Keys is a signing setup: one online policy key and a root that grants it.
type Keys struct {
	Root *signv1.Root
	priv ed25519.PrivateKey
	id   []byte
}

// NewKeys makes a root with one policy key and one bundle key pair of offline
// keys, the shape the production root has.
func NewKeys(t testing.TB) *Keys {
	t.Helper()
	mk := func() (*signv1.PublicKey, ed25519.PrivateKey) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &signv1.PublicKey{KeyId: manifest.KeyID(pub), Ed25519: pub}, priv
	}
	pol, polPriv := mk()
	o1, _ := mk()
	o2, _ := mk()
	far := int64(1) << 40
	root := &signv1.Root{Version: 1, ExpiresAt: far, Keys: []*signv1.PublicKey{o1, o2, pol}, Threshold: 2,
		RootKeyIds: [][]byte{o1.KeyId, o2.KeyId}, Roles: []*signv1.RoleGrant{
			{Role: signv1.Role_ROLE_BUNDLE, KeyIds: [][]byte{o1.KeyId, o2.KeyId}, Threshold: 2, ExpiresAt: far},
			{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{pol.KeyId}, Threshold: 1, ExpiresAt: far},
		}}
	return &Keys{Root: root, priv: polPriv, id: pol.KeyId}
}

// Sign signs a PairTable as the hub's policy key does.
func (k *Keys) Sign(t testing.TB, pt *policyv1.PairTable) *signv1.Envelope {
	t.Helper()
	payload, err := proto.Marshal(pt)
	if err != nil {
		t.Fatal(err)
	}
	return k.SignPayload(manifest.TypePairTable, payload)
}

// SignPayload signs arbitrary bytes under a payload type.
func (k *Keys) SignPayload(typ string, payload []byte) *signv1.Envelope {
	return &signv1.Envelope{PayloadType: typ, Payload: payload, Signatures: []*signv1.Signature{
		{KeyId: k.id, Sig: ed25519.Sign(k.priv, manifest.SigningInput(typ, payload))},
	}}
}

// Hub is a fake hub: blobs by hash, a snapshot, counters and hooks. It
// implements blobfetch.Source and apply.SnapshotSource.
type Hub struct {
	mu    sync.Mutex
	Blobs map[[32]byte][]byte
	// OpenHook, when set, may replace the answer: return a non-nil reader or error.
	OpenHook func(ctx context.Context, h [32]byte) (io.ReadCloser, error, bool)
	Opens    int
	Snapshot *signv1.Snapshot
	Snaps    int
	// Fetch counts per hash.
	Count map[[32]byte]int
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{Blobs: map[[32]byte][]byte{}, Count: map[[32]byte]int{}} }

// Add stores a blob and returns its hash.
func (h *Hub) Add(d []byte) [32]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := sha256.Sum256(d)
	h.Blobs[k] = d
	return k
}

// Remove deletes a blob, so the next fetch finds it missing.
func (h *Hub) Remove(k [32]byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.Blobs, k)
}

// OpenBlob implements blobfetch.Source.
func (h *Hub) OpenBlob(ctx context.Context, k [32]byte, _ policyv1.BlobKind, _ int64) (io.ReadCloser, error) {
	h.mu.Lock()
	h.Opens++
	h.Count[k]++
	hook := h.OpenHook
	d, ok := h.Blobs[k]
	h.mu.Unlock()
	if hook != nil {
		if rc, err, handled := hook(ctx, k); handled {
			return rc, err
		}
	}
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(d)), nil
}

// GetSnapshot implements apply.SnapshotSource.
func (h *Hub) GetSnapshot(_ context.Context, atLeast uint64) (*signv1.Snapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Snaps++
	if h.Snapshot == nil || h.Snapshot.Seq < atLeast {
		return nil, errors.New("no snapshot that recent")
	}
	return h.Snapshot, nil
}

// Contains reports whether any regular file under dir holds secret, which is how
// the tests check that something never reached disk.
func Contains(t testing.TB, dir string, secret []byte) bool {
	t.Helper()
	if len(secret) == 0 {
		t.Fatal("empty secret")
	}
	found := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, secret) {
			t.Logf("secret found in %s", p)
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// RandomSecret returns n random bytes.
func RandomSecret(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
