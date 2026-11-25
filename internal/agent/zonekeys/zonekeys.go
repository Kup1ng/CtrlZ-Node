// Package zonekeys keeps the zone certificates the hub sends in CertBundle
// (p4-nodes 4.3): the private key arrives sealed to the node's enrolled public
// key with HPKE, so only this node opens it; the node stores the sealed bundle
// by the leaf's SAN set and opens it again at start with no panel.
//
// What is checked before a bundle is kept: it opens with the node's key, the key
// it holds is the one in the leaf, the chain is consistent (each certificate is
// signed by the next), the leaf is valid now, and its names are exactly the
// three of a live zone of the NodeConfig (`<zone>`, `*.<zone>`,
// `*.verify.<zone>`, 4.3). The leaf is not chained to a root here: the node has
// no anchor for the private zone CA in P4's key files, and the hub is the only
// party that could send the bundle. Clients and probes verify it as any client
// does. The private-CA root that the probes trust is taken from the bundle
// (CARoots).
package zonekeys

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"crypto/hpke"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// Info is the HPKE info string of the seal (4.3).
const Info = "ctrlz-certbundle-v1"

const filePrefix = "zone-"
const fileSuffix = ".cb"

// maxBundle bounds a CertBundle read from disk or taken from the hub.
const maxBundle = 1 << 20

// Cert is an opened zone certificate.
type Cert struct {
	SANs     []string
	ChainPEM []byte
	KeyDER   []byte // PKCS#8
	NotAfter int64
	// Roots are the self-signed certificates of the chain, which the probes trust in
	// private-CA mode.
	Roots []*x509.Certificate
}

// Store keeps the sealed bundles in keys/.
type Store struct {
	Root *store.Root
	Key  *ecdsa.PrivateKey
	// Zones returns the live zones of the NodeConfig, nil when none is known.
	Zones func() []string
	Now   func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ErrNoZones is returned by Open while the node knows no live zone, and
// ErrNotLiveZone when the bundle's names are not those of a zone it knows. Both
// are about timing, not about the bundle: the NodeConfig that names the zone may
// be on its way (CertBundle and NodeConfig are handled on separate workers, L11),
// so the caller keeps such a bundle and offers it again after the next NodeConfig.
var (
	ErrNoZones     = errors.New("zonekeys: no live zone is known yet")
	ErrNotLiveZone = errors.New("zonekeys: the names are not those of a live zone")
)

// Open unseals and checks a CertBundle. It stores nothing. With no live zone
// known it refuses with ErrNoZones: a bundle of any names must not be kept and
// served before the zone it is for is known (4.3, exactly the three names of a
// live zone).
func (s *Store) Open(cb *hubv1.CertBundle) (*Cert, error) { return s.open(cb, true) }

func (s *Store) open(cb *hubv1.CertBundle, checkZones bool) (*Cert, error) {
	if cb == nil || cb.Kind != signv1.Kind_KIND_CERTS || len(cb.WrappedKey) == 0 || len(cb.WrappedKey) > maxBundle || len(cb.ChainPem) == 0 || len(cb.ChainPem) > maxBundle {
		return nil, errors.New("zonekeys: not a certificate bundle")
	}
	if s.Key == nil {
		return nil, errors.New("zonekeys: no node key")
	}
	ecdhKey, err := s.Key.ECDH()
	if err != nil {
		return nil, errors.New("zonekeys: the node key is not usable for HPKE")
	}
	kemKey, err := hpke.NewDHKEMPrivateKey(ecdhKey)
	if err != nil {
		return nil, errors.New("zonekeys: the node key is not usable for HPKE")
	}
	keyDER, err := hpke.Open(kemKey, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(Info), cb.WrappedKey)
	if err != nil {
		return nil, errors.New("zonekeys: the bundle does not open with the node's key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, errors.New("zonekeys: the sealed key is not PKCS#8")
	}
	chain, err := parseChain(cb.ChainPem)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	if !samePublic(leaf.PublicKey, priv) {
		return nil, errors.New("zonekeys: the key is not the leaf's key")
	}
	now := s.now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("zonekeys: the leaf is not valid now")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, errors.New("zonekeys: the chain is not consistent")
		}
	}
	sans := append([]string(nil), leaf.DNSNames...)
	sort.Strings(sans)
	if checkZones {
		zs := zonesOf(s.Zones)
		if len(zs) == 0 {
			return nil, ErrNoZones
		}
		if !matchesAZone(sans, zs) {
			return nil, ErrNotLiveZone
		}
	}
	c := &Cert{SANs: sans, ChainPEM: cb.ChainPem, KeyDER: keyDER, NotAfter: leaf.NotAfter.Unix()}
	for _, x := range chain {
		if x.IsCA && x.CheckSignatureFrom(x) == nil {
			c.Roots = append(c.Roots, x)
		}
	}
	return c, nil
}

func zonesOf(f func() []string) []string {
	if f == nil {
		return nil
	}
	return f()
}

// Live reports whether the SANs are exactly the three names of one of the zones.
func Live(sans, zones []string) bool { return matchesAZone(sans, zones) }

// matchesAZone: the SANs are exactly {zone, *.zone, *.verify.zone} for a live zone.
func matchesAZone(sans, zones []string) bool {
	for _, z := range zones {
		z = strings.TrimSuffix(strings.ToLower(z), ".")
		want := []string{z, "*." + z, "*.verify." + z}
		sort.Strings(want)
		if len(sans) != len(want) {
			continue
		}
		ok := true
		for i := range want {
			if strings.ToLower(sans[i]) != want[i] {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func parseChain(p []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, p = pem.Decode(p)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, errors.New("zonekeys: the chain holds something that is not a certificate")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, errors.New("zonekeys: a certificate does not parse")
		}
		out = append(out, c)
		if len(out) > 8 {
			return nil, errors.New("zonekeys: the chain is too long")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("zonekeys: empty chain")
	}
	return out, nil
}

// SetKey is the file name of a SAN set.
func fileName(sans []string) string {
	h := sha256.Sum256([]byte(strings.Join(sans, ",")))
	return filePrefix + hex.EncodeToString(h[:8]) + fileSuffix
}

// Accept opens a bundle and, when it is good, stores it sealed by its SAN set,
// replacing the earlier bundle for the same names.
func (s *Store) Accept(cb *hubv1.CertBundle) (*Cert, error) {
	c, err := s.Open(cb)
	if err != nil {
		return nil, err
	}
	b, err := proto.Marshal(cb)
	if err != nil {
		return nil, err
	}
	if err := s.Root.WriteKey(fileName(c.SANs), b); err != nil {
		return nil, fmt.Errorf("zonekeys: store: %w", err)
	}
	return c, nil
}

// LoadAll opens every stored bundle: at start, with no panel. A bundle that no
// longer opens or has expired is skipped and counted in bad.
func (s *Store) LoadAll() (certs []*Cert, bad int) {
	ents, err := os.ReadDir(s.Root.Path(store.DirKeys))
	if err != nil {
		return nil, 0
	}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, filePrefix) || !strings.HasSuffix(n, fileSuffix) {
			continue
		}
		b, err := os.ReadFile(s.Root.KeyPath(n))
		if err != nil || len(b) > maxBundle {
			bad++
			continue
		}
		cb := &hubv1.CertBundle{}
		if proto.Unmarshal(b, cb) != nil {
			bad++
			continue
		}
		// A bundle on disk passed the zone check when it was accepted. With no
		// NodeConfig yet (a damaged config directory) it is still loaded, so dns has
		// its certificate; Prune drops it once the NodeConfig says it is retired.
		c, err := s.open(cb, len(zonesOf(s.Zones)) > 0)
		if err != nil {
			bad++
			continue
		}
		certs = append(certs, c)
	}
	return certs, bad
}

// Prune removes the stored bundles whose names are not those of a live zone and
// returns the SAN sets it removed. A bundle that no zone of the NodeConfig names
// any more (a domain change finished, a placeholder zone replaced) must not stay
// as a fallback certificate or as a root the probes trust.
func (s *Store) Prune(zones []string) [][]string {
	if len(zones) == 0 {
		return nil
	}
	ents, err := os.ReadDir(s.Root.Path(store.DirKeys))
	if err != nil {
		return nil
	}
	var gone [][]string
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, filePrefix) || !strings.HasSuffix(n, fileSuffix) {
			continue
		}
		b, err := os.ReadFile(s.Root.KeyPath(n))
		cb := &hubv1.CertBundle{}
		if err != nil || len(b) > maxBundle || proto.Unmarshal(b, cb) != nil {
			continue
		}
		c, err := s.open(cb, false)
		if err != nil || matchesAZone(c.SANs, zones) {
			continue
		}
		if os.Remove(s.Root.KeyPath(n)) == nil {
			gone = append(gone, c.SANs)
		}
	}
	return gone
}

// CARoots is a pool of the roots of the stored bundles, for the probes in
// private-CA mode. An empty pool trusts nothing, which fails a probe closed.
func CARoots(certs []*Cert) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		for _, r := range c.Roots {
			pool.AddCert(r)
		}
	}
	return pool
}

// Seal is the hub's side of the seal, for tests and for the lab hub: it seals a
// PKCS#8 key to a node's public key.
func Seal(pub *ecdsa.PublicKey, keyDER []byte) ([]byte, error) {
	ek, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	pk, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(ek.Bytes())
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(Info), keyDER)
}

func samePublic(leafPub any, priv any) bool {
	pk, ok := priv.(interface{ Public() crypto.PublicKey })
	if !ok {
		return false
	}
	eq, ok := pk.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(leafPub)
}
