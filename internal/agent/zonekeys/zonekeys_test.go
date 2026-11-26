package zonekeys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

type fixture struct {
	t       *testing.T
	nodeKey *ecdsa.PrivateKey
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	st      *Store
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, now: time.Now()}
	f.nodeKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "zone CA"}, NotBefore: f.now.Add(-time.Hour),
		NotAfter: f.now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.caKey.PublicKey, f.caKey)
	f.caCert, _ = x509.ParseCertificate(der)
	root, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.st = &Store{Root: root, Key: f.nodeKey, Zones: func() []string { return []string{"dns.example.net"} }, Now: func() time.Time { return f.now }}
	return f
}

// bundle makes a CertBundle for the given SANs, sealing the leaf's key to sealTo.
func (f *fixture) bundle(sans []string, notAfter time.Time, sealTo *ecdsa.PublicKey) *hubv1.CertBundle {
	f.t.Helper()
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: sans[0]}, DNSNames: sans,
		NotBefore: f.now.Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, &lk.PublicKey, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(lk)
	wrapped, err := Seal(sealTo, keyDER)
	if err != nil {
		f.t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})...)
	return &hubv1.CertBundle{Kind: signv1.Kind_KIND_CERTS, WrappedKey: wrapped, ChainPem: chain, NotAfter: notAfter.Unix()}
}

var zoneSANs = []string{"dns.example.net", "*.dns.example.net", "*.verify.dns.example.net"}

func TestAcceptStoresSealedAndReloadsAtStart(t *testing.T) {
	f := newFixture(t)
	cb := f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)
	c, err := f.st.Accept(cb)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SANs) != 3 || len(c.Roots) != 1 || c.NotAfter != cb.NotAfter {
		t.Errorf("cert: %+v", c)
	}
	// the private key is in no file in the clear
	files := f.st.Root.Dir()
	var found bool
	_ = filepathWalk(files, func(b []byte) {
		if bytes.Contains(b, c.KeyDER) {
			found = true
		}
	})
	if found {
		t.Error("the opened key is on disk in the clear")
	}
	// a restart: a new Store over the same directory opens it with no hub
	again := &Store{Root: f.st.Root, Key: f.nodeKey, Zones: f.st.Zones, Now: f.st.Now}
	certs, bad := again.LoadAll()
	if len(certs) != 1 || bad != 0 || !bytes.Equal(certs[0].KeyDER, c.KeyDER) {
		t.Fatalf("reload: %d certs, %d bad", len(certs), bad)
	}
	// a newer bundle for the same names replaces the old one
	if _, err := f.st.Accept(f.bundle(zoneSANs, f.now.Add(2*time.Hour), &f.nodeKey.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if certs, _ := again.LoadAll(); len(certs) != 1 {
		t.Errorf("the same SAN set must keep one bundle, got %d", len(certs))
	}
	if pool := CARoots(certs); len(pool.Subjects()) != 1 { //nolint:staticcheck // counting roots in a test
		t.Error("CARoots")
	}
}

func filepathWalk(dir string, fn func([]byte)) error {
	return walk(dir, fn)
}

func TestRefusals(t *testing.T) {
	f := newFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, mk := range map[string]func() *hubv1.CertBundle{
		"sealed to another node": func() *hubv1.CertBundle {
			return f.bundle(zoneSANs, f.now.Add(time.Hour), &other.PublicKey)
		},
		"expired leaf": func() *hubv1.CertBundle {
			return f.bundle(zoneSANs, f.now.Add(-time.Second), &f.nodeKey.PublicKey)
		},
		"names of another zone": func() *hubv1.CertBundle {
			return f.bundle([]string{"dns.other.org", "*.dns.other.org", "*.verify.dns.other.org"}, f.now.Add(time.Hour), &f.nodeKey.PublicKey)
		},
		"an extra name": func() *hubv1.CertBundle {
			return f.bundle(append([]string{"evil.example.net"}, zoneSANs...), f.now.Add(time.Hour), &f.nodeKey.PublicKey)
		},
		"a missing verify name": func() *hubv1.CertBundle {
			return f.bundle(zoneSANs[:2], f.now.Add(time.Hour), &f.nodeKey.PublicKey)
		},
		"wrong kind": func() *hubv1.CertBundle {
			b := f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)
			b.Kind = signv1.Kind_KIND_NODE
			return b
		},
		"empty chain": func() *hubv1.CertBundle {
			b := f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)
			b.ChainPem = []byte("nothing")
			return b
		},
		"key of another leaf": func() *hubv1.CertBundle {
			a := f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)
			b := f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)
			a.WrappedKey = b.WrappedKey
			return a
		},
		"garbage wrapped key": func() *hubv1.CertBundle {
			b := f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)
			b.WrappedKey = []byte("not hpke")
			return b
		},
		"nil": func() *hubv1.CertBundle { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.st.Accept(mk()); err == nil {
				t.Error("accepted")
			}
		})
	}
	if certs, bad := f.st.LoadAll(); len(certs) != 0 || bad != 0 {
		t.Errorf("a refused bundle was stored: %d %d", len(certs), bad)
	}
	// stored bundles that expired are skipped at start
	if _, err := f.st.Accept(f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(3 * time.Hour)
	if certs, bad := f.st.LoadAll(); len(certs) != 0 || bad != 1 {
		t.Errorf("expired: %d certs, %d bad", len(certs), bad)
	}
}

// p4n-W5b-r1-20: with no live zone known a bundle is not kept, whatever its
// names; the error says it is a matter of timing so the caller can hold it.
func TestNoZoneKnownRefusesAndStoresNothing(t *testing.T) {
	f := newFixture(t)
	f.st.Zones = nil
	_, err := f.st.Accept(f.bundle([]string{"x.test"}, f.now.Add(time.Hour), &f.nodeKey.PublicKey))
	if !errors.Is(err, ErrNoZones) {
		t.Fatalf("got %v, want ErrNoZones", err)
	}
	if certs, bad := f.st.LoadAll(); len(certs) != 0 || bad != 0 {
		t.Errorf("a bundle was stored: %d %d", len(certs), bad)
	}
	f.st.Zones = func() []string { return []string{"other.example"} }
	if _, err := f.st.Accept(f.bundle(zoneSANs, f.now.Add(time.Hour), &f.nodeKey.PublicKey)); !errors.Is(err, ErrNotLiveZone) {
		t.Fatalf("got %v, want ErrNotLiveZone", err)
	}
}

// p4n-W5b-r1-15: a bundle of a retired zone is removed from disk by Prune and a
// live one stays; with no NodeConfig at start the stored bundles still load.
func TestPruneRemovesRetiredZones(t *testing.T) {
	f := newFixture(t)
	oldSANs := []string{"dns.old.example", "*.dns.old.example", "*.verify.dns.old.example"}
	f.st.Zones = func() []string { return []string{"dns.example.net", "dns.old.example"} }
	for _, s := range [][]string{zoneSANs, oldSANs} {
		if _, err := f.st.Accept(f.bundle(s, f.now.Add(time.Hour), &f.nodeKey.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
	f.st.Zones = nil
	if certs, bad := f.st.LoadAll(); len(certs) != 2 || bad != 0 {
		t.Fatalf("with no NodeConfig: %d certs, %d bad", len(certs), bad)
	}
	gone := f.st.Prune([]string{"dns.example.net"})
	if len(gone) != 1 || !strings.Contains(strings.Join(gone[0], ","), "dns.old.example") {
		t.Fatalf("pruned %v", gone)
	}
	if certs, _ := f.st.LoadAll(); len(certs) != 1 {
		t.Fatalf("after prune: %d certs", len(certs))
	}
	if f.st.Prune(nil) != nil {
		t.Error("prune with no zones must remove nothing")
	}
}
