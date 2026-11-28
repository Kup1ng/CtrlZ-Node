package agent_test

// N7 on the agent's side (p4-nodes 11.2, SC 5.2a No trace, Plan T-555): canary
// proof_key, zone private key and node key go through the agent's error paths, and
// none of them may be in what the agent says (the process's log output, its
// alerts), in a file under its roots, or in a command it ran. The dns side of N7,
// with names, addresses and DoH tokens, is internal/dns TestN7NoTraceOfCanaries.
//
// The error paths: a NodeConfig that does not validate (it carries the canary
// proof_key), a CertBundle for a live zone whose wrapped key does not open (it is
// sealed to another key and holds a canary zone key), and a CertBundle that does
// open, whose key must reach the socket and the sealed store and nothing else.
// Linux only, like the other lab tests (skipWindows).
//
// Mutants: the agent logs a NodeConfig with %+v (the proof_key shows in the
// alert text or the log output); the CertBundle failure prints the unwrapped key or
// the error text of the open (it can carry key bytes); a zone key stored in the
// clear in keys/. Each is a line in onNodeConfig, the cert bundle handler or the
// zonekeys store, and each fails one of the scans below.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/zonekeys"
	"github.com/Kup1ng/CtrlZ-Node/internal/testsink"
)

// teeAlerts keeps what the lab's checks read and also writes each alert the way the
// production Log does, to the captured output.
type teeAlerts struct {
	mem *alert.Memory
	out *testsink.Capture
}

func (a teeAlerts) Alert(x alert.Alert) {
	a.mem.Alert(x)
	fmt.Fprintf(a.out, "ctrlz-agent alert %s: %s\n", x.Code, x.Detail)
}

// n7Bundle is a CertBundle for the zone, whose key is sealed to sealTo. It returns
// the message and the zone's private key in the clear (the canary).
func (l *lab) n7Bundle(zone string, sealTo *ecdsa.PublicKey) (*hubv1.HubMessage, []byte) {
	l.t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "zone ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cder, err := x509.CreateCertificate(rand.Reader, ctmpl, ctmpl, &caKey.PublicKey, caKey)
	if err != nil {
		l.t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(cder)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notAfter := time.Now().Add(2 * time.Hour)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: zone},
		DNSNames: []string{zone, "*." + zone, "*.verify." + zone}, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &lk.PublicKey, caKey)
	if err != nil {
		l.t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(lk)
	wrapped, err := zonekeys.Seal(sealTo, kder)
	if err != nil {
		l.t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder})...)
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_CertBundle{CertBundle: &hubv1.CertBundle{
		Kind: signv1.Kind_KIND_CERTS, WrappedKey: wrapped, ChainPem: chain, NotAfter: notAfter.Unix()}}}, kder
}

// forms is a secret in the shapes it can leak in: raw, hex, and the front of its
// base64 (a PEM body wraps at 64 columns, so only that much is contiguous).
func forms(b []byte) [][]byte {
	// Each encoding is cut by its own length: the padded standard form of a
	// 32-byte key is longer than its raw URL form, so sharing one length panics.
	b64 := base64.StdEncoding.EncodeToString(b)
	raw := base64.RawURLEncoding.EncodeToString(b)
	return [][]byte{b, []byte(hex.EncodeToString(b)), []byte(b64[:min(len(b64), 48)]), []byte(raw[:min(len(raw), 48)])}
}

func TestN7AgentErrorPathsLeaveNoCanary(t *testing.T) {
	var sinks *testsink.Capture
	l := newLab(t, func(l *lab) {}) // skips on Windows before anything else
	sinks = testsink.Start(t)
	l.cfg.Alert = teeAlerts{mem: l.alerts, out: sinks}
	sinks.Control(t)

	proof := make([]byte, 32)
	if _, err := rand.Read(proof); err != nil {
		t.Fatal(err)
	}
	nodeKey, _ := x509.MarshalPKCS8PrivateKey(l.idp.node)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())

	// 1. A NodeConfig that does not validate and carries the canary proof_key.
	bad := testNodeConfig(1, proof)
	bad.DnsBindIp = []byte{1, 2} // neither an IPv4 nor an IPv6 address
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: bad}})
	eventually(t, "the refusal", func() bool { return l.alerts.Count(alert.ConfigFallback) > 0 })

	// 2. A good one with the same key, so the zone is live.
	_ = s.Send(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: testNodeConfig(2, proof)}})
	eventually(t, "the config", func() bool { return lastHB(s).NodeConfigVersion == 2 })

	// 3. A CertBundle for the live zone that does not open: sealed to another key.
	msg, zoneKeyBad := l.n7Bundle("dns.example.net", &other.PublicKey)
	_ = s.Send(msg)
	eventually(t, "the refusal of the bundle", func() bool { return l.alerts.Count(alert.CertBundleRefused) > 0 })

	// 4. One that does open.
	msg, zoneKeyGood := l.n7Bundle("dns.example.net", &l.idp.node.PublicKey)
	_ = s.Send(msg)
	l.waitDNS("the zone key at dns", func() bool { return len(l.zoneKeyMsgs()) >= 1 })

	time.Sleep(300 * time.Millisecond)
	l.stop()
	sinks.Stop()

	var needles [][]byte
	for _, secret := range [][]byte{proof, nodeKey, zoneKeyBad, zoneKeyGood} {
		needles = append(needles, forms(secret)...)
	}
	check := func(what string, hay []byte) {
		t.Helper()
		for _, n := range needles {
			if bytes.Contains(hay, n) {
				t.Errorf("%s holds a canary secret (%d bytes, starting %x)", what, len(n), n[:min(len(n), 4)])
			}
		}
	}
	check("the log output and alerts", sinks.Bytes())
	var calls strings.Builder
	for _, c := range l.runner.Calls() {
		calls.WriteString(c.String() + "\n")
		check("the stdin of "+c.Name, c.Stdin)
	}
	check("a command line", []byte(calls.String()))
	var files int
	err := filepath.WalkDir(l.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		files++
		check("file "+filepath.Base(p), b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no file was scanned")
	}
	if l.keyFiles() == 0 {
		t.Error("the opened zone key was not stored: the test did not reach the path it guards")
	}
}
