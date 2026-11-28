package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
)

// renewEvery is how often the agent looks at its certificate.
const renewEvery = time.Hour

func (a *Agent) renewLoop(ctx context.Context) {
	// The first look is a few seconds after the start, so the Control stream and
	// the transfer connection are up before a CSR goes out.
	wait := 10 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = renewEvery
		if _, err := a.RenewIfDue(ctx); err != nil && ctx.Err() == nil {
			a.al.Alert(alert.Alert{Code: alert.HubUnreachable, Detail: "the node certificate could not be renewed"})
		}
	}
}

// RenewIfDue renews the node certificate when a third of its life is left (4.3):
// a CSR over the enrolled key, RenewCert on the transfer connection, and the
// answer checked before it is kept. It reports whether a new certificate is in
// use. The hub refuses a CSR of another key, and so does the check here: a
// certificate that is not for the node's key would break the next handshake.
func (a *Agent) RenewIfDue(ctx context.Context) (renewed bool, err error) {
	// A panic while parsing what the hub sent costs this attempt, never the agent.
	defer func() {
		if recover() != nil {
			renewed, err = false, errors.New("agent: panic while renewing the certificate")
		}
	}()
	leaf := a.cfg.Identity.Leaf()
	total := leaf.NotAfter.Sub(leaf.NotBefore)
	if leaf.NotAfter.Sub(a.now()) > total/3 {
		return false, nil
	}
	key, ok := a.cfg.Identity.Key().PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return false, errors.New("agent: the node key is not an ECDSA key")
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: leaf.Subject}, key)
	if err != nil {
		return false, fmt.Errorf("agent: CSR: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := a.xferPool.Client().RenewCert(ctx, &hubv1.RenewCertRequest{CsrDer: csr})
	if err != nil {
		return false, fmt.Errorf("agent: RenewCert: %w", err)
	}
	cert, err := x509.ParseCertificate(resp.CertDer)
	if err != nil {
		return false, errors.New("agent: the renewed certificate does not parse")
	}
	// The hub's answer is untrusted input. The key is compared as its encoding, not
	// through PublicKey: x509 leaves PublicKey nil for an algorithm it does not know
	// and gives a DSA key no Equal method, and a failed assertion here would end the
	// whole process, in a loop, since the renewal is still due after the restart.
	wantSPKI, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return false, errors.New("agent: the node key does not encode")
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, wantSPKI) || cert.Subject.CommonName != leaf.Subject.CommonName || !cert.NotAfter.After(leaf.NotAfter) {
		return false, errors.New("agent: the renewed certificate is not a renewal of this node's")
	}
	// It must also be one the hub could use: issued by the node CA, for client
	// authentication, and valid now.
	if _, err := cert.Verify(x509.VerifyOptions{Roots: a.cfg.Identity.CA(), CurrentTime: a.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return false, errors.New("agent: the renewed certificate does not chain to the node CA")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.CertDer})
	// Disk first, so a restart finds the certificate that is in use.
	if err := a.root.WriteKey(hubconn.NodeCertFile, pemBytes); err != nil {
		return false, fmt.Errorf("agent: store the renewed certificate: %w", err)
	}
	if err := a.cfg.Identity.SetCertificate(pemBytes); err != nil {
		return false, err
	}
	// New connections present the new certificate; the three that are open keep the
	// old one until they end, which the hub accepts until it expires.
	return true, nil
}
