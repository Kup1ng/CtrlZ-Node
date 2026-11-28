package agent

import (
	"context"
	"errors"
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/blockside"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

func TestBlockPageBlobOnlyForKnownBlockPages(t *testing.T) {
	page, profile := [32]byte{1}, [32]byte{2}
	read := func(h [32]byte) ([]byte, error) {
		if h == page || h == profile {
			return []byte("bytes"), nil
		}
		return nil, errors.New("missing")
	}
	isPage := func(h [32]byte) bool { return h == page }
	if b := blockPageBlob(page, isPage, read); b == nil {
		t.Fatal("a known block page was not returned")
	}
	if b := blockPageBlob(profile, isPage, read); b != nil {
		t.Fatal("a profile blob was handed to the block process")
	}
	if b := blockPageBlob([32]byte{3}, isPage, read); b != nil {
		t.Fatal("an unknown hash returned bytes")
	}
	huge := func(h [32]byte) ([]byte, error) { return make([]byte, sock.MaxPageBlob+1), nil }
	if b := blockPageBlob(page, isPage, huge); b != nil {
		t.Fatal("a page over a frame was returned")
	}
}

// bundlePart is a Part that takes block bundles.
type bundlePart struct {
	got []*hubv1.CertBundle
	err error
}

func (b *bundlePart) Run(context.Context)        {}
func (b *bundlePart) Config(*hubv1.NodeConfig)   {}
func (b *bundlePart) Heartbeat(*hubv1.Heartbeat) {}
func (b *bundlePart) Bundle(cb *hubv1.CertBundle) error {
	b.got = append(b.got, cb)
	return b.err
}

// A block intermediate goes to the part and never to the zone path: the agent here
// has no zone key store at all, so reaching it would panic.
func TestBlockIntermediateBundleGoesToThePartNotTheZonePath(t *testing.T) {
	mem := &alert.Memory{}
	bp := &bundlePart{}
	a := &Agent{cfg: Config{Parts: []Part{bp}}, al: mem}
	cb := &hubv1.CertBundle{Use: hubv1.CertUse_CERT_USE_BLOCK_INTERMEDIATE}
	a.onCertBundle(context.Background(), cb)
	if len(bp.got) != 1 || bp.got[0] != cb {
		t.Fatal("the part did not get the bundle")
	}
	if n := len(mem.Codes()); n != 0 {
		t.Fatalf("%d alerts for a good bundle", n)
	}
	bp.err = blockside.ErrOtherEpoch
	a.onCertBundle(context.Background(), cb)
	if n := len(mem.Codes()); n != 0 {
		t.Fatalf("a bundle of another epoch alerted (%d)", n)
	}
	bp.err = errors.New("refused")
	a.onCertBundle(context.Background(), cb)
	if n := len(mem.Codes()); n != 1 {
		t.Fatalf("a refused bundle gave %d alerts", n)
	}
}
