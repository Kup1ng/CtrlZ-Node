package agent

import (
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/blockside"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/zonekeys"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
)

// The agent's end of the block page process (p4b-proxy 17 row B6) joins the agent
// here and nowhere else: boot makes the part with wireBlockPart before New, and
// attaches it to the agent with attach after. The part needs the agent's node key,
// stored blobs and hub queue, none of which exist when the Config is built, so the
// Host it gets is a set of closures over the agent that is bound late.

// bundleTaker is a Part that takes CertBundles of use block_intermediate. The agent
// offers such a bundle to every part that says so; the zone bundle path, which
// matches names against the zones of the NodeConfig, never sees it.
type bundleTaker interface {
	Bundle(cb *hubv1.CertBundle) error
}

type blockWiring struct{ part *blockside.Part }

// wireBlockPart makes the part and adds it to the Config's parts.
func wireBlockPart(cfg *Config) *blockWiring {
	if cfg.Faults == nil {
		cfg.Faults = NewFaults()
	}
	p := blockside.New(blockside.Config{Faults: cfg.Faults, Now: cfg.Now})
	cfg.Parts = append(cfg.Parts, p)
	return &blockWiring{part: p}
}

// attach binds the part to the built agent.
func (w *blockWiring) attach(a *Agent) {
	w.part.Attach(blockside.Host{
		Unseal:    func(wrapped []byte) ([]byte, error) { return zonekeys.Unseal(a.zk.Key, wrapped) },
		PageBlob:  a.storedBlockPage,
		Outside:   a.ctl.Outside,
		ControlUp: a.streamUp.Load,
		HubNow:    a.hubNow,
	})
}

// storedBlockPage returns the stored blob of a block page and of no other kind of
// blob: the applied state says which hashes are valid block page records, so a
// profile blob cannot be had by asking for its hash (10.2). ReadBlob checks the
// bytes against the hash.
func (a *Agent) storedBlockPage(h [32]byte) []byte {
	return blockPageBlob(h, func(h [32]byte) (known bool) {
		a.app.Inspect(func(ap *store.Applied) { known = ap.Q.BlockPages[h] })
		return known
	}, a.root.ReadBlob)
}

// blockPageBlob is storedBlockPage over its two sources, so that the rule is
// testable without an applier: a hash that is not a known block page gets nothing
// and the blob is not even read.
func blockPageBlob(h [32]byte, isPage func([32]byte) bool, read func([32]byte) ([]byte, error)) []byte {
	if !isPage(h) {
		return nil
	}
	b, err := read(h)
	if err != nil || len(b) > sock.MaxPageBlob {
		return nil
	}
	return b
}

// blockBundle hands a block intermediate to the part that takes it. It reports
// whether any part did; the zone path is not tried for such a bundle either way.
func (a *Agent) blockBundle(cb *hubv1.CertBundle) {
	for _, p := range a.cfg.Parts {
		bt, ok := p.(bundleTaker)
		if !ok {
			continue
		}
		var err error
		func() {
			defer func() {
				if recover() != nil {
					notePanic(&a.partPanics, "Bundle of a part")
				}
			}()
			err = bt.Bundle(cb)
		}()
		// A bundle of another epoch is only dropped (10.3): a rotation makes it happen.
		if err != nil && err != blockside.ErrOtherEpoch {
			a.al.Alert(alert.Alert{Code: alert.CertBundleRefused, Detail: "a block intermediate was refused"})
		}
		return
	}
}
