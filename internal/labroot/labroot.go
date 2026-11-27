// Package labroot is the deny list of the lab test root (p4-nodes 7.1).
//
// Dev, CI and lab bundles are signed by a test root whose private keys are
// public (testdata/): anyone can sign a bundle with it. A production node must
// therefore never trust it. The key ids are compiled into every binary, and a
// binary built without the ctrlz_lab tag refuses a root that names one of them:
// ctrlz-verify at install, and the agent when it loads root.json. A lab build
// accepts it, which is the only difference the tag makes.
//
// The hub-side refusal (CTRLZ_ENV=production) is the Panel's.
package labroot

import (
	"encoding/hex"
	"errors"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
)

// ErrLabRoot is returned for a root that names a key of the lab test root.
var ErrLabRoot = errors.New("labroot: the root names a lab test key and this binary is not a lab build")

// IDs returns the key ids on the deny list.
func IDs() [][]byte {
	hexIDs := denyHex()
	out := make([][]byte, 0, len(hexIDs))
	for _, h := range hexIDs {
		b, err := hex.DecodeString(h)
		if err != nil {
			panic("labroot: bad generated id") // a generator bug, found by the first test run
		}
		out = append(out, b)
	}
	return out
}

// Check refuses root when it names a lab key and the binary is not a lab build.
// A nil root is refused too: callers hand over what they parsed, and "no root"
// is never a reason to skip the check. Any key in keys or in a grant counts, so
// a root that merely lists a lab key cannot slip it in under another role.
func Check(root *signv1.Root) error {
	if root == nil {
		return errors.New("labroot: no root")
	}
	if Lab {
		return nil
	}
	deny := map[string]bool{}
	for _, id := range IDs() {
		deny[string(id)] = true
	}
	for _, k := range root.Keys {
		if deny[string(k.GetKeyId())] {
			return ErrLabRoot
		}
	}
	for _, g := range root.Roles {
		for _, id := range g.GetKeyIds() {
			if deny[string(id)] {
				return ErrLabRoot
			}
		}
	}
	for _, id := range root.RootKeyIds {
		if deny[string(id)] {
			return ErrLabRoot
		}
	}
	return nil
}
