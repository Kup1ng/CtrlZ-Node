package store

import policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

// PeekMemberAt is PeekMember for a store directory that is already open in this
// process. It does not call Open, whose cleanup of temporary and incoming files
// belongs to the one that owns the store: a part that only needs the node table (the
// Xray manager's list of addresses that `direct` refuses, p4b-proxy 7.4) reads it
// this way.
func PeekMemberAt(dir string) *policyv1.PairTable { return (&Root{dir: dir}).PeekMember() }
