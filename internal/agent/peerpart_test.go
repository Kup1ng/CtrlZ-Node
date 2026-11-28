package agent

import (
	"testing"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
)

// The peer part decides on the pair_id of an Endpoint's record in the applied state. An
// empty one means the global pair, a named one is that pair, and an Endpoint the state
// does not hold is unknown and never the global pair (B6p-r1-3).
func TestEndpointPairInReadsTheRecordsPairID(t *testing.T) {
	ap := store.NewApplied()
	global, named, missing := [16]byte{1}, [16]byte{2}, [16]byte{3}
	pair := append([]byte{7}, make([]byte, 15)...)
	ap.Q.Endpoints[global] = &policyv1.EndpointRecord{EndpointId: global[:]}
	ap.Q.Endpoints[named] = &policyv1.EndpointRecord{EndpointId: named[:], PairId: pair}

	if p, ok := endpointPairIn(ap, global[:]); !ok || len(p) != 0 {
		t.Fatalf("a record with no pair_id: %x %v", p, ok)
	}
	if p, ok := endpointPairIn(ap, named[:]); !ok || string(p) != string(pair) {
		t.Fatalf("a record with a pair_id: %x %v", p, ok)
	}
	if _, ok := endpointPairIn(ap, missing[:]); ok {
		t.Fatal("an Endpoint the state does not hold is known")
	}
	if _, ok := endpointPairIn(ap, named[:8]); ok {
		t.Fatal("a short id is known")
	}
}
