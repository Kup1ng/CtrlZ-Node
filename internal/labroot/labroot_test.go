package labroot

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
)

func loadLab(t *testing.T) *signv1.Root {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &signv1.Root{}
	if err := protojson.Unmarshal(b, r); err != nil {
		t.Fatal(err)
	}
	return r
}

// The deny list must be the key ids of the committed test root, no more and no
// fewer: a regenerated root with an id missing from the list would be trusted by
// a production binary.
func TestDenyListIsTheTestRoot(t *testing.T) {
	r := loadLab(t)
	want := map[string]bool{}
	for _, k := range r.Keys {
		if !bytes.Equal(k.KeyId, manifest.KeyID(k.Ed25519)) {
			t.Fatalf("testdata root has a key whose id is not derived")
		}
		want[hex.EncodeToString(k.KeyId)] = true
	}
	got := map[string]bool{}
	for _, id := range IDs() {
		got[hex.EncodeToString(id)] = true
	}
	if len(got) != len(want) {
		t.Fatalf("deny list has %d ids, root has %d keys", len(got), len(want))
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("key %s of the test root is not on the deny list", id)
		}
	}
}

func TestCheckLabRootByBuild(t *testing.T) {
	r := loadLab(t)
	err := Check(r)
	if Lab && err != nil {
		t.Fatalf("lab build refused the lab root: %v", err)
	}
	if !Lab && err != ErrLabRoot {
		t.Fatalf("production build accepted the lab root: %v", err)
	}
}

func TestCheckOtherRootAndNil(t *testing.T) {
	other := &signv1.Root{Version: 1, Keys: []*signv1.PublicKey{{KeyId: bytes.Repeat([]byte{7}, 16), Ed25519: bytes.Repeat([]byte{7}, 32)}}}
	if err := Check(other); err != nil {
		t.Fatalf("a root with no lab key was refused: %v", err)
	}
	if err := Check(nil); err == nil {
		t.Fatal("nil root accepted")
	}
}

// A lab id hidden in only one place of the root still trips the check.
func TestCheckEachPlace(t *testing.T) {
	if Lab {
		t.Skip("lab build accepts the lab root")
	}
	id := IDs()[0]
	for name, r := range map[string]*signv1.Root{
		"keys":  {Keys: []*signv1.PublicKey{{KeyId: id}}},
		"grant": {Roles: []*signv1.RoleGrant{{KeyIds: [][]byte{id}}}},
		"root":  {RootKeyIds: [][]byte{id}},
	} {
		if err := Check(r); err != ErrLabRoot {
			t.Errorf("%s: %v", name, err)
		}
	}
}
