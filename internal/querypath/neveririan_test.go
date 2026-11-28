package querypath

import (
	"bytes"
	"testing"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

func TestNeverIranian(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"example.ir", true}, {"www.shop.example.ir", true}, {"ir", true}, {"example.xn--mgba3a4f16a", true},
		{"example.com", false}, {"ir.example.com", false}, {"notir", false}, {"example.irx", false},
	} {
		if got := NeverIranian(names.MustString(c.name)); got != c.want {
			t.Errorf("NeverIranian(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// The looping upstreams are cut from a copy: the config the Env holds is shared
// with every reader and is never changed, and an upstream-only config left with
// nothing yields no config at all (the node has no path).
func TestWithoutLoops(t *testing.T) {
	id := func(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }
	cfg := &hubv1.NodeConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, Upstreams: []*hubv1.Upstream{{Id: id(1)}, {Id: id(2)}}}
	loops := map[[16]byte]bool{[16]byte(id(1)): true}
	got := withoutLoops(cfg, loops)
	if len(got.Upstreams) != 1 || !bytes.Equal(got.Upstreams[0].Id, id(2)) {
		t.Fatalf("filtered: %v", got.Upstreams)
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatal("the shared config was changed")
	}
	if withoutLoops(cfg, nil) != cfg {
		t.Fatal("with no loop the config is used as it is")
	}
	loops[[16]byte(id(2))] = true
	if withoutLoops(cfg, loops) != nil {
		t.Fatal("an upstream-only config with no usable upstream must give no config")
	}
	cfg.Mode = commonv1.ResolveMode_RESOLVE_MODE_HYBRID
	if g := withoutLoops(cfg, loops); g == nil || len(g.Upstreams) != 0 {
		t.Fatal("hybrid still has the local Unbound, so it keeps a config")
	}
	if keyOf(loops) == "" || keyOf(nil) != "" {
		t.Fatal("the loop key names the set")
	}
}
