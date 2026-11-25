package nodecfg_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

func cfg(version uint64, proofKey []byte) *hubv1.NodeConfig {
	return &hubv1.NodeConfig{
		Version: version, DnsBindIp: []byte{10, 0, 0, 5}, DnsAdvertisedIp: []byte{8, 8, 8, 8}, ProxyBindIp: []byte{10, 0, 0, 5}, ProxyAdvertisedIp: []byte{8, 8, 8, 8},
		Zones: []string{"ctrlz.example"}, PanelHostnames: []string{"panel.example"},
		Mode: commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE, ProofKey: proofKey,
	}
}

func agentConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.conf")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodConf = "# written by the install script\ndns_advertised_ip=8.8.8.8\ndns_bind_ip = 10.0.0.5\nproxy_bind_ip=10.0.0.5\n"

func TestSaveZeroesTheProofKeyAndLoadsBack(t *testing.T) {
	dir := t.TempDir()
	s := nodecfg.New(dir, nil)
	key := storetest.RandomSecret(t, 32)
	c := cfg(7, key)
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.ProofKey, key) {
		t.Fatal("Save edited the caller's config")
	}
	if storetest.Contains(t, dir, key) {
		t.Fatal("the real proof_key reached a file")
	}
	got, err := s.LoadServing(agentConf(t, goodConf))
	if err != nil || got.Source != nodecfg.Current || got.Reason != "" {
		t.Fatalf("%+v %v", got, err)
	}
	if got.Config.Version != 7 || !bytes.Equal(got.Config.ProofKey, make([]byte, 16)) {
		t.Fatalf("%+v", got.Config)
	}
}

func TestSaveRefusesAConfigThatDoesNotValidate(t *testing.T) {
	dir := t.TempDir()
	s := nodecfg.New(dir, nil)
	bad := cfg(1, make([]byte, 32))
	bad.Zones = nil
	if err := s.Save(bad); err == nil {
		t.Fatal("saved an invalid config")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatal("an invalid config left files")
	}
}

// The redacted copy always validates on its key, so the key of the config as
// given must be checked on its own (review round 3, r3-1).
func TestSaveRefusesAShortProofKey(t *testing.T) {
	dir := t.TempDir()
	s := nodecfg.New(dir, nil)
	for _, key := range [][]byte{nil, {1, 2, 3}, make([]byte, 15)} {
		if err := s.Save(cfg(1, key)); err == nil {
			t.Fatalf("saved a config with a %d-byte proof_key", len(key))
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatal("a refused config left files")
	}
}

func TestTwoGenerations(t *testing.T) {
	dir := t.TempDir()
	s := nodecfg.New(dir, nil)
	for v := uint64(1); v <= 3; v++ {
		if err := s.Save(cfg(v, make([]byte, 32))); err != nil {
			t.Fatal(err)
		}
	}
	conf := agentConf(t, goodConf)
	cur, _ := s.LoadServing(conf)
	if cur.Source != nodecfg.Current || cur.Config.Version != 3 {
		t.Fatalf("%+v", cur)
	}
	// Corrupt the current file: the previous (version 2) is used, with the reason.
	p := filepath.Join(dir, "current")
	b, _ := os.ReadFile(p)
	b[len(b)-3] ^= 0xff
	_ = os.WriteFile(p, b, 0o640)
	prev, err := s.LoadServing(conf)
	if err != nil || prev.Source != nodecfg.Previous || prev.Config.Version != 2 || prev.Reason == "" {
		t.Fatalf("%+v %v", prev, err)
	}
	// Both corrupt: Plain-only on the bind address of agent.conf.
	pp := filepath.Join(dir, "previous")
	_ = os.WriteFile(pp, []byte("not a config"), 0o640)
	plain, err := s.LoadServing(conf)
	if err != nil || plain.Source != nodecfg.PlainOnly || plain.Config != nil || plain.PlainBind.String() != "10.0.0.5" || plain.Reason == "" {
		t.Fatalf("%+v %v", plain, err)
	}
	// None at all (a new node): the same fallback, and the reason says none exist.
	empty := nodecfg.New(t.TempDir(), nil)
	none, err := empty.LoadServing(conf)
	if err != nil || none.Source != nodecfg.PlainOnly {
		t.Fatalf("%+v %v", none, err)
	}
}

// A generation that is intact as a file but does not pass ValidateNodeConfig is
// refused like a corrupt one: the validator is the door (N1), whoever wrote the file.
func TestAGenerationThatFailsValidationIsRefused(t *testing.T) {
	dir := t.TempDir()
	s := nodecfg.New(dir, nil)
	if err := s.Save(cfg(1, make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(cfg(2, make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	// Re-seal a valid frame around an invalid config.
	bad := nodecfg.Redact(cfg(9, nil))
	bad.Zones = []string{"a.example", "b.example", "c.example"}
	body, _ := proto.Marshal(bad)
	_ = os.WriteFile(filepath.Join(dir, "current"), fsx.Seal("CZNC", body), 0o640)
	got, err := s.LoadServing(agentConf(t, goodConf))
	if err != nil || got.Source != nodecfg.Previous || got.Config.Version != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

// A corrupt current file is never copied over a good previous one.
func TestACorruptCurrentIsNotPromotedToPrevious(t *testing.T) {
	dir := t.TempDir()
	s := nodecfg.New(dir, nil)
	_ = s.Save(cfg(1, make([]byte, 32)))
	_ = s.Save(cfg(2, make([]byte, 32)))
	_ = os.WriteFile(filepath.Join(dir, "current"), []byte("junk"), 0o640)
	if err := s.Save(cfg(3, make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "current"))
	got, _ := s.LoadServing(agentConf(t, goodConf))
	if got.Source != nodecfg.Previous || got.Config.Version != 1 {
		t.Fatalf("%+v", got)
	}
}

// A write cut at any step of a Save leaves a config that loads: the new one or
// the old one, never none.
func TestSaveInterruptedAtEveryStepStillLoads(t *testing.T) {
	conf := agentConf(t, goodConf)
	for _, step := range fsx.Steps() {
		for _, which := range []string{"previous", "current"} {
			dir := t.TempDir()
			base := nodecfg.New(dir, nil)
			_ = base.Save(cfg(1, make([]byte, 32)))
			_ = base.Save(cfg(2, make([]byte, 32)))
			w := &fsx.Writer{Hook: func(p string, s fsx.Step) error {
				if s == step && filepath.Base(p) == which {
					return fsx.ErrInjected
				}
				return nil
			}}
			_ = nodecfg.New(dir, w).Save(cfg(3, make([]byte, 32)))
			// A restart: leftovers are cleaned and the node loads.
			if _, err := fsx.CleanTemps(dir, false); err != nil {
				t.Fatal(err)
			}
			got, err := nodecfg.New(dir, nil).LoadServing(conf)
			if err != nil || got.Source == nodecfg.PlainOnly {
				t.Fatalf("%v/%s: %+v %v", step, which, got, err)
			}
			if v := got.Config.Version; v != 2 && v != 3 {
				t.Fatalf("%v/%s: loaded version %d", step, which, v)
			}
		}
	}
}

func TestReadBindIP(t *testing.T) {
	for _, c := range []struct {
		body string
		want string
		err  bool
	}{
		{goodConf, "10.0.0.5", false},
		{"dns_bind_ip=2001:db8::1\n", "2001:db8::1", false},
		{"dns_bind_ip=::ffff:10.0.0.5\n", "10.0.0.5", false},
		{"", "", true},
		{"dns_bind_ip=\n", "", true},
		{"dns_bind_ip=not-an-ip\n", "", true},
		{"dns_bind_ip=0.0.0.0\n", "", true},
		{"dns_bind_ip=224.0.0.1\n", "", true},
		{"# dns_bind_ip=10.0.0.5\n", "", true},
		{"dns_advertised_ip=8.8.8.8\n", "", true},
	} {
		got, err := nodecfg.ReadBindIP(agentConf(t, c.body))
		if (err != nil) != c.err || (err == nil && got.String() != c.want) {
			t.Errorf("%q: %v %v", c.body, got, err)
		}
	}
	if _, err := nodecfg.ReadBindIP(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file gave an address")
	}
	// No fallback address and no config: an error, still with the source and reason.
	s := nodecfg.New(t.TempDir(), nil)
	got, err := s.LoadServing(filepath.Join(t.TempDir(), "missing"))
	if err == nil || got.Source != nodecfg.PlainOnly || got.Reason == "" {
		t.Fatalf("%+v %v", got, err)
	}
	if errors.Is(err, os.ErrNotExist) == false {
		t.Logf("error: %v", err)
	}
}
