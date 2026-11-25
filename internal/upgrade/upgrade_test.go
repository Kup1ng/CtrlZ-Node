package upgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
	"github.com/Kup1ng/CtrlZ-Node/internal/verify"
)

// call is one command the upgrade ran.
type call struct {
	name string
	args []string
}

// fakeRunner stands in for the root-owned ctrlz-verify (the real verifier, run
// in-process) and for `sh apply.sh`, which it records instead of running. hook
// runs before each command, so a test can play the agent changing the files it
// downloaded while the upgrade is under way.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []call
	verify  string
	hook    func(c call)
	onApply func(c call) error
}

func (f *fakeRunner) Run(_ context.Context, stdout, stderr io.Writer, name string, args ...string) error {
	c := call{name, args}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	if f.hook != nil {
		f.hook(c)
	}
	if name == f.verify {
		if code := verify.Main(args, stdout, stderr); code != 0 {
			return errors.New("verify failed")
		}
		return nil
	}
	if name == "sh" && f.onApply != nil {
		return f.onApply(c)
	}
	return nil
}

func (f *fakeRunner) names() []string {
	var out []string
	for _, c := range f.calls {
		n := c.name
		if len(c.args) > 0 && (c.args[0] == "list" || c.args[0] == "check" || c.args[0] == "upgrade") {
			n += " " + c.args[0]
		}
		if c.name == "sh" {
			n = "apply " + c.args[1]
		}
		out = append(out, n)
	}
	return out
}

type host struct {
	env      Env
	runner   *fakeRunner
	src      string // the downloaded bundle of version 4
	keys     []ed25519.PrivateKey
	root     *signv1.Root
	manifest *signv1.Manifest
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) *signv1.PublicKey {
	p := k.Public().(ed25519.PublicKey)
	return &signv1.PublicKey{KeyId: manifest.KeyID(p), Ed25519: p}
}

// newHost makes a host at installed version 3 with a signed bundle of version 4
// in the agent's download directory.
func newHost(t *testing.T, signers int) *host {
	t.Helper()
	d := t.TempDir()
	h := &host{}
	exp := time.Now().Add(24 * time.Hour).Unix()
	var ids [][]byte
	r := &signv1.Root{Version: 1, ExpiresAt: exp, Threshold: 2}
	for i := 0; i < 3; i++ {
		k := newKey(t)
		h.keys = append(h.keys, k)
		r.Keys = append(r.Keys, pub(k))
		ids = append(ids, pub(k).KeyId)
	}
	r.RootKeyIds = ids
	r.Roles = []*signv1.RoleGrant{{Role: signv1.Role_ROLE_BUNDLE, KeyIds: ids, Threshold: 2, ExpiresAt: exp}}
	h.root = r
	rb, _ := protojson.Marshal(r)

	write(t, filepath.Join(d, "pkg/install/node.sh"), "V='"+bundle.VerifyPlaceholder+"' N='"+bundle.VersionPlaceholder+"'\n")
	write(t, filepath.Join(d, "pkg/install/apply.sh"), "echo apply\n")
	write(t, filepath.Join(d, "pkg/accounts.conf"), "group x\n")
	write(t, filepath.Join(d, "node"), "NODE-4")
	write(t, filepath.Join(d, "verify"), "VERIFY")
	write(t, filepath.Join(d, "debs/a_1_all.deb"), "DEB-A")
	out := filepath.Join(d, "build")
	m, err := bundle.Build(bundle.Options{Out: out, Version: 4, MinVersion: 1, CreatedAt: 1, ExpiresAt: exp,
		Packaging: filepath.Join(d, "pkg"), NodeBin: filepath.Join(d, "node"), VerifyBin: filepath.Join(d, "verify"), Debs: filepath.Join(d, "debs")})
	if err != nil {
		t.Fatal(err)
	}
	h.manifest = m
	unsigned, err := bundle.ReadEnvelope(bundle.UnsignedPath(out))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < signers; i++ {
		bundle.Sign(unsigned, h.keys[i])
	}
	raw, _ := bundle.MarshalEnvelope(unsigned)
	if err := os.WriteFile(filepath.Join(out, bundle.ManifestFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	h.src = filepath.Join(d, "var/lib/ctrlz/bundles/node/4")
	if err := os.MkdirAll(filepath.Dir(h.src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(out, h.src); err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(d, "etc/ctrlz/root.json"), string(rb))
	write(t, filepath.Join(d, "etc/ctrlz/versions/node"), "3\n")
	h.runner = &fakeRunner{verify: "ctrlz-verify-under-test"}
	h.env = Env{
		Bundles: filepath.Join(d, "var/lib/ctrlz/bundles"), VersionFile: filepath.Join(d, "etc/ctrlz/versions/node"),
		RootJSON: filepath.Join(d, "etc/ctrlz/root.json"), Verify: "ctrlz-verify-under-test",
		StageParent: d, Runner: h.runner, Geteuid: func() int { return 0 }, Stdout: io.Discard, Stderr: io.Discard,
	}
	return h
}

func (h *host) stages(t *testing.T) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(h.env.StageParent, "ctrlz-upgrade-*"))
	return m
}

func TestUpgradeInstallsTheVerifiedCopy(t *testing.T) {
	h := newHost(t, 2)
	var staged map[string]string
	h.runner.onApply = func(c call) error {
		// apply.sh gets the staging directory and the version, and every file of the
		// manifest is there with the right bytes.
		stage := c.args[3]
		if c.args[2] != "--stage" || c.args[4] != "--version" || c.args[5] != "4" || c.args[1] != "upgrade" || c.args[0] != filepath.Join(stage, "packaging", "install", "apply.sh") {
			t.Errorf("apply arguments %v", c.args)
		}
		staged = map[string]string{}
		for _, f := range h.manifest.Files {
			b, err := os.ReadFile(filepath.Join(stage, filepath.FromSlash(f.Path)))
			if err != nil {
				t.Errorf("%s: %v", f.Path, err)
				continue
			}
			staged[f.Path] = string(b)
		}
		return nil
	}
	if err := h.env.Do(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
	if len(staged) != len(h.manifest.Files) || staged["bin/ctrlz-node"] != "NODE-4" {
		t.Fatalf("staged %v", staged)
	}
	want := []string{"ctrlz-verify-under-test list", "ctrlz-verify-under-test check", "apply upgrade"}
	if got := h.runner.names(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands %v, want %v", got, want)
	}
	// The verifier was told to hold the manifest above the installed version and to
	// the version asked for, against the root-owned root.
	l := strings.Join(h.runner.calls[0].args, " ")
	for _, s := range []string{"--above", "--installed 3", "--version 4", "--root " + h.env.RootJSON} {
		if !strings.Contains(l, s) {
			t.Errorf("verify list lacks %q: %s", s, l)
		}
	}
	if len(h.stages(t)) != 0 {
		t.Error("the staging directory was left behind")
	}
}

func TestVersionNotAboveInstalledIsRefusedBeforeAnything(t *testing.T) {
	for _, v := range []uint64{3, 2, 1} {
		h := newHost(t, 2)
		if err := h.env.Do(context.Background(), v); err == nil || !strings.Contains(err.Error(), "not above") {
			t.Errorf("version %d: %v", v, err)
		}
		if len(h.runner.calls) != 0 || len(h.stages(t)) != 0 {
			t.Errorf("version %d: something ran: %v", v, h.runner.calls)
		}
	}
}

func TestNeedsRootAndAnInstall(t *testing.T) {
	h := newHost(t, 2)
	h.env.Geteuid = func() int { return 1000 }
	if err := h.env.Do(context.Background(), 4); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("got %v", err)
	}
	h = newHost(t, 2)
	if err := os.Remove(h.env.VersionFile); err != nil {
		t.Fatal(err)
	}
	if err := h.env.Do(context.Background(), 4); err == nil {
		t.Fatal("an upgrade of a host with no install ran")
	}
	write(t, h.env.VersionFile, "not a number\n")
	if err := h.env.Do(context.Background(), 4); err == nil {
		t.Fatal("a version file that is not a number was accepted")
	}
	h = newHost(t, 2)
	if err := os.RemoveAll(h.src); err != nil {
		t.Fatal(err)
	}
	if err := h.env.Do(context.Background(), 4); err == nil {
		t.Fatal("an upgrade with no downloaded bundle ran")
	}
}

// A manifest that does not verify costs one command and copies nothing else of
// what the agent wrote.
func TestUnsignedOrUnderSignedManifestInstallsNothing(t *testing.T) {
	for _, signers := range []int{0, 1} {
		h := newHost(t, signers)
		applied := false
		h.runner.onApply = func(call) error { applied = true; return nil }
		err := h.env.Do(context.Background(), 4)
		if err == nil || !strings.Contains(err.Error(), "did not verify") {
			t.Fatalf("%d signers: %v", signers, err)
		}
		if got := h.runner.names(); len(got) != 1 || got[0] != "ctrlz-verify-under-test list" || applied {
			t.Fatalf("%d signers: commands %v", signers, got)
		}
	}
}

func TestTamperedFileIsRefused(t *testing.T) {
	h := newHost(t, 2)
	write(t, filepath.Join(h.src, "bin/ctrlz-node"), "NODE-X") // same size, other bytes
	applied := false
	h.runner.onApply = func(call) error { applied = true; return nil }
	if err := h.env.Do(context.Background(), 4); err == nil || applied {
		t.Fatalf("a tampered bundle was installed: %v", err)
	}
	if got := h.runner.names(); got[len(got)-1] != "ctrlz-verify-under-test check" {
		t.Fatalf("commands %v", got)
	}
}

func TestGrownFileAndMissingFileAreRefused(t *testing.T) {
	h := newHost(t, 2)
	write(t, filepath.Join(h.src, "bin/ctrlz-node"), "NODE-4-and-much-more-than-listed")
	applied := false
	h.runner.onApply = func(call) error { applied = true; return nil }
	if err := h.env.Do(context.Background(), 4); err == nil || applied {
		t.Fatalf("a grown file was installed: %v", err)
	}
	h = newHost(t, 2)
	if err := os.Remove(filepath.Join(h.src, "debs/a_1_all.deb")); err != nil {
		t.Fatal(err)
	}
	h.runner.onApply = func(call) error { applied = true; return nil }
	if err := h.env.Do(context.Background(), 4); err == nil || applied {
		t.Fatalf("a bundle with a file missing was installed: %v", err)
	}
	if len(h.stages(t)) != 0 {
		t.Error("staging left behind after a refusal")
	}
}

// What the manifest does not list is never copied, so the agent cannot add a file
// to what root installs.
func TestUnlistedFilesAreNotCopied(t *testing.T) {
	h := newHost(t, 2)
	write(t, filepath.Join(h.src, "packaging/systemd/evil.service"), "[Service]\nExecStart=/bin/sh\n")
	write(t, filepath.Join(h.src, "extra.deb"), "x")
	h.runner.onApply = func(c call) error {
		stage := c.args[3]
		for _, p := range []string{"packaging/systemd/evil.service", "extra.deb"} {
			if _, err := os.Stat(filepath.Join(stage, p)); err == nil {
				t.Errorf("%s was copied into the staging directory", p)
			}
		}
		return nil
	}
	if err := h.env.Do(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkInTheDownloadIsRefused(t *testing.T) {
	h := newHost(t, 2)
	secret := filepath.Join(t.TempDir(), "secret")
	write(t, secret, "NODE-4")
	p := filepath.Join(h.src, "bin/ctrlz-node")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, p); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	applied := false
	h.runner.onApply = func(call) error { applied = true; return nil }
	if err := h.env.Do(context.Background(), 4); err == nil || applied {
		t.Fatalf("a symlink was followed: %v", err)
	}
}

// The agent can write the download directory at any moment. After the copy,
// nothing it does there reaches the install: apply.sh reads the staged bytes.
func TestChangesAfterTheCopyDoNotReachTheInstall(t *testing.T) {
	h := newHost(t, 2)
	h.runner.hook = func(c call) {
		if c.name == "sh" {
			write(t, filepath.Join(h.src, "bin/ctrlz-node"), "NODE-X")
		}
	}
	h.runner.onApply = func(c call) error {
		b, err := os.ReadFile(filepath.Join(c.args[3], "bin/ctrlz-node"))
		if err != nil || !bytes.Equal(b, []byte("NODE-4")) {
			t.Errorf("the install saw %q, %v", b, err)
		}
		return nil
	}
	if err := h.env.Do(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
}

func TestFailedApplyIsAnError(t *testing.T) {
	h := newHost(t, 2)
	h.runner.onApply = func(call) error { return errors.New("exit 1") }
	if err := h.env.Do(context.Background(), 4); err == nil || !strings.Contains(err.Error(), "install") {
		t.Fatalf("got %v", err)
	}
	if len(h.stages(t)) != 0 {
		t.Error("staging left behind")
	}
}

func TestMainArguments(t *testing.T) {
	var out, errb bytes.Buffer
	h := newHost(t, 2)
	h.env.Stdout, h.env.Stderr = &out, &errb
	for _, args := range [][]string{nil, {"4", "5"}, {"0"}, {"04"}, {"-1"}, {"4x"}, {""}} {
		if code := h.env.Main(context.Background(), args); code != 2 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
	if len(h.runner.calls) != 0 {
		t.Error("a bad argument ran a command")
	}
	if code := h.env.Main(context.Background(), []string{"3"}); code != 1 || !strings.Contains(errb.String(), "not above") {
		t.Errorf("exit %d, %q", code, errb.String())
	}
	if code := h.env.Main(context.Background(), []string{"4"}); code != 0 {
		t.Errorf("exit %d, %q", code, errb.String())
	}
}
