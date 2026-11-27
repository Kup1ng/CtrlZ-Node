// Package nodecfg keeps the applied NodeConfig on disk in two generations and
// decides what the node serves with after a restart (spec p4-nodes 7.2, T-074).
//
// The file never holds the real proof_key: Save replaces it with 16 zero bytes
// before anything is written (an all-zero key means "no code", so with no panel
// a UDP proof answer carries none, and the real key lives in agent and dns memory
// only). Every load goes through wire.ValidateNodeConfig like any door (N1),
// whatever wrote the file.
//
// LoadServing is the one decision that both dns and the agent make, so they
// cannot disagree: the current generation if it loads, else the previous, else
// the Plain-only fallback, which binds only Plain UDP and TCP 53 on the
// dns_bind_ip the install script wrote into /etc/ctrlz/agent.conf and serves from
// image/ with no zone answers. The returned Reason says which, for the alert.
package nodecfg

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
)

const (
	currentFile  = "current"
	previousFile = "previous"
	magic        = "CZNC"

	// ZeroProofKeyLen is the length of the stand-in for proof_key. It is the
	// shortest key wire.ValidateNodeConfig accepts.
	ZeroProofKeyLen = 16

	// maxFile bounds what a load reads. A NodeConfig is a few kilobytes plus the
	// resolver rules and Xray configs; a file far above that is damaged.
	maxFile = 8 << 20
)

// Source says what LoadServing chose.
type Source uint8

const (
	// Current is the current generation.
	Current Source = iota + 1
	// Previous is the previous generation, used because the current failed.
	Previous
	// PlainOnly is the fallback: no valid NodeConfig is on disk.
	PlainOnly
)

func (s Source) String() string {
	switch s {
	case Current:
		return "current"
	case Previous:
		return "previous"
	case PlainOnly:
		return "plain-only"
	}
	return "source?"
}

// Store is the config/ directory.
type Store struct {
	dir string
	w   *fsx.Writer
}

// New returns the store for dir (the config/ directory of the root).
func New(dir string, w *fsx.Writer) *Store {
	if w == nil {
		w = &fsx.Writer{}
	}
	return &Store{dir: dir, w: w}
}

// Strip returns a copy of c without the Xray fragments (p4b-proxy 7.5, finding 15).
// A fragment holds the credentials of an exit. The agent keeps them in the Xray
// manager's own 0600 files, and neither this store, which dns may read, nor the copy
// dns gets over agent.sock holds one. The rest of each XrayConfig row stays: dns and
// the validators need the ids, locations and priorities.
func Strip(c *hubv1.NodeConfig) *hubv1.NodeConfig {
	out := proto.Clone(c).(*hubv1.NodeConfig)
	for _, x := range out.XrayConfigs {
		if x != nil {
			x.FragmentJson = nil
		}
	}
	return out
}

// Redact returns a copy of c with proof_key replaced by ZeroProofKeyLen zero
// bytes and the fragments stripped. It is the only form that reaches a file.
func Redact(c *hubv1.NodeConfig) *hubv1.NodeConfig {
	out := Strip(c)
	out.ProofKey = make([]byte, ZeroProofKeyLen)
	return out
}

func encode(c *hubv1.NodeConfig) ([]byte, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		return nil, err
	}
	return fsx.Seal(magic, b), nil
}

// decode reads and validates one generation.
func decode(file []byte) (*hubv1.NodeConfig, error) {
	if len(file) > maxFile {
		return nil, errors.New("nodecfg: file over the cap")
	}
	body, err := fsx.Unseal(magic, file)
	if err != nil {
		return nil, err
	}
	c := &hubv1.NodeConfig{}
	if err := proto.Unmarshal(body, c); err != nil {
		return nil, fmt.Errorf("nodecfg: %w", err)
	}
	if err := wire.ValidateNodeConfig(c); err != nil {
		return nil, fmt.Errorf("nodecfg: %w", err)
	}
	return c, nil
}

func (s *Store) read(name string) (*hubv1.NodeConfig, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return nil, err
	}
	return decode(b)
}

// Save makes c the current generation and the one it replaces the previous one.
// It refuses a config that ValidateNodeConfig refuses, and writes nothing then.
//
// The order is what keeps a loadable config at every instant. The current file
// is copied to previous first (atomically) and only then replaced (atomically),
// so a cut between the two leaves current and previous equal and both valid. A
// current file that does not load is not copied over a good previous.
func (s *Store) Save(c *hubv1.NodeConfig) error {
	// The config as given is checked first: the redacted copy always has a
	// 16-byte proof_key, so only the original shows a key the door check would
	// refuse. The redacted copy is checked too, because that is what is stored.
	if err := wire.ValidateNodeConfig(c); err != nil {
		return fmt.Errorf("nodecfg: refusing to store a config that does not validate: %w", err)
	}
	red := Redact(c)
	if err := wire.ValidateNodeConfig(red); err != nil {
		return fmt.Errorf("nodecfg: refusing to store a config that does not validate: %w", err)
	}
	b, err := encode(red)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(filepath.Join(s.dir, currentFile)); err == nil {
		if _, derr := decode(old); derr == nil {
			if err := s.w.WriteFile(filepath.Join(s.dir, previousFile), old, 0o640); err != nil {
				return fmt.Errorf("nodecfg: keep previous: %w", err)
			}
		}
	}
	return s.w.WriteFile(filepath.Join(s.dir, currentFile), b, 0o640)
}

// Serving is what dns and the agent start from.
type Serving struct {
	Source Source
	// Config is the loaded NodeConfig, proof_key zeroed. Nil for PlainOnly.
	Config *hubv1.NodeConfig
	// PlainBind is the address Plain-only mode binds, set for PlainOnly only.
	PlainBind netip.Addr
	// Reason says why the node is not on its current generation: empty for
	// Current, and for the others the failure of each generation tried. It
	// holds no config content, only error text of the validator.
	Reason string
}

// LoadServing returns the current generation, else the previous, else the
// Plain-only fallback with dns_bind_ip read from agentConf. It returns an error
// only when even the fallback is impossible (no valid bind address), because
// then dns has nothing to bind and the agent must alert and keep retrying.
func (s *Store) LoadServing(agentConf string) (Serving, error) {
	cur, curErr := s.read(currentFile)
	if curErr == nil {
		return Serving{Source: Current, Config: cur}, nil
	}
	prev, prevErr := s.read(previousFile)
	if prevErr == nil {
		return Serving{Source: Previous, Config: prev, Reason: "current: " + describe(curErr)}, nil
	}
	reason := "current: " + describe(curErr) + "; previous: " + describe(prevErr)
	ip, err := ReadBindIP(agentConf)
	if err != nil {
		return Serving{Source: PlainOnly, Reason: reason}, fmt.Errorf("nodecfg: no valid NodeConfig and no bind address for Plain-only mode: %w", err)
	}
	return Serving{Source: PlainOnly, PlainBind: ip, Reason: reason}, nil
}

func describe(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "none"
	}
	return err.Error()
}

// ReadBindIP reads dns_bind_ip from the agent's local configuration. The install
// script writes the file as lines of key=value (blank lines and lines starting
// with # are ignored), next to the other three enrolled addresses; only
// dns_bind_ip is read here. The agent configuration is written by root at
// install and is not tenant or network input, but it is still parsed strictly: an
// unspecified or multicast address is no address to bind.
func ReadBindIP(path string) (netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	var got string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == "dns_bind_ip" {
			got = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(got)
	if err != nil {
		return netip.Addr{}, errors.New("dns_bind_ip missing or not an address")
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, errors.New("dns_bind_ip is not a bindable address")
	}
	return a, nil
}
