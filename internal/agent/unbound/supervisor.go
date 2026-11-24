package unbound

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
)

// Unit names and file names. The agent may start, stop and restart exactly
// these units (the polkit rule of 7.1 names the same list).
const (
	UnitIdentified = "ctrlz-unbound.service"
	UnitFree       = "ctrlz-unbound-free.service"
	ConfIdentified = "identified.conf"
	ConfFree       = "free.conf"
	EphemeralPath  = "/proc/sys/net/ipv4/ip_local_port_range"
)

// Config is what a Supervisor needs.
type Config struct {
	Runner sysx.Runner
	Files  sysx.Files
	Alert  alert.Alerter
	// ConfDir is /etc/ctrlz/unbound, which the agent owns.
	ConfDir    string
	Identified Params
	Free       Params
	// Binary and Control default to "unbound" and "unbound-control".
	Binary, Control string
	// Gate is the host check that must hold whenever a process is started (core
	// dumps ruled out, SC 5.2a No trace). Start runs it through the agent before it
	// calls Start; the supervisor runs it again before it restarts a dead unit, so a
	// crash does not bring a process back into a host that would now leave a core.
	Gate func() error
	// StartRetry is how long after a start that did not happen (a refusal, a failed
	// systemctl, the Gate) the next try is made, default one minute. The reason is
	// usually the host's, and the host gets fixed while the agent runs.
	StartRetry time.Duration
	// Watch lists the files whose change after a process started means it runs old code
	// (default BinaryPath and DpkgStatus). ChangeTime gives a file's change time (default:
	// the later of mtime and ctime) and Now the clock; both are for tests.
	Watch      []string
	ChangeTime func(path string) (time.Time, error)
	Now        func() time.Time
}

// Supervisor starts and watches the two processes through systemd.
type Supervisor struct {
	cfg Config

	mu      sync.Mutex
	started map[Kind]bool
	// wanted is the kinds the agent means to run; lastTry is when each was last
	// started or refused. A wanted kind that is not started is tried again by Check.
	wanted  map[Kind]bool
	lastTry map[Kind]time.Time
	// dnq is the list wanted; reloaded[k] is the list the running process k was last
	// given, so a reload that failed is tried again and a list is never taken for
	// applied before the process has it.
	dnq      []netip.Prefix
	reloaded map[Kind][]netip.Prefix
	// stale marks a process that was already running when Start wrote its file: it has
	// not been told to read it, whatever reloaded says.
	stale map[Kind]bool
	// lastStale is when each kind was last restarted for a replaced binary or library.
	lastStale map[Kind]time.Time
	version   string
	patched   bool // the distribution build of DistroBase with the backports
	unwant    int64
}

// New returns a Supervisor.
func New(cfg Config) *Supervisor {
	if cfg.Binary == "" {
		cfg.Binary = "unbound"
	}
	if cfg.Control == "" {
		cfg.Control = "unbound-control"
	}
	if cfg.Alert == nil {
		cfg.Alert = alert.Discard{}
	}
	if cfg.StartRetry == 0 {
		cfg.StartRetry = time.Minute
	}
	if cfg.Watch == nil {
		cfg.Watch = []string{BinaryPath, DpkgStatus}
	}
	if cfg.ChangeTime == nil {
		cfg.ChangeTime = fileChangeTime
	}
	return &Supervisor{cfg: cfg, started: map[Kind]bool{}, wanted: map[Kind]bool{}, lastTry: map[Kind]time.Time{},
		reloaded: map[Kind][]netip.Prefix{}, stale: map[Kind]bool{}, lastStale: map[Kind]time.Time{}}
}

// Want says the agent means to run k although it has not been able to start it
// (the host check that gates a start failed): Check starts it once that holds.
func (s *Supervisor) Want(kinds ...Kind) {
	s.mu.Lock()
	for _, k := range kinds {
		s.wanted[k] = true
	}
	s.mu.Unlock()
}

func (s *Supervisor) params(k Kind) Params {
	p := s.cfg.Identified
	if k == Free {
		p = s.cfg.Free
	}
	p.DoNotQuery = s.dnq
	return p
}

func (s *Supervisor) unit(k Kind) string {
	if k == Free {
		return UnitFree
	}
	return UnitIdentified
}

func (s *Supervisor) confPath(k Kind) string {
	if k == Free {
		return path.Join(s.cfg.ConfDir, ConfFree)
	}
	return path.Join(s.cfg.ConfDir, ConfIdentified)
}

// Version runs unbound -V once and returns the upstream version.
func (s *Supervisor) Version(ctx context.Context) (string, error) {
	s.mu.Lock()
	v := s.version
	s.mu.Unlock()
	if v != "" {
		return v, nil
	}
	out, err := s.cfg.Runner.Run(ctx, nil, s.cfg.Binary, "-V")
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("unbound: run %s -V: %w", s.cfg.Binary, err)
	}
	v, err = ParseVersion(out)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.version = v
	s.mu.Unlock()
	return v, nil
}

var debVersionRE = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]{0,63}$`)

// checkFloor holds the version of `unbound -V` to the floor, accepting the one
// distribution build that carries the fixes as patches (see DistroFloor).
func (s *Supervisor) checkFloor(ctx context.Context, v string) error {
	err := CheckVersion(v)
	if err == nil || v != DistroBase {
		return err
	}
	out, rerr := s.cfg.Runner.Run(ctx, nil, "dpkg-query", "-W", "-f=${Version}", Package)
	rev := strings.TrimSpace(string(out))
	if rerr != nil || !debVersionRE.MatchString(rev) {
		return err
	}
	// dpkg itself compares Debian versions (epochs, ~, letters); exit 0 means "ge".
	if _, cerr := s.cfg.Runner.Run(ctx, nil, "dpkg", "--compare-versions", rev, "ge", DistroFloor); cerr != nil {
		return err
	}
	s.mu.Lock()
	s.patched = true
	s.mu.Unlock()
	return nil
}

// refuse raises the alert and returns the error that stops the start.
func (s *Supervisor) refuse(detail string, err error) error {
	s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundRefused, Detail: detail})
	return err
}

// Start checks everything the agent insists on, writes the configuration and
// starts the unit. It starts nothing when a check fails (T-559).
func (s *Supervisor) Start(ctx context.Context, k Kind, doNotQuery []netip.Prefix) error {
	s.mu.Lock()
	s.dnq = append([]netip.Prefix(nil), doNotQuery...)
	s.wanted[k] = true
	s.lastTry[k] = time.Now()
	s.mu.Unlock()
	v, err := s.Version(ctx)
	if err != nil {
		return s.refuse(k.String()+": version unreadable", err)
	}
	if err := s.checkFloor(ctx, v); err != nil {
		return s.refuse(k.String()+": version below the floor", err)
	}
	p := s.params(k)
	if err := p.Validate(); err != nil {
		return s.refuse(k.String()+": parameters", err)
	}
	if k == Free {
		b, err := s.cfg.Files.ReadFile(EphemeralPath)
		if err != nil {
			return s.refuse("free: ephemeral port range unreadable", fmt.Errorf("unbound: read the ephemeral port range: %w", err))
		}
		lo, hi, err := ParseEphemeral(b)
		if err != nil {
			return s.refuse("free: ephemeral port range unreadable", err)
		}
		if err := CheckRanges(s.cfg.Free, s.cfg.Identified, lo, hi); err != nil {
			return s.refuse("free: outgoing port range overlaps another", err)
		}
	}
	path := s.confPath(k)
	if old, err := s.cfg.Files.ReadFile(path); err == nil {
		// A file that is there was written by an earlier run, or by someone else.
		// Its pinned settings must be the template's before this run rewrites it,
		// or a changed limit would be silently put back and never noticed.
		if err := Verify(string(old), p); err != nil {
			if s.active(ctx, k) {
				// An older agent's process is still up under this file: it keeps running with
				// no supervision (no reload of its do-not-query list, no restart), which the
				// owner has to know apart from a refusal to start.
				s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundUnsupervised, Detail: k.String() + ": running, not taken over"})
			}
			return s.refuse(k.String()+": pinned setting changed", err)
		}
	}
	conf, err := Render(p)
	if err != nil {
		return s.refuse(k.String()+": render", err)
	}
	if err := s.cfg.Files.WriteFile(path, []byte(conf), 0o640); err != nil {
		return fmt.Errorf("unbound: write the configuration of %s: %w", k, err)
	}
	// `systemctl start` on a unit that is up does nothing: the process keeps the list it
	// was started or last reloaded with, which is not what was just written (an agent
	// restart finds both Unbounds running). Such a unit is told to reload, and counts
	// as holding the list only once that has worked.
	already := s.active(ctx, k)
	if !already {
		if _, err := s.cfg.Runner.Run(ctx, nil, "systemctl", "start", s.unit(k)); err != nil {
			return s.refuse(k.String()+": unit did not start", fmt.Errorf("unbound: start %s: %w", s.unit(k), err))
		}
	}
	s.mu.Lock()
	s.started[k] = true
	s.reloaded[k] = append([]netip.Prefix(nil), s.dnq...)
	if already {
		s.stale[k] = true
	}
	s.mu.Unlock()
	if already {
		_ = s.reconcile(ctx) // a failed reload alerted, and the next pass tries again
	}
	return nil
}

// active reports whether systemd says the unit of k is running.
func (s *Supervisor) active(ctx context.Context, k Kind) bool {
	out, _ := s.cfg.Runner.Run(ctx, nil, "systemctl", "is-active", s.unit(k))
	return strings.TrimSpace(string(out)) == "active"
}

// SetDoNotQuery rewrites both configurations for a new address list and asks the
// running processes to reload with `reload_keep_cache`, so neither loses its
// cache (SC 5.2a). A list that did not change does nothing.
func (s *Supervisor) SetDoNotQuery(ctx context.Context, list []netip.Prefix) error {
	s.mu.Lock()
	s.dnq = append([]netip.Prefix(nil), list...)
	s.mu.Unlock()
	return s.reconcile(ctx)
}

// reconcile brings every running process to the wanted list: the ones that do not
// hold it yet get the file and a reload. It is also what Check runs, so a reload
// that failed is retried on the next pass.
func (s *Supervisor) reconcile(ctx context.Context) error {
	s.mu.Lock()
	want := append([]netip.Prefix(nil), s.dnq...)
	var kinds []Kind
	for _, k := range []Kind{Identified, Free} {
		if s.started[k] && (s.stale[k] || !samePrefixes(s.reloaded[k], want)) {
			kinds = append(kinds, k)
		}
	}
	s.mu.Unlock()
	var firstErr error
	for _, k := range kinds {
		// Start refuses a file whose pinned settings differ from the template, and so
		// must this path: it runs on every do-not-query change and every retry, and
		// writing the template over an operator's or a package's changed limit would
		// put it back with no alert, which is the silent overwrite the spec forbids.
		// The process keeps running on what it has, unsupervised, until someone looks.
		if old, rerr := s.cfg.Files.ReadFile(s.confPath(k)); rerr == nil {
			if verr := Verify(string(old), s.params(k)); verr != nil {
				s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundRefused, Detail: k.String() + ": pinned setting changed"})
				s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundUnsupervised, Detail: k.String() + ": running, not reloaded"})
				if firstErr == nil {
					firstErr = fmt.Errorf("unbound: %s: %w", k, verr)
				}
				continue
			}
		}
		conf, err := Render(s.params(k))
		if err == nil {
			err = s.cfg.Files.WriteFile(s.confPath(k), []byte(conf), 0o640)
		}
		if err == nil {
			_, err = s.cfg.Runner.Run(ctx, nil, s.cfg.Control, "-c", s.confPath(k), "reload_keep_cache")
		}
		if err != nil {
			s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundReloadFail, Detail: k.String()})
			if firstErr == nil {
				firstErr = fmt.Errorf("unbound: reload %s: %w", k, err)
			}
			continue
		}
		s.mu.Lock()
		s.reloaded[k] = append([]netip.Prefix(nil), want...)
		delete(s.stale, k)
		s.mu.Unlock()
	}
	return firstErr
}

// guard is every check that must hold before a dead unit is brought back: the host
// gate (core dumps), the version floor, and the pinned settings of the file on
// disk (a changed limit is a reason not to run, not something to write over).
func (s *Supervisor) guard(k Kind) error {
	if s.cfg.Gate != nil {
		if err := s.cfg.Gate(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	v, patched := s.version, s.patched
	s.mu.Unlock()
	if v != "" && !(patched && v == DistroBase) {
		if err := CheckVersion(v); err != nil {
			return err
		}
	}
	if old, err := s.cfg.Files.ReadFile(s.confPath(k)); err == nil {
		return Verify(string(old), s.params(k))
	}
	return nil
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[netip.Prefix]int{}
	for _, p := range a {
		m[p]++
	}
	for _, p := range b {
		m[p]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

// Check is one supervision pass: a started unit that is not active is restarted
// and alerted, and the identified process's unwanted.replies counter is read.
func (s *Supervisor) Check(ctx context.Context) {
	s.mu.Lock()
	var kinds []Kind
	for _, k := range []Kind{Identified, Free} {
		if s.started[k] {
			kinds = append(kinds, k)
		}
	}
	var retry []Kind
	for _, k := range []Kind{Identified, Free} {
		if s.wanted[k] && !s.started[k] && time.Since(s.lastTry[k]) >= s.cfg.StartRetry {
			retry = append(retry, k)
		}
	}
	list := append([]netip.Prefix(nil), s.dnq...)
	s.mu.Unlock()
	for _, k := range retry {
		// A start that never happened gets the same chance a dead unit gets below: the
		// host gate first (the agent's own host check alerts for it), then every check
		// Start makes.
		if s.cfg.Gate != nil && s.cfg.Gate() != nil {
			s.mu.Lock()
			s.lastTry[k] = time.Now()
			s.mu.Unlock()
			continue
		}
		_ = s.Start(ctx, k, list)
	}
	s.mu.Lock()
	kinds = kinds[:0]
	for _, k := range []Kind{Identified, Free} {
		if s.started[k] {
			kinds = append(kinds, k)
		}
	}
	s.mu.Unlock()
	_ = s.reconcile(ctx) // a reload that failed before; it alerted then
	for _, k := range kinds {
		out, _ := s.cfg.Runner.Run(ctx, nil, "systemctl", "is-active", s.unit(k))
		if strings.TrimSpace(string(out)) == "active" {
			s.restartIfStale(ctx, k)
			continue
		}
		s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundDown, Detail: k.String()})
		if err := s.guard(k); err != nil {
			// The same refusals as at the start: it stays down, and is looked at again on
			// the next pass, so it comes back when the host is right again.
			s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundRefused, Detail: k.String() + ": not restarted, a start check fails"})
			continue
		}
		_, _ = s.cfg.Runner.Run(ctx, nil, "systemctl", "restart", s.unit(k))
	}
	for _, k := range kinds {
		if k == Identified {
			s.checkUnwanted(ctx)
		}
	}
}

// checkUnwanted alerts when the identified process's counter of unwanted replies
// rises (SC 11). stats_noreset holds no name or address.
func (s *Supervisor) checkUnwanted(ctx context.Context) {
	out, err := s.cfg.Runner.Run(ctx, nil, s.cfg.Control, "-c", s.confPath(Identified), "stats_noreset")
	if err != nil {
		return
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if v, ok := strings.CutPrefix(string(line), "unwanted.replies="); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return
			}
			s.mu.Lock()
			rose := s.unwant != 0 && n > s.unwant || s.unwant == 0 && n > 0
			s.unwant = n
			s.mu.Unlock()
			if rose {
				s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundUnwanted, Detail: "unwanted.replies rose"})
			}
			return
		}
	}
}

// Run supervises until ctx ends.
func (s *Supervisor) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Check(ctx)
		}
	}
}

// Started reports whether a kind was started by this supervisor.
func (s *Supervisor) Started(k Kind) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started[k]
}
