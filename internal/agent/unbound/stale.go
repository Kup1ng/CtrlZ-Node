package unbound

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
)

// Files whose change after a process started means the process runs old code: the
// binary, and dpkg's status file, which dpkg rewrites on every package change and so
// also covers a library of the closure (libssl3t64 for DNSSEC, libevent, ...) that a
// security update replaced while /usr/sbin/unbound stayed as it was.
const (
	BinaryPath = "/usr/sbin/unbound"
	DpkgStatus = "/var/lib/dpkg/status"
)

// staleSlack covers the one-second resolution of the boot time in /proc/stat: a file
// changed within this much of the start is not taken as newer than the process.
const staleSlack = 2 * time.Second

// staleEvery is the least time between two restarts the agent makes for one kind
// because of a changed file. It is what stops a restart loop on a host whose clock
// puts a file's change time after every start (a clock that stepped back).
const staleEvery = 10 * time.Minute

// restartIfStale restarts the unit of k when the files it runs from changed after
// its main process started (p4-nodes 7.1: a package update does not restart a unit
// that is masked or not enabled, and the agent only reloads a running Unbound, so
// without this a security fix would leave the old process answering until the next
// reboot). It cannot read /proc/<pid>/exe or maps the way apply.sh can: the agent
// has no CAP_SYS_PTRACE and the process belongs to another user. What it can read
// is /proc/<pid>/stat and /proc/stat, which everyone may, and the change time of
// the files. The restart goes through the same checks as the restart of a dead unit.
func (s *Supervisor) restartIfStale(ctx context.Context, k Kind) {
	now := s.now()
	s.mu.Lock()
	last := s.lastStale[k]
	s.mu.Unlock()
	if !last.IsZero() && now.Sub(last) < staleEvery {
		return
	}
	start, ok := s.processStart(ctx, k)
	if !ok {
		return
	}
	var newest time.Time
	for _, p := range s.cfg.Watch {
		if t, err := s.cfg.ChangeTime(p); err == nil && t.After(newest) && !t.After(now) {
			newest = t
		}
	}
	if !newest.After(start.Add(staleSlack)) {
		return
	}
	s.mu.Lock()
	s.lastStale[k] = now
	s.mu.Unlock()
	// The files on disk are new, so what the floor was judged on at the start (and
	// cached) says nothing about them: ask the binary again before it is run. A
	// package rolled back below the floor must leave the old, patched process alone
	// and be told to the owner, not be started (spec 7.3, T-559).
	v, err := s.recheckBinary(ctx)
	if err == nil {
		err = s.guard(k)
	}
	if err != nil {
		s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundRefused, Detail: k.String() + ": not restarted onto replaced files, a start check fails"})
		return
	}
	s.cfg.Alert.Alert(alert.Alert{Code: alert.UnboundStale, Detail: k.String()})
	if _, err := s.cfg.Runner.Run(ctx, nil, "systemctl", "restart", s.unit(k)); err == nil {
		s.mu.Lock()
		s.ran = v
		s.mu.Unlock()
	}
}

// recheckBinary forgets the version and the patched state that were cached for the
// binary of the start, reads them again from the binary now on disk and holds them to
// the floor. It returns the version.
func (s *Supervisor) recheckBinary(ctx context.Context) (string, error) {
	s.mu.Lock()
	s.version, s.patched = "", false
	s.mu.Unlock()
	v, err := s.Version(ctx)
	if err != nil {
		return "", err
	}
	return v, s.checkFloor(ctx, v)
}

func (s *Supervisor) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// processStart is the wall-clock time the main process of k started, from the start
// time (clock ticks since boot, 100 a second on Linux for every user-space reader) in
// /proc/<pid>/stat and the boot time of /proc/stat.
func (s *Supervisor) processStart(ctx context.Context, k Kind) (time.Time, bool) {
	out, err := s.cfg.Runner.Run(ctx, nil, "systemctl", "show", "-p", "MainPID", "--value", s.unit(k))
	if err != nil {
		return time.Time{}, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return time.Time{}, false
	}
	st, err := s.cfg.Files.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, false
	}
	// The command name is in parentheses and may hold spaces: count from the last ')'.
	str := string(st)
	i := strings.LastIndexByte(str, ')')
	if i < 0 {
		return time.Time{}, false
	}
	f := strings.Fields(str[i+1:])
	// Field 22 of the line is the start time; f begins at field 3.
	if len(f) < 20 {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil || ticks < 0 {
		return time.Time{}, false
	}
	gen, err := s.cfg.Files.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(gen), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			boot, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || boot <= 0 {
				return time.Time{}, false
			}
			return time.Unix(boot, 0).Add(time.Duration(ticks) * 10 * time.Millisecond), true
		}
	}
	return time.Time{}, false
}
