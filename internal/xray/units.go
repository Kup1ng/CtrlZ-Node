package xray

import (
	"context"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
)

// Units starts, stops and reads the two slot units. The agent does this by systemd
// and polkit (the rule of packaging names the two instances), not by signalling.
type Units interface {
	Start(ctx context.Context, slot string) error
	Stop(ctx context.Context, slot string) error
	Status(ctx context.Context, slot string) (UnitStatus, error)
}

// UnitStatus is what the manager needs to know of a slot: whether it runs, which
// process it is, how often systemd restarted it, and how the last process ended.
type UnitStatus struct {
	Active     bool
	PID        int
	Restarts   int
	Result     string // systemd's Result of the last end: success, signal, exit-code, oom-kill, core-dump, ...
	ExitStatus int    // ExecMainStatus
}

// IsEnd reports whether the last end of the process is an *end* in the sense of 7.5
// step 4: a death by a signal (the memory kill included) or exit status 2, Go's
// panic. SIGTERM and SIGINT exit 0 (B0 E12), a configuration error is 23 and a
// start that cannot bind 255: those are a start that failed and count as no end.
func IsEnd(result string, exit int) bool {
	switch result {
	case "signal", "core-dump", "oom-kill", "watchdog":
		return true
	case "exit-code":
		return exit == 2
	}
	return false
}

// SystemdUnits is the real Units, over `systemctl`.
type SystemdUnits struct {
	Runner sysx.Runner
}

func unitName(slot string) string { return "ctrlz-xray@" + slot + ".service" }

// Start implements Units.
func (u SystemdUnits) Start(ctx context.Context, slot string) error {
	_, err := u.Runner.Run(ctx, nil, "systemctl", "start", unitName(slot))
	return err
}

// Stop implements Units.
func (u SystemdUnits) Stop(ctx context.Context, slot string) error {
	_, err := u.Runner.Run(ctx, nil, "systemctl", "stop", unitName(slot))
	return err
}

// Status implements Units.
func (u SystemdUnits) Status(ctx context.Context, slot string) (UnitStatus, error) {
	out, err := u.Runner.Run(ctx, nil, "systemctl", "show",
		"-p", "ActiveState,MainPID,NRestarts,Result,ExecMainStatus", unitName(slot))
	if err != nil {
		return UnitStatus{}, err
	}
	var st UnitStatus
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, _ := strconv.Atoi(v)
		switch k {
		case "ActiveState":
			st.Active = v == "active" || v == "activating"
		case "MainPID":
			st.PID = n
		case "NRestarts":
			st.Restarts = n
		case "Result":
			st.Result = v
		case "ExecMainStatus":
			st.ExitStatus = n
		}
	}
	return st, nil
}
