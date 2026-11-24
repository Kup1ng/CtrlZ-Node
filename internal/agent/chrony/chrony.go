// Package chrony writes the node's chrony drop-in (p4-nodes 7.10, Plan T-087):
// the panel host is the node's only time source, over NTS, trusting the node CA.
//
// The install script, as root and once, makes /etc/chrony/chrony.conf hold only
// fixed settings and `confdir /etc/ctrlz/chrony`; the agent owns that directory
// and writes /etc/ctrlz/chrony/ctrlz.conf. The CA file sits beside it because
// keys/ is the agent's alone and chrony cannot read it.
package chrony

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"text/template"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
)

// Files of the drop-in directory and the unit the agent restarts.
const (
	Dir      = "/etc/ctrlz/chrony"
	ConfName = "ctrlz.conf"
	CAName   = "node_ca.pem"
	// StateName records whether the restart that follows a change has happened.
	StateName    = "restart.state"
	statePending = "pending\n"
	stateDone    = "done\n"
	Unit         = "chrony.service"
)

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// ValidHost reports whether s is an IP address or a plain host name, so no
// chrony directive can be injected through the hub setting of agent.conf.
func ValidHost(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return hostRE.MatchString(s) && !strings.Contains(s, "..")
}

const tmpl = `# Written by ctrlz-agent. The panel is the only time source (p4-nodes 7.10).
server {{.Host}} iburst nts
ntstrustedcerts {{.CA}}
# Without this, ntstrustedcerts only adds to the system CAs, and any public CA would do for NTS-KE.
nosystemcert
minsources 1
makestep 1.0 3
`

var parsed = template.Must(template.New("chrony").Parse(tmpl))

// Render returns the drop-in for a panel host, with the CA file at caPath.
func Render(host, caPath string) (string, error) {
	if !ValidHost(host) {
		return "", errors.New("chrony: the panel host is not a host name or an address")
	}
	if caPath == "" || strings.ContainsAny(caPath, " \t\r\n\"") {
		return "", errors.New("chrony: bad CA path")
	}
	var b bytes.Buffer
	if err := parsed.Execute(&b, struct{ Host, CA string }{host, caPath}); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Update writes the drop-in and the CA and restarts chrony, only when either
// changed (a restart drops chrony's sources for a moment). It reports whether it
// changed anything.
func Update(ctx context.Context, files sysx.Files, run sysx.Runner, host string, caPEM []byte) (bool, error) {
	caPath := path.Join(Dir, CAName)
	conf, err := Render(host, caPath)
	if err != nil {
		return false, err
	}
	if len(caPEM) == 0 {
		return false, errors.New("chrony: no node CA to trust")
	}
	changed := false
	for _, f := range []struct {
		path string
		data []byte
	}{{path.Join(Dir, ConfName), []byte(conf)}, {caPath, caPEM}} {
		if old, err := files.ReadFile(f.path); err == nil && bytes.Equal(old, f.data) {
			continue
		}
		if err := files.WriteFile(f.path, f.data, 0o644); err != nil {
			return changed, fmt.Errorf("chrony: write %s: %w", path.Base(f.path), err)
		}
		changed = true
	}
	// "Files written" is not "chrony runs with them": a restart that failed (the unit
	// not up yet, a polkit rule not loaded) would otherwise be skipped by every later
	// run, which finds the files as they should be. The state file is on disk so that
	// an agent restart retries it too.
	statePath := path.Join(Dir, StateName)
	pending := false
	if b, err := files.ReadFile(statePath); err == nil && string(b) == statePending {
		pending = true
	}
	if changed && !pending {
		if err := files.WriteFile(statePath, []byte(statePending), 0o644); err != nil {
			return changed, fmt.Errorf("chrony: write the state: %w", err)
		}
		pending = true
	}
	if pending {
		if _, err := run.Run(ctx, nil, "systemctl", "restart", Unit); err != nil {
			return changed, fmt.Errorf("chrony: restart: %w", err)
		}
		if err := files.WriteFile(statePath, []byte(stateDone), 0o644); err != nil {
			return changed, fmt.Errorf("chrony: write the state: %w", err)
		}
		return true, nil
	}
	return changed, nil
}
