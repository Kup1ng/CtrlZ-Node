package xrayrun

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Env is what Run needs from the host, so a test runs it without exec.
type Env struct {
	Layout   Layout
	ReadFile func(string) ([]byte, error)
	Remove   func(string) error
	// Exec replaces the process. It returns only on failure.
	Exec func(path string, argv []string) error
}

// OSEnv is the real host.
func OSEnv() Env {
	return Env{Layout: DefaultLayout(), ReadFile: os.ReadFile, Remove: os.Remove, Exec: execve}
}

// Run starts Xray for a slot (7.6): it reads `<slot>.version`, refuses a release that
// is not in xray.allow, removes the slot's api.sock and api.sock.lock, and replaces
// itself with the binary. It returns an exit status only when it did not exec.
//
// The two files go first because Xray never removes a socket that an earlier
// process left and cannot bind over it (B0 E11), and the unit restarts after a
// SIGKILL. Removing the lock too is safe: the flock died with the process, and the
// unit runs one process of the slot at a time.
func Run(args []string, env Env) int {
	if len(args) != 1 || !ValidSlot(args[0]) {
		fmt.Fprintln(os.Stderr, "usage: ctrlz-node xray-run a|b")
		return 2
	}
	slot := args[0]
	l := env.Layout
	raw, err := env.ReadFile(l.SlotVersion(slot))
	if err != nil {
		fmt.Fprintln(os.Stderr, "xray-run: the slot has no version file")
		return 1
	}
	version := strings.TrimSpace(string(raw))
	if !ValidVersion(version) {
		fmt.Fprintln(os.Stderr, "xray-run: the version file does not hold a release tag")
		return 1
	}
	allow, err := env.ReadFile(l.Allow())
	if err != nil {
		fmt.Fprintln(os.Stderr, "xray-run: xray.allow cannot be read")
		return 1
	}
	if !Allowed(allow, version) {
		// The release tag is not a secret and tells the admin which file to fix.
		fmt.Fprintf(os.Stderr, "xray-run: release %s is not in xray.allow\n", version)
		return 1
	}
	for _, p := range []string{l.APISock(slot), l.APILock(slot)} {
		if err := env.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "xray-run: a stale api file cannot be removed")
			return 1
		}
	}
	bin := l.Binary(version)
	// Exec returns only on failure, and its error can name a path, never a secret.
	_ = env.Exec(bin, []string{bin, "run", "-c", l.SlotJSON(slot)})
	fmt.Fprintln(os.Stderr, "xray-run: exec failed")
	return 1
}

// Allowed reports whether the allow file lists version. Blank lines and comment
// lines are ignored; a line must equal the tag, so v26.11.9 never matches v26.11.99.
func Allowed(allow []byte, version string) bool {
	sc := bufio.NewScanner(bytes.NewReader(allow))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == version {
			return true
		}
	}
	return false
}
