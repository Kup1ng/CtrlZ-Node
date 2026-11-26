// Package fake holds the test doubles of package sysx.
package fake

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"sync"
)

// Call is one command the fake saw.
type Call struct {
	Name  string
	Args  []string
	Stdin []byte
}

// String is the command line, for assertions.
func (c Call) String() string { return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " ")) }

// Runner records commands and answers them from Reply.
type Runner struct {
	mu    sync.Mutex
	calls []Call
	// Reply gives the stdout and error of a command. Nil means empty output and no error.
	Reply func(c Call) ([]byte, error)
}

// Run implements sysx.Runner.
func (r *Runner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	c := Call{Name: name, Args: append([]string(nil), args...), Stdin: append([]byte(nil), stdin...)}
	r.mu.Lock()
	r.calls = append(r.calls, c)
	reply := r.Reply
	r.mu.Unlock()
	if reply == nil {
		return nil, nil
	}
	return reply(c)
}

// Calls returns a copy of the commands seen so far.
func (r *Runner) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Call(nil), r.calls...)
}

// Lines returns the command lines seen so far.
func (r *Runner) Lines() []string {
	var out []string
	for _, c := range r.Calls() {
		out = append(out, c.String())
	}
	return out
}

// Files is an in-memory sysx.Files.
type Files struct {
	mu sync.Mutex
	M  map[string][]byte
	// Modes records the mode of the last write of each path.
	Modes map[string]fs.FileMode
	// WriteErr, when set, makes every write fail.
	WriteErr error
}

// NewFiles returns Files holding the given contents.
func NewFiles(m map[string]string) *Files {
	f := &Files{M: map[string][]byte{}, Modes: map[string]fs.FileMode{}}
	for k, v := range m {
		f.M[k] = []byte(v)
	}
	return f
}

// ReadFile implements sysx.Files.
func (f *Files) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.M[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

// WriteFile implements sysx.Files.
func (f *Files) WriteFile(path string, data []byte, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.WriteErr != nil {
		return f.WriteErr
	}
	f.M[path] = append([]byte(nil), data...)
	f.Modes[path] = mode
	return nil
}

// Set replaces a file's contents.
func (f *Files) Set(path, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.M[path] = []byte(data)
}

// Get returns a file's contents.
func (f *Files) Get(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.M[path])
}

// Units answers `systemctl is-active` the way a host does: a unit is inactive until
// it is started or restarted, so a test of a first start does not look like an agent
// restart that finds its units already running. Preset marks a unit as already up.
type Units struct {
	mu sync.Mutex
	on map[string]bool
}

// Preset marks a unit as running before the agent started.
func (u *Units) Preset(unit string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.on == nil {
		u.on = map[string]bool{}
	}
	u.on[unit] = true
}

// Handle answers a systemctl start, restart or is-active and reports whether the
// call was one of those.
func (u *Units) Handle(c Call) (out []byte, err error, ok bool) {
	if c.Name != "systemctl" || len(c.Args) < 2 {
		return nil, nil, false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.on == nil {
		u.on = map[string]bool{}
	}
	switch c.Args[0] {
	case "start", "restart":
		u.on[c.Args[1]] = true
		return nil, nil, false // the caller's own Reply may still fail it
	case "is-active":
		if u.on[c.Args[1]] {
			return []byte("active\n"), nil, true
		}
		return []byte("inactive\n"), errors.New("exit status 3"), true
	}
	return nil, nil, false
}
