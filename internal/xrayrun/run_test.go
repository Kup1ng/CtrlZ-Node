package xrayrun

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
)

type fakeHost struct {
	files   map[string]string
	removed []string
	execArg []string
	rmErr   error
}

func (h *fakeHost) env() Env {
	return Env{
		Layout: Layout{Etc: "/e", Lib: "/l", Run: "/r"},
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := h.files[p]; ok {
				return []byte(s), nil
			}
			return nil, fs.ErrNotExist
		},
		Remove:  func(p string) error { h.removed = append(h.removed, p); return h.rmErr },
		Exec:    func(path string, argv []string) error { h.execArg = argv; return errors.New("test") },
		Geteuid: func() int { return 1001 },
	}
}

func TestRunExecsAllowedVersionAfterRemovingStaleFiles(t *testing.T) {
	h := &fakeHost{files: map[string]string{
		"/e/xray/a.version":      "v26.11.9\n",
		"/e/versions/xray.allow": "# c\nv26.10.1\nv26.11.9\n",
	}}
	if got := Run([]string{"a"}, h.env()); got != 1 { // Exec returns only on failure
		t.Fatalf("status %d", got)
	}
	want := []string{"/l/v26.11.9/xray", "run", "-c", "/e/xray/a.json"}
	if !reflect.DeepEqual(h.execArg, want) {
		t.Fatalf("argv %v", h.execArg)
	}
	if !reflect.DeepEqual(h.removed, []string{"/r-a/api.sock", "/r-a/api.sock.lock"}) {
		t.Fatalf("removed %v", h.removed)
	}
}

func TestRunRefusals(t *testing.T) {
	base := map[string]string{"/e/xray/b.version": "v26.11.9", "/e/versions/xray.allow": "v26.10.1\n"}
	for name, c := range map[string]struct {
		args  []string
		files map[string]string
	}{
		"not allowed":  {[]string{"b"}, base},
		"bad slot":     {[]string{"../a"}, base},
		"no args":      {nil, base},
		"no version":   {[]string{"a"}, base},
		"junk version": {[]string{"b"}, map[string]string{"/e/xray/b.version": "v1/../x", "/e/versions/xray.allow": "v1/../x"}},
		"allow prefix": {[]string{"b"}, map[string]string{"/e/xray/b.version": "v26.11.9", "/e/versions/xray.allow": "v26.11.99\n"}},
	} {
		h := &fakeHost{files: c.files}
		if Run(c.args, h.env()) == 0 || h.execArg != nil || len(h.removed) != 0 {
			t.Errorf("%s: ran (exec %v, removed %v)", name, h.execArg, h.removed)
		}
	}
}

func TestRunStopsWhenAStaleFileCannotBeRemoved(t *testing.T) {
	h := &fakeHost{files: map[string]string{"/e/xray/a.version": "v26.11.9", "/e/versions/xray.allow": "v26.11.9"}, rmErr: errors.New("busy")}
	if Run([]string{"a"}, h.env()) == 0 || h.execArg != nil {
		t.Fatal("exec after a failed removal")
	}
}

// B5-r1-6: xray-run does not start Xray as root, whatever the unit file says.
func TestRunRefusesToRunAsRoot(t *testing.T) {
	h := &fakeHost{files: map[string]string{
		"/e/xray/a.version":      "v26.11.9\n",
		"/e/versions/xray.allow": "v26.11.9\n",
	}}
	env := h.env()
	env.Geteuid = func() int { return 0 }
	if got := Run([]string{"a"}, env); got != 1 {
		t.Fatalf("status %d", got)
	}
	if h.execArg != nil || len(h.removed) != 0 {
		t.Fatalf("root went on: exec %v removed %v", h.execArg, h.removed)
	}
	if RefuseRoot(0) == nil || RefuseRoot(1001) != nil {
		t.Fatal("RefuseRoot must refuse uid 0 only")
	}
}
