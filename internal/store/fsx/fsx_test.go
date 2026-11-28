package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteFileReplacesAtomically(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	var w Writer
	if err := w.WriteFile(p, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFile(p, []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	if read(t, p) != "two" {
		t.Fatal("not replaced")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o640 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
}

// A write that stops before each step, as a crash would, leaves the previous
// content whole, and never a partial file under the real name.
func TestCrashAtEveryStepKeepsThePreviousFile(t *testing.T) {
	for _, step := range Steps() {
		t.Run(step.String(), func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "f")
			if err := (&Writer{}).WriteFile(p, []byte("old content"), 0o600); err != nil {
				t.Fatal(err)
			}
			w := &Writer{Hook: func(path string, s Step) error {
				if s == step {
					return ErrInjected
				}
				return nil
			}}
			err := w.WriteFile(p, []byte("new content that is longer"), 0o600)
			if !errors.Is(err, ErrInjected) {
				t.Fatalf("got %v", err)
			}
			got := read(t, p)
			// The rename is the only step after which the new bytes are visible.
			want := "old content"
			if step == StepSyncDir {
				want = "new content that is longer"
			}
			if got != want {
				t.Fatalf("after a stop before %v the file holds %q", step, got)
			}
			// A crash leaves a temporary file (before the rename); CleanTemps removes it.
			n, err := CleanTemps(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			if step != StepSyncDir && step != StepCreate && n != 1 {
				t.Fatalf("expected one leftover temporary file, removed %d", n)
			}
			ents, _ := os.ReadDir(dir)
			if len(ents) != 1 || ents[0].Name() != "f" {
				t.Fatalf("directory after cleanup: %v", ents)
			}
		})
	}
}

// A real failure (not an injected one) cleans up after itself.
func TestRealFailureRemovesTheTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	// The target is a directory, so the rename fails.
	p := filepath.Join(dir, "f")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Writer{}).WriteFile(p, []byte("data"), 0o600); err == nil {
		t.Fatal("expected a failure")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestSealDetectsAFlippedBit(t *testing.T) {
	b := Seal("TEST", []byte("hello"))
	if got, err := Unseal("TEST", b); err != nil || string(got) != "hello" {
		t.Fatalf("%q %v", got, err)
	}
	for i := range b {
		c := append([]byte(nil), b...)
		c[i] ^= 1
		if _, err := Unseal("TEST", c); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("flip at %d accepted", i)
		}
	}
	if _, err := Unseal("TEST", b[:10]); !errors.Is(err, ErrCorrupt) {
		t.Fatal("truncated file accepted")
	}
	if _, err := Unseal("OTHR", b); !errors.Is(err, ErrCorrupt) {
		t.Fatal("wrong magic accepted")
	}
}

func TestReplaceSymlinkNeverLeavesNoLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename over a directory symlink; the node runs on Linux")
	}
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "current")
	if err := os.Symlink("a", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, step := range []Step{StepCreate, StepRename, StepSyncDir} {
		w := &Writer{Hook: func(_ string, s Step) error {
			if s == step {
				return ErrInjected
			}
			return nil
		}}
		_ = w.ReplaceSymlink(link, "b")
		got, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("link missing after a stop before %v: %v", step, err)
		}
		if step != StepSyncDir && got != "a" {
			t.Fatalf("link moved by a stop before %v: %s", step, got)
		}
		if err := (&Writer{}).ReplaceSymlink(link, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if err := (&Writer{}).ReplaceSymlink(link, "b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(link); got != "b" {
		t.Fatalf("link %s", got)
	}
	if _, err := CleanTemps(dir, false); err != nil {
		t.Fatal(err)
	}
}
