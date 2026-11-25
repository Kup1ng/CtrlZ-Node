package zonekeys

import (
	"io/fs"
	"os"
	"path/filepath"
)

// walk calls fn with the content of every file under dir.
func walk(dir string, fn func([]byte)) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err == nil {
			fn(b)
		}
		return nil
	})
}
