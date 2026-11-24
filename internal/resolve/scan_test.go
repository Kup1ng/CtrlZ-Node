package resolve

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// N6 (p4-nodes.md 11.2), second half: an upstream client is built by
// resolve.NewUpstream and nowhere else. dnsproxy's upstream package is imported
// by exactly one non-test file of the module, upstream.go, so no other code can
// build a client with a missing bootstrap address or a zero timeout, and none can
// take dnsproxy's own DoH client back in (Plan.md D66).
func TestOnlyNewUpstreamBuildsClients(t *testing.T) {
	var offenders []string
	for _, root := range []string{"..", "../../cmd"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), "dnsproxy/upstream") && filepath.Base(p) != "upstream.go" {
				offenders = append(offenders, filepath.ToSlash(p))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(offenders) != 0 {
		t.Fatalf("dnsproxy upstream imported outside resolve/upstream.go: %v", offenders)
	}
	b, err := os.ReadFile("upstream.go")
	if err != nil {
		t.Fatal(err)
	}
	// The DoH kind never reaches dnsproxy: it returns before the options are built.
	s := string(b)
	i := strings.Index(s, "UPSTREAM_KIND_DOH {\n\t\t// D66")
	j := strings.Index(s, "upstream.AddressToUpstream(")
	if i < 0 || j < 0 || i > j {
		t.Fatal("the DoH branch of NewUpstream must come before the dnsproxy constructor")
	}
}
