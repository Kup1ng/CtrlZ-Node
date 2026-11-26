package dns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R21 and N7 on the query path: no access log, no logger of any kind in the
// packages that see a name, an address or a token. The only logger the node's
// DNS packages may construct is slog on a discard handler, which dnsproxy needs
// handing and which holds nothing (resolve/upstream.go).
//
// This walks the source, so a log call added later fails here, whoever adds it.
func TestNoLoggingInTheQueryPathPackages(t *testing.T) {
	dirs := []string{".", "../cache", "../policy", "../resolve", "../lru"}
	allowSlog := map[string]bool{"../resolve/upstream.go": true}
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.ToSlash(filepath.Join(dir, name))
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if p == "log" || (p == "log/slog" && !allowSlog[path]) {
					t.Errorf("%s imports %s", path, p)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok {
					switch {
					case id.Name == "os" && (sel.Sel.Name == "Stderr" || sel.Sel.Name == "Stdout"):
						t.Errorf("%s uses os.%s", path, sel.Sel.Name)
					case id.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Print"):
						t.Errorf("%s calls fmt.%s", path, sel.Sel.Name)
					case id.Name == "slog" && sel.Sel.Name != "New" && sel.Sel.Name != "DiscardHandler" && sel.Sel.Name != "Logger":
						t.Errorf("%s uses slog.%s", path, sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
}

// The dnsproxy logger is handed to dnsproxy discarded and never the default one
// (it would print the qname of every exchange).
func TestResolveUsesOnlyADiscardLogger(t *testing.T) {
	b, err := os.ReadFile("../resolve/upstream.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "slog.New(slog.DiscardHandler)") {
		t.Fatal("upstream.go does not hand dnsproxy a discard logger")
	}
}
