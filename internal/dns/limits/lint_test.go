package limits

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The N5 lint of p4-nodes.md 11.2: a limiter, or the settings of a listener,
// constructed anywhere but in internal/dns/limits is a limit that the registry
// walks cannot see. The lint reads the source of the module and fails on:
//
//   - an import of a rate limiter or a connection limiter of a library
//     (golang.org/x/time/rate, golang.org/x/net/netutil, a semaphore package);
//   - a type declared outside this package whose name says it limits
//     (limiter, rate limit, token bucket, bucket, semaphore);
//   - a composite literal or new() of this package's engine types (Set, Conn, Pending)
//     or of its data types (Entry, ListenerSettings, Key) outside it: the only
//     way to get them is NewSet, Default and Listeners.
//
// It is a lint, not a proof: a limiter written with a map and a mutex under
// another name passes it, and review catches that.

var bannedImports = []string{
	"golang.org/x/time/rate",
	"golang.org/x/net/netutil",
	"golang.org/x/sync/semaphore",
	"github.com/juju/ratelimit",
	"github.com/didip/tollbooth",
	"github.com/ulule/limiter",
	"go.uber.org/ratelimit",
}

var bannedTypeName = regexp.MustCompile(`(?i)(limiter|ratelimit|tokenbucket|bucket|semaphore)`)

var ownTypes = map[string]bool{"Set": true, "Conn": true, "Pending": true, "Entry": true, "ListenerSettings": true, "Key": true, "Exemption": false}

// lintFile returns the violations of one file. pkgDir is the directory of the
// file relative to the module root, slash separated.
func lintFile(pkgDir, name string, src []byte) []string {
	if strings.HasSuffix(name, "_test.go") || pkgDir == "internal/dns/limits" {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	add := func(pos token.Pos, msg string) {
		out = append(out, pkgDir+"/"+name+":"+strconv.Itoa(fset.Position(pos).Line)+": "+msg)
	}
	limitsName := ""
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		for _, b := range bannedImports {
			if p == b || strings.HasPrefix(p, b+"/") {
				add(imp.Pos(), "imports "+p+": limits live in internal/dns/limits")
			}
		}
		if strings.HasSuffix(p, "/internal/dns/limits") {
			limitsName = "limits"
			if imp.Name != nil {
				limitsName = imp.Name.Name
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.TypeSpec:
			if bannedTypeName.MatchString(v.Name.Name) {
				add(v.Pos(), "type "+v.Name.Name+" looks like a limiter")
			}
		case *ast.CompositeLit:
			if isOwnType(v.Type, limitsName) {
				add(v.Pos(), "constructs a type of internal/dns/limits")
			}
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "new" && len(v.Args) == 1 && isOwnType(v.Args[0], limitsName) {
				add(v.Pos(), "new() of a type of internal/dns/limits")
			}
		}
		return true
	})
	return out
}

func isOwnType(e ast.Expr, limitsName string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || limitsName == "" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == limitsName && ownTypes[sel.Sel.Name]
}

func TestLintFindsLimiters(t *testing.T) {
	cases := map[string]string{
		"an x/time/rate import": `package p
import "golang.org/x/time/rate"
var _ = rate.NewLimiter`,
		"netutil.LimitListener": `package p
import _ "golang.org/x/net/netutil"`,
		"a type called limiter": `package p
type perIPLimiter struct{}`,
		"a token bucket": `package p
type tokenBucket struct{}`,
		"a Set literal": `package p
import "github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
var _ = limits.Set{}`,
		"new(limits.Set)": `package p
import "github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
var _ = new(limits.Set)`,
		"listener settings of its own": `package p
import "github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
var _ = limits.ListenerSettings{MaxQueriesPerConn: 128}`,
		"an entry of its own, under another import name": `package p
import lim "github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
var _ = []lim.Entry{{Name: "x"}}
var _ = lim.Entry{}`,
	}
	for name, src := range cases {
		if got := lintFile("internal/dns/listen", "x.go", []byte(src)); len(got) == 0 {
			t.Errorf("the lint missed %s", name)
		}
	}
	// The sanctioned ways are not flagged.
	ok := `package p
import "github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
func f() { s, _ := limits.NewSet(limits.Default()); _ = s; _ = limits.Listeners() }
type conn struct{ c *limits.Conn }`
	if got := lintFile("internal/dns/listen", "x.go", []byte(ok)); len(got) != 0 {
		t.Errorf("false positive: %v", got)
	}
	// The package itself is exempt, and so are tests.
	if got := lintFile("internal/dns/limits", "x.go", []byte(cases["a token bucket"])); len(got) != 0 {
		t.Errorf("the limits package was linted: %v", got)
	}
	if got := lintFile("internal/dns/listen", "x_test.go", []byte(cases["a token bucket"])); len(got) != 0 {
		t.Errorf("a test file was linted: %v", got)
	}
}

// TestNoLimiterOutsideLimits runs the lint over the module.
func TestNoLimiterOutsideLimits(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s", root)
	}
	files := 0
	var bad []string
	for _, top := range []string{"internal", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			src, rerr := os.ReadFile(p)
			if rerr != nil {
				t.Error(rerr)
				return nil
			}
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			files++
			bad = append(bad, lintFile(filepath.ToSlash(rel), filepath.Base(p), src)...)
			return nil
		})
	}
	if files < 10 {
		t.Fatalf("the lint saw only %d files", files)
	}
	for _, b := range bad {
		t.Error(b)
	}
}
