package main

// The source half of the start check: what the pinned Xray-core release says in its Go files, read with go/parser, so the
// lists come from the tag and not from memory (p4b-proxy.md 7.2, Plan.md G4).
//
//   K1  the keys of infra/conf, type by type, reachable from an outbound
//   K2  where infra/conf folds the case of a value (strings.ToLower in a switch) and where it does not
//   K3  every use of os, os/exec, io/ioutil, syscall, net/http, plugin, the platform filesystem and the Lua engine, with the
//       function it is in: the inventory that the always-rejected keys of 7.2 have to cover
//
// The program prints; it decides nothing. The lists are copied into docs/research/xray-start-check.md by hand, so that a
// person has read each one.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type pkgSrc struct {
	fset  *token.FileSet
	files map[string]*ast.File // by path relative to the source root, slash separated
	root  string
}

func parseDir(root, rel string, recursive bool) (*pkgSrc, error) {
	p := &pkgSrc{fset: token.NewFileSet(), files: map[string]*ast.File{}, root: root}
	start := filepath.Join(root, filepath.FromSlash(rel))
	err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != start && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(p.fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		r, _ := filepath.Rel(root, path)
		p.files[filepath.ToSlash(r)] = f
		return nil
	})
	return p, err
}

func (p *pkgSrc) names() []string { return sortedKeys(p.files) }

func (p *pkgSrc) pos(n ast.Node) string {
	pp := p.fset.Position(n.Pos())
	r, err := filepath.Rel(p.root, pp.Filename)
	if err != nil {
		r = pp.Filename
	}
	return fmt.Sprintf("%s:%d", filepath.ToSlash(r), pp.Line)
}

// ---------------------------------------------------------------------------------------------------------------------

func analyzeSource(root string) {
	conf, err := parseDir(root, "infra/conf", false)
	if err != nil {
		rep("K1", "ERR", "cannot parse infra/conf: %v", err)
		return
	}
	k1(conf)
	k2(conf)
	rest, err := parseDir(root, ".", true)
	if err != nil {
		rep("K3", "ERR", "cannot parse the module: %v", err)
		return
	}
	k3(rest)
}

type fieldInfo struct {
	key  string
	kids []string
	raw  bool
}

func k1(p *pkgSrc) {
	specs := map[string]*ast.TypeSpec{}
	where := map[string]string{}
	custom := map[string]bool{}
	loaders := map[string]map[string]string{}
	for _, name := range p.names() {
		f := p.files[name]
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.TypeSpec:
				if _, dup := specs[x.Name.Name]; !dup {
					specs[x.Name.Name] = x
					where[x.Name.Name] = p.pos(x)
				}
			case *ast.FuncDecl:
				if x.Recv != nil && x.Name.Name == "UnmarshalJSON" && len(x.Recv.List) == 1 {
					custom[recvName(x.Recv.List[0].Type)] = true
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if (id.Name == "inboundConfigLoader" || id.Name == "outboundConfigLoader") && i < len(x.Values) {
						loaders[id.Name] = loaderTable(x.Values[i])
					}
				}
			}
			return true
		})
	}

	if top := specs["Config"]; top != nil {
		var keys []string
		for _, fi := range structFields(top, specs) {
			keys = append(keys, fi.key)
		}
		sort.Strings(keys)
		logf("K1 top-level keys of Config (%d): %s", len(keys), strings.Join(keys, " "))
	}
	for _, ln := range []string{"outboundConfigLoader", "inboundConfigLoader"} {
		t := loaders[ln]
		var ps []string
		for _, k := range sortedKeys(t) {
			ps = append(ps, k+"="+t[k])
		}
		logf("K1 %s protocols (%d): %s", ln, len(ps), strings.Join(ps, " "))
	}

	// Walk from an outbound; the settings of each protocol are children of the Settings key.
	seen := map[string]bool{}
	var order []string
	var visit func(string)
	visit = func(name string) {
		if seen[name] || specs[name] == nil {
			return
		}
		seen[name] = true
		order = append(order, name)
		if custom[name] {
			return
		}
		for _, fi := range structFields(specs[name], specs) {
			for _, k := range fi.kids {
				visit(k)
			}
		}
	}
	visit("OutboundDetourConfig")
	for _, t := range loaders["outboundConfigLoader"] {
		visit(strings.TrimPrefix(t, "*"))
	}
	sort.Strings(order)
	logf("K1 types reachable from an outbound: %d", len(order))
	total := 0
	for _, name := range order {
		sp := specs[name]
		tag := ""
		if custom[name] {
			tag = " [UnmarshalJSON: own JSON form]"
		}
		if _, ok := sp.Type.(*ast.StructType); !ok {
			logf("K1 type %s (%s) = %s%s", name, where[name], exprStr(sp.Type), tag)
			continue
		}
		var parts []string
		for _, fi := range structFields(sp, specs) {
			s := fi.key
			if fi.raw {
				s += "{raw}"
			}
			parts = append(parts, s)
			total++
		}
		logf("K1 type %s (%s)%s keys(%d): %s", name, where[name], tag, len(parts), strings.Join(parts, " "))
	}
	logf("K1 keys in the reachable structs, counted per struct: %d", total)

	// json.Unmarshal calls: a json.RawMessage field is read again by code, and those keys are in no struct above.
	for _, name := range p.names() {
		ast.Inspect(p.files[name], func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if s, ok := ce.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Unmarshal" {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == "json" && len(ce.Args) == 2 {
					logf("K1 raw re-read %s json.Unmarshal(.., %s)", p.pos(ce), exprStr(ce.Args[1]))
				}
			}
			return true
		})
	}
	rep("K1", "INFO", "%d outbound protocols, %d types and %d keys reachable from an outbound in this release; the lists are in the log lines K1", len(loaders["outboundConfigLoader"]), len(order), total)
}

func recvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return recvName(x.X)
	}
	return ""
}

func loaderTable(e ast.Expr) map[string]string {
	out := map[string]string{}
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return out
	}
	lit, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return out
	}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		k, _ := kv.Key.(*ast.BasicLit)
		fl, _ := kv.Value.(*ast.FuncLit)
		if k == nil || fl == nil {
			continue
		}
		name, _ := strconv.Unquote(k.Value)
		ast.Inspect(fl.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
					out[name] = exprStr(x.Args[0])
				}
			case *ast.UnaryExpr:
				if cl, ok := x.X.(*ast.CompositeLit); ok {
					out[name] = exprStr(cl.Type)
				}
			}
			return true
		})
	}
	return out
}

// structFields lists the keys a struct type reads: tagged fields by their json name, untagged embedded structs expanded.
func structFields(sp *ast.TypeSpec, specs map[string]*ast.TypeSpec) []fieldInfo {
	st, ok := sp.Type.(*ast.StructType)
	if !ok {
		return nil
	}
	return fieldsOfStruct(st, specs, 0)
}

func fieldsOfStruct(st *ast.StructType, specs map[string]*ast.TypeSpec, depth int) []fieldInfo {
	var out []fieldInfo
	for _, f := range st.Fields.List {
		tag := ""
		if f.Tag != nil {
			tag, _ = strconv.Unquote(f.Tag.Value)
		}
		jt := reflect.StructTag(tag).Get("json")
		key, _, _ := strings.Cut(jt, ",")
		if key == "-" {
			continue
		}
		if len(f.Names) == 0 { // embedded
			if key == "" && depth < 4 {
				if id := baseIdent(f.Type); id != "" {
					if sp := specs[id]; sp != nil {
						if inner, ok := sp.Type.(*ast.StructType); ok {
							out = append(out, fieldsOfStruct(inner, specs, depth+1)...)
						}
					}
				}
			}
			continue
		}
		for _, n := range f.Names {
			if !n.IsExported() {
				continue
			}
			k := key
			if k == "" {
				k = n.Name
			}
			out = append(out, fieldInfo{key: k, kids: typeNames(f.Type), raw: strings.Contains(exprStr(f.Type), "RawMessage")})
		}
	}
	return out
}

func baseIdent(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return baseIdent(x.X)
	}
	return ""
}

func typeNames(e ast.Expr) []string {
	switch x := e.(type) {
	case *ast.Ident:
		return []string{x.Name}
	case *ast.StarExpr:
		return typeNames(x.X)
	case *ast.ArrayType:
		return typeNames(x.Elt)
	case *ast.MapType:
		return typeNames(x.Value)
	}
	return nil
}

func exprStr(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return "*" + exprStr(x.X)
	case *ast.ArrayType:
		return "[]" + exprStr(x.Elt)
	case *ast.MapType:
		return "map[" + exprStr(x.Key) + "]" + exprStr(x.Value)
	case *ast.SelectorExpr:
		return exprStr(x.X) + "." + x.Sel.Name
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.StructType:
		return "struct{...}"
	case *ast.UnaryExpr:
		return x.Op.String() + exprStr(x.X)
	case *ast.CompositeLit:
		return exprStr(x.Type) + "{}"
	case *ast.CallExpr:
		return exprStr(x.Fun) + "()"
	case *ast.BasicLit:
		return x.Value
	}
	return fmt.Sprintf("%T", e)
}

// ---------------------------------------------------------------------------------------------------------------------

func isFoldCall(e ast.Expr) bool {
	ce, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	s, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == "strings" && (s.Sel.Name == "ToLower" || s.Sel.Name == "ToUpper")
}

func k2(p *pkgSrc) {
	folded, exact := 0, 0
	for _, name := range p.names() {
		f := p.files[name]
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			// identifiers assigned from strings.ToLower in this function
			lowered := map[string]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, r := range as.Rhs {
					if isFoldCall(r) && i < len(as.Lhs) {
						lowered[exprStr(as.Lhs[i])] = true
					}
				}
				return true
			})
			fn := fd.Name.Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				sw, ok := n.(*ast.SwitchStmt)
				if !ok || sw.Tag == nil {
					return true
				}
				var cases []string
				for _, st := range sw.Body.List {
					cc := st.(*ast.CaseClause)
					for _, e := range cc.List {
						bl, ok := e.(*ast.BasicLit)
						if !ok || bl.Kind != token.STRING {
							return true // a switch on something that is not a table of words
						}
						s, _ := strconv.Unquote(bl.Value)
						cases = append(cases, s)
					}
				}
				if len(cases) == 0 {
					return true
				}
				kind := "EXACT"
				if isFoldCall(sw.Tag) || lowered[exprStr(sw.Tag)] {
					kind = "FOLDED"
					folded++
				} else {
					exact++
				}
				logf("K2 %-6s %s in %s: switch %s { %s }", kind, p.pos(sw), fn, exprStr(sw.Tag), strings.Join(cases, ", "))
				return true
			})
		}
	}
	eq := 0
	for _, name := range p.names() {
		ast.Inspect(p.files[name], func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if s, ok := ce.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "EqualFold" {
				eq++
				logf("K2 EQUALFOLD %s", p.pos(ce))
			}
			return true
		})
	}
	rep("K2", "INFO", "%d switches over words fold the case, %d do not, %d EqualFold calls (lines K2); loader ids fold too (loader.go LoadWithID)", folded, exact, eq)
}

// ---------------------------------------------------------------------------------------------------------------------

type interest struct{ label, match string }

var interests = []interest{
	{"os", "os"},
	{"os/exec", "os/exec"},
	{"io/ioutil", "io/ioutil"},
	{"syscall", "syscall"},
	{"x/sys", "golang.org/x/sys/unix"},
	{"net/http", "net/http"},
	{"plugin", "plugin"},
	{"filesystem", "github.com/xtls/xray-core/common/platform/filesystem"},
	{"platform", "github.com/xtls/xray-core/common/platform"},
	{"lua", "github.com/xtls/xray-core/common/lua"},
	{"gopher-luar", "layeh.com/gopher-luar"},
}

func k3(p *pkgSrc) {
	perPkg := map[string]map[string]int{}
	files := 0
	for _, name := range p.names() {
		if strings.HasPrefix(name, "main/") || strings.HasPrefix(name, "testing/") || strings.Contains(name, "/testing/") {
			continue
		}
		f := p.files[name]
		local := map[string]string{} // local name -> label
		for _, im := range f.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			for _, it := range interests {
				if path == it.match {
					ln := filepath.Base(path)
					if im.Name != nil {
						ln = im.Name.Name
					}
					local[ln] = it.label
				}
			}
		}
		if len(local) == 0 {
			continue
		}
		files++
		dir := filepath.ToSlash(filepath.Dir(name))
		type site struct{ fn, label, call string }
		sites := map[site][]int{}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				se, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := se.X.(*ast.Ident)
				if !ok {
					return true
				}
				if label, ok := local[id.Name]; ok {
					s := site{fd.Name.Name, label, id.Name + "." + se.Sel.Name}
					sites[s] = append(sites[s], p.fset.Position(se.Pos()).Line)
				}
				return true
			})
		}
		var imps []string
		for _, l := range local {
			imps = append(imps, l)
		}
		sort.Strings(imps)
		logf("K3 FILE %s imports %s", name, strings.Join(imps, ","))
		var keys []string
		idx := map[string]site{}
		for s := range sites {
			k := s.fn + "|" + s.call
			keys = append(keys, k)
			idx[k] = s
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := idx[k]
			ls := sites[s]
			sort.Ints(ls)
			logf("K3   %s: %s  L%v", s.fn, s.call, ls)
			if perPkg[dir] == nil {
				perPkg[dir] = map[string]int{}
			}
			perPkg[dir][s.label]++
		}
		if len(keys) == 0 {
			logf("K3   (imported, no selector use found)")
		}
	}
	for _, d := range sortedKeys(perPkg) {
		var ps []string
		for _, l := range sortedKeys(perPkg[d]) {
			ps = append(ps, fmt.Sprintf("%s=%d", l, perPkg[d][l]))
		}
		logf("K3 DIR %s: %s", d, strings.Join(ps, " "))
	}
	rep("K3", "INFO", "%d files outside main/ and testing/ import one of os, os/exec, io/ioutil, syscall, x/sys, net/http, plugin, the platform and filesystem packages or the Lua engine (lines K3)", files)
}
