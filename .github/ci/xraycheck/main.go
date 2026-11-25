package main

// xraycheck is the Xray start check of package B0 (docs/specs/p4b-proxy.md 17, Plan.md D69). It runs on a GitHub runner, from
// .github/ci/xray-check.sh, against the real release binary and the source of the same tag, and prints one RESULT line for
// each claim the P4b spec makes about Xray. Nothing here is a test of our code: the output is read by a person, who writes
// docs/research/xray-start-check.md from it.
//
//   go run ./.github/ci/xraycheck -xray <binary> [-zip <archive>] -src <module source dir> [-only E05,E10] [-work <dir>]
//
// The experiments are independent: one that breaks prints ERR and the next one runs.

import (
	"archive/zip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

type experiment struct {
	id    string
	title string
	linux bool // needs Linux
	run   func(c *tctx)
	limit time.Duration
}

func experiments() []experiment {
	return []experiment{
		{"E01", "archive, hash, version, commands", false, e01Archive, 2 * time.Minute},
		{"E03", "api over a unix socket (finding 2)", true, e03APIUnix, 3 * time.Minute},
		{"E04", "socks inbound on a unix socket (finding 3)", true, e04SocksUnix, 3 * time.Minute},
		{"E05", "live add and removal under open connections (finding 4)", false, e05Live, 6 * time.Minute},
		{"E06", "dead exit after the SOCKS success (finding 20)", false, e06DeadExit, 3 * time.Minute},
		{"E07", "finalRules (finding 5)", false, e07FinalRules, 6 * time.Minute},
		{"E08", "tcp+local DNS", false, e08DNS, 4 * time.Minute},
		{"E09", "splice both ways", true, e09Splice, 5 * time.Minute},
		{"E10", "the dial limit (5.5)", true, e10DialLimit, 5 * time.Minute},
		{"E11", "restart after SIGKILL and after a kill by memory limit, stale api.sock", true, e11Restart, 8 * time.Minute},
		{"E12", "exit statuses (7.5 step 4)", false, e12Exit, 4 * time.Minute},
		{"E13", "a dialerProxy cycle (finding 27)", true, e13Cycle, 4 * time.Minute},
		{"E14", "key and value folding, unknown keys, removed keys, on the binary (finding 6, 22)", false, e14Folding, 4 * time.Minute},
		{"K", "source: key lists, folding, file access (G4)", false, nil, 5 * time.Minute},
	}
}

func main() {
	xray := flag.String("xray", "", "path of the xray binary")
	zipPath := flag.String("zip", "", "the release archive (E01 lists it)")
	src := flag.String("src", "", "directory of the xray-core module source at the same tag")
	extract := flag.String("extract", "", "extract the member xray of -zip to this path first")
	work := flag.String("work", "", "scratch directory (default: a new temp dir)")
	only := flag.String("only", "", "comma list of experiment ids")
	flag.Parse()
	if *xray == "" && *src == "" {
		fmt.Fprintln(os.Stderr, "xraycheck: -xray or -src is needed")
		os.Exit(2)
	}
	if *extract != "" {
		if err := extractMember(*zipPath, "xray", *extract); err != nil {
			fmt.Fprintln(os.Stderr, "xraycheck: "+err.Error())
			os.Exit(1)
		}
	}
	dir := *work
	if dir == "" {
		d, err := os.MkdirTemp("", "xraycheck")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		dir = d
	}
	abs, _ := filepath.Abs(dir)
	logf("xraycheck on %s/%s, go %s, work dir %s", runtime.GOOS, runtime.GOARCH, runtime.Version(), abs)
	want := map[string]bool{}
	for _, s := range strings.Split(*only, ",") {
		if s != "" {
			want[s] = true
		}
	}
	for _, e := range experiments() {
		if len(want) > 0 && !want[e.id] {
			continue
		}
		if e.id == "K" {
			if *src == "" {
				continue
			}
			guard(e, func() { analyzeSource(*src) })
			continue
		}
		if *xray == "" {
			continue
		}
		if e.linux && !onLinux {
			rep(e.id, "SKIP", "%s: needs Linux", e.title)
			continue
		}
		sub := filepath.Join(abs, e.id)
		_ = os.MkdirAll(sub, 0o755)
		c := &tctx{dir: sub, xray: mustAbs(*xray)}
		if e.id == "E01" {
			c.bin = *zipPath
		}
		logf("==== %s %s", e.id, e.title)
		guard(e, func() { e.run(c) })
		killAll()
	}
	summary()
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// guard runs one experiment with a recover and a watchdog that kills its children when it overruns, so one stuck socket
// cannot hold the job to its timeout.
func guard(e experiment, f func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				rep(e.id, "ERR", "panic: %v\n%s", r, oneLine(string(debug.Stack()), 600))
			}
		}()
		f()
	}()
	limit := e.limit
	if limit == 0 {
		limit = 5 * time.Minute
	}
	select {
	case <-done:
	case <-time.After(limit):
		rep(e.id, "ERR", "overran its %v and was abandoned", limit)
		killAll()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}
}

func summary() {
	resMu.Lock()
	defer resMu.Unlock()
	counts := map[string]int{}
	for _, r := range results {
		counts[r.status]++
	}
	var ks []string
	for k := range counts {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	fmt.Println()
	fmt.Println("=== SUMMARY (PASS: the spec holds; FAIL: the binary contradicts the spec; INFO: measured; ERR: not proved) ===")
	for _, r := range results {
		fmt.Printf("%-5s %-4s %s\n", r.id, r.status, oneLine(r.text, 400))
	}
	for _, k := range ks {
		fmt.Printf("%s=%d ", k, counts[k])
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------------------------------------------------

// e01Archive proves what the release is: the archive contents, the hash of the binary, the version string, how it is linked,
// and that the api commands the spec relies on exist.
func e01Archive(c *tctx) {
	if c.bin != "" {
		zr, err := zip.OpenReader(c.bin)
		if err != nil {
			rep("E01", "ERR", "cannot open the archive: %v", err)
		} else {
			var names []string
			for _, f := range zr.File {
				names = append(names, fmt.Sprintf("%s(%d)", f.Name, f.UncompressedSize64))
			}
			zr.Close()
			rep("E01", "INFO", "archive members: %s", strings.Join(names, " "))
		}
	}
	b, err := os.ReadFile(c.xray)
	if err != nil {
		rep("E01", "ERR", "cannot read the binary: %v", err)
		return
	}
	sum := sha256.Sum256(b)
	rep("E01", "INFO", "binary sha256 %s size %d", hex.EncodeToString(sum[:]), len(b))
	if f, err := elf.Open(c.xray); err == nil {
		libs, _ := f.ImportedLibraries()
		interp := false
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				interp = true
			}
		}
		rep("E01", "INFO", "elf machine %v, dynamic interpreter %v, imported libraries %v", f.Machine, interp, libs)
		f.Close()
	}
	v := runCmd(10*time.Second, "", c.xray, "version")
	rep("E01", "INFO", "xray version: %s", oneLine(v.out, 300))
	h := runCmd(10*time.Second, "", c.xray, "api")
	need := []string{"adi", "rmi", "ado", "rmo", "lsi", "lso", "adrules", "rmrules", "lsrules"}
	var missing []string
	for _, n := range need {
		if !strings.Contains(h.out, "\t"+n+" ") && !strings.Contains(h.out, "\n\t"+n) {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		rep("E01", "PASS", "xray api lists adi rmi ado rmo lsi lso adrules rmrules lsrules")
	} else {
		rep("E01", "FAIL", "xray api does not list %v: %s", missing, oneLine(h.out, 300))
	}
	r := runCmd(10*time.Second, "", c.xray, "help", "run")
	rep("E01", "INFO", "xray help run: %s", oneLine(r.out, 500))
}

var _ = io.EOF

// extractMember writes one member of the release archive to dest, executable. The archive is the one whose hash the caller
// has checked; the name is fixed and never taken from the archive, so a crafted member name cannot choose a path.
func extractMember(zipPath, member, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != member {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("the archive has no member %q", member)
}
