package verify

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Node/internal/labroot"
)

// ExitAddr is an address argument that the agent would refuse.
const ExitAddr = 14

const usage = `usage: ctrlz-verify list  --root FILE --manifest FILE [--installed N] [--above] [--version N]
       ctrlz-verify sizes --root FILE --manifest FILE [--installed N] [--above] [--version N]
       ctrlz-verify check --root FILE --manifest FILE --dir DIR [--installed N] [--above] [--version N]
       ctrlz-verify addr ADDRESS...

list prints the file paths of a manifest that verifies, sizes the signed size and
path of each ("SIZE PATH"). check also checks every file of DIR against it.
addr exits 0 when every argument is an address agent.conf can hold.
Exit codes: 0 ok, 2 usage, 10 root, 11 manifest,
12 freshness or version, 13 files, 14 address.`

// Main is the command: ctrlz-verify <list|check> flags. It returns the exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "addr" {
		return addrMain(args[1:], stderr)
	}
	if len(args) == 0 || (args[0] != "list" && args[0] != "sizes" && args[0] != "check") {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o Options
	var dir string
	fs.StringVar(&o.RootPath, "root", "", "")
	fs.StringVar(&o.ManifestPath, "manifest", "", "")
	fs.StringVar(&dir, "dir", "", "")
	fs.Uint64Var(&o.Installed, "installed", 0, "")
	fs.BoolVar(&o.Above, "above", false, "")
	fs.Uint64Var(&o.WantVersion, "version", 0, "")
	// A clock override would defeat the expiry check for anything that can choose the
	// arguments, so a release build does not have the flag at all (labroot.Lab is a
	// constant: the branch is gone from it). Tests set Options.Now directly.
	if labroot.Lab {
		fs.Int64Var(&o.Now, "now", 0, "")
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || o.RootPath == "" || o.ManifestPath == "" || (args[0] == "check" && dir == "") {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	m, err := Manifest(o)
	if err == nil && args[0] == "check" {
		err = Dir(m, dir)
	}
	if err != nil {
		var f *Failure
		if errors.As(err, &f) {
			fmt.Fprintf(stderr, "ctrlz-verify: %s\n", f.Error())
			return f.Code
		}
		fmt.Fprintln(stderr, "ctrlz-verify: check failed")
		return ExitManifest
	}
	switch args[0] {
	case "list":
		for _, p := range List(m) {
			fmt.Fprintln(stdout, p)
		}
	case "sizes":
		for _, l := range Sizes(m) {
			fmt.Fprintf(stdout, "%d %s\n", l.Size, l.Path)
		}
	}
	return ExitOK
}

// addrMain checks the addresses node.sh and apply.sh are about to write into
// agent.conf. Their shell test looks at characters only, so "10.0.0.256", "1.2.3" and
// "0.0.0.0" pass it, the install reports success and the agent then refuses its own
// configuration on every start (p4n-W5c-r6-3). The rule is the agent's (conf.Read):
// it parses, and is neither unspecified nor multicast. A zone is refused too: the
// file has no use for one and the shell test never lets a "%" through. The message
// names no value, so a mistyped token pasted in the wrong place is not echoed.
func addrMain(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	for _, s := range args {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			fmt.Fprintln(stderr, "ctrlz-verify: an address is not one the node can run with")
			return ExitAddr
		}
	}
	return ExitOK
}
