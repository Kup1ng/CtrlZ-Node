// Command ctrlz-bundle is the release job's manifest builder (p4-nodes 7.1).
//
//	ctrlz-bundle build --out DIR --version N --min-version N --created T --expires T \
//	    --packaging packaging --node-bin PATH --verify-bin PATH --debs DIR [--tag S]
//
// It writes the bundle directory and <out>.manifest.unsigned.json, and stamps the
// SHA-256 of ctrlz-verify into node.sh. It signs nothing: the owner signs the
// manifest offline (3.3). A build with the ctrlz_lab tag also has `sign-lab`
// for dev and lab runs.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ctrlz-bundle build|sign-lab ...")
		return 2
	}
	switch args[0] {
	case "build":
		return build(args[1:])
	case "sign-lab":
		return signLab(args[1:])
	}
	fmt.Fprintln(os.Stderr, "ctrlz-bundle: unknown command")
	return 2
}

func build(args []string) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o bundle.Options
	fs.StringVar(&o.Out, "out", "", "")
	fs.Uint64Var(&o.Version, "version", 0, "")
	fs.Uint64Var(&o.MinVersion, "min-version", 0, "")
	fs.Int64Var(&o.CreatedAt, "created", 0, "")
	fs.Int64Var(&o.ExpiresAt, "expires", 0, "")
	fs.StringVar(&o.Tag, "tag", "", "")
	fs.StringVar(&o.Packaging, "packaging", "", "")
	fs.StringVar(&o.NodeBin, "node-bin", "", "")
	fs.StringVar(&o.VerifyBin, "verify-bin", "", "")
	fs.StringVar(&o.Debs, "debs", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || o.Packaging == "" || o.NodeBin == "" || o.VerifyBin == "" || o.Debs == "" {
		fmt.Fprintln(os.Stderr, "usage: ctrlz-bundle build --out DIR --version N --min-version N --created T --expires T --packaging DIR --node-bin FILE --verify-bin FILE --debs DIR [--tag S]")
		return 2
	}
	m, err := bundle.Build(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctrlz-bundle: %v\n", err)
		return 1
	}
	fmt.Printf("%d files, unsigned manifest %s\n", len(m.Files), bundle.UnsignedPath(o.Out))
	return 0
}
