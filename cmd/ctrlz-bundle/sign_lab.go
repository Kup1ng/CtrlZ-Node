//go:build ctrlz_lab

package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Kup1ng/CtrlZ-Node/internal/bundle"
)

// signLab signs manifest.unsigned.json with seed files (the lab test root's keys
// under internal/labroot/testdata) and writes manifest.json beside it.
//
//	ctrlz-bundle sign-lab --dir BUNDLE --seed FILE --seed FILE
func signLab(args []string) int {
	fs := flag.NewFlagSet("sign-lab", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dir string
	var seeds multi
	fs.StringVar(&dir, "dir", "", "")
	fs.Var(&seeds, "seed", "")
	if err := fs.Parse(args); err != nil || dir == "" || len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ctrlz-bundle sign-lab --dir BUNDLE --seed FILE [--seed FILE]")
		return 2
	}
	doc, err := bundle.ReadEnvelope(bundle.UnsignedPath(dir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctrlz-bundle: %v\n", err)
		return 1
	}
	var keys []ed25519.PrivateKey
	for _, s := range seeds {
		k, err := bundle.ReadSeed(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctrlz-bundle: %v\n", err)
			return 1
		}
		keys = append(keys, k)
	}
	bundle.Sign(doc, keys...)
	raw, err := bundle.MarshalEnvelope(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctrlz-bundle: %v\n", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(dir, bundle.ManifestFile), raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "ctrlz-bundle: %v\n", err)
		return 1
	}
	return 0
}

type multi []string

func (m *multi) String() string     { return "" }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }
