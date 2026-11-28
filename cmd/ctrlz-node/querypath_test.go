package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// Production switches the proxy's Grants on: without this line dns writes none and
// serves no proxy.sock, and every other test still passes.
func TestProductionWiresTheProxyGrants(t *testing.T) {
	if queryPathOptions().Proxy == nil {
		t.Fatal("the query path is built with no proxy options")
	}
}

// grants-stats reads the counters over proxy.sock and prints them sorted, with no
// value but a number.
func TestGrantsStatsPrintsTheCounters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path")
	}
	path := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if m, err := sock.LinkCodec.Read(c); err == nil && m.Type == sock.TLinkStats {
			_ = sock.LinkCodec.Write(c, &sock.LinkMsg{Type: sock.TLinkStatsRes, StatsRes: &sock.LinkStatsRes{
				Counters: []sock.Counter{{Name: "puts_ok", Value: 7}, {Name: "a64500_exact", Value: 2}}, LastRefused: "collision"}})
		}
	}()
	var out, errw bytes.Buffer
	if code := grantsStats(&out, &errw, path); code != 0 {
		t.Fatalf("%d %s", code, errw.String())
	}
	if got := out.String(); got != "a64500_exact 2\nputs_ok 7\nlast_refused collision\n" {
		t.Fatalf("%q", got)
	}
	if code := grantsStats(&out, &errw, filepath.Join(t.TempDir(), "none")); code != 1 || !strings.Contains(errw.String(), "not serving") {
		t.Fatalf("a missing socket: %d %q", code, errw.String())
	}
	_ = os.Remove(path)
}
