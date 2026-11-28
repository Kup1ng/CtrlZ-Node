package main

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/link"
	"github.com/Kup1ng/CtrlZ-Node/internal/querypath"
)

// queryPath is the one place the dns role learns which query path to run: the
// query path of SC 5.2 joined to the cache and the resolve router (internal/
// querypath). The free path (querypath.Options.Free, SC 5.2a) and the drain (the
// dns role follows drain_since) are wired: the free path answers only while the
// agent's facts say it is on and caught up, and refuses otherwise. The proxy's
// Grants and proxy.sock (P4b B3) are wired by queryPathOptions.
func queryPath() dnsrole.HandlerFactory { return querypath.Factory(queryPathOptions()) }

// queryPathOptions is what production gives the join. A test reads it, because a merge
// that drops the Proxy line leaves dns with no Grants and no proxy.sock, and builds and
// passes every test of those parts alone.
func queryPathOptions() querypath.Options {
	return querypath.Options{Proxy: &querypath.ProxyOptions{}}
}

// grantsStats prints the counters of dns (4.3), one `name value` a line, sorted. It
// runs as root: the socket lets a peer of uid 0 send `stats` and nothing else.
func grantsStats(out, errw io.Writer, path string) int {
	res, err := link.FetchStats(path, 5*time.Second)
	if err != nil {
		fmt.Fprintf(errw, "ctrlz-node grants-stats: %v\n", err)
		return 1
	}
	sort.Slice(res.Counters, func(i, j int) bool { return res.Counters[i].Name < res.Counters[j].Name })
	for _, c := range res.Counters {
		fmt.Fprintf(out, "%s %d\n", c.Name, c.Value)
	}
	if res.LastRefused != "" {
		fmt.Fprintf(out, "last_refused %s\n", res.LastRefused)
	}
	return 0
}
