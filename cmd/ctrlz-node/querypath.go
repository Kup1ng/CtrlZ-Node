package main

import (
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/querypath"
)

// queryPath is the one place the dns role learns which query path to run: the
// query path of SC 5.2 joined to the cache and the resolve router (internal/
// querypath). The free path (querypath.Options.Free, SC 5.2a) and the drain (the
// dns role follows drain_since) are wired: the free path answers only while the
// agent's facts say it is on and caught up, and refuses otherwise.
func queryPath() dnsrole.HandlerFactory { return querypath.Factory(querypath.Options{}) }
