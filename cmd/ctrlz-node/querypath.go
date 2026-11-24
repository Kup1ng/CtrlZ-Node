package main

import (
	"github.com/Kup1ng/CtrlZ-Node/internal/dnsrole"
	"github.com/Kup1ng/CtrlZ-Node/internal/querypath"
)

// queryPath is the one place the dns role learns which query path to run: the
// query path of SC 5.2 joined to the cache and the resolve router (internal/
// querypath). The free path (W9) and the drain (W8) are seams in it that stay
// closed until those packages are built.
func queryPath() dnsrole.HandlerFactory { return querypath.Factory(querypath.Options{}) }
