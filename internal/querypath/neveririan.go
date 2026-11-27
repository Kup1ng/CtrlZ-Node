package querypath

import "github.com/Kup1ng/CtrlZ-Shared/names"

// NeverIranian is the interim predicate of D42 (T-524) the node uses until P2's
// noredirect.Name (the full Iranian list over the catalog rows) can be passed in
// Options.NeverProxied: a name under the .ir top-level domain or its IDN form is
// never proxied, whatever a rule says. It is a subset of the real list, so it can
// only err toward proxying fewer names, never more. The proxy is idle in P4, so no
// Redirect reaches a location anyway; the predicate also decides which Redirects to
// an address act as Bypass.
func NeverIranian(n names.Name) bool {
	if n.Labels() == 0 {
		return false
	}
	switch string(n.Label(n.Labels() - 1)) {
	case "ir", "xn--mgba3a4f16a":
		return true
	}
	return false
}
