// Package resolve routes a cache miss to Unbound or to configured upstreams
// (recursive, upstream or hybrid mode), applies the Sanity Gate before a
// result reaches the cache, and tracks upstream health. Rule matching is the
// shared route package; failover and health checks are here.
package resolve

import "github.com/Kup1ng/CtrlZ-Shared/route"

// Router holds the ordered hybrid rules from NodeConfig.
type Router struct {
	Rules []route.Rule
}
