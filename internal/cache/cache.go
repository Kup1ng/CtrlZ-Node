// Package cache is the shared answer cache. It holds only true answers that
// passed the Sanity Gate, keyed by (qname, qtype, class, effective CD, ECS
// range, route) (contract section 6). A synthesized Block or Redirect answer is
// never stored here, so one tenant's policy cannot reach another through it.
package cache

// Key is the cache key. It has no tenant field on purpose.
type Key struct {
	QName       string
	QType       uint16
	Class       uint16
	EffectiveCD bool
	ECS         string
	Route       string
}
