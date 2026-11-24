// Package xray manages the Xray process: it validates the fragments the panel
// sends against the versioned allow-list (shared xrayschema, once it exists),
// runs `xray run -test` before applying, applies ordinary changes through the
// live API, keeps the last good configuration, and reports per-location health.
package xray
