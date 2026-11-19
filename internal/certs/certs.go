// Package certs holds the node's certificates: the mTLS client certificate for
// the panel link and the serving certificates for DoT, DoH and DoQ. Private
// keys stay encrypted on disk so a reboot without the panel still works.
package certs
