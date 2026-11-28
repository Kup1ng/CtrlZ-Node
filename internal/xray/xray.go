// Package xray is the Xray manager of the node agent (p4b-proxy 7.4 to 7.7 and the
// node side of 6.4). It validates the fragments the panel sends against the allow
// list of the release the node runs (shared xrayschema), renders the slot files,
// applies ordinary changes through the API of the running slot, keeps the last good
// set and undoes a set that ends the process, rebuilds in the idle slot when a live
// change is not possible, switches slots on an upgrade, probes every config and
// reports the port map and the health of every location to dns.
//
// The manager is the one part that starts and stops the slots and the one that
// holds the credentials of the exits (it is a FragmentPart). It never runs the Xray
// binary itself: every `run -test` and `api` call goes through ctrlz-xrayctl
// (package xrayctl), whose answers it treats as untrusted text.
package xray
