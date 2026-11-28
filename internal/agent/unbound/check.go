package unbound

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/nets"
)

// VersionFloor is the lowest upstream Unbound version the agent starts. SC 5.2a
// defines the floor as the first release with the fixes for NXNSAttack (1.10.1),
// NRDelegation (1.16.3), KeyTrap (1.19.1) and DNSBomb, CVE-2024-33655 (1.20.0), as
// NLnet Labs' security advisories list them (checked for W5b round 2); 1.20.0 is
// the last of the four. It is a floor, not a pin: later advisories raise it, and
// Plan.md records the value.
const VersionFloor = "1.20.0"

// Ubuntu 24.04 ships Unbound 1.19.2, which carries the first three fixes upstream
// and the DNSBomb fix as a distribution patch from package revision
// 1.19.2-1ubuntu3.1 (Ubuntu's CVE-2024-33655 page). `unbound -V` cannot show the
// revision, so that one build is accepted only when dpkg says the installed package
// is at least that revision.
const (
	DistroBase  = "1.19.2"
	DistroFloor = "1.19.2-1ubuntu3.1"
	// Package is the dpkg package of the unbound binary.
	Package = "unbound"
)

// ErrBelowFloor is returned for an Unbound older than VersionFloor.
var ErrBelowFloor = errors.New("unbound: version below the floor")

// ParseVersion reads the version out of `unbound -V` output ("Version 1.19.2").
func ParseVersion(out []byte) (string, error) {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "Version "); ok {
			v = strings.TrimSpace(v)
			if _, err := versionParts(v); err == nil {
				return v, nil
			}
		}
	}
	return "", errors.New("unbound: no version in the output of unbound -V")
}

func versionParts(v string) ([3]int, error) {
	var out [3]int
	core, _, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, errors.New("bad version")
	}
	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return out, errors.New("bad version")
		}
		out[i] = n
	}
	return out, nil
}

// AtLeast reports whether version v is at or above floor. A version that does
// not parse is below every floor.
func AtLeast(v, floor string) bool {
	a, err := versionParts(v)
	if err != nil {
		return false
	}
	b, err := versionParts(floor)
	if err != nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// CheckVersion refuses a version under the floor.
func CheckVersion(v string) error {
	if !AtLeast(v, VersionFloor) {
		return fmt.Errorf("%w: have %s, floor %s", ErrBelowFloor, v, VersionFloor)
	}
	return nil
}

// settings reduces a config file to its settings as "key: value" strings,
// dropping comments and blank lines and section headers. Order does not matter
// to Unbound for the keys used here, so the comparison is on the sorted set.
func settings(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasSuffix(line, ":") && !strings.Contains(line, " ") {
			continue
		}
		key, val, _ := strings.Cut(line, ":")
		out = append(out, strings.TrimSpace(key)+": "+strings.Join(strings.Fields(val), " "))
	}
	sort.Strings(out)
	return out
}

// ErrPinned is returned when a file differs from what the template gives.
var ErrPinned = errors.New("unbound: a pinned setting differs from the template")

// Verify checks a configuration file that already exists against what the
// agent would write for p. Every setting must match the template, with two
// exceptions that are the agent's to change: the do-not-query-address list (it
// follows the applied PairTable) may differ as long as it still holds every
// non-public range, and nothing may be included from elsewhere. The agent
// refuses to start the process on any other difference (T-559): a fixed limit
// that an operator or a package upgrade changed is not a limit.
func Verify(conf string, p Params) error {
	want, err := Render(p)
	if err != nil {
		return err
	}
	var gotS, wantS []string
	var dnq []netip.Prefix
	for _, s := range settings(conf) {
		switch {
		case strings.HasPrefix(s, "include"):
			return fmt.Errorf("%w: include", ErrPinned)
		case strings.HasPrefix(s, "do-not-query-address: "):
			if pf, err := netip.ParsePrefix(strings.TrimPrefix(s, "do-not-query-address: ")); err == nil {
				dnq = append(dnq, pf)
			}
		default:
			gotS = append(gotS, s)
		}
	}
	for _, s := range settings(want) {
		if !strings.HasPrefix(s, "do-not-query-address: ") {
			wantS = append(wantS, s)
		}
	}
	if len(gotS) != len(wantS) {
		return ErrPinned
	}
	for i := range gotS {
		if gotS[i] != wantS[i] {
			// Name the key, never the value: it may be an address.
			key, _, _ := strings.Cut(wantS[i], ":")
			return fmt.Errorf("%w: %s", ErrPinned, key)
		}
	}
	// settings() sorts, but Unbound reads the outgoing-port lines in file order (an
	// avoid after a permit would take the range away again), so their order is part
	// of what is pinned.
	if !equalStrings(portLines(conf), portLines(want)) {
		return fmt.Errorf("%w: outgoing-port order", ErrPinned)
	}
	for _, need := range nets.NonPublic() {
		if !nets.Contains(dnq, need.Addr()) || !coversPrefix(dnq, need) {
			return fmt.Errorf("%w: do-not-query-address misses a non-public range", ErrPinned)
		}
	}
	return nil
}

func coversPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, q := range list {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// ErrRanges is returned when the outgoing port ranges overlap each other or the
// host's ephemeral range.
var ErrRanges = errors.New("unbound: outgoing port ranges overlap")

// ParseEphemeral reads the content of /proc/sys/net/ipv4/ip_local_port_range.
func ParseEphemeral(b []byte) (lo, hi int, err error) {
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, 0, errors.New("unbound: bad ip_local_port_range")
	}
	if lo, err = strconv.Atoi(f[0]); err != nil {
		return 0, 0, errors.New("unbound: bad ip_local_port_range")
	}
	if hi, err = strconv.Atoi(f[1]); err != nil {
		return 0, 0, errors.New("unbound: bad ip_local_port_range")
	}
	return lo, hi, nil
}

// CheckRanges refuses to let the free Unbound start when its outgoing port
// range overlaps the identified Unbound's range or the host's ephemeral range:
// the notrack rule accepts replies to the free range without state, and it must
// reach no other socket (SC 5.2a, Connection tracking).
func CheckRanges(free, identified Params, ephLo, ephHi int) error {
	overlap := func(aLo, aHi, bLo, bHi int) bool { return aLo <= bHi && bLo <= aHi }
	if overlap(free.PortLo, free.PortHi, identified.PortLo, identified.PortHi) ||
		overlap(free.PortLo, free.PortHi, ephLo, ephHi) {
		return ErrRanges
	}
	return nil
}

// portLines is the outgoing-port-avoid and -permit lines of a configuration in
// file order.
func portLines(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "outgoing-port-") {
			key, val, _ := strings.Cut(line, ":")
			out = append(out, strings.TrimSpace(key)+": "+strings.Join(strings.Fields(val), " "))
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
