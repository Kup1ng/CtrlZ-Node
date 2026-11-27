package sock

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

// Field checks shared by the validators of the P4b sockets. Each returns an error
// that names the field and never its value: a value may be a source address or a
// name, and nothing here may put one in a log (the rule of 5.2 step 7).

// one reports which of the fields of an envelope is set. A frame must set exactly
// the field that its type names (an unknown type matches none), so a peer cannot
// smuggle a second message in the first's frame. have lists the (type, set) pairs
// in the order of the struct; check is called with the one that matched.
type field struct {
	name string
	set  bool
	chk  func() error
}

func one(typ string, fields ...field) error {
	var found *field
	n := 0
	for i := range fields {
		if fields[i].set {
			n++
			found = &fields[i]
		}
	}
	if typ == "" {
		return errors.New("sock: frame without a type")
	}
	if n != 1 || found.name != typ {
		return fmt.Errorf("sock: type %q does not match the fields set", clip(typ))
	}
	return found.chk()
}

// clip bounds an attacker-chosen type name before it goes into an error.
func clip(s string) string {
	if len(s) > 24 {
		return s[:24]
	}
	return s
}

func lenIs(name string, b []byte, ns ...int) error {
	for _, n := range ns {
		if len(b) == n {
			return nil
		}
	}
	return fmt.Errorf("sock: %s has the wrong length", name)
}

func lenMax(name string, n, max int) error {
	if n > max {
		return fmt.Errorf("sock: %s over its cap", name)
	}
	return nil
}

// ipPort checks the form ip:port of an address that names a local socket of the
// node (a SOCKS inbound, the bind address). Hostnames are refused: nothing here
// may cause a lookup.
func ipPort(name, s string) error {
	// A zone ("fe80::1%text") is refused: the text is peer-chosen and as long as the
	// frame, and an interface-scoped address is not a thing 2.1 allows anywhere.
	if a, err := netip.ParseAddrPort(s); err != nil || a.Addr().Zone() != "" {
		return fmt.Errorf("sock: %s is not ip:port", name)
	}
	return nil
}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)

// hostOrIP checks a dial host of a verdict target: a name in the normal lower-case
// form of `names`, or an IP literal.
func hostOrIP(name, s string) error {
	if s == "" || len(s) > 253 {
		return fmt.Errorf("sock: %s is empty or too long", name)
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return fmt.Errorf("sock: %s carries an IPv6 zone", name)
		}
		return nil
	}
	if !hostRE.MatchString(s) {
		return fmt.Errorf("sock: %s is not a host name", name)
	}
	return nil
}

// srcIP checks a client source: 4 or 16 raw bytes.
func srcIP(name string, b []byte) error { return lenIs(name, b, 4, 16) }

var reasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func reasonName(name, s string) error {
	if !reasonRE.MatchString(s) {
		return fmt.Errorf("sock: %s is not a counter name", name)
	}
	return nil
}

// ipOnly checks a bare IP address (the proxy bind address).
func ipOnly(name, s string) error {
	if a, err := netip.ParseAddr(s); err != nil || a.Zone() != "" {
		return fmt.Errorf("sock: %s is not an IP address", name)
	}
	return nil
}

// wireName checks the wire form of a lookup name: length-prefixed labels of 1 to
// 63 bytes, ended by the zero label, at most 255 bytes, in the lower-case form
// `names` makes (a to z, 0 to 9, hyphen, underscore). The proxy parses hostile
// ClientHellos, so dns must not take on trust that a name it is handed was
// normalised: a label that runs past the end, or a byte outside the set, is a bug
// or an attack, and either way the frame ends the connection.
func wireName(b []byte) error {
	if len(b) < 2 || len(b) > MaxNameWire {
		return errors.New("sock: lookup name has the wrong length")
	}
	i := 0
	for {
		if i >= len(b) {
			return errors.New("sock: lookup name is not rooted")
		}
		l := int(b[i])
		if l == 0 {
			if i != len(b)-1 || i == 0 {
				return errors.New("sock: lookup name has bytes after its root or no label")
			}
			return nil
		}
		if l > 63 || i+1+l >= len(b) {
			return errors.New("sock: lookup name has a bad label")
		}
		for _, c := range b[i+1 : i+1+l] {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return errors.New("sock: lookup name has a byte outside its form")
			}
		}
		i += 1 + l
	}
}
