package verify

import (
	"bytes"
	"strings"
	"testing"
)

// The shell test of node.sh and apply.sh passes every string of hex digits, dots and
// colons that has a dot or a colon; this is the check that matches what the agent
// will accept (p4n-W5c-r6-3).
func TestAddrAcceptsOnlyWhatTheAgentAccepts(t *testing.T) {
	good := []string{"10.0.0.1", "192.168.1.200", "2001:db8::1", "::1", "127.0.0.1", "fd00::5", "::ffff:10.0.0.1"}
	bad := []string{"10.0.0.256", "1.2.3", "0.0.0.0", "::", "1..2", "256.1.1.1", "ab.cd", "224.0.0.1", "ff02::1",
		"1.2.3.4.5", "01.2.3.4", "fe80::1%eth0", ":", ".", "1:2", "", "a:b:c:d:e:f:1:2:3"}
	for _, a := range good {
		var e bytes.Buffer
		if code := Main([]string{"addr", a}, nil, &e); code != ExitOK {
			t.Errorf("%q refused: %d %s", a, code, e.String())
		}
	}
	for _, a := range bad {
		var e bytes.Buffer
		code := Main([]string{"addr", a}, nil, &e)
		if code != ExitAddr {
			t.Errorf("%q accepted or wrong code: %d", a, code)
		}
		if len(a) > 3 && strings.Contains(e.String(), a) {
			t.Errorf("the message echoes the value: %q", e.String())
		}
	}
	// One bad value among good ones refuses the lot; no argument is a usage error.
	var e bytes.Buffer
	if code := Main([]string{"addr", "10.0.0.1", "0.0.0.0"}, nil, &e); code != ExitAddr {
		t.Errorf("mixed: %d", code)
	}
	if code := Main([]string{"addr"}, nil, &e); code != ExitUsage {
		t.Errorf("no argument: %d", code)
	}
}
