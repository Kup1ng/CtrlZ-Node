package enroll

import (
	"strings"
	"testing"
)

func TestOSRelease(t *testing.T) {
	for in, want := range map[string]string{
		"NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n": "Ubuntu 24.04.1 LTS",
		"ID=debian\n":                    "unknown",
		"":                               "unknown",
		"PRETTY_NAME=\"Caf\xc3\xa9 OS\"": "Caf?? OS",
		"PRETTY_NAME=\"\x01\x02\"":       "??",
		"PRETTY_NAME=":                   "unknown",
		"PRETTY_NAME=" + strings.Repeat("a", 500): strings.Repeat("a", 128),
	} {
		got := OSRelease([]byte(in))
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
		if !printable(got, maxFreeText) {
			t.Errorf("%q: result is not printable ASCII", in)
		}
	}
}
