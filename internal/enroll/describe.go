package enroll

import (
	"bufio"
	"bytes"
	"strings"
)

// OSRelease turns the content of /etc/os-release into the os_release field of
// Enroll: the PRETTY_NAME, as printable ASCII of at most 128 characters (3.2 item 3
// holds the hub to that grammar). Anything else a file might carry is replaced, so a
// strange file can never make Enroll fail its format check, and the admin still sees
// what the host says it is.
func OSRelease(content []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		var b strings.Builder
		for i := 0; i < len(v) && b.Len() < maxFreeText; i++ {
			if v[i] < 0x20 || v[i] > 0x7e {
				b.WriteByte('?')
			} else {
				b.WriteByte(v[i])
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	return "unknown"
}
