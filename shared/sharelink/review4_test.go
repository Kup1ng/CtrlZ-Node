package sharelink

import (
	"strings"
	"testing"
)

// B1-r4-9: a padding gap of the VLESS encryption text is a sleep inside the handshake
// that nothing cancels, so the converter names the parameter instead of passing it on.
func TestVLESSEncryptionGapIsNamed(t *testing.T) {
	key := strings.Repeat("A", 43)
	link := func(enc string) string {
		return "vless://" + uuid + "@203.0.113.7:443?encryption=" + enc + "&type=tcp"
	}
	norm(t, link("none"))
	norm(t, link("mlkem768x25519plus.native.1rtt.100-35-35.1-3-10000."+key))
	_, _, _, err := Convert(link("mlkem768x25519plus.native.1rtt.100-35-35.1-3600000-86400000." + key))
	if err == nil {
		t.Fatal("a gap of a day is accepted")
	}
	if !strings.Contains(err.Error(), `"encryption"`) || strings.Contains(err.Error(), "86400000") {
		t.Errorf("the error does not name the parameter alone: %v", err)
	}
}
