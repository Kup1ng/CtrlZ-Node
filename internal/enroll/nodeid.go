package enroll

import "encoding/hex"

// ParseNodeID decodes the node id a certificate's subject CN carries (p4-nodes 4.2
// step 6): 32 hexadecimal digits, or the same 16 bytes as a canonical dashed UUID
// (8-4-4-4-12). The hub's database keeps node ids as UUIDs and either text is a
// natural way to write one, so the node reads both and compares bytes, never text.
// Any other CN is not a node id.
func ParseNodeID(cn string) ([]byte, bool) {
	if len(cn) == 36 && cn[8] == '-' && cn[13] == '-' && cn[18] == '-' && cn[23] == '-' {
		cn = cn[:8] + cn[9:13] + cn[14:18] + cn[19:23] + cn[24:]
	}
	if len(cn) != 2*idLen {
		return nil, false
	}
	id, err := hex.DecodeString(cn)
	if err != nil || len(id) != idLen {
		return nil, false
	}
	return id, true
}
