package xrayschema

import (
	"strings"
	"testing"
	"time"
)

// A fragment built to cost the most the limits allow must still be judged in well under
// a second: nested "extra" objects each hold many keys, and the table builds a node
// for every level (it holds itself).
func TestWorstCaseFragmentIsJudgedQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"outbounds":[{"protocol":"vless","streamSettings":{"xhttpSettings":`)
	depth := 12
	for i := 0; i < depth; i++ {
		b.WriteString(`{"host":"h","path":"/p","mode":"auto","headers":{"a":"b"},"xmux":{"maxConcurrency":1},"extra":`)
	}
	b.WriteString(`{}`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}`)
	}
	b.WriteString(`}}]}`)
	if b.Len() > MaxFragmentBytes {
		t.Fatalf("fragment of %d bytes", b.Len())
	}
	start := time.Now()
	r := Newest().Check([]byte(b.String()), nil)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("took %v", d)
	}
	if len(r.Rejected) != 0 {
		t.Errorf("rejected: %v", r.Rejected)
	}
	// Many unknown keys in one object.
	var m strings.Builder
	m.WriteString(`{"outbounds":[{"protocol":"vless"`)
	for i := 0; i < 250; i++ {
		m.WriteString(`,"k` + strings.Repeat("x", i%50) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `":1`)
	}
	m.WriteString(`}]}`)
	start = time.Now()
	_ = Newest().Check([]byte(m.String()), nil)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("many keys took %v", d)
	}
}
