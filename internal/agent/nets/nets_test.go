package nets

import (
	"math/rand"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// TestMatchesNetclassIPv4 sweeps IPv4 at /22 granularity (the
// smallest prefix netclass has) and checks every block, plus the boundaries of
// every listed prefix, against netclass.ClassOf. Any difference is a range that
// Unbound would accept and the Sanity Gate refuses, or the other way round.
func TestMatchesNetclassIPv4(t *testing.T) {
	list := NonPublic()
	var bad atomic.Int64
	check := func(a netip.Addr) {
		want := netclass.ClassOf(a) != netclass.Public
		if got := Contains(list, a); got != want {
			if bad.Add(1) <= 5 {
				t.Errorf("%s: list says %v, netclass says non-public=%v", a, got, want)
			}
		}
	}
	for _, p := range v4() {
		first := p.Masked().Addr()
		a4 := first.As4()
		last := a4
		for i := 0; i < 4; i++ {
			if p.Bits() <= i*8 {
				last[i] = 0xff
			} else if p.Bits() < (i+1)*8 {
				last[i] |= byte(0xff >> (p.Bits() - i*8))
			}
		}
		lastA := netip.AddrFrom4(last)
		check(first)
		check(lastA)
		if first.Prev().IsValid() {
			check(first.Prev())
		}
		if lastA.Next().IsValid() {
			check(lastA.Next())
		}
	}
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	// One address in every /22 keeps the run near 10 s. The full sweep (two
	// addresses in each of the 16.7 million /24 blocks) was run once by hand and
	// passed in 84 s; set step to 1 to repeat it.
	const step = 4
	const blocks = 1 << 24
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for b := w * step; b < blocks; b += workers * step {
				check(netip.AddrFrom4([4]byte{byte(b >> 16), byte(b >> 8), byte(b), 0x80}))
			}
		}(w)
	}
	wg.Wait()
}

func TestMatchesNetclassIPv6(t *testing.T) {
	list := NonPublic()
	rng := rand.New(rand.NewSource(7))
	teredo := netip.MustParsePrefix("2001::/32")
	for i := 0; i < 200000; i++ {
		var b [16]byte
		rng.Read(b[:])
		// Bias toward the forms that matter: pick a base and keep its fixed bits.
		switch i % 6 {
		case 0: // random
		case 1: // mapped
			copy(b[:12], netip.MustParseAddr("::ffff:0:0").AsSlice()[:12])
		case 2: // compat
			copy(b[:12], make([]byte, 12))
		case 3: // nat64
			copy(b[:12], netip.MustParseAddr("64:ff9b::").AsSlice()[:12])
		case 4: // 6to4
			b[0], b[1] = 0x20, 0x02
		case 5: // teredo
			b[0], b[1], b[2], b[3] = 0x20, 0x01, 0, 0
		}
		if i%3 == 0 { // make the embedded IPv4 part land in a listed range often
			ranges := v4()
			p := ranges[rng.Intn(len(ranges))]
			a4 := p.Addr().As4()
			off := 12
			switch i % 6 {
			case 4:
				off = 2
			case 5:
				off = 4
			}
			copy(b[off:off+4], a4[:])
		}
		a := netip.AddrFrom16(b)
		want := netclass.ClassOf(a) != netclass.Public
		got := Contains(list, a)
		switch {
		case want && !got:
			t.Fatalf("%s is non-public for netclass and not in the list", a)
		case got && !want && !teredo.Contains(a):
			t.Fatalf("%s is in the list and public for netclass, outside the Teredo superset", a)
		}
	}
}

func TestTeredoClientFormCovered(t *testing.T) {
	// 2001:0:<server>:<flags>:<port>:<~client>: client 10.0.0.1 inverted is f5ff:fffe
	a := netip.MustParseAddr("2001:0:4136:e378:8000:63bf:f5ff:fffe")
	if netclass.ClassOf(a) == netclass.Public {
		t.Fatal("netclass should call a Teredo address with a private client non-public")
	}
	if !Contains(NonPublic(), a) {
		t.Fatal("Teredo with a private client is not covered")
	}
}

func TestForAddrCoversEmbeddings(t *testing.T) {
	a := netip.MustParseAddr("203.0.114.9")
	l := ForAddr(a)
	for _, s := range []string{"203.0.114.9", "::ffff:203.0.114.9", "::203.0.114.9", "64:ff9b::203.0.114.9", "2002:cb00:7209::1", "2001:0:cb00:7209::5"} {
		if !Contains(l, netip.MustParseAddr(s)) {
			t.Errorf("%s not covered", s)
		}
	}
	if Contains(l, netip.MustParseAddr("203.0.114.10")) {
		t.Error("covers a neighbour")
	}
}

func TestListIsMinimalAndStable(t *testing.T) {
	a, b := NonPublic(), NonPublic()
	if len(a) != len(b) {
		t.Fatal("not deterministic")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("not deterministic")
		}
	}
	for i, p := range a {
		for j, q := range a {
			if i != j && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				t.Fatalf("%s is inside %s", p, q)
			}
		}
	}
}
