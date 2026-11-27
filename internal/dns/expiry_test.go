package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const (
	epExp byte = 11 // a rule that expires at lapseAt
	epLap byte = 12 // a profile disabled until lapseAt

	// lapseAt is the expires_at and the disabled_until of the two profiles, in
	// the node clock's own time.
	lapseAt = 1_800_001_000
)

// expiryWorld has an Endpoint whose only Block rule expires at lapseAt (Default
// Bypass) and one whose profile is disabled until lapseAt (Default Block). The
// image is built once and never replaced: the panel is cut for the whole test, so
// every change of answer below is the node's clock alone (T-035, spec 11.3).
func expiryWorld(t *testing.T) *world {
	t.Helper()
	w := newWorldTuned(t, func(in *image.Input, put func(string, []byte, [32]byte)) {
		pat, err := rules.Parse("www.example.com")
		if err != nil {
			t.Fatal(err)
		}
		d, h := mkSpec(t, &blob.Spec{Default: blob.ActBypass,
			Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: pat, Action: blob.ActBlock, ExpiresAt: lapseAt}}})
		put("exp", d, h)
		addEndpoint(in, record(epExp, h))
		d, h = mkSpec(t, &blob.Spec{Default: blob.ActBlock, DisabledUntil: lapseAt})
		put("lap", d, h)
		addEndpoint(in, record(epLap, h))
	})
	w.setNow(time.Unix(lapseAt-60, 0))
	return w
}

func mkSpec(t testing.TB, s *blob.Spec) ([]byte, [32]byte) {
	t.Helper()
	d, err := blob.Build(s)
	if err != nil {
		t.Fatal(err)
	}
	return d, storetest.Hash(d)
}

// A rule lapses at expires_at and a Disable lapses at disabled_until on the node's
// clock, through every transport, with no push and no new image after the first
// (T-035). Mutants: a handler that stamps the query with the image's build time or
// leaves Now at zero (handler.go, `Now: now.Unix()`) keeps the rule alive and the
// Disable on for good, which fails the "at the instant" and "three hours" steps; one
// that took the clock once at SetImage does the same.
func TestExpiryAndDisableLapseOnTheNodeClockOnEveryTransport(t *testing.T) {
	askers := append(allAskers(), asker{"udp", listen.UDP, func(w *world, ep byte, name string, qt uint16) listen.Reply {
		return w.call(qopt{t: listen.UDP, src: "127.0.0." + itoa(int(ep)), validated: vptr(true)}, name, qt)
	}})
	steps := []struct {
		name string
		at   int64
		exp  string // www.example.com for the Endpoint with the expiring rule
		lap  string // and for the one with the Disable
	}{
		{"before", lapseAt - 60, "0.0.0.0", "192.0.2.20"},
		{"one second before", lapseAt - 1, "0.0.0.0", "192.0.2.20"},
		{"at the instant", lapseAt, "192.0.2.20", "0.0.0.0"},
		{"three hours later", lapseAt + 3*3600, "192.0.2.20", "0.0.0.0"},
	}
	for _, a := range askers {
		t.Run(a.name, func(t *testing.T) {
			w := expiryWorld(t)
			for _, s := range steps {
				w.setNow(time.Unix(s.at, 0))
				wantA(t, s.name+": expiring rule", a.ask(w, epExp, "www.example.com", dns.TypeA), s.exp)
				wantA(t, s.name+": disable", a.ask(w, epLap, "www.example.com", dns.TypeA), s.lap)
			}
		})
	}
}
