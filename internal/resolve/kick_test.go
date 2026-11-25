package resolve

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	"github.com/Kup1ng/CtrlZ-Shared/route"
)

// Tests of p4n-W7-r9-2: traffic must not sample checks at round-trip rate, one
// lost probe must not make a healthy member dark, a dark member comes back within
// seconds, and a member that answers is never dark.

// lossyFake stalls live names under .y.test (a tenant's names that no server
// answers), answers every other live name, and fails every second check, so no
// two checks in a row ever fail: the loss pattern of a real path with a lost
// packet now and then, made worse.
type lossyFake struct {
	name   string
	probes atomic.Int64
	// failProbes makes every check fail, for the dark and recheck test.
	failProbes atomic.Bool
	liveDown   atomic.Bool
}

func (f *lossyFake) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	qn := req.Question[0].Name
	if len(strings.SplitN(qn, ".", 2)[0]) == 32 {
		n := f.probes.Add(1)
		if f.failProbes.Load() || n%2 == 0 {
			return nil, errors.New("lost")
		}
	} else if strings.HasSuffix(qn, ".y.test.") || f.liveDown.Load() {
		if f.liveDown.Load() {
			return nil, errors.New("down")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: qn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{f.name}})
	return m, nil
}

func TestTenantTimeoutsCannotSampleChecksAtProbeRate(t *testing.T) {
	rule, err := route.ParseRule(10, "suffix", "test", "g", false)
	if err != nil {
		t.Fatal(err)
	}
	u1, local := &lossyFake{name: "u1"}, &lossyFake{name: "local"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
		Local:     Member{X: local, Every: 3600 * time.Second},
		Upstreams: []Member{{ID: id(1), X: u1, Every: 3600 * time.Second}},
		Groups:    map[string][][16]byte{"g": {id(1)}}, Rules: []route.Rule{rule}})
	waitFor(t, func() bool { return u1.probes.Load() >= 1 }, "the first check")
	base := u1.probes.Load()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				q := new(dns.Msg)
				q.SetQuestion("n"+string(rune('a'+w))+string(rune('a'+i%26))+".y.test.", dns.TypeA)
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
				_, _, _ = r.Exchange(ctx, q)
				cancel()
			}
		}(w)
	}
	start := time.Now()
	for time.Since(start) < 700*time.Millisecond {
		if !r.ups[0].preferred() {
			t.Fatal("a tenant's timing-out names made a healthy member dark")
		}
		time.Sleep(3 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	elapsed := time.Since(start)
	// one check at most per kickGap, each of at most two probes
	maxChecks := int64(elapsed/r.kickGap) + 2
	if got := u1.probes.Load() - base; got > 2*maxChecks {
		t.Fatalf("%d probes in %v with a kick gap of %v", got, elapsed, r.kickGap)
	}
	if got := who(t, r, "x.test", dns.TypeA); got != "u1" {
		t.Fatalf("x.test answered by %s", got)
	}
}

func TestDarkMemberIsRecheckedWithinSeconds(t *testing.T) {
	rule, err := route.ParseRule(10, "suffix", "test", "g", false)
	if err != nil {
		t.Fatal(err)
	}
	u1, local := &lossyFake{name: "u1"}, &lossyFake{name: "local"}
	r := newTestRouter(t, RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
		Local:     Member{X: local, Every: 3600 * time.Second},
		Upstreams: []Member{{ID: id(1), X: u1, Every: 3600 * time.Second}},
		Groups:    map[string][][16]byte{"g": {id(1)}}, Rules: []route.Rule{rule}})
	waitFor(t, func() bool { return u1.probes.Load() >= 1 }, "the first check")
	u1.liveDown.Store(true)
	u1.failProbes.Store(true)
	// u1 fails and local answers; errors go on, because a kick inside kickGap of
	// the last check is dropped and the next error asks again
	waitFor(t, func() bool { who(t, r, "x.test", dns.TypeA); return !r.ups[0].preferred() }, "two failed checks to make the member dark")
	// the path recovers; its next scheduled check is an hour away
	u1.liveDown.Store(false)
	u1.failProbes.Store(false)
	var passed bool
	waitFor(t, func() bool { passed = r.ups[0].preferred(); return passed }, "the recheck of the dark member")
	if got := who(t, r, "x.test", dns.TypeA); got != "u1" {
		t.Fatalf("x.test answered by %s after recovery", got)
	}
}

// A member that answered while the check was out is not dark, whatever the check
// said, and a reply that races the verdict undoes it.
func TestMemberThatAnsweredIsNeverLeftDark(t *testing.T) {
	m := newMember(Member{X: &lossyFake{}})
	m.liveFails.Store(failsToDown)
	seen := m.replies.Load()
	m.replies.Add(1) // a live reply while the check was out
	m.order(false, seen)
	if m.dark.Load() {
		t.Fatal("a member that answered went dark")
	}
	m.liveFails.Store(failsToDown)
	m.order(false, m.replies.Load())
	if !m.dark.Load() {
		t.Fatal("a suspect member whose check failed with no reply did not go dark")
	}
	m.order(true, m.replies.Load())
	if m.dark.Load() || m.liveFails.Load() != 0 {
		t.Fatal("a passed check did not clear suspicion")
	}
}

// p4n-W7-r10-1: a scheduled check that has just ended must not delay the first
// kick. With the real gap of 5 s, a member whose first scheduled check ended and
// that then fails three live errors goes dark within the two probes of the
// confirming check, not after kickGap.
func TestScheduledCheckDoesNotDelayTheFirstKick(t *testing.T) {
	rule, err := route.ParseRule(10, "suffix", "test", "g", false)
	if err != nil {
		t.Fatal(err)
	}
	u1, local := &lossyFake{name: "u1"}, &lossyFake{name: "local"}
	r, err := NewRouter(RouterConfig{Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID, IntervalUnit: time.Second,
		Local:     Member{X: local, Every: 3600 * time.Second},
		Upstreams: []Member{{ID: id(1), X: u1, Every: 3600 * time.Second}},
		Groups:    map[string][][16]byte{"g": {id(1)}}, Rules: []route.Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if r.kickGap < 5*time.Second {
		t.Fatalf("kick gap %v", r.kickGap)
	}
	waitFor(t, func() bool { return u1.probes.Load() >= 1 }, "the first scheduled check")
	time.Sleep(50 * time.Millisecond) // let the scheduled check end
	u1.liveDown.Store(true)
	u1.failProbes.Store(true)
	start := time.Now()
	for r.ups[0].preferred() {
		who(t, r, "x.test", dns.TypeA)
		if time.Since(start) > 2*time.Second {
			t.Fatalf("member still preferred %v after its first errors; the kick waited for kickGap", time.Since(start))
		}
		time.Sleep(5 * time.Millisecond)
	}
}
