package agent_test

import (
	"testing"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

// p4n-W5b-r7-1: the agent holds expiries in hub time, so what it persists, reloads
// and tells dns about must not depend on the node clock being right.

// A node whose clock moved forward by more than a revocation's lifetime restarts
// while the hub is silent: the revocation is still in force, and once the first
// ServerTime arrives its expiry is in hub time again.
func TestRevocationsSurviveARestartWithAMovedClock(t *testing.T) {
	l := newLab(t)
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(revMsg(9, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, time.Now().Unix()+900, 5))
	l.waitDNS("the revocation at dns", func() bool { return revItems(l) == 1 })
	l.stop() // writes the file
	l.skew.Store(7200)
	l.start()
	l.attachDNS()
	l.waitDNS("the revocation after the restart with the clock moved", func() bool { return revItems(l) == 1 })
	s = l.session()
	_ = s.Send(serverTime()) // hub time is the real time: the node is 2 h ahead
	real := time.Now().Unix()
	l.waitDNS("the expiry in hub time", func() bool {
		m := l.lastDNS(sock.TypeRevocations)
		if m == nil || len(m.Revocations.Items) != 1 {
			return false
		}
		exp := m.Revocations.Items[0].ExpiresAt
		return exp > real && exp <= real+int64((20*time.Minute)/time.Second)+5
	})
	l.waitDNS("the offset in the facts", func() bool {
		f := l.lastDNS(sock.TypeFacts).Facts
		return f.HubOffset < -7190 && f.HubOffset > -7210
	})
}

// p4n-MB-r1-4: dns judges a revocation with its clock plus the offset the agent
// last sent. After a restart the loaded revocations are node-dated until the first
// ServerTime, so the offset and the rebased expiry must reach dns in an order that
// never has dns holding the new offset with the old expiry (the node behind the
// hub) or the new expiry with the old offset (the node ahead). Replay what dns
// received and check every state it passed through.
func TestLoadedRevocationsNeverLapseBetweenTheOffsetAndTheRebase(t *testing.T) {
	for _, tc := range []struct {
		name string
		skew int64 // node clock minus hub clock at the restart
	}{{"node behind the hub", -7200}, {"node ahead of the hub", 7200}} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			l.start()
			l.attachDNS()
			s := l.session()
			_ = s.Send(serverTime())
			// Held for 15 minutes, less than the offset either way.
			_ = s.Send(revMsg(9, policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, time.Now().Unix()+900, 5))
			l.waitDNS("the revocation at dns", func() bool { return revItems(l) == 1 })
			l.stop()
			l.skew.Store(tc.skew)
			l.start()
			l.attachDNS()
			l.waitDNS("the loaded revocation", func() bool { return revItems(l) == 1 })
			s = l.session()
			_ = s.Send(serverTime())
			l.waitDNS("the offset", func() bool {
				f := l.lastDNS(sock.TypeFacts)
				return f != nil && f.Facts.HubOffset != 0
			})
			// The rebased expiry is in hub time: real time plus what is left.
			l.waitDNS("the rebased expiry", func() bool {
				m := l.lastDNS(sock.TypeRevocations)
				return m != nil && len(m.Revocations.Items) == 1 && m.Revocations.Items[0].ExpiresAt > time.Now().Unix()
			})

			l.dnsMu.Lock()
			msgs := append([]*sock.Msg(nil), l.dnsMsgs...)
			l.dnsMu.Unlock()
			var off, exp int64
			for i, m := range msgs {
				switch m.Type {
				case sock.TypeFacts:
					off = m.Facts.HubOffset
				case sock.TypeRevocations:
					if len(m.Revocations.Items) == 1 {
						exp = m.Revocations.Items[0].ExpiresAt
					}
				}
				if exp == 0 {
					continue
				}
				// dns on this machine reads the node clock the agent reads.
				if judged := l.now().Unix() + off; exp <= judged {
					t.Fatalf("after message %d (%s) dns would judge the revocation at %d against an expiry of %d: it has lapsed", i, m.Type, judged, exp)
				}
			}
		})
	}
}

// p4n-MB-r1-5: the query path stamps an activity item with hub time, so the agent
// checks it against hub time. A node whose clock is behind the hub by more than the
// 5 minute window must still report the bucket dns stamped.
func TestActivityStampedInHubTimeKeepsItsBucketOnASkewedNode(t *testing.T) {
	l := newLab(t)
	b1 := storetest.Blob(t, "a.example.com")
	ep := storetest.Endpoint(1, b1)
	ep.ClientCap = 2
	l.addEntry([][]byte{b1}, &policyv1.ConfigEntry{PutEndpoints: []*policyv1.EndpointRecord{ep}, PairTable: storetest.Table(3, 0)})
	l.skew.Store(-600) // the node is 10 minutes behind the hub
	l.start()
	l.attachDNS()
	s := l.session()
	_ = s.Send(serverTime())
	_ = s.Send(headNotice(1))
	eventually(t, "entry 1", func() bool { return lastHB(s).AppliedSeq == 1 })
	hub := time.Now().Unix()
	l.dnsCl.Send(&sock.Msg{Type: sock.TypeActivity, Activity: &sock.Activity{Items: []sock.ActivityItem{{Endpoint: ep.EndpointId, Label: "default", Proto: int32(commonv1.Protocol_PROTOCOL_DOH), At: hub}}}})
	time.Sleep(100 * time.Millisecond)
	l.skew.Store(-600 + 1000) // time moves on so the bucket closes and goes out
	eventually(t, "an activity batch", func() bool { return len(l.hub.Activity()) > 0 })
	got := l.hub.Activity()[0].Entries[0].LastSeenBucket
	if want := hub - hub%wire.FreeBucketSeconds; got != want {
		t.Fatalf("the bucket went out as %d, dns stamped %d (hub time)", got, want)
	}
}
