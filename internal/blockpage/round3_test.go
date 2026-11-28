package blockpage

import (
	"context"
	"testing"
	"time"
)

// A need_key that could not be sent (the agent link is down) does not start the
// 10 s pause: the next handshake, with the agent back, asks at once (B6-r3-1).
func TestUnsentKeyAskDoesNotStartThePause(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	sent := 0
	linkUp := false
	k := newKeyring(func(_, _ []byte) bool {
		if !linkUp {
			return false
		}
		sent++
		return true
	}, nil, func() time.Time { return now })
	k.setEpoch([]byte("EPOCH001"))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := k.get(ctx, ids(1), ids(2)); err != ErrNoKey {
		t.Fatalf("with the link down: %v", err)
	}
	linkUp = true
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	_, _ = k.get(ctx2, ids(1), ids(2))
	if sent != 1 {
		t.Fatalf("%d need_key sent after the link came back, want 1", sent)
	}
	// A sent ask still paces the next one.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel3()
	_, _ = k.get(ctx3, ids(1), ids(2))
	if sent != 1 {
		t.Fatalf("a second ask went out inside the pause (%d)", sent)
	}
}

// A refund from a window that has turned does not take a count from the new one
// (B6-r3-2).
func TestRefundOfAnEarlierHourLeavesTheNewWindowAlone(t *testing.T) {
	now := time.Unix(10*3600+3599, 0)
	u, err := newUnblocker(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	src := []byte{192, 0, 2, 7}
	oldHour, ok := u.admit(ids(1), src)
	if !ok {
		t.Fatal("first request refused")
	}
	now = now.Add(2 * time.Second) // the clock hour turns
	newHour, ok := u.admit(ids(1), src)
	if !ok || newHour == oldHour {
		t.Fatalf("second request: ok=%v hours %d %d", ok, oldHour, newHour)
	}
	u.refund(oldHour, ids(1), src)
	var sk srcKey
	copy(sk.endpoint[:], ids(1))
	copy(sk.source[:], src)
	if u.perSrc[sk] != 1 || u.perEP[sk.endpoint] != 1 {
		t.Fatalf("the new window lost a count: %d %d", u.perSrc[sk], u.perEP[sk.endpoint])
	}
	// A refund inside its own window still gives the count back.
	u.refund(newHour, ids(1), src)
	if u.perSrc[sk] != 0 || u.perEP[sk.endpoint] != 0 {
		t.Fatalf("own-window refund did not apply: %d %d", u.perSrc[sk], u.perEP[sk.endpoint])
	}
}
