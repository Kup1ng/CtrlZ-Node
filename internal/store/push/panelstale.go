package push

import (
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// PanelStaleAfter is the one threshold of SC 8a.5.
const PanelStaleAfter = 30 * time.Second

// StaleClocks is what PanelStale needs that the writer does not hold: the Control
// stream and the hub's clock belong to the agent.
type StaleClocks struct {
	// StreamDownFor is how long the Control stream has been down, 0 while it is up.
	StreamDownFor time.Duration
	// SinceServerTime is the time since the latest valid ServerTime, or since the
	// start before the first one.
	SinceServerTime time.Duration
	// HubNow is the node's clock plus the offset of the latest ServerTime (8a.4, Clock).
	HubNow int64
}

// PanelStale is SC 8a.5: no Control stream for 30 s, no valid ServerTime for 30 s,
// no push accepted since the start (a redelivery counts), the push in use past its
// expires_at by hub_now, or the latest push refused for any reason but a lower
// version. It is a function of the writer's Status so that the agent and the
// pair-table-apply vector run (T-541) judge it by one rule.
func (s Status) PanelStale(c StaleClocks) bool {
	if c.StreamDownFor >= PanelStaleAfter || c.SinceServerTime >= PanelStaleAfter {
		return true
	}
	if !s.AcceptedSinceStart {
		return true
	}
	if s.ExpiresAt != 0 && s.ExpiresAt <= c.HubNow {
		return true
	}
	return s.LatestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED && s.LatestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION
}
