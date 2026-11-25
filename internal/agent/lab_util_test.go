package agent_test

import "time"

func lifeEnd(short bool) time.Time {
	if short {
		return time.Now().Add(30 * time.Minute)
	}
	return time.Now().Add(10 * time.Hour)
}
