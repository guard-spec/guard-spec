// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"time"

	"github.com/giaplee/guard-spec/internal/events"
)

// Delivery decisions for quiet hours.
const (
	sendNow      = "now"
	sendSuppress = "suppress"
	sendDelay    = "delay"
)

func clock(s string) (int, int) {
	return int(s[0]-'0')*10 + int(s[1]-'0'), int(s[3]-'0')*10 + int(s[4]-'0')
}

// quietWindow reports whether now falls in q, and when that window ends.
// A window with start after end spans midnight (22:00 to 07:00).
func quietWindow(q *QuietHours, now time.Time) (bool, time.Time) {
	loc, err := time.LoadLocation(q.TZ)
	if err != nil {
		return false, time.Time{}
	}
	local := now.In(loc)
	sh, sm := clock(q.Start)
	eh, em := clock(q.End)
	day := func(d int, h, m int) time.Time {
		return time.Date(local.Year(), local.Month(), local.Day()+d, h, m, 0, 0, loc)
	}
	start, end := day(0, sh, sm), day(0, eh, em)
	if !start.After(end) { // same-day window, 01:00 to 05:00
		if !local.Before(start) && local.Before(end) {
			return true, end
		}
		return false, time.Time{}
	}
	// Spans midnight: in the window after today's start, or before today's end.
	if !local.Before(start) {
		return true, day(1, eh, em)
	}
	if local.Before(end) {
		return true, end
	}
	return false, time.Time{}
}

// quietDecision says what to do with a notification of severity at now:
// send it, suppress it, or delay it until the returned time.
func quietDecision(q *QuietHours, severity string, now time.Time) (string, time.Time) {
	if q == nil {
		return sendNow, now
	}
	in, end := quietWindow(q, now)
	if !in {
		return sendNow, now
	}
	if q.CriticalBypass && severity == events.Critical {
		return sendNow, now
	}
	if q.Mode == "delay" {
		return sendDelay, end
	}
	return sendSuppress, time.Time{}
}
