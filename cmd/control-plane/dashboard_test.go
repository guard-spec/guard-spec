// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
)

func TestParseDashboardWindow(t *testing.T) {
	for _, tc := range []struct {
		raw, name, bucket string
		d                 time.Duration
	}{
		{"", "24h", "hour", 24 * time.Hour},
		{"24h", "24h", "hour", 24 * time.Hour},
		{"7d", "7d", "day", 7 * 24 * time.Hour},
		{"30d", "30d", "day", 30 * 24 * time.Hour},
	} {
		name, d, bucket, err := parseDashboardWindow(tc.raw)
		if err != nil || name != tc.name || d != tc.d || bucket != tc.bucket {
			t.Errorf("%q: %s %v %s %v", tc.raw, name, d, bucket, err)
		}
	}
	for _, bad := range []string{"1h", "90d", "24", "7D", "-24h"} {
		if _, _, _, err := parseDashboardWindow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFillSeries(t *testing.T) {
	to := time.Date(2026, 11, 4, 8, 30, 0, 0, time.UTC)
	from := to.Add(-24 * time.Hour)
	h := time.Date(2026, 11, 4, 6, 0, 0, 0, time.UTC)
	got := fillSeries(from, to, "hour", map[time.Time]dashBucket{h: {Count: 3, Blocked: 1}})
	// 08:00 the day before through 08:00: the partial buckets at both ends.
	if len(got) != 25 || !got[0].Start.Equal(from.Truncate(time.Hour)) || !got[24].Start.Equal(to.Truncate(time.Hour)) {
		t.Fatalf("%d buckets, %v .. %v", len(got), got[0].Start, got[len(got)-1].Start)
	}
	var n int64
	for _, b := range got {
		n += b.Count
		if b.Start.Equal(h) && (b.Count != 3 || b.Blocked != 1) {
			t.Errorf("bucket %v = %+v", h, b)
		}
	}
	if n != 3 {
		t.Errorf("total %d", n)
	}

	// Days start at midnight UTC, whatever the zone of from.
	loc := time.FixedZone("ICT", 7*3600)
	got = fillSeries(to.Add(-7*24*time.Hour).In(loc), to, "day", nil)
	if len(got) != 8 || got[0].Start != time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC) || got[7].Start != time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("%d buckets, %v .. %v", len(got), got[0].Start, got[len(got)-1].Start)
	}
	for _, b := range got {
		if b.Count != 0 || b.Blocked != 0 {
			t.Errorf("empty bucket %+v", b)
		}
	}
}
