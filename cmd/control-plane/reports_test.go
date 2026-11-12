// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestReportRange(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 30, 0, 0, time.UTC)
	from, to, bucket, err := reportRange("", "", "", now)
	if err != nil || bucket != "hour" || !to.Equal(now) || !from.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("default: %v %v %s %v", from, to, bucket, err)
	}
	if _, _, bucket, err := reportRange("30d", "", "", now); err != nil || bucket != "day" {
		t.Errorf("30d: %s %v", bucket, err)
	}
	if _, _, _, err := reportRange("1y", "", "", now); !errors.Is(err, errReportRange) {
		t.Errorf("bad window: %v", err)
	}
	from, to, bucket, err = reportRange("", "2026-11-01T00:00:00Z", "2026-11-03T00:00:00Z", now)
	if err != nil || bucket != "hour" || from.Day() != 1 || to.Day() != 3 {
		t.Errorf("explicit 48h: %v %v %s %v", from, to, bucket, err)
	}
	if _, _, bucket, err := reportRange("", "2026-10-01T00:00:00Z", "", now); err != nil || bucket != "day" {
		t.Errorf("from only: %s %v", bucket, err)
	}
	for _, bad := range [][2]string{{"nope", ""}, {"2026-11-03T00:00:00Z", "2026-11-01T00:00:00Z"}, {"2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"}} {
		if _, _, _, err := reportRange("", bad[0], bad[1], now); !errors.Is(err, errReportRange) {
			t.Errorf("%v accepted: %v", bad, err)
		}
	}
	if _, _, _, err := reportRange("7d", "2026-11-01T00:00:00Z", "", now); !errors.Is(err, errReportRange) {
		t.Error("window and from together accepted")
	}
}

func TestWriteReportCSV(t *testing.T) {
	start := time.Date(2026, 11, 10, 0, 0, 0, 0, time.FixedZone("ICT", 7*3600))
	var buf bytes.Buffer
	err := writeReportCSV(&buf, []reportRow{
		{Start: start, End: start.Add(24 * time.Hour), Section: "total", Key: "all", Requests: 12, Blocked: 3},
		{Start: start, End: start.Add(24 * time.Hour), Section: "reason", Key: `policy:high "l2", strict`, Requests: 3, Blocked: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "period_start,period_end,section,key,requests,blocked\n" +
		"2026-11-09T17:00:00Z,2026-11-10T17:00:00Z,total,all,12,3\n" +
		"2026-11-09T17:00:00Z,2026-11-10T17:00:00Z,reason,\"policy:high \"\"l2\"\", strict\",3,3\n"
	if buf.String() != want {
		t.Errorf("csv =\n%s\nwant\n%s", buf.String(), want)
	}
	if got := reportFilename("Acme Corp!", start, start.Add(24*time.Hour)); got != "guard-spec-acme-corp--20261109T1700-20261110T1700.csv" {
		t.Errorf("filename = %s", got)
	}
}

func TestSortReportRows(t *testing.T) {
	a := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	b := a.Add(24 * time.Hour)
	rows := []reportRow{
		{Start: b, Section: "total", Key: "all"},
		{Start: a, Section: "project", Key: "z"},
		{Start: a, Section: "action", Key: "block"},
		{Start: a, Section: "action", Key: "allow"},
		{Start: a, Section: "total", Key: "all"},
	}
	sortReportRows(rows)
	got := ""
	for _, r := range rows {
		got += r.Start.Format("02") + r.Section + r.Key + " "
	}
	if got != "10totalall 10actionallow 10actionblock 10projectz 11totalall " {
		t.Errorf("order = %s", got)
	}
}
