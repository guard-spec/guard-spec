// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeCIDRs(t *testing.T) {
	got, err := normalizeCIDRs([]string{" 10.1.2.3/8 ", "192.0.2.1", "2001:db8::1", "", "192.0.2.1", "2001:DB8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	want := "10.0.0.0/8,192.0.2.1,2001:db8::1,2001:db8::/32"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
	if got, err := normalizeCIDRs(nil); err != nil || len(got) != 0 || got == nil {
		t.Errorf("nil: %v %v", got, err)
	}
	for _, bad := range [][]string{{"nope"}, {"10.0.0.0/33"}, {"300.1.1.1"}, make([]string, maxKeyCIDRs+1)} {
		if _, err := normalizeCIDRs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestApplyKeyLifetime(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	in := func(d time.Duration) *time.Time {
		x := now.Add(d)
		return &x
	}
	// No maximum: whatever was given, as long as it is in the future.
	if got, err := applyKeyLifetime(nil, 0, now); err != nil || got != nil {
		t.Errorf("no max, none: %v %v", got, err)
	}
	if got, err := applyKeyLifetime(in(400*24*time.Hour), 0, now); err != nil || got == nil {
		t.Errorf("no max, late: %v %v", got, err)
	}
	if _, err := applyKeyLifetime(in(-time.Minute), 0, now); !errors.Is(err, errKeyLifetime) {
		t.Errorf("past expiry accepted: %v", err)
	}
	// A maximum fills in an absent expiry and refuses a later one.
	if got, err := applyKeyLifetime(nil, 30, now); err != nil || got == nil || !got.Equal(now.Add(30*24*time.Hour)) {
		t.Errorf("max fills in: %v %v", got, err)
	}
	if got, err := applyKeyLifetime(in(7*24*time.Hour), 30, now); err != nil || got == nil || !got.Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("within max: %v %v", got, err)
	}
	if _, err := applyKeyLifetime(in(31*24*time.Hour), 30, now); !errors.Is(err, errKeyLifetime) {
		t.Errorf("over max accepted: %v", err)
	}
}
