// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
)

func TestUpstreamReachable(t *testing.T) {
	now := time.Now()
	before := now.Add(-time.Hour)
	str := func(b *bool) string {
		if b == nil {
			return "nil"
		}
		if *b {
			return "true"
		}
		return "false"
	}
	for _, c := range []struct {
		answer, failure *time.Time
		want            string
	}{
		{nil, nil, "nil"},
		{&now, nil, "true"},
		{nil, &now, "false"},
		{&now, &before, "true"},
		{&before, &now, "false"},
	} {
		if got := str(upstreamReachable(c.answer, c.failure)); got != c.want {
			t.Errorf("answer %v failure %v: %s, want %s", c.answer, c.failure, got, c.want)
		}
	}
}

func TestStartComplete(t *testing.T) {
	done := gettingStarted{Upstream: startUpstream{Configured: true}, APIKeys: 1, Policies: 1,
		Models: startModels{Configured: true, Reachable: true, Layers: []string{"l1"}}}
	if !startComplete(done) {
		t.Fatal("every required step is done")
	}
	// Alert channels and input settings are recommended, not required.
	if done.AlertChannels != 0 || done.InputSettings {
		t.Fatal("test setup")
	}
	for name, mut := range map[string]func(*gettingStarted){
		"no upstream": func(s *gettingStarted) { s.Upstream.Configured = false },
		"no key":      func(s *gettingStarted) { s.APIKeys = 0 },
		"no policy":   func(s *gettingStarted) { s.Policies = 0 },
		"no gateway":  func(s *gettingStarted) { s.Models.Reachable = false },
		"no layers":   func(s *gettingStarted) { s.Models.Layers = nil },
	} {
		s := done
		mut(&s)
		if startComplete(s) {
			t.Errorf("%s: complete", name)
		}
	}
}
