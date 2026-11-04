// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/giaplee/guard-spec/internal/events"
	"github.com/google/uuid"
)

func TestActivityEvents(t *testing.T) {
	org, actor, target := uuid.New(), uuid.New(), uuid.New()
	var nilID *uuid.UUID
	cases := []struct {
		e     activityEntry
		types []string
	}{
		{activityEntry{Action: "login.failed", ActorID: actor, IP: "10.0.0.1",
			Details: map[string]any{"email": "A@Example.com", "method": "password"}}, []string{events.SecurityLoginFailed}},
		{activityEntry{Action: "mfa.locked", ActorID: actor}, []string{events.SecurityMFALocked}},
		{activityEntry{Org: &org, Action: "member.role_changed", ActorID: actor, Target: target.String(),
			Details: map[string]any{"from": "admin", "to": "owner"}}, []string{events.SecurityRoleChanged, events.SecurityOwnerAdded}},
		{activityEntry{Org: &org, Action: "policy.updated", ActorID: actor, Target: target.String()}, []string{events.ConfigPolicyChanged}},
		{activityEntry{Org: &org, Action: "upstream.default_changed", ActorID: actor,
			Details: map[string]any{"upstream_id": nilID}}, []string{events.ConfigUpstreamChange}},
		{activityEntry{Org: &org, Action: "security.updated", ActorID: actor}, []string{events.SecuritySSOChanged}},
		{activityEntry{Org: &org, Action: "api_key.created", ActorID: actor}, []string{"activity.api_key.created"}},
		{activityEntry{Org: &org, Action: "inv%te.wild"}, nil},
		{activityEntry{Action: "user.created", ActorID: actor}, nil},
	}
	for _, tc := range cases {
		evs := activityEvents(tc.e)
		var got []string
		for _, ev := range evs {
			got = append(got, ev.Type)
			raw, _ := json.Marshal(ev.Attrs)
			if strings.Contains(strings.ToLower(string(raw)), "example.com") {
				t.Fatalf("%s: email in attrs: %s", tc.e.Action, raw)
			}
		}
		if strings.Join(got, ",") != strings.Join(tc.types, ",") {
			t.Fatalf("%s: %v, want %v", tc.e.Action, got, tc.types)
		}
	}
	if h := emailHash("A@Example.com "); h != emailHash("a@example.com") || len(h) != 32 {
		t.Fatal("email hash")
	}
}
