// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"testing"

	"github.com/google/uuid"
)

func TestSecretEnvBinding(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	allow, err := ParseSecretOrgs("WEBHOOK_SECRET_A=" + orgA.String() + ";A2A_SHARED=*")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		kind, name string
		org        uuid.UUID
		ok         bool
	}{
		{"webhook", "WEBHOOK_SECRET_A", orgA, true},
		{"webhook", "WEBHOOK_SECRET_A", orgB, false},
		{"a2a", "A2A_SHARED", orgB, true},
		{"a2a", "WEBHOOK_SECRET_A", orgA, false}, // another kind's prefix
		{"a2a", "SLACK_BOT_TOKEN", orgA, false},
		{"slack", "SLACK_BOT_TOKEN", orgA, false}, // the instance token
		{"webhook", "DATABASE_URL", orgA, false},
	}
	for _, tc := range cases {
		if err := CheckSecretEnv(tc.kind, tc.name, tc.org, allow); (err == nil) != tc.ok {
			t.Fatalf("%s %s: %v", tc.kind, tc.name, err)
		}
	}
	for _, bad := range []string{"DATABASE_URL=*", "WEBHOOK_SECRET_A=not-a-uuid", "SLACK_BOT_TOKEN=*", "WEBHOOK_SECRET_A"} {
		if _, err := ParseSecretOrgs(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	var zero SecretOrgs
	if zero.Allows("WEBHOOK_SECRET_A", orgA) {
		t.Fatal("the zero value allows a variable")
	}
}
