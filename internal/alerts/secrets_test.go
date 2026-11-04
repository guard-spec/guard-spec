// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSecretEnvBinding(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	allow, err := ParseSecretOrgs("WEBHOOK_SECRET_A=webhook:" + orgA.String() + ";A2A_SHARED=a2a:*;" +
		"GUARDSPEC_ALERT_SLACK_BOT=slack:*")
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
		{"slack", "GUARDSPEC_ALERT_SLACK_BOT", orgA, true},
		// Security review H1: the shared prefix is bound to the listed kind.
		{"a2a", "GUARDSPEC_ALERT_SLACK_BOT", orgA, false},
		{"webhook", "GUARDSPEC_ALERT_SLACK_BOT", orgA, false},
	}
	for _, tc := range cases {
		if err := CheckSecretEnv(tc.kind, tc.name, tc.org, allow); (err == nil) != tc.ok {
			t.Fatalf("%s %s: %v", tc.kind, tc.name, err)
		}
	}
	for _, bad := range []string{
		"DATABASE_URL=webhook:*", "WEBHOOK_SECRET_A=webhook:not-a-uuid", "SLACK_BOT_TOKEN=slack:*",
		"WEBHOOK_SECRET_A", "WEBHOOK_SECRET_A=*", // no kind
		"WEBHOOK_SECRET_A=a2a:*",                 // prefix of another kind
		"GUARDSPEC_ALERT_X=email:*",              // email has no secret
		"A2A_X=a2a:*;A2A_X=a2a:" + orgA.String(), // twice
	} {
		if _, err := ParseSecretOrgs(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	var zero SecretOrgs
	if zero.Allows("webhook", "WEBHOOK_SECRET_A", orgA) {
		t.Fatal("the zero value allows a variable")
	}
}

// Security review H1 (reviewer's test): a GUARDSPEC_ALERT_ variable granted
// for Slack cannot be named by an A2A channel.
func TestSharedPrefixDoesNotCrossKinds(t *testing.T) {
	allow, err := ParseSecretOrgs("GUARDSPEC_ALERT_SLACK_BOT=slack:*")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSecretEnv("a2a", "GUARDSPEC_ALERT_SLACK_BOT", uuid.New(), allow); err == nil {
		t.Fatal("a2a channel may name a GUARDSPEC_ALERT_ variable meant for another kind")
	}
}

// Security review M1 (reviewer's test): a shared Telegram channel without
// its own token posts with the instance bot only to a chat verified by /link.
func TestTelegramInstanceBotNeedsAVerifiedChat(t *testing.T) {
	d := &Dispatcher{TelegramToken: "123456:INSTANCE", Getenv: func(string) string { return "" }}
	ch := &ChannelRow{ID: uuid.New(), Kind: "telegram", Config: map[string]any{"chat_id": "987654321"}}
	m, err := d.message(uuid.New(), &outboxRow{Kind: "telegram", ChannelID: &ch.ID, channel: ch})
	if err == nil && m.Secret == "123456:INSTANCE" {
		t.Fatal("org-defined chat_id is sent with the instance bot token")
	}
	now := time.Now()
	ch.VerifiedAt = &now
	if m, err := d.message(uuid.New(), &outboxRow{Kind: "telegram", ChannelID: &ch.ID, channel: ch}); err != nil ||
		m.Secret != "123456:INSTANCE" {
		t.Fatalf("verified chat: %v", err)
	}
}

// Security review M2: a shared email channel goes only to confirmed addresses.
func TestEmailChannelNeedsConfirmedAddresses(t *testing.T) {
	d := &Dispatcher{Getenv: func(string) string { return "" }}
	ch := &ChannelRow{ID: uuid.New(), Kind: "email", Config: map[string]any{"to": []any{"a@example.com", "b@example.com"}}}
	if _, err := d.message(uuid.New(), &outboxRow{Kind: "email", ChannelID: &ch.ID, channel: ch}); err == nil {
		t.Fatal("sent with no confirmed address")
	}
	ch.confirmed = []string{"b@example.com"}
	m, err := d.message(uuid.New(), &outboxRow{Kind: "email", ChannelID: &ch.ID, channel: ch})
	if err != nil {
		t.Fatal(err)
	}
	if to := m.Config["to"].([]any); len(to) != 1 || to[0] != "b@example.com" {
		t.Fatalf("to %v", to)
	}
}

func TestParsePrivateOrgs(t *testing.T) {
	a := uuid.New()
	p, err := ParsePrivateOrgs(" " + a.String() + " ,")
	if err != nil || !p[a.String()] || len(p) != 1 {
		t.Fatal(p, err)
	}
	if _, err := ParsePrivateOrgs("1"); err == nil {
		t.Fatal("bad id accepted")
	}
}
