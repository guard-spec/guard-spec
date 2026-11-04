// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"fmt"
	"strings"

	"github.com/giaplee/guard-spec/internal/alerts/channels"
	"github.com/google/uuid"
)

// kindPrefixes binds secret_env prefixes to channel kinds, so a channel
// cannot read a secret meant for another kind: an A2A channel, which sends
// its secret to an org-chosen URL, cannot name a Slack or Telegram token.
var kindPrefixes = map[string][]string{
	channels.KindTelegram: {"TELEGRAM_BOT_TOKEN_", "GUARDSPEC_ALERT_"},
	channels.KindSlack:    {"SLACK_", "GUARDSPEC_ALERT_"},
	channels.KindTeams:    {"TEAMS_", "GUARDSPEC_ALERT_"},
	channels.KindWebhook:  {"WEBHOOK_SECRET_", "GUARDSPEC_ALERT_"},
	channels.KindA2A:      {"A2A_", "GUARDSPEC_ALERT_"},
}

// instanceVars are the instance's own tokens: never a channel's secret.
var instanceVars = map[string]bool{EnvTelegramToken: true, EnvSlackToken: true}

// AllowedSecretEnvFor reports whether a channel of kind may name the variable.
func AllowedSecretEnvFor(kind, name string) bool {
	if !AllowedSecretEnv(name) || instanceVars[name] {
		return false
	}
	for _, p := range kindPrefixes[kind] {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// KindPrefixes lists the prefixes a kind's secret_env may start with.
func KindPrefixes(kind string) []string { return kindPrefixes[kind] }

// SecretOrgs is ALERTS_SECRET_ORGS, the operator's allowlist of which
// organizations may name which channel secret variable. Without it an org
// could name another org's variable and have its secret sent to a URL the
// org controls, so the zero value allows nothing.
//
// Format: WEBHOOK_SECRET_MAIN=*;A2A_ACME=<org-uuid>,<org-uuid>
type SecretOrgs struct {
	all  map[string]bool
	orgs map[string]map[uuid.UUID]bool
}

// ParseSecretOrgs parses ALERTS_SECRET_ORGS.
func ParseSecretOrgs(s string) (SecretOrgs, error) {
	k := SecretOrgs{all: map[string]bool{}, orgs: map[string]map[uuid.UUID]bool{}}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, list, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if !ok || !AllowedSecretEnv(name) || instanceVars[name] {
			return SecretOrgs{}, fmt.Errorf("ALERTS_SECRET_ORGS: %q must be <VARIABLE>=* or <VARIABLE>=<org-id>,<org-id>", entry)
		}
		list = strings.TrimSpace(list)
		if list == "*" {
			k.all[name] = true
			continue
		}
		for _, item := range strings.Split(list, ",") {
			id, err := uuid.Parse(strings.TrimSpace(item))
			if err != nil {
				return SecretOrgs{}, fmt.Errorf("ALERTS_SECRET_ORGS: %s: %q is not an organization id or *", name, item)
			}
			if k.orgs[name] == nil {
				k.orgs[name] = map[uuid.UUID]bool{}
			}
			k.orgs[name][id] = true
		}
	}
	return k, nil
}

// Allows reports whether org may name the variable.
func (k SecretOrgs) Allows(name string, org uuid.UUID) bool {
	return k.all[name] || k.orgs[name][org]
}

// CheckSecretEnv checks a channel's secret_env: the kind's prefixes and the
// org allowlist. The error is safe to show.
func CheckSecretEnv(kind, name string, org uuid.UUID, allow SecretOrgs) error {
	if !AllowedSecretEnvFor(kind, name) {
		return fmt.Errorf("secret_env of a %s channel must be a variable name (A-Z, 0-9, _) starting with %s",
			kind, strings.Join(kindPrefixes[kind], " or "))
	}
	if !allow.Allows(name, org) {
		return fmt.Errorf("the variable %s is not allowed for this organization; the operator lists it in ALERTS_SECRET_ORGS", name)
	}
	return nil
}
