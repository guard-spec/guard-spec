// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/alerts/channels"
)

// kindPrefixes binds secret_env prefixes to channel kinds, so a channel
// cannot read a secret meant for another kind: an A2A channel, which sends
// its secret to an org-chosen URL, cannot name a Slack or Telegram token.
// GUARDSPEC_ALERT_ is accepted for every kind, but ALERTS_SECRET_ORGS binds
// each variable to exactly one kind, so it never crosses kinds either.
var kindPrefixes = map[string][]string{
	channels.KindTelegram: {"TELEGRAM_BOT_TOKEN_", "GUARDSPEC_ALERT_"},
	channels.KindSlack:    {"SLACK_", "GUARDSPEC_ALERT_"},
	channels.KindTeams:    {"TEAMS_", "GUARDSPEC_ALERT_"},
	channels.KindWebhook:  {"WEBHOOK_SECRET_", "GUARDSPEC_ALERT_"},
	channels.KindA2A:      {"A2A_", "GUARDSPEC_ALERT_"},
	// SIEM export sinks (internal/siem): HEC tokens, API keys, client secrets.
	KindSIEM: {"SIEM_", "GUARDSPEC_ALERT_"},
}

// KindSIEM is the secret kind of SIEM export sinks in ALERTS_SECRET_ORGS
// ("SIEM_SPLUNK=siem:*").
const KindSIEM = "siem"

// instanceVars are the instance's own tokens: never a channel's secret.
var instanceVars = map[string]bool{EnvTelegramToken: true, EnvSlackToken: true}

// AllowedSecretEnvFor reports whether a channel of kind may name the variable
// by its form (prefix); ALERTS_SECRET_ORGS decides the rest.
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

// secretGrant is one entry of ALERTS_SECRET_ORGS.
type secretGrant struct {
	kind string
	all  bool
	orgs map[uuid.UUID]bool
}

// SecretOrgs is ALERTS_SECRET_ORGS, the operator's allowlist of which
// organizations may name which channel secret variable, and for which channel
// kind. Any logged-in user can create an org and own it, so without this an
// org could name another org's variable, or put a Slack token on an A2A
// channel aimed at its own server. The zero value allows nothing.
//
// Format: WEBHOOK_SECRET_MAIN=webhook:*;A2A_ACME=a2a:<org-uuid>,<org-uuid>
type SecretOrgs struct {
	grants map[string]secretGrant
}

// ParseSecretOrgs parses ALERTS_SECRET_ORGS.
func ParseSecretOrgs(s string) (SecretOrgs, error) {
	k := SecretOrgs{grants: map[string]secretGrant{}}
	usage := "must be <VARIABLE>=<kind>:* or <VARIABLE>=<kind>:<org-id>,<org-id>"
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, rest, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		kind, list, hasKind := strings.Cut(strings.TrimSpace(rest), ":")
		kind = strings.TrimSpace(kind)
		if !ok || !hasKind {
			return SecretOrgs{}, fmt.Errorf("ALERTS_SECRET_ORGS: %q %s", entry, usage)
		}
		if _, known := kindPrefixes[kind]; !known {
			return SecretOrgs{}, fmt.Errorf("ALERTS_SECRET_ORGS: %s: kind %q must be one of telegram, slack, teams, webhook, a2a, siem", name, kind)
		}
		if !AllowedSecretEnvFor(kind, name) {
			return SecretOrgs{}, fmt.Errorf("ALERTS_SECRET_ORGS: %s cannot be a %s secret (prefixes %s)", name, kind,
				strings.Join(kindPrefixes[kind], ", "))
		}
		if _, dup := k.grants[name]; dup {
			return SecretOrgs{}, fmt.Errorf("ALERTS_SECRET_ORGS: %s is listed twice", name)
		}
		g := secretGrant{kind: kind, orgs: map[uuid.UUID]bool{}}
		list = strings.TrimSpace(list)
		if list == "*" {
			g.all = true
		} else {
			for _, item := range strings.Split(list, ",") {
				id, err := uuid.Parse(strings.TrimSpace(item))
				if err != nil {
					return SecretOrgs{}, fmt.Errorf("ALERTS_SECRET_ORGS: %s: %q is not an organization id or *", name, item)
				}
				g.orgs[id] = true
			}
		}
		k.grants[name] = g
	}
	return k, nil
}

// Allows reports whether org may name the variable on a channel of kind.
func (k SecretOrgs) Allows(kind, name string, org uuid.UUID) bool {
	g, ok := k.grants[name]
	return ok && g.kind == kind && (g.all || g.orgs[org])
}

// CheckSecretEnv checks a channel's secret_env: the kind's prefixes and the
// kind-bound org allowlist. The error is safe to show.
func CheckSecretEnv(kind, name string, org uuid.UUID, allow SecretOrgs) error {
	if !AllowedSecretEnvFor(kind, name) {
		return fmt.Errorf("secret_env of a %s channel must be a variable name (A-Z, 0-9, _) starting with %s",
			kind, strings.Join(kindPrefixes[kind], " or "))
	}
	if !allow.Allows(kind, name, org) {
		return fmt.Errorf("the variable %s is not allowed for %s channels of this organization; "+
			"the operator lists it in ALERTS_SECRET_ORGS", name, kind)
	}
	return nil
}

// PrivateOrgs is ALERTS_PRIVATE_ORGS: the orgs whose channels may reach
// loopback and private addresses (with allow_private set on the channel).
type PrivateOrgs map[string]bool

// ParsePrivateOrgs parses a comma-separated list of org ids.
func ParsePrivateOrgs(s string) (PrivateOrgs, error) {
	out := PrivateOrgs{}
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		id, err := uuid.Parse(item)
		if err != nil {
			return nil, fmt.Errorf("ALERTS_PRIVATE_ORGS: %q is not an organization id", item)
		}
		out[id.String()] = true
	}
	return out, nil
}

// IDs lists the orgs, sorted.
func (p PrivateOrgs) IDs() []string {
	out := make([]string, 0, len(p))
	for id := range p {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
