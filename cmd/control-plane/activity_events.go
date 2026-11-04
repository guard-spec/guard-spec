// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/giaplee/guard-spec/internal/events"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every activity log write also emits alert events (docs/alerts.md §1):
// security and config actions as their contract types, any other org action
// as activity.<action>. Instance-level rows (logins, SSO providers) go to the
// orgs of the user concerned. Attributes are ids, names and flags only, as
// in the activity log itself; an email address is hashed.

// activityEmitter is the control plane's emitter; nil emits nothing.
var activityEmitter atomic.Pointer[events.Emitter]

var activityTypeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// emitActivity emits the events of an activity row. It never blocks on the
// emitter; it may read the orgs of a user for instance-level rows.
func emitActivity(ctx context.Context, db *pgxpool.Pool, e activityEntry) {
	em := activityEmitter.Load()
	if em == nil {
		return
	}
	evs := activityEvents(e)
	if len(evs) == 0 {
		return
	}
	orgs := []uuid.UUID{}
	switch {
	case e.Org != nil:
		orgs = append(orgs, *e.Org)
	default:
		// Logins and SSO changes: the orgs of the user (or of the actor).
		user := e.ActorID
		if user == uuid.Nil {
			return // a failed login of an unknown email belongs to no org
		}
		rows, err := db.Query(ctx, `SELECT id FROM user_organizations($1)`, user)
		if err != nil {
			return
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return
		}
		orgs = ids
	}
	for _, org := range orgs {
		for _, ev := range evs {
			ev.OrgID = org
			em.Emit(ev)
		}
	}
}

func detailString(d map[string]any, key string) string {
	switch v := d[key].(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// emailHash is how an email appears in events.
func emailHash(email string) string {
	if email == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:16])
}

// activityEvents maps an activity row to events (OrgID left for the caller).
func activityEvents(e activityEntry) []events.Event {
	actor := ""
	if e.ActorID != uuid.Nil {
		actor = e.ActorID.String()
	}
	ev := func(typ, sev string, attrs map[string]any) events.Event {
		return events.Event{Type: typ, Severity: sev, Attrs: attrs}
	}
	family, verb, _ := strings.Cut(e.Action, ".")
	switch e.Action {
	case "login.failed", "login.mfa_failed":
		reason := detailString(e.Details, "reason")
		if reason == "" {
			reason = map[string]string{"login.failed": "invalid_credentials", "login.mfa_failed": "mfa_failed"}[e.Action]
		}
		var user any
		if actor != "" {
			user = actor
		}
		return []events.Event{ev(events.SecurityLoginFailed, events.Warning, map[string]any{
			"user_id": user, "email_hash": emailHash(detailString(e.Details, "email")), "ip": e.IP, "reason": reason})}
	case "mfa.locked":
		return []events.Event{ev(events.SecurityMFALocked, events.Critical, map[string]any{"user_id": actor})}
	case "member.role_changed":
		to := detailString(e.Details, "to")
		out := []events.Event{ev(events.SecurityRoleChanged, events.Warning, map[string]any{
			"actor_id": actor, "user_id": e.Target, "from": detailString(e.Details, "from"), "to": to})}
		if to == "owner" {
			out = append(out, ev(events.SecurityOwnerAdded, events.Critical, map[string]any{"actor_id": actor, "user_id": e.Target}))
		}
		return out
	case "security.updated":
		return []events.Event{ev(events.SecuritySSOChanged, events.Warning, map[string]any{
			"actor_id": actor, "provider_id": "", "action": "org_security_updated"})}
	case "identity_provider.created", "identity_provider.updated", "identity_provider.deleted":
		return []events.Event{ev(events.SecuritySSOChanged, events.Warning, map[string]any{
			"actor_id": actor, "provider_id": detailString(e.Details, "id"), "action": verb})}
	case "policy.created", "policy.updated", "policy.deleted":
		id := detailString(e.Details, "id")
		if id == "" {
			id = e.Target
		}
		return []events.Event{ev(events.ConfigPolicyChanged, events.Info, map[string]any{
			"actor_id": actor, "policy_id": id, "action": verb})}
	case "config.applied":
		return []events.Event{ev(events.ConfigPolicyChanged, events.Info, map[string]any{
			"actor_id": actor, "policy_id": "", "action": "config_applied"})}
	case "upstream.created", "upstream.updated", "upstream.deleted", "upstream.default_changed":
		id := detailString(e.Details, "id")
		if id == "" {
			id = detailString(e.Details, "upstream_id")
		}
		return []events.Event{ev(events.ConfigUpstreamChange, events.Info, map[string]any{
			"actor_id": actor, "upstream_id": id, "action": verb})}
	}
	if e.Org == nil || family == "" {
		return nil
	}
	typ := "activity." + e.Action
	if len(typ) > 80 || !activityTypeRe.MatchString(typ) {
		return nil
	}
	return []events.Event{ev(typ, events.Info, map[string]any{"actor_id": actor, "action": e.Action})}
}
