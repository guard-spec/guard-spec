// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IdP groups → roles (org_group_roles, migration 025).
//
// A SAML login applies the mappings of the provider it came through to the
// organizations the user already belongs to: the highest role whose group the
// assertion lists becomes the user's role. A login never adds a membership
// and never changes an owner; when no mapped group matches, the role stays.
// SCIM groups are applied by scim.go.

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// mappedRole is the highest role mapped to one of groups in org, for a SAML
// provider (provider set) or the org's SCIM directory (provider nil).
func mappedRole(ctx context.Context, tx pgx.Tx, org uuid.UUID, provider *uuid.UUID, groups []string) (string, bool, error) {
	var role string
	// org_role sorts owner, admin, member, viewer: the first is the highest.
	err := tx.QueryRow(ctx,
		`SELECT role::text FROM org_group_roles
		 WHERE org_id = $1 AND provider_id IS NOT DISTINCT FROM $2 AND lower(group_key) = ANY($3)
		 ORDER BY role LIMIT 1`, org, provider, lowerAll(groups)).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return role, err == nil, err
}

func applySAMLGroupRoles(ctx context.Context, db *pgxpool.Pool, user, provider uuid.UUID, groups []string) error {
	rows, err := db.Query(ctx, `SELECT org_id FROM user_org_security($1)`, user)
	if err != nil {
		return err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, org := range orgs {
		var old, role string
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			var ok bool
			var err error
			role, ok, err = mappedRole(ctx, tx, org, &provider, groups)
			if err != nil || !ok {
				return err
			}
			err = tx.QueryRow(ctx,
				`UPDATE org_memberships m SET role = $3::org_role
				 FROM (SELECT role FROM org_memberships WHERE user_id = $1 AND org_id = $2 FOR UPDATE) o
				 WHERE m.user_id = $1 AND m.org_id = $2 AND m.role <> 'owner' AND m.role <> $3::org_role
				 RETURNING o.role::text`, user, org, role).Scan(&old)
			if errors.Is(err, pgx.ErrNoRows) {
				old = ""
				return nil
			}
			return err
		})
		if err != nil {
			return err
		}
		if old != "" {
			writeActivity(ctx, db, activityEntry{Org: &org, Action: "member.role_from_group", Target: user.String(),
				Details: map[string]any{"from": old, "to": role, "source": "saml", "provider_id": provider}})
		}
	}
	return nil
}
