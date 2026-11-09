//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// Saving org security without allowed_login_methods keeps the restriction.
func TestOrgSecurityKeepsLoginMethods(t *testing.T) {
	h := newCPHarness(t)
	org, _, owner := h.org(auth.RoleOwner)
	path := "/v1/organizations/" + org.String() + "/security"
	h.expect(200, "PUT", path, owner, `{"allowed_login_methods":["password"],"session_lifetime_hours":12}`)
	h.expect(200, "PUT", path, owner, `{"session_lifetime_hours":8}`)
	got := h.expect(200, "GET", path, owner, "")
	if m, _ := got["allowed_login_methods"].([]any); len(m) != 1 || m[0] != "password" || got["session_lifetime_hours"] != float64(8) {
		t.Errorf("after a partial save: %v", got)
	}
	h.expect(200, "PUT", path, owner, `{"allowed_login_methods":null,"session_lifetime_hours":8}`)
	var methods []string
	if err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT allowed_login_methods FROM org_security WHERE org_id = $1`, org).Scan(&methods)
	}); err != nil || methods != nil {
		t.Errorf("explicit null must lift it: %v %v", methods, err)
	}
}
