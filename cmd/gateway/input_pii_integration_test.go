//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Personal data in requests end to end with Postgres, as the application
// role: the org's input_pii setting (organizations.guard_settings), a stored
// policy with a rule on input.pii.count, and the audit row. On chat
// completions, /v1/messages and /v1/responses, stream and not, the rule
// blocks or logs only while the setting is on; turning it on or off applies
// to the next request; the row holds kinds and counts, never the values.
func TestInputPIIWithPostgres(t *testing.T) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"
	}
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	org := uuid.New()
	inOrg := func(sql string, args ...any) {
		t.Helper()
		err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	inOrg(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'pii', $2)`, org, org.String())
	t.Cleanup(func() {
		_ = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `DELETE FROM requests WHERE org_id = $1`, org); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org)
			return err
		})
	})
	policyID := uuid.New()
	inOrg(`INSERT INTO policies (id, org_id, name, rules) VALUES ($1, $2, 'pii', '[]')`, policyID, org)
	setRule := func(action policy.Action) uuid.UUID {
		r := rule(action, "input.pii.count", ">", 0)
		raw, _ := json.Marshal([]policy.Rule{r})
		inOrg(`UPDATE policies SET rules = $1, version = version + 1 WHERE id = $2`, raw, policyID)
		return r.ID
	}
	setPII := func(on bool) {
		settings := `{}`
		if on {
			settings = `{"input_pii":true}`
		}
		inOrg(`UPDATE organizations SET guard_settings = $1::jsonb WHERE id = $2`, settings, org)
	}

	runner, err := inference.NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, keyHash string) (tenant.KeyInfo, error) {
		return tenant.KeyInfo{OrgID: org}, nil
	}

	for _, api := range piiAPIs() {
		t.Run(api.name, func(t *testing.T) {
			up := newFakeUpstream(t, api.upstream)
			gw := testGateway(t, runner)
			gw.policies, gw.settings = dbPolicyLoader(db), dbSettingsLoader(db)
			gw.audit = newAuditLog(func(e requestEntry) { logRequest(db, false, e) })
			if api.anthropic {
				withAnthropic(up.URL)(&gw)
			} else {
				px, err := proxy.New(proxy.Config{BaseURL: up.URL + "/v1"})
				if err != nil {
					t.Fatal(err)
				}
				gw.upstream = px
			}
			app := newApp(gw, lookup)
			send := func() int {
				t.Helper()
				req := httptest.NewRequest("POST", api.path, strings.NewReader(api.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("x-api-key", "test")
				resp, err := app.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				gw.audit.wait()
				return resp.StatusCode
			}
			for _, step := range []struct {
				name   string
				on     bool
				action policy.Action
				status int
				row    string // the audit row's action
				tags   []string
			}{
				{"off, block rule", false, policy.ActionBlock, 200, actionAllow, nil},
				{"on, block rule", true, policy.ActionBlock, 400, actionBlock, []string{"input:pii_email=1", "input:pii_phone=1"}},
				{"on, log rule", true, policy.ActionLog, 200, actionAllow, []string{"input:pii_email=1", "input:pii_phone=1"}},
				{"off again, log rule", false, policy.ActionLog, 200, actionAllow, nil},
			} {
				setPII(step.on)
				ruleID := setRule(step.action)
				if status := send(); status != step.status {
					t.Errorf("%s: status %d, want %d", step.name, status, step.status)
				}
				var (
					action  string
					rule    *uuid.UUID
					tags    []string
					content *string
				)
				err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, `SELECT action, rule_id, pii_entities, request_content FROM requests
						WHERE org_id = $1 ORDER BY created_at DESC LIMIT 1`, org).Scan(&action, &rule, &tags, &content)
				})
				if err != nil {
					t.Fatal(err)
				}
				tags = withoutDetector(tags)
				if action != step.row || !slices.Equal(tags, step.tags) || content != nil {
					t.Errorf("%s: row %s %v content %v", step.name, action, tags, content)
				}
				if matched := rule != nil && *rule == ruleID; matched != step.on {
					t.Errorf("%s: row rule %v, rule %s", step.name, rule, ruleID)
				}
				noValues(t, step.name+": audit row", tags...)
			}
		})
	}
}
