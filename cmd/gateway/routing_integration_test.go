//go:build integration

package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires migration 011. Connects as the application role.
func TestUpstreamLoader(t *testing.T) {
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

	org, other := uuid.New(), uuid.New()
	project, bare := uuid.New(), uuid.New()
	ids := map[string]uuid.UUID{}
	setup := func(orgID uuid.UUID, fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := tenant.WithOrg(ctx, db, orgID, fn); err != nil {
			t.Fatal(err)
		}
	}
	setup(org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'o',$2)`, org, org.String()); err != nil {
			return err
		}
		for _, name := range []string{"org-up", "proj-up", "named"} {
			var id uuid.UUID
			if err := tx.QueryRow(ctx, `INSERT INTO upstreams (org_id, name, base_url, api_key_env)
				VALUES ($1, $2, 'http://x/v1', 'UPSTREAM_KEY_X') RETURNING id`, org, name).Scan(&id); err != nil {
				return err
			}
			ids[name] = id
		}
		if _, err := tx.Exec(ctx, `UPDATE organizations SET default_upstream_id = $1 WHERE id = $2`, ids["org-up"], org); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO projects (id, org_id, name, slug, default_upstream_id)
			VALUES ($1, $3, 'p', $5, $4), ($2, $3, 'b', $6, NULL)`, project, bare, org, ids["proj-up"],
			project.String(), bare.String())
		return err
	})
	setup(other, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'o',$2)`, other, other.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO upstreams (org_id, name, base_url) VALUES ($1, 'foreign', 'http://y/v1')`, other)
		return err
	})

	load := dbUpstreamLoader(db)
	tests := []struct {
		project uuid.UUID
		target  string
		want    string
		source  string
	}{
		{project, "named", "named", sourceRule},
		{project, "", "proj-up", sourceProject},
		{bare, "", "org-up", sourceOrg},
		{uuid.Nil, "", "org-up", sourceOrg},
	}
	for _, tt := range tests {
		up, source, err := load(ctx, org, tt.project, tt.target)
		if err != nil {
			t.Fatal(err)
		}
		if up == nil || up.Name != tt.want || source != tt.source || up.KeyEnv != "UPSTREAM_KEY_X" || !up.Enabled {
			t.Errorf("project %s target %q: got %+v %q", tt.project, tt.target, up, source)
		}
	}
	// Another org's upstream is invisible.
	if _, _, err := load(ctx, org, uuid.Nil, "foreign"); !errors.Is(err, errNoSuchUpstream) {
		t.Errorf("foreign target: %v", err)
	}
	// No default anywhere: nil, and the gateway falls back to env.
	if up, _, err := load(ctx, other, uuid.Nil, ""); err != nil || up != nil {
		t.Errorf("no default: %+v %v", up, err)
	}

	// Policies and the upstreams they may need come from one transaction.
	setup(org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO policies (org_id, name, rules) VALUES ($1, 'routing',
			'[{"id":"`+uuid.NewString()+`","name":"r","action":"route","route_target":"named","condition":{"field":"scores.l2","operator":">","value":0.5}}]')`, org)
		return err
	})
	policies, snap, err := dbPolicyRouteLoader(db)(ctx, org, project)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || snap.named["named"] == nil || len(snap.named) != 1 ||
		snap.def == nil || snap.def.Name != "proj-up" || snap.defSource != sourceProject {
		t.Errorf("policies %d, snapshot %+v", len(policies), snap)
	}
	if _, snap, _ := dbPolicyRouteLoader(db)(ctx, other, uuid.Nil); snap == nil || snap.def != nil || len(snap.named) != 0 {
		t.Errorf("other org snapshot %+v", snap)
	}

	// The audit row keeps the route target.
	logRequest(db, false, requestEntry{OrgID: org, Action: actionRoute, RouteTarget: "named"})
	var target *string
	setup(org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT route_target FROM requests WHERE org_id = $1`, org).Scan(&target)
	})
	if target == nil || *target != "named" {
		t.Errorf("route_target = %v", target)
	}

	// The model provider fields of migration 014 reach the route.
	setup(org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE upstreams SET provider = 'azure_openai', models = '{gpt-4o}', model = 'gpt-4o',
			headers = '{"OpenAI-Organization":"org_x"}', api_version = '2024-10-21', max_tokens_cap = 64, retries = 2
			WHERE org_id = $1 AND name = 'named'`, org)
		return err
	})
	up, _, err := load(ctx, org, uuid.Nil, "named")
	if err != nil {
		t.Fatal(err)
	}
	if up.Provider != "azure_openai" || len(up.Models) != 1 || up.Headers["OpenAI-Organization"] != "org_x" ||
		up.APIVersion != "2024-10-21" || up.MaxTokensCap == nil || *up.MaxTokensCap != 64 || up.Retries != 2 {
		t.Errorf("provider fields %+v", up)
	}
	r := route{model: up.Model, models: up.Models}
	if _, err := r.applyModel("gpt-3.5"); !errors.Is(err, errModelNotAllowed) {
		t.Errorf("model allowlist: %v", err)
	}
}
