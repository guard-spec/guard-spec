//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A scan with shadow mode on writes its requests row and its shadow_results
// row in one transaction, as the application role; the comparison holds
// scores and decisions, no content.
func TestShadowRowWritten(t *testing.T) {
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
	var migrated bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('shadow_results') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Skip("database lacks migration 017_shadow_results")
	}
	org := uuid.New()
	if err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'shadow', $2)`, org, org.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}

	gw, _ := modelTestGateway(t, true, 0, nil)
	gw.audit = newAuditLog(func(e requestEntry) { logRequest(db, false, e) })
	lookup := func(context.Context, string) (tenant.KeyInfo, error) { return tenant.KeyInfo{OrgID: org}, nil }
	req := httptest.NewRequest("POST", "/guardrail/scan", strings.NewReader(`{"text":"Please summarize the attached report."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test")
	resp, err := newApp(gw, lookup).Test(req, -1)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("scan: %v %v", resp.StatusCode, err)
	}
	gw.audit.wait()

	var status, activeModel, shadowModel, activeDec, shadowDec string
	var activeScore, shadowScore float64
	var sameTime bool
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT s.status, s.active_model, s.shadow_model, s.active_score, s.shadow_score,
			s.active_decision, s.shadow_decision, s.created_at = r.created_at
			FROM shadow_results s JOIN requests r ON r.id = s.request_id WHERE s.org_id = $1`, org).
			Scan(&status, &activeModel, &shadowModel, &activeScore, &shadowScore, &activeDec, &shadowDec, &sameTime)
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != "ok" || activeModel != "guardspec-classifier@v3b" || shadowModel != "guardspec-classifier@v2" ||
		activeDec != "allow" || shadowDec != "block" || shadowScore < 0.9 || activeScore > 0.5 || !sameTime {
		t.Fatalf("row: %s %s %s %v %v %s %s %v", status, activeModel, shadowModel, activeScore, shadowScore, activeDec, shadowDec, sameTime)
	}
}
