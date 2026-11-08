//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guard-spec/guard-spec/internal/alerts"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/siem"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

// The SIEM export end to end: an admin adds a sink, the worker sends the
// org's events as OCSF records, moves the cursor, backs off on errors.
func TestSIEMExport(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var got []map[string]any
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer siem-token" {
			w.WriteHeader(401)
			return
		}
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var recs []map[string]any
		_ = json.Unmarshal(b, &recs)
		got = append(got, recs...)
	}))
	defer srv.Close()

	var orgID uuid.UUID
	env := map[string]string{"SIEM_TEST_TOKEN": "siem-token"}
	secretOrgs, _ := alerts.ParseSecretOrgs("SIEM_TEST_TOKEN=siem:*")
	cfg := &alertsConfig{secretOrgs: secretOrgs, privateOrgs: alerts.PrivateOrgs{}, getenv: func(k string) string { return env[k] }}
	h := newCPHarness(t, func(s *appSettings) { s.alertsCfg = cfg })
	org, _, admin := h.org(auth.RoleAdmin)
	orgID = org
	cfg.privateOrgs[orgID.String()] = true
	viewer := h.member(org, auth.RoleViewer)
	base := "/v1/organizations/" + org.String() + "/siem-sinks"

	// Validation: unknown kind, a variable not granted, private without the grant.
	if st, _ := h.do("POST", base, admin, `{"name":"x","kind":"kafka"}`); st != 400 {
		t.Fatalf("kind: %d", st)
	}
	if st, body := h.do("POST", base, admin, `{"name":"x","kind":"http","config":{"url":"https://siem.example"},"secret_env":"SIEM_OTHER"}`); st != 400 || !strings.Contains(body["error"].(string), "ALERTS_SECRET_ORGS") {
		t.Fatalf("secret grant: %d %v", st, body)
	}
	if st, _ := h.do("GET", base, viewer, ""); st != 403 {
		t.Fatalf("viewer: %d", st)
	}
	sink := h.expect(201, "POST", base, admin, jsonBody(map[string]any{"name": "SOC", "kind": "http",
		"config": map[string]any{"url": srv.URL}, "secret_env": "SIEM_TEST_TOKEN", "allow_private": true,
		"event_types": []string{"detection.", "security.login_failed"}}))
	id := sink["id"].(string)
	if sink["secret_set"] != true {
		t.Fatalf("sink: %v", sink)
	}

	// Events after the sink was made (a new sink starts at its creation):
	// two wanted, one filtered out, one too recent for the first run (settle).
	t0 := time.Now().Add(time.Second)
	old := t0
	insert := func(typ, sev string, created time.Time) {
		t.Helper()
		if err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO events (org_id, type, severity, attrs, created_at, occurred_at)
				VALUES ($1, $2, $3::alert_severity, '{"layer":"l2","score":0.97,"request_id":"r1"}', $4, $4)`, org, typ, sev, created)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("detection.blocked", "warning", old)
	insert("config.policy_changed", "info", old.Add(time.Second))
	insert("security.login_failed", "warning", old.Add(2*time.Second))
	insert("detection.flagged", "info", t0.Add(30*time.Second))
	run := func(at time.Time) int {
		t.Helper()
		n, err := siem.Once(ctx, h.db, newSIEMResolver(cfg), at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	resolver := newSIEMResolver(cfg)
	_ = resolver
	first := t0.Add(siem.Settle + 5*time.Second)
	n, err := siem.Once(ctx, h.db, resolver, first)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if n < 2 || len(got) != 2 || got[0]["class_uid"] != float64(2004) || got[1]["class_uid"] != float64(3002) {
		t.Fatalf("delivered %d: %v", n, got)
	}
	mu.Unlock()
	// Nothing new: nothing sent again.
	run(first)
	mu.Lock()
	if len(got) != 2 {
		t.Fatalf("sent again: %d", len(got))
	}
	mu.Unlock()
	// After the settle time the recent one goes too.
	later := t0.Add(30*time.Second + siem.Settle + time.Second)
	run(later)
	mu.Lock()
	if len(got) != 3 {
		t.Fatalf("after settle: %d", len(got))
	}
	status = 503
	mu.Unlock()

	// The SIEM is down: the error is recorded, the cursor stays, the sink waits.
	insert("detection.blocked", "warning", t0.Add(31*time.Second))
	insert("detection.blocked", "warning", t0.Add(32*time.Second))
	evenLater := t0.Add(32*time.Second + siem.Settle + time.Second)
	run(evenLater)
	list := h.expect(200, "GET", base, admin, "")
	row := list["data"].([]any)[0].(map[string]any)
	if row["failures"] != float64(1) || !strings.Contains(row["last_error"].(string), "503") || row["delivered"] != float64(3) {
		t.Fatalf("after a failure: %v", row)
	}
	// Turned on again by an update: due now, the missed events go out.
	mu.Lock()
	status = 200
	mu.Unlock()
	h.expect(200, "PUT", base+"/"+id, admin, jsonBody(map[string]any{"name": "SOC", "kind": "http",
		"config": map[string]any{"url": srv.URL}, "secret_env": "SIEM_TEST_TOKEN", "allow_private": true, "event_types": []string{"detection."}}))
	run(evenLater)
	mu.Lock()
	if len(got) != 5 {
		t.Fatalf("after recovery: %d", len(got))
	}
	mu.Unlock()

	// Test delivery, then delete.
	if res := h.expect(200, "POST", base+"/"+id+"/test", admin, ""); res["ok"] != true {
		t.Fatalf("test: %v", res)
	}
	mu.Lock()
	last := got[len(got)-1]
	mu.Unlock()
	if last["message"] != "alert.test" {
		t.Fatalf("test record: %v", last)
	}
	h.expect(204, "DELETE", base+"/"+id, admin, "")
	if st, _ := h.do("DELETE", base+"/"+id, admin, ""); st != 404 {
		t.Fatalf("deleted twice: %d", st)
	}
}
