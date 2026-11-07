//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	appconfig "github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires the compose stack (migrations through 019). /v1/responses and
// /v1/embeddings go to a named upstream read from the database, with its key
// as a bearer token and its model allowlist; a policy rule sees tool outputs
// as on the chat path; previous_response_id is refused and flagged in the
// audit row; an org whose default upstream is ollama gets a 400 naming it on
// /v1/responses, while its embeddings go through. No row stores content.
func TestResponsesAndEmbeddingsNamedUpstream(t *testing.T) {
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

	up := newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/embeddings") {
			embeddingsUpstream(w, r)
			return
		}
		responseJSON(w, responseObject(textItem("Hello from the fake upstream, mail me at a@corp.vn.")))
	})

	org, other := uuid.New(), uuid.New()
	key, otherKey := "gs_"+strings.ReplaceAll(uuid.NewString(), "-", ""), "gs_"+strings.ReplaceAll(uuid.NewString(), "-", "")
	setup := func(orgID uuid.UUID, provider, apiKey string) {
		t.Helper()
		err := tenant.WithOrg(ctx, db, orgID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'r',$2)`, orgID, orgID.String()); err != nil {
				return err
			}
			var upID uuid.UUID
			if err := tx.QueryRow(ctx, `INSERT INTO upstreams (org_id, name, base_url, api_key_env, provider, models)
				VALUES ($1, 'oai', $2, 'UPSTREAM_KEY_RFTEST', $3, '{gpt-x,emb}') RETURNING id`,
				orgID, up.URL+"/v1", provider).Scan(&upID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE organizations SET default_upstream_id = $1 WHERE id = $2`, upID, orgID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO api_keys (key_hash, key_prefix, org_id) VALUES ($1, $2, $3)`,
				tenant.HashKey(apiKey), apiKey[:11], orgID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO policies (org_id, name, rules) VALUES ($1, 'no-tools', $2)`, orgID,
				`[{"id":"`+uuid.NewString()+`","name":"mcp","action":"block","condition":{"field":"mcp.is_tool_response","operator":"==","value":true}}]`)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	setup(org, "openai", key)
	setup(other, "ollama", otherKey)

	runner, err := inference.NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	keyOrgs, err := appconfig.ParseKeyOrgs("UPSTREAM_KEY_RFTEST=" + org.String() + "," + other.String())
	if err != nil {
		t.Fatal(err)
	}
	gw := testGateway(t, runner)
	gw.policies = dbPolicyLoader(db)
	gw.policyRoutes = dbPolicyRouteLoader(db)
	gw.upstreams = dbUpstreamLoader(db)
	gw.pool = newUpstreamPool(poolConfig{allowPrivate: true, keyOrgs: keyOrgs,
		getenv: func(k string) string {
			if k == "UPSTREAM_KEY_RFTEST" {
				return "sk-fake-integration"
			}
			return ""
		}})
	gw.audit = newAuditLog(func(e requestEntry) { logRequest(db, false, e) })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(gw, dbKeyLookup(db))
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(time.Second) })
	h := &harness{url: "http://" + ln.Addr().String(), gw: gw}
	auth := func(k string) map[string]string {
		return map[string]string{"x-api-key": "", "Authorization": "Bearer " + k}
	}

	// Allowed, guarded on the way back.
	resp, got := h.post(t, "/v1/responses", `{"model":"gpt-x","input":"hello"}`, auth(key))
	if resp.StatusCode != 200 || !strings.Contains(got, "fake upstream") || strings.Contains(got, "a@corp.vn") {
		t.Fatalf("allowed: %d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	path, bearer := up.path, up.headers.Get("Authorization")
	up.mu.Unlock()
	if path != "/v1/responses" || bearer != "Bearer sk-fake-integration" {
		t.Errorf("upstream path %s auth %q", path, bearer)
	}
	// Tool outputs are tool responses for policies.
	resp, got = h.post(t, "/v1/responses", `{"model":"gpt-x","input":[{"type":"function_call_output","call_id":"c","output":"22 degrees"}]}`, auth(key))
	if out := assertOpenAIError(t, resp, got, 400, "content_filter"); !strings.Contains(out.Error.Message, "policy") {
		t.Errorf("policy block: %s", got)
	}
	// Conversation state the upstream keeps is refused.
	resp, got = h.post(t, "/v1/responses", `{"model":"gpt-x","previous_response_id":"resp_1","input":"more"}`, auth(key))
	assertOpenAIError(t, resp, got, 400, "server_state_refused")
	// The model allowlist applies.
	resp, got = h.post(t, "/v1/responses", `{"model":"gpt-other","input":"hello"}`, auth(key))
	assertOpenAIError(t, resp, got, 400, "model_not_allowed")
	// Embeddings: forwarded with the same key and allowlist.
	resp, got = h.post(t, "/v1/embeddings", `{"model":"emb","input":"hello"}`, auth(key))
	if resp.StatusCode != 200 || !strings.Contains(got, `"embedding"`) {
		t.Errorf("embeddings: %d %s", resp.StatusCode, got)
	}
	// An ollama upstream: /v1/responses refused with its name, embeddings pass.
	resp, got = h.post(t, "/v1/responses", `{"model":"gpt-x","input":"hello"}`, auth(otherKey))
	if out := assertOpenAIError(t, resp, got, 400, "unsupported_upstream"); !strings.Contains(out.Error.Message, `"oai"`) {
		t.Errorf("other provider: %s", got)
	}
	resp, got = h.post(t, "/v1/embeddings", `{"model":"emb","input":"hello"}`, auth(otherKey))
	if resp.StatusCode != 200 {
		t.Errorf("ollama embeddings: %d %s", resp.StatusCode, got)
	}

	gw.audit.wait()
	type row struct {
		action      string
		target      *string
		tags        []string
		reqHash     *string
		reqContent  *string
		respContent *string
	}
	var rows []row
	err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT action, route_target, pii_entities, request_sha256, request_content, response_content
			FROM requests WHERE org_id = $1`, org)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var x row
			if err := r.Scan(&x.action, &x.target, &x.tags, &x.reqHash, &x.reqContent, &x.respContent); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return r.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	serverState := 0
	for _, r := range rows {
		count[r.action]++
		if r.reqHash == nil || r.reqContent != nil || r.respContent != nil {
			t.Errorf("%s row: hash %v, content stored", r.action, r.reqHash)
		}
		if r.action == actionAllow && (r.target == nil || *r.target != "oai") {
			t.Errorf("allowed row target %v", r.target)
		}
		if slices.Contains(r.tags, "input:server_state=1") {
			serverState++
		}
	}
	if len(rows) != 5 || count[actionAllow] != 2 || count[actionBlock] != 3 || serverState != 1 {
		t.Errorf("rows %v, server_state rows %d", count, serverState)
	}
}
