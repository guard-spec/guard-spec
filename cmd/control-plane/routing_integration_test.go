//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/config"
	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// raw sends a request with a raw body and returns the status and body.
func (h *cpHarness) raw(method, path, token, contentType, body string) (int, string) {
	h.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.app.Test(req, -1)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func (h *cpHarness) project(org uuid.UUID, slug string) uuid.UUID {
	h.t.Helper()
	id := uuid.New()
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO projects (id, org_id, name, slug) VALUES ($1,$2,$3,$3)`, id, org, slug)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *cpHarness) member(org uuid.UUID, role auth.Role) string {
	h.t.Helper()
	ctx := context.Background()
	var user uuid.UUID
	err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`,
			uuid.NewString()+"@example.com").Scan(&user); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1,$2,$3::org_role)`,
			user, org, string(role))
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	token, err := h.sessionToken(user)
	if err != nil {
		h.t.Fatal(err)
	}
	return token
}

func TestUpstreamsAndDefaults(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	viewer := h.member(org, auth.RoleViewer)
	base := "/v1/organizations/" + org.String()
	web := h.project(org, "web")

	status, body := h.do("POST", base+"/upstreams", admin,
		`{"name":"safe-model","base_url":"http://ollama:11434/v1","model":"qwen3:4b","api_key_env":"UPSTREAM_KEY_SAFE"}`)
	if status != 201 || body["timeout_ms"].(float64) != defaultTimeoutMs || body["enabled"] != true {
		t.Fatalf("create: %d %v", status, body)
	}
	safeID := body["id"].(string)
	if _, leaked := body["api_key"]; leaked {
		t.Error("response has a key field")
	}
	for _, bad := range []string{
		`{"name":"Bad Name","base_url":"http://a/v1"}`,
		`{"name":"x","base_url":"http://169.254.169.254/v1"}`,
		`{"name":"x","base_url":"http://user:pw@a/v1"}`,
		`{"name":"x","base_url":"http://a/v1","api_key_env":"JWT_SECRET"}`,
		`{"name":"x","base_url":"http://a/v1","timeout_ms":10}`,
	} {
		if status, body := h.do("POST", base+"/upstreams", admin, bad); status != 400 {
			t.Errorf("%s: %d %v", bad, status, body)
		}
	}
	if status, _ := h.do("POST", base+"/upstreams", admin, `{"name":"safe-model","base_url":"http://b/v1"}`); status != 409 {
		t.Errorf("duplicate name: %d", status)
	}
	if status, _ := h.do("POST", base+"/upstreams", viewer, `{"name":"v","base_url":"http://b/v1"}`); status != 403 {
		t.Errorf("viewer create: %d", status)
	}
	if status, body := h.do("GET", base+"/upstreams", viewer, ""); status != 200 || len(body["data"].([]any)) != 1 {
		t.Errorf("viewer list: %d %v", status, body)
	}

	// Defaults.
	if status, body := h.do("PUT", base+"/default-upstream", admin, `{"upstream_id":"`+safeID+`"}`); status != 200 {
		t.Fatalf("org default: %d %v", status, body)
	}
	if status, body := h.do("PUT", base+"/projects/"+web.String()+"/default-upstream", admin,
		`{"upstream_id":"`+safeID+`"}`); status != 200 {
		t.Fatalf("project default: %d %v", status, body)
	}
	if status, _ := h.do("PUT", base+"/default-upstream", admin, `{}`); status != 400 {
		t.Errorf("missing upstream_id: %d", status)
	}
	if status, _ := h.do("PUT", base+"/projects/"+uuid.NewString()+"/default-upstream", admin, `{"upstream_id":null}`); status != 404 {
		t.Errorf("unknown project: %d", status)
	}
	if _, body := h.do("GET", base, viewer, ""); body["default_upstream_id"] != safeID {
		t.Errorf("org: %v", body)
	}
	_, body = h.do("GET", base+"/projects", viewer, "")
	if p := body["data"].([]any)[0].(map[string]any); p["default_upstream_id"] != safeID {
		t.Errorf("projects: %v", body)
	}

	// Another org cannot use this upstream.
	other, _, otherAdmin := h.org(auth.RoleAdmin)
	if status, _ := h.do("PUT", "/v1/organizations/"+other.String()+"/default-upstream", otherAdmin,
		`{"upstream_id":"`+safeID+`"}`); status != 400 {
		t.Errorf("foreign upstream as default: %d", status)
	}

	// A route rule must name an upstream of the org.
	cond := `{"field":"injection.score","operator":">","value":0.5}`
	if status, body := h.do("POST", base+"/policies", admin,
		`{"name":"p","rules":[{"name":"r","action":"route","route_target":"nowhere","condition":`+cond+`}]}`); status != 400 ||
		!strings.Contains(body["error"].(string), "nowhere") {
		t.Errorf("unknown target: %d %v", status, body)
	}
	if status, body := h.do("POST", "/v1/organizations/"+other.String()+"/policies", otherAdmin,
		`{"name":"p","rules":[{"name":"r","action":"route","route_target":"safe-model","condition":`+cond+`}]}`); status != 400 {
		t.Errorf("other org's upstream as target: %d %v", status, body)
	}
	status, body = h.do("POST", base+"/policies", admin,
		`{"name":"routing","rules":[{"name":"to safe","action":"route","route_target":"safe-model","condition":`+cond+`}]}`)
	if status != 201 {
		t.Fatalf("route policy: %d %v", status, body)
	}
	policyID := body["id"].(string)

	// Delete and rename are refused while it is used; the 409 names the users.
	status, body = h.do("DELETE", base+"/upstreams/"+safeID, admin, "")
	if status != 409 {
		t.Fatalf("delete in use: %d %v", status, body)
	}
	refs := body["references"].([]any)
	kinds := map[string]bool{}
	for _, r := range refs {
		kinds[r.(map[string]any)["kind"].(string)] = true
	}
	if !kinds["rule"] || !kinds["org_default"] || !kinds["project_default"] ||
		!strings.Contains(body["error"].(string), `rule "to safe"`) || !strings.Contains(body["error"].(string), `"web"`) {
		t.Errorf("references: %v", body)
	}
	if status, body := h.do("PUT", base+"/upstreams/"+safeID, admin, `{"name":"renamed"}`); status != 409 {
		t.Errorf("rename in use: %d %v", status, body)
	}
	// Disabling keeps references; the gateway then fails closed.
	if status, body := h.do("PUT", base+"/upstreams/"+safeID, admin, `{"enabled":false,"model":""}`); status != 200 ||
		body["enabled"] != false || body["model"] != "" || body["base_url"] != "http://ollama:11434/v1" {
		t.Errorf("disable: %d %v", status, body)
	}

	// Once nothing uses it, it goes.
	h.do("DELETE", base+"/policies/"+policyID, admin, "")
	h.do("PUT", base+"/default-upstream", admin, `{"upstream_id":null}`)
	h.do("PUT", base+"/projects/"+web.String()+"/default-upstream", admin, `{"upstream_id":null}`)
	if status, body := h.do("DELETE", base+"/upstreams/"+safeID, admin, ""); status != 204 {
		t.Errorf("delete: %d %v", status, body)
	}
	if status, _ := h.do("DELETE", base+"/upstreams/"+safeID, admin, ""); status != 404 {
		t.Errorf("delete again: %d", status)
	}
}

func TestConfigApply(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	viewer := h.member(org, auth.RoleViewer)
	h.project(org, "web")
	path := "/v1/organizations/" + org.String() + "/config"

	if status, _ := h.raw("PUT", path, viewer, "text/yaml", contractYAML); status != 403 {
		t.Errorf("viewer put: %d", status)
	}

	// Dry run reports and writes nothing.
	status, body := h.raw("PUT", path+"?dry_run=true", admin, "text/yaml", contractYAML)
	var res struct {
		Applied bool           `json:"applied"`
		Changes []configChange `json:"changes"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &res) != nil || res.Applied || len(res.Changes) != 4 {
		t.Fatalf("dry run: %d %s", status, body)
	}
	if _, upstreams := h.do("GET", "/v1/organizations/"+org.String()+"/upstreams", admin, ""); len(upstreams["data"].([]any)) != 0 {
		t.Fatal("dry run wrote upstreams")
	}

	status, body = h.raw("PUT", path, admin, "application/yaml", contractYAML)
	if status != 200 || json.Unmarshal([]byte(body), &res) != nil || !res.Applied || len(res.Changes) != 4 {
		t.Fatalf("apply: %d %s", status, body)
	}
	ruleIDs := func() map[string]string {
		_, list := h.do("GET", "/v1/organizations/"+org.String()+"/policies", admin, "")
		out := map[string]string{}
		for _, p := range list["data"].([]any) {
			for _, r := range p.(map[string]any)["rules"].([]any) {
				rule := r.(map[string]any)
				out[rule["name"].(string)] = rule["id"].(string)
			}
		}
		return out
	}
	before := ruleIDs()
	if len(before) != 2 {
		t.Fatalf("rules = %v", before)
	}

	// The exported file applies as a no-op.
	status, exported := h.raw("GET", path, viewer, "", "")
	if status != 200 || !strings.Contains(exported, "route_target: safe-model") ||
		!strings.Contains(exported, "default_upstream: main") {
		t.Fatalf("export: %d %s", status, exported)
	}
	status, body = h.raw("PUT", path, admin, "text/yaml", exported)
	if status != 200 || json.Unmarshal([]byte(body), &res) != nil || len(res.Changes) != 0 {
		t.Errorf("re-apply export: %d %s", status, body)
	}

	// Edit: drop upstream main and the org default, change one rule, add a
	// project default. The unchanged rule keeps its ID; the changed one too.
	edited := `version: 1
default_upstream: null
project_defaults:
  web: safe-model
upstreams:
  - name: safe-model
    base_url: http://ollama:11434/v1
    model: qwen3:4b
policies:
  - name: block-injection
    project: web
    rules:
      - name: high l2
        when: scores.l2 > 0.95
        action: block
      - name: suspicious to safe model
        when: injection.score > 0.5
        action: route
        route_target: safe-model
  - name: second
    rules:
      - name: log all
        when: request.tokens >= 0
        action: log
`
	status, body = h.raw("PUT", path, admin, "text/yaml", edited)
	if status != 200 || json.Unmarshal([]byte(body), &res) != nil {
		t.Fatalf("edit: %d %s", status, body)
	}
	got := map[configChange]bool{}
	for _, c := range res.Changes {
		got[c] = true
	}
	for _, want := range []configChange{{"upstream", "main", "delete"}, {"default", "org", "delete"},
		{"default", "project:web", "create"}, {"policy", "block-injection", "update"}, {"policy", "second", "create"}} {
		if !got[want] {
			t.Errorf("missing %+v in %+v", want, res.Changes)
		}
	}
	after := ruleIDs()
	if after["high l2"] != before["high l2"] || after["suspicious to safe model"] != before["suspicious to safe model"] {
		t.Errorf("rule ids changed: %v -> %v", before, after)
	}
	_, upstreams := h.do("GET", "/v1/organizations/"+org.String()+"/upstreams", admin, "")
	if list := upstreams["data"].([]any); len(list) != 1 || list[0].(map[string]any)["name"] != "safe-model" {
		t.Errorf("upstreams: %v", list)
	}

	// Deleting everything: an empty file.
	status, body = h.raw("PUT", path, admin, "text/yaml", "version: 1\nupstreams: []\npolicies: []\n")
	if status != 200 || json.Unmarshal([]byte(body), &res) != nil {
		t.Fatalf("empty: %d %s", status, body)
	}
	if _, list := h.do("GET", "/v1/organizations/"+org.String()+"/policies", admin, ""); len(list["data"].([]any)) != 0 {
		t.Errorf("policies left: %v", list)
	}

	// Errors: 422 with paths, nothing written.
	status, body = h.raw("PUT", path, admin, "text/yaml", `version: 1
upstreams: []
policies:
  - name: p
    project: nope
    rules:
      - name: r
        when: scores.l2 > 0.5
        action: route
        route_target: ghost
`)
	var bad struct {
		Errors []configError `json:"errors"`
	}
	if status != 422 || json.Unmarshal([]byte(body), &bad) != nil || len(bad.Errors) == 0 ||
		bad.Errors[0].Path != "policies[0].rules[0].route_target" {
		t.Errorf("invalid: %d %s", status, body)
	}
	status, body = h.raw("PUT", path, admin, "text/yaml", "version: 1\nupstreams: []\npolicies:\n  - name: p\n    project: nope\n    rules: []\n")
	if status != 422 || !strings.Contains(body, "policies[0].project") {
		t.Errorf("unknown project: %d %s", status, body)
	}
}

func TestSimulateEndpoint(t *testing.T) {
	h := newCPHarness(t)
	h.app = newApp(h.db, testSecret, mustEngine(t), "", withEnvUpstream("http://env-llm:8000/v1"), withKeyOrgs(testKeyOrgs))
	org, _, admin := h.org(auth.RoleAdmin)
	viewer := h.member(org, auth.RoleViewer)
	web := h.project(org, "web")
	base := "/v1/organizations/" + org.String()
	status, created := h.do("POST", base+"/upstreams", admin, `{"name":"safe-model","base_url":"http://ollama:11434/v1"}`)
	if status != 201 {
		t.Fatal(created)
	}
	h.do("POST", base+"/upstreams", admin, `{"name":"proj","base_url":"http://proj:1/v1"}`)
	status, p := h.do("POST", base+"/policies", admin, `{"name":"routing","rules":[
		{"name":"log high","action":"log","condition":{"field":"scores.l2","operator":">","value":0.5}},
		{"name":"jailbreak to safe","action":"route","route_target":"safe-model",
		 "condition":{"field":"injection.category","operator":"=","value":"jailbreak"}},
		{"name":"block high","action":"block","condition":{"field":"scores.l2","operator":">","value":0.9}}]}`)
	if status != 201 {
		t.Fatal(p)
	}

	sim := func(body string) map[string]any {
		t.Helper()
		status, out := h.do("POST", base+"/policies/simulate", viewer, body)
		if status != 200 {
			t.Fatalf("simulate %s: %d %v", body, status, out)
		}
		return out
	}
	out := sim(`{"vars":{"scores.l2":0.91,"injection.category":"jailbreak","request.model":"gpt-4o"}}`)
	trace := out["trace"].([]any)
	if len(trace) != 3 {
		t.Fatalf("trace = %v", trace)
	}
	for i, want := range []bool{true, true, true} {
		if trace[i].(map[string]any)["matched"] != want {
			t.Errorf("trace[%d] = %v", i, trace[i])
		}
	}
	d := out["decision"].(map[string]any)
	up := out["upstream"].(map[string]any)
	if d["action"] != "route" || d["route_target"] != "safe-model" || up["source"] != "rule" ||
		up["name"] != "safe-model" || up["base_url"] != "http://ollama:11434/v1" {
		t.Errorf("route: %v", out)
	}

	// No match: env, then the project default once set.
	out = sim(`{"vars":{"scores.l2":0.1}}`)
	if out["decision"].(map[string]any)["action"] != "allow" || out["upstream"].(map[string]any)["source"] != "env" {
		t.Errorf("env: %v", out)
	}
	_, list := h.do("GET", base+"/upstreams", admin, "")
	var projID string
	for _, u := range list["data"].([]any) {
		if u.(map[string]any)["name"] == "proj" {
			projID = u.(map[string]any)["id"].(string)
		}
	}
	h.do("PUT", base+"/projects/"+web.String()+"/default-upstream", admin, `{"upstream_id":"`+projID+`"}`)
	out = sim(`{"project_id":"` + web.String() + `","vars":{"scores.l2":0.1}}`)
	if up := out["upstream"].(map[string]any); up["source"] != "project" || up["name"] != "proj" {
		t.Errorf("project default: %v", out)
	}

	// Unsaved rules, with a target that does not exist.
	out = sim(`{"rules":[{"name":"x","action":"route","route_target":"ghost",
		"condition":{"field":"scores.l2","operator":">","value":0.5}}],"vars":{"scores.l2":0.9}}`)
	if up := out["upstream"].(map[string]any); up["source"] != "rule" || up["error"] == "" || up["name"] != "ghost" {
		t.Errorf("ghost target: %v", out)
	}
	// Block: no upstream.
	out = sim(`{"policy_id":"` + p["id"].(string) + `","vars":{"scores.l2":0.95}}`)
	if out["decision"].(map[string]any)["action"] != "block" || out["upstream"] != nil {
		t.Errorf("block: %v", out)
	}
	if status, _ := h.do("POST", base+"/policies/simulate", viewer, `{"vars":{"nope":1}}`); status != 400 {
		t.Errorf("unknown var: %d", status)
	}
	if status, _ := h.do("POST", base+"/policies/simulate", viewer, `{"policy_id":"`+uuid.NewString()+`","vars":{}}`); status != 404 {
		t.Errorf("unknown policy: %d", status)
	}
}

func mustEngine(t *testing.T) *policy.Engine {
	t.Helper()
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestRequestsListRouteTarget(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO requests (org_id, action, route_target, injection_score, toxicity_score, anomaly_score,
			   had_tag_chars, had_bidi)
			 VALUES ($1, 'route', 'safe-model', 0, 0, 0, false, false), ($1, 'allow', NULL, 0, 0, 0, false, false)`, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body := h.do("GET", "/v1/organizations/"+org.String()+"/requests", admin, "")
	targets := map[any]bool{}
	for _, r := range body["data"].([]any) {
		row := r.(map[string]any)
		if _, ok := row["route_target"]; !ok {
			t.Errorf("row lacks route_target: %v", row)
		}
		targets[row["route_target"]] = true
	}
	if !targets["safe-model"] || !targets[nil] {
		t.Errorf("targets = %v", targets)
	}
}

// acmeOrg is the only org allowed UPSTREAM_KEY_ACME in the tests.
var acmeOrg = uuid.MustParse("00000000-0000-0000-0000-00000000acee")

var testKeyOrgs = config.MustParseKeyOrgs("UPSTREAM_KEY_SAFE=*;UPSTREAM_KEY_MAIN=*;UPSTREAM_KEY_ACME=" + acmeOrg.String())

// Any user can create an org; it must not get to send another org's (or the
// operator's) key to a base_url it controls.
func TestUpstreamKeyAllowlist(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()

	status, body := h.do("POST", base+"/upstreams", admin,
		`{"name":"steal","base_url":"https://attacker.example/v1","api_key_env":"UPSTREAM_KEY_ACME"}`)
	if status != 400 || !strings.Contains(body["error"].(string), "UPSTREAM_KEY_ORGS") {
		t.Errorf("other org's key: %d %v", status, body)
	}
	if status, body := h.do("POST", base+"/upstreams", admin,
		`{"name":"unlisted","base_url":"https://a.example/v1","api_key_env":"UPSTREAM_KEY_OTHER"}`); status != 400 {
		t.Errorf("unlisted key: %d %v", status, body)
	}
	status, created := h.do("POST", base+"/upstreams", admin, `{"name":"nokey","base_url":"https://a.example/v1"}`)
	if status != 201 {
		t.Fatalf("no key: %d %v", status, created)
	}
	if status, body := h.do("PUT", base+"/upstreams/"+created["id"].(string), admin,
		`{"api_key_env":"UPSTREAM_KEY_ACME"}`); status != 400 {
		t.Errorf("update to other org's key: %d %v", status, body)
	}

	status, out := h.raw("PUT", base+"/config", admin, "text/yaml",
		"version: 1\nupstreams:\n  - name: steal\n    base_url: https://attacker.example/v1\n    api_key_env: UPSTREAM_KEY_ACME\npolicies: []\n")
	if status != 422 || !strings.Contains(out, "upstreams[0].api_key_env") {
		t.Errorf("config with other org's key: %d %s", status, out)
	}
}

func TestPolicyNamesAndExportConflicts(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	cond := `{"field":"scores.l2","operator":">","value":0.5}`
	status, first := h.do("POST", base+"/policies", admin, `{"name":"p","rules":[{"name":"r","action":"block","condition":`+cond+`}]}`)
	if status != 201 {
		t.Fatal(first)
	}
	if status, body := h.do("POST", base+"/policies", admin, `{"name":"p","rules":[]}`); status != 409 {
		t.Errorf("duplicate create: %d %v", status, body)
	}
	status, second := h.do("POST", base+"/policies", admin, `{"name":"q","rules":[]}`)
	if status != 201 {
		t.Fatal(second)
	}
	if status, body := h.do("PUT", base+"/policies/"+second["id"].(string), admin, `{"name":"p"}`); status != 409 {
		t.Errorf("rename onto another policy: %d %v", status, body)
	}
	if status, body := h.do("PUT", base+"/policies/"+first["id"].(string), admin, `{"name":"p","enabled":false}`); status != 200 {
		t.Errorf("keeping its own name: %d %v", status, body)
	}

	// Rows from before this check (or written directly) make the export 409.
	dup, legacy := uuid.New(), uuid.New()
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO policies (id, org_id, name, rules) VALUES
			($1, $3, 'p', '[]'),
			($2, $3, 'legacy', '[{"id":"`+uuid.NewString()+`","name":"toxic","action":"block","condition":{"field":"toxicity.score","operator":">","value":0.5}}]')`,
			dup, legacy, org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := h.do("GET", base+"/config", admin, "")
	problems, _ := body["problems"].([]any)
	if status != 409 || len(problems) != 2 {
		t.Fatalf("export: %d %v", status, body)
	}
	text, _ := json.Marshal(problems)
	if !strings.Contains(string(text), dup.String()) || !strings.Contains(string(text), "toxicity.score") ||
		!strings.Contains(string(text), "/policies/"+legacy.String()) {
		t.Errorf("problems = %s", text)
	}
	h.do("DELETE", base+"/policies/"+dup.String(), admin, "")
	h.do("DELETE", base+"/policies/"+legacy.String(), admin, "")
	if status, _ := h.raw("GET", base+"/config", admin, "", ""); status != 200 {
		t.Errorf("export after fixing: %d", status)
	}
}
