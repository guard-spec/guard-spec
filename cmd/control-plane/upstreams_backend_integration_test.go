// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/auth"
)

// A custom backend is stored with its configuration, normalized, and can
// never become a chat upstream: not a default, not a route target.
func TestCustomBackendUpstream(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String()
	web := h.project(org, "web")

	status, body := h.do("POST", base+"/upstreams", admin, `{"name":"search","base_url":"http://search:8080/api",
		"provider":"custom","backend":{"path_prefixes":["/v1/search/"],"methods":["post"],
		"scan":{"request":["$.query","$.filters.*"],"response":["$.results[*].snippet"]}}}`)
	if status != 201 {
		t.Fatalf("create: %d %v", status, body)
	}
	id := body["id"].(string)
	b := body["backend"].(map[string]any)
	if b["path_prefixes"].([]any)[0] != "/v1/search" || b["methods"].([]any)[0] != "POST" ||
		b["scan"].(map[string]any)["request"].([]any)[1] != "$.filters[*]" {
		t.Errorf("backend not normalized: %v", b)
	}

	for _, bad := range []struct{ body, want string }{
		{`{"name":"b2","base_url":"http://x","provider":"custom"}`, "backend is required"},
		{`{"name":"b2","base_url":"http://x","provider":"custom","backend":{"path_prefixes":["/"],"scan":{"request":["q"]}}}`,
			"backend.scan.request[0]"},
		{`{"name":"b2","base_url":"http://x","provider":"custom","backend":{"path_prefixes":["/"],"methods":["TRACE"],
			"scan":{"all_strings":true}}}`, "backend.methods"},
		{`{"name":"b2","base_url":"http://x","backend":{"path_prefixes":["/"],"scan":{"all_strings":true}}}`,
			"only used with provider custom"},
	} {
		if status, body := h.do("POST", base+"/upstreams", admin, bad.body); status != 400 ||
			!strings.Contains(body["error"].(string), bad.want) {
			t.Errorf("%s: %d %v", bad.body, status, body)
		}
	}

	// Never a chat upstream.
	if status, body := h.do("PUT", base+"/default-upstream", admin, `{"upstream_id":"`+id+`"}`); status != 400 ||
		!strings.Contains(body["error"].(string), "custom backend") {
		t.Errorf("org default: %d %v", status, body)
	}
	if status, body := h.do("PUT", base+"/projects/"+web.String()+"/default-upstream", admin,
		`{"upstream_id":"`+id+`"}`); status != 400 {
		t.Errorf("project default: %d %v", status, body)
	}
	cond := `{"field":"injection.score","operator":">","value":0.5}`
	if status, body := h.do("POST", base+"/policies", admin,
		`{"name":"p","rules":[{"name":"r","action":"route","route_target":"search","condition":`+cond+`}]}`); status != 400 ||
		!strings.Contains(body["error"].(string), "custom backend") {
		t.Errorf("route target: %d %v", status, body)
	}

	// A model upstream in use cannot turn into a custom backend.
	status, body = h.do("POST", base+"/upstreams", admin, `{"name":"chat","base_url":"http://ollama:11434/v1"}`)
	if status != 201 {
		t.Fatalf("chat upstream: %d %v", status, body)
	}
	chatID := body["id"].(string)
	if status, body := h.do("PUT", base+"/default-upstream", admin, `{"upstream_id":"`+chatID+`"}`); status != 200 {
		t.Fatalf("default: %d %v", status, body)
	}
	if status, body := h.do("PUT", base+"/upstreams/"+chatID, admin,
		`{"provider":"custom","backend":{"path_prefixes":["/"],"scan":{"all_strings":true}}}`); status != 409 {
		t.Errorf("default turned custom: %d %v", status, body)
	}

	// Edits keep the backend unless it is sent; leaving custom drops it.
	if status, body := h.do("PUT", base+"/upstreams/"+id, admin, `{"display_name":"Search API"}`); status != 200 ||
		body["backend"] == nil {
		t.Errorf("edit: %d %v", status, body)
	}
	if status, body := h.do("PUT", base+"/upstreams/"+id, admin, `{"provider":"openai_compatible"}`); status != 200 ||
		body["backend"] != nil {
		t.Errorf("to openai_compatible: %d %v", status, body)
	}
}

// Config as code keeps a custom backend: applied from a file, exported with
// its provider and backend, re-applied as a no-op; a file that drops its
// provider is refused and the stored backend stays.
func TestConfigApplyCustomBackend(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	path := "/v1/organizations/" + org.String() + "/config"
	status, body := h.raw("PUT", path, admin, "text/yaml", backendYAML)
	var res struct {
		Changes []configChange `json:"changes"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &res) != nil || len(res.Changes) != 3 {
		t.Fatalf("apply: %d %s", status, body)
	}
	backendOf := func() map[string]any {
		_, list := h.do("GET", "/v1/organizations/"+org.String()+"/upstreams", admin, "")
		for _, u := range list["data"].([]any) {
			if m := u.(map[string]any); m["name"] == "search" {
				if m["provider"] != "custom" {
					t.Fatalf("search: %v", m)
				}
				return m["backend"].(map[string]any)
			}
		}
		t.Fatal("search not stored")
		return nil
	}
	if b := backendOf(); b["path_prefixes"].([]any)[0] != "/search" {
		t.Errorf("backend %v", b)
	}
	status, exported := h.raw("GET", path, admin, "", "")
	if status != 200 || !strings.Contains(exported, "provider: custom") {
		t.Fatalf("export: %d %s", status, exported)
	}
	if status, body := h.raw("PUT", path, admin, "text/yaml", exported); status != 200 ||
		json.Unmarshal([]byte(body), &res) != nil || len(res.Changes) != 0 {
		t.Errorf("re-apply: %d %s", status, body)
	}
	plain := strings.Replace(backendYAML, "    provider: custom\n", "", 1)
	plain = plain[:strings.Index(plain, "    backend:")] + "policies: []\n"
	if status, body := h.raw("PUT", path, admin, "text/yaml", plain); status != 422 || !strings.Contains(body, "keep provider: custom") {
		t.Errorf("downgrade: %d %s", status, body)
	}
	if status, body := h.raw("PUT", path, admin, "text/yaml",
		strings.Replace(backendYAML, "default_upstream: main", "default_upstream: search", 1)); status != 422 {
		t.Errorf("default: %d %s", status, body)
	}
	if b := backendOf(); b["scan"].(map[string]any)["request"].([]any)[0] != "$.query" {
		t.Errorf("backend changed: %v", b)
	}
}
