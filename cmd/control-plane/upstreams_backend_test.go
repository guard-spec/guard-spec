// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/backend"
)

func customUpstream(t *testing.T, body string) upstream {
	t.Helper()
	var u upstream
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestValidateCustomBackend(t *testing.T) {
	u := customUpstream(t, `{"name":"search","base_url":"https://search.internal.example/api","provider":"custom",
		"api_key_env":"UPSTREAM_KEY_SEARCH","backend":{"path_prefixes":["/search/"],"methods":["post","get"],
		"scan":{"request":["$.query"],"response":["$.results[*].snippet"]}}}`)
	if err := u.validate(); err != nil {
		t.Fatal(err)
	}
	if u.Backend.PathPrefixes[0] != "/search" || u.Backend.Methods[0] != "POST" {
		t.Errorf("not normalized: %+v", u.Backend)
	}

	tests := []struct {
		name, body, want string
	}{
		{"backend missing", `{"name":"b","base_url":"http://a","provider":"custom"}`, "backend is required"},
		{"backend on a model provider", `{"name":"b","base_url":"http://a","provider":"openai",
			"backend":{"path_prefixes":["/"],"scan":{"all_strings":true}}}`, "only used with provider custom"},
		{"no scan", `{"name":"b","base_url":"http://a","provider":"custom","backend":{"path_prefixes":["/"]}}`,
			"backend.scan.request"},
		{"bad jsonpath", `{"name":"b","base_url":"http://a","provider":"custom",
			"backend":{"path_prefixes":["/"],"scan":{"request":["$..q"]}}}`, "recursive descent"},
		{"models", `{"name":"b","base_url":"http://a","provider":"custom","models":["m"],
			"backend":{"path_prefixes":["/"],"scan":{"all_strings":true}}}`, "has no models"},
		{"retries", `{"name":"b","base_url":"http://a","provider":"custom","retries":1,
			"backend":{"path_prefixes":["/"],"scan":{"all_strings":true}}}`, "retries must be 0"},
		{"metadata address", `{"name":"b","base_url":"http://169.254.169.254","provider":"custom",
			"backend":{"path_prefixes":["/"],"scan":{"all_strings":true}}}`, "base_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := customUpstream(t, tt.body)
			if err := u.validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPatchBackend(t *testing.T) {
	u := upstream{Provider: backend.Provider, Backend: &backend.Config{PathPrefixes: []string{"/"}}}
	var keep upstreamPatch
	_ = json.Unmarshal([]byte(`{"enabled":false}`), &keep)
	keep.apply(&u)
	if u.Backend == nil {
		t.Fatal("an absent backend cleared the stored one")
	}
	var toOpenAI upstreamPatch
	_ = json.Unmarshal([]byte(`{"provider":"openai"}`), &toOpenAI)
	toOpenAI.apply(&u)
	if u.Backend != nil {
		t.Error("changing the provider kept the backend")
	}
	var set upstreamPatch
	_ = json.Unmarshal([]byte(`{"provider":"custom","backend":{"path_prefixes":["/x"]}}`), &set)
	set.apply(&u)
	if u.Backend == nil || u.Backend.PathPrefixes[0] != "/x" {
		t.Errorf("backend = %+v", u.Backend)
	}
	var clear upstreamPatch
	_ = json.Unmarshal([]byte(`{"backend":null}`), &clear)
	clear.apply(&u)
	if u.Backend != nil {
		t.Error("null did not clear the backend")
	}
}
