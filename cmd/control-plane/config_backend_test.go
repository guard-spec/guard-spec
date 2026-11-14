// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/backend"
	"gopkg.in/yaml.v3"
)

const backendYAML = `version: 1
default_upstream: main
upstreams:
  - name: main
    base_url: https://api.openai.com/v1
    api_key_env: UPSTREAM_KEY_MAIN
  - name: search
    base_url: http://search:8080/api
    provider: custom
    backend:
      path_prefixes: [/search]
      methods: [POST]
      scan:
        request: ["$.query"]
        response: ["$.results[*].snippet"]
        all_strings: false
        raw_text: false
policies: []
`

func storedSearch() upstream {
	return upstream{ID: uuid.New(), Name: "search", BaseURL: "http://search:8080/api", TimeoutMs: defaultTimeoutMs,
		Enabled: true, Provider: backend.Provider, Backend: &backend.Config{PathPrefixes: []string{"/search"},
			Methods: []string{"POST"}, Scan: backend.Scan{Request: []string{"$.query"},
				Response: []string{"$.results[*].snippet"}}}}
}

// A custom backend goes through the file with its provider and backend:
// an export applies as a no-op, and a change of its backend is an update.
func TestConfigCarriesCustomBackend(t *testing.T) {
	plan, errs := planFor(t, backendYAML)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if u := plan.upstreams[1]; u.Provider != backend.Provider || u.Backend == nil || u.Backend.Scan.Request[0] != "$.query" {
		t.Fatalf("plan upstream %+v", u)
	}
	mainID := uuid.New()
	stored := &storedConfig{orgDefault: &mainID, upstreams: []upstream{
		{ID: mainID, Name: "main", BaseURL: "https://api.openai.com/v1", APIKeyEnv: "UPSTREAM_KEY_MAIN",
			TimeoutMs: defaultTimeoutMs, Enabled: true, Provider: "openai"},
		storedSearch(),
	}}
	if errs := plan.checkBackends(stored); len(errs) > 0 {
		t.Fatal(errs)
	}
	if changes := plan.diff(stored); len(changes) != 0 {
		t.Errorf("changes = %+v", changes)
	}

	// The export round-trips.
	doc, err := stored.document()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := yaml.NewEncoder(&buf).Encode(doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "provider: custom") || strings.Count(buf.String(), "provider:") != 1 {
		t.Errorf("export:\n%s", buf.String())
	}
	again, errs := planFor(t, buf.String())
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if changes := again.diff(stored); len(changes) != 0 {
		t.Errorf("exported file changes %+v", changes)
	}

	edited, errs := planFor(t, strings.Replace(backendYAML, `request: ["$.query"]`, `request: ["$.query", "$.filters[*]"]`, 1))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if changes := edited.diff(stored); len(changes) != 1 || changes[0] != (configChange{"upstream", "search", "update"}) {
		t.Errorf("changes = %+v", changes)
	}
}

// A file can neither name a custom backend as a default or a route target,
// nor turn a stored custom backend into a model provider.
func TestConfigCustomBackendRefusals(t *testing.T) {
	cases := map[string]struct{ yaml, path, want string }{
		"org default": {strings.Replace(backendYAML, "default_upstream: main", "default_upstream: search", 1),
			"default_upstream", "is a custom backend"},
		"project default": {strings.Replace(backendYAML, "upstreams:", "project_defaults:\n  web: search\nupstreams:", 1),
			"project_defaults.web", "is a custom backend"},
		"route target": {strings.Replace(backendYAML, "policies: []", `policies:
  - name: p
    project: null
    rules:
      - name: r
        when: injection.score > 0.5
        action: route
        route_target: search`, 1), "policies[0].rules[0].route_target", "route rules can only name model providers"},
		"other provider": {strings.Replace(backendYAML, "provider: custom", "provider: openai", 1),
			"upstreams[1].provider", "only written for custom backends"},
		"no backend": {strings.Replace(backendYAML, "    backend:\n", "    unused:\n", 1), "", "yaml"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, errs := planFor(t, tc.yaml)
			found := false
			for _, e := range errs {
				if (tc.path == "" || e.Path == tc.path) && strings.Contains(e.Message, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("errors = %+v, want %s: %s", errs, tc.path, tc.want)
			}
		})
	}

	// The stored custom backend listed without its provider: refused, not downgraded.
	plain := strings.Replace(backendYAML, "    provider: custom\n", "", 1)
	plain = plain[:strings.Index(plain, "    backend:")] + "policies: []\n"
	plan, errs := planFor(t, plain)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	errs = plan.checkBackends(&storedConfig{upstreams: []upstream{storedSearch()}})
	if len(errs) != 1 || errs[0].Path != "upstreams[1]" || !strings.Contains(errs[0].Message, "keep provider: custom") {
		t.Errorf("errors = %+v", errs)
	}
}
