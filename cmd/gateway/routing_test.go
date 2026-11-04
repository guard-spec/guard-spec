package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/google/uuid"
)

// fakeUpstreams resolves like dbUpstreamLoader over in-memory rows.
type fakeUpstreams struct {
	rows           map[string]*upstreamRow
	projectDefault string
	orgDefault     string
	err            error
	gotProject     uuid.UUID
}

func (f *fakeUpstreams) add(name, baseURL string) *upstreamRow {
	if f.rows == nil {
		f.rows = map[string]*upstreamRow{}
	}
	u := &upstreamRow{ID: uuid.New(), Name: name, BaseURL: baseURL + "/v1", TimeoutMs: 30000,
		Enabled: true, UpdatedAt: time.Now()}
	f.rows[name] = u
	return u
}

func (f *fakeUpstreams) load(_ context.Context, _, project uuid.UUID, target string) (*upstreamRow, string, error) {
	f.gotProject = project
	if f.err != nil {
		return nil, "", f.err
	}
	if target != "" {
		u, ok := f.rows[target]
		if !ok {
			return nil, "", errNoSuchUpstream
		}
		return u, sourceRule, nil
	}
	if f.projectDefault != "" {
		return f.rows[f.projectDefault], sourceProject, nil
	}
	if f.orgDefault != "" {
		return f.rows[f.orgDefault], sourceOrg, nil
	}
	return nil, "", nil
}

func routeRule(target string) policy.Rule {
	r := rule(policy.ActionRoute, "request.model", "=", "m")
	r.RouteTarget = target
	return r
}

func withUpstreams(f *fakeUpstreams, env map[string]string, rules ...policy.Rule) func(*gateway) {
	return func(gw *gateway) {
		gw.upstreams = f.load
		gw.pool = newUpstreamPool(false, func(k string) string { return env[k] })
		withRules(rules...)(gw)
	}
}

func TestRouteResolutionOrder(t *testing.T) {
	ruleUp := newFakeUpstream(t, okUpstream)
	projUp := newFakeUpstream(t, okUpstream)
	orgUp := newFakeUpstream(t, okUpstream)
	envUp := newFakeUpstream(t, okUpstream)

	tests := []struct {
		name       string
		rules      []policy.Rule
		project    string
		org        string
		env        bool
		want       *fakeUpstream
		action     string
		target     string
		stubAnswer bool
	}{
		{"rule wins over defaults", []policy.Rule{routeRule("rule-up")}, "proj-up", "org-up", true, ruleUp, actionRoute, "rule-up", false},
		{"project default", nil, "proj-up", "org-up", true, projUp, actionAllow, "proj-up", false},
		{"org default", nil, "", "org-up", true, orgUp, actionAllow, "org-up", false},
		{"env", nil, "", "", true, envUp, actionAllow, "", false},
		{"stub", nil, "", "", false, nil, actionAllow, "", true},
		{"allow rule uses the defaults", []policy.Rule{rule(policy.ActionAllow, "request.model", "=", "m"),
			routeRule("rule-up")}, "", "org-up", true, orgUp, actionAllow, "org-up", false},
		{"log rule then route", []policy.Rule{rule(policy.ActionLog, "request.model", "=", "m"),
			routeRule("rule-up")}, "", "", true, ruleUp, actionRoute, "rule-up", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeUpstreams{projectDefault: tt.project, orgDefault: tt.org}
			f.add("rule-up", ruleUp.URL)
			f.add("proj-up", projUp.URL)
			f.add("org-up", orgUp.URL)
			envURL := ""
			if tt.env {
				envURL = envUp.URL
			}
			before := map[*fakeUpstream]int32{}
			for _, u := range []*fakeUpstream{ruleUp, projUp, orgUp, envUp} {
				before[u] = u.hits.Load()
			}
			h := startGateway(t, envURL, withUpstreams(f, nil, tt.rules...))
			resp, body := h.post(t, "/v1/chat/completions", clean, nil)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			if tt.stubAnswer != strings.Contains(body, "chatcmpl-stub") {
				t.Errorf("body = %s", body)
			}
			for _, u := range []*fakeUpstream{ruleUp, projUp, orgUp, envUp} {
				hits := u.hits.Load() - before[u]
				if want := int32(0); u == tt.want {
					if hits != 1 {
						t.Errorf("chosen upstream hits = %d", hits)
					}
				} else if hits != want {
					t.Errorf("upstream %s got %d hits", u.URL, hits)
				}
			}
			row := h.oneRow(t)
			if row.Action != tt.action || row.RouteTarget != tt.target {
				t.Errorf("row action=%q target=%q, want %q %q", row.Action, row.RouteTarget, tt.action, tt.target)
			}
		})
	}
}

func TestRouteFailsClosed(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	env := newFakeUpstream(t, okUpstream)
	tests := []struct {
		name   string
		setup  func(f *fakeUpstreams)
		rules  []policy.Rule
		target string
	}{
		{"missing target", nil, []policy.Rule{routeRule("gone")}, "gone"},
		{"disabled target", func(f *fakeUpstreams) { f.rows["safe"].Enabled = false },
			[]policy.Rule{routeRule("safe")}, "safe"},
		{"disabled project default", func(f *fakeUpstreams) {
			f.rows["safe"].Enabled = false
			f.projectDefault = "safe"
		}, nil, "safe"},
		{"disabled org default", func(f *fakeUpstreams) {
			f.rows["safe"].Enabled = false
			f.orgDefault = "safe"
		}, nil, "safe"},
		{"key variable unset", func(f *fakeUpstreams) { f.rows["safe"].KeyEnv = "UPSTREAM_KEY_UNSET" },
			[]policy.Rule{routeRule("safe")}, "safe"},
		{"key variable outside UPSTREAM_KEY_", func(f *fakeUpstreams) { f.rows["safe"].KeyEnv = "JWT_SECRET" },
			[]policy.Rule{routeRule("safe")}, "safe"},
		{"link-local base url", func(f *fakeUpstreams) { f.rows["safe"].BaseURL = "http://169.254.169.254/v1" },
			[]policy.Rule{routeRule("safe")}, "safe"},
		{"route rule without target", nil, []policy.Rule{routeRule("")}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeUpstreams{}
			f.add("safe", up.URL)
			if tt.setup != nil {
				tt.setup(f)
			}
			before, beforeEnv := up.hits.Load(), env.hits.Load()
			h := startGateway(t, env.URL, withUpstreams(f, map[string]string{"JWT_SECRET": "x"}, tt.rules...))
			resp, body := h.post(t, "/v1/chat/completions", clean, nil)
			if resp.StatusCode != 502 || !strings.Contains(body, "route_unavailable") {
				t.Errorf("got %d %s, want 502 route_unavailable", resp.StatusCode, body)
			}
			if up.hits.Load() != before || env.hits.Load() != beforeEnv {
				t.Error("request reached an upstream")
			}
			row := h.oneRow(t)
			if row.Action != actionError || row.RouteTarget != tt.target {
				t.Errorf("row action=%q target=%q", row.Action, row.RouteTarget)
			}
		})
	}

	t.Run("lookup failure is a 503", func(t *testing.T) {
		f := &fakeUpstreams{err: errors.New("db down")}
		h := startGateway(t, env.URL, withUpstreams(f, nil))
		resp, body := h.post(t, "/v1/chat/completions", clean, nil)
		if resp.StatusCode != 503 {
			t.Errorf("got %d %s", resp.StatusCode, body)
		}
	})
}

func TestRouteKeyAndModel(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	f := &fakeUpstreams{}
	u := f.add("safe", up.URL)
	u.KeyEnv = "UPSTREAM_KEY_SAFE"
	u.Model = "qwen3:4b"
	h := startGateway(t, "", withUpstreams(f, map[string]string{"UPSTREAM_KEY_SAFE": "sk-test-value"}, routeRule("safe")))
	resp, body := h.post(t, "/v1/chat/completions", clean, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	up.mu.Lock()
	auth, sent := up.headers.Get("Authorization"), up.body
	up.mu.Unlock()
	if auth != "Bearer sk-test-value" {
		t.Errorf("authorization = %q", auth)
	}
	if !strings.Contains(sent, `"model":"qwen3:4b"`) {
		t.Errorf("model not rewritten: %s", sent)
	}
	if row := h.oneRow(t); row.Model != "m" || row.Action != actionRoute || row.RouteTarget != "safe" {
		t.Errorf("row = model %q action %q target %q", row.Model, row.Action, row.RouteTarget)
	}
}

func TestUpstreamPoolReusesProxies(t *testing.T) {
	pool := newUpstreamPool(false, func(string) string { return "k" })
	u := &upstreamRow{ID: uuid.New(), Name: "a", BaseURL: "http://127.0.0.1:1/v1", KeyEnv: "UPSTREAM_KEY_A",
		TimeoutMs: 1000, Enabled: true, UpdatedAt: time.Now()}
	p1, err := pool.get(u)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := pool.get(u)
	if p1 != p2 {
		t.Error("same row built a new proxy")
	}
	changed := *u
	changed.UpdatedAt = u.UpdatedAt.Add(time.Second)
	if p3, _ := pool.get(&changed); p3 == p1 {
		t.Error("changed row reused the old proxy")
	}
}
