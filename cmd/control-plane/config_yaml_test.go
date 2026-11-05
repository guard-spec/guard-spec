package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/policy"
)

const contractYAML = `version: 1
default_upstream: main
upstreams:
  - name: main
    base_url: https://api.openai.com/v1
    api_key_env: UPSTREAM_KEY_MAIN
  - name: safe-model
    base_url: http://ollama:11434/v1
    model: qwen3:4b
policies:
  - name: block-injection
    project: null            # or project name
    enabled: true
    rules:
      - name: high l2
        when: scores.l2 > 0.9 && injection.category != "benign"
        action: block
      - name: suspicious to safe model
        when: injection.score > 0.5
        action: route
        route_target: safe-model
`

func planFor(t *testing.T, text string) (*configPlan, []configError) {
	t.Helper()
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	doc, errs := decodeConfig([]byte(text))
	if len(errs) > 0 {
		return nil, errs
	}
	return validateConfig(eng, doc, config.MustParseKeyOrgs("UPSTREAM_KEY_MAIN=*"), uuid.New())
}

func TestConfigContractExample(t *testing.T) {
	plan, errs := planFor(t, contractYAML)
	if len(errs) > 0 {
		t.Fatalf("errors: %+v", errs)
	}
	if errs := plan.resolveProjects(&storedConfig{}); len(errs) > 0 {
		t.Fatal(errs)
	}
	changes := plan.diff(&storedConfig{})
	want := []configChange{
		{"upstream", "main", "create"}, {"upstream", "safe-model", "create"},
		{"default", "org", "create"}, {"policy", "block-injection", "create"},
	}
	if len(changes) != len(want) {
		t.Fatalf("changes = %+v", changes)
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Errorf("change %d = %+v, want %+v", i, changes[i], want[i])
		}
	}
	if plan.upstreams[1].TimeoutMs != defaultTimeoutMs || !plan.upstreams[1].Enabled {
		t.Errorf("defaults not applied: %+v", plan.upstreams[1])
	}
}

func TestConfigValidationErrors(t *testing.T) {
	bad := `version: 2
default_upstream: nowhere
project_defaults:
  web: missing
upstreams:
  - name: Main
    base_url: ftp://x
  - name: dup
    base_url: http://a/v1
    api_key_env: JWT_SECRET
  - name: dup
    base_url: http://169.254.169.254/v1
policies:
  - name: p
    rules:
      - name: a
        when: scores.l2 >
        action: block
      - name: b
        when: scores.l2 > 0.5
        action: route
        route_target: nowhere
      - name: c
        when: scores.l2 > 0.5
        action: redact
      - name: d
        when: toxicity.score > 0.5
        action: block
  - name: p
    rules: []
`
	_, errs := planFor(t, bad)
	paths := map[string]string{}
	for _, e := range errs {
		paths[e.Path] = e.Message
	}
	for _, want := range []string{"version", "default_upstream", "project_defaults.web", "upstreams[0]",
		"upstreams[1]", "upstreams[2].name", "upstreams[2]", "policies[0].rules[0].when",
		"policies[0].rules[1].route_target", "policies[0].rules[2]", "policies[0].rules[3].when", "policies[1].name"} {
		if _, ok := paths[want]; !ok {
			t.Errorf("no error at %s; got %+v", want, errs)
		}
	}
	if msg := paths["policies[0].rules[0].when"]; !strings.Contains(msg, "position 11") {
		t.Errorf("when error lacks position: %q", msg)
	}

	for _, text := range []string{"", "version: 1\nnope: 1\n", "version: 1\n---\nversion: 1\n", "[1, 2]", "version: [x"} {
		if _, errs := planFor(t, text); len(errs) == 0 {
			t.Errorf("%q accepted", text)
		}
	}
}

func TestConfigDiffKeepsRuleIDsAndDeletes(t *testing.T) {
	plan, errs := planFor(t, contractYAML)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	mainID, oldID, projectID := uuid.New(), uuid.New(), uuid.New()
	highL2 := uuid.New()
	cond, err := policy.ParseCondition(`scores.l2 > 0.9 && injection.category != "benign"`)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	stored := &storedConfig{
		upstreams: []upstream{
			{ID: mainID, Name: "main", BaseURL: "https://api.openai.com/v1", APIKeyEnv: "UPSTREAM_KEY_MAIN",
				TimeoutMs: defaultTimeoutMs, Enabled: true},
			{ID: oldID, Name: "old", BaseURL: "http://old/v1", TimeoutMs: defaultTimeoutMs, Enabled: true},
		},
		orgDefault: &mainID,
		projects:   []storedProject{{ID: projectID, Slug: "web", DefaultUpstream: &oldID}},
		policies: []configPolicyRow{
			{ID: uuid.New(), Name: "block-injection", Enabled: true, CreatedAt: created, Rules: []policy.Rule{
				{ID: highL2, Name: "high l2", Action: policy.ActionBlock, Condition: cond},
			}},
			{ID: uuid.New(), Name: "gone", Enabled: true, CreatedAt: created.Add(time.Second)},
		},
	}
	if errs := plan.resolveProjects(stored); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := map[configChange]bool{}
	for _, c := range plan.diff(stored) {
		got[c] = true
	}
	for _, want := range []configChange{
		{"upstream", "safe-model", "create"}, {"upstream", "old", "delete"},
		{"default", "project:web", "delete"}, {"policy", "block-injection", "update"}, {"policy", "gone", "delete"},
	} {
		if !got[want] {
			t.Errorf("missing change %+v in %+v", want, got)
		}
	}
	if got[configChange{"upstream", "main", "update"}] || got[configChange{"default", "org", "update"}] {
		t.Errorf("unchanged objects reported: %+v", got)
	}
	rules := plan.rulesFor(0, &stored.policies[0])
	if rules[0].ID != highL2 {
		t.Errorf("rule id not kept: %s", rules[0].ID)
	}
	if string(rules[0].Condition) != string(cond) {
		t.Error("unchanged condition rewritten")
	}
	if rules[1].ID == uuid.Nil || rules[1].ID == highL2 {
		t.Errorf("new rule id = %s", rules[1].ID)
	}

	// The stored state written back as a file is a no-op.
	stored.policies[0].Rules = rules
	stored.upstreams = append(stored.upstreams[:1], upstream{ID: uuid.New(), Name: "safe-model",
		BaseURL: "http://ollama:11434/v1", Model: "qwen3:4b", TimeoutMs: defaultTimeoutMs, Enabled: true})
	stored.projects[0].DefaultUpstream = nil
	stored.policies = stored.policies[:1]
	doc, err := stored.document()
	if err != nil {
		t.Fatal(err)
	}
	if doc.DefaultUpstream == nil || *doc.DefaultUpstream != "main" || len(doc.Policies[0].Rules) != 2 ||
		doc.Policies[0].Rules[1].RouteTarget != "safe-model" {
		raw, _ := json.Marshal(doc)
		t.Errorf("document = %s", raw)
	}
	if changes := plan.diff(stored); len(changes) != 0 {
		t.Errorf("no-op apply reports %+v", changes)
	}
}

func TestPolicyOrder(t *testing.T) {
	base := time.Now().Truncate(time.Microsecond)
	a := &configPolicyRow{CreatedAt: base}
	b := &configPolicyRow{CreatedAt: base.Add(time.Second)}
	p := &configPlan{}
	// Kept in order: stored times stay.
	order := p.policyOrder([]*configPolicyRow{a, b}, base.Add(time.Hour))
	if !order[0].Equal(a.CreatedAt) || !order[1].Equal(b.CreatedAt) {
		t.Errorf("in order: %v", order)
	}
	// Swapped: a moves after b. A new policy goes last.
	order = p.policyOrder([]*configPolicyRow{b, a, nil}, base.Add(time.Hour))
	if !order[0].Equal(b.CreatedAt) || !order[1].After(order[0]) || !order[2].After(order[1]) {
		t.Errorf("swapped: %v", order)
	}
}

// A key variable the operator did not allow for the org is refused on save.
func TestConfigRefusesKeyOfAnotherOrg(t *testing.T) {
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	acme, other := uuid.New(), uuid.New()
	keys := config.MustParseKeyOrgs("UPSTREAM_KEY_ACME=" + acme.String())
	doc, errs := decodeConfig([]byte("version: 1\nupstreams:\n  - name: x\n    base_url: https://attacker.example/v1\n" +
		"    api_key_env: UPSTREAM_KEY_ACME\npolicies: []\n"))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if _, errs := validateConfig(eng, doc, keys, acme); len(errs) != 0 {
		t.Errorf("allowed org refused: %+v", errs)
	}
	_, errs = validateConfig(eng, doc, keys, other)
	if len(errs) != 1 || errs[0].Path != "upstreams[0].api_key_env" || !strings.Contains(errs[0].Message, "UPSTREAM_KEY_ORGS") {
		t.Errorf("other org: %+v", errs)
	}
	if _, errs := validateConfig(eng, doc, config.KeyOrgs{}, acme); len(errs) != 1 {
		t.Errorf("empty allowlist: %+v", errs)
	}
}

// GET /config refuses (409) what a PUT of its own output would refuse.
func TestExportProblems(t *testing.T) {
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := policy.ParseCondition("scores.l2 > 0.5")
	removed := json.RawMessage(`{"field":"toxicity.score","operator":">","value":0.5}`)
	org, a, b, c := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := &storedConfig{policies: []configPolicyRow{
		{ID: a, Name: "p", Rules: []policy.Rule{{ID: uuid.New(), Name: "fine", Action: policy.ActionBlock, Condition: ok}}},
		{ID: b, Name: "p"},
		{ID: c, Name: "legacy", Rules: []policy.Rule{{ID: uuid.New(), Name: "toxic", Action: policy.ActionBlock, Condition: removed}}},
	}}
	problems := s.exportProblems(eng, org)
	if len(problems) != 2 || problems[0].PolicyID != b || problems[1].PolicyID != c ||
		!strings.Contains(problems[1].Message, "toxicity.score") || !strings.Contains(problems[1].Fix, c.String()) {
		t.Errorf("problems = %+v", problems)
	}
	s.policies = s.policies[:1]
	if p := s.exportProblems(eng, org); len(p) != 0 {
		t.Errorf("clean config: %+v", p)
	}
}
