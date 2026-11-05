package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/policy"
)

func TestCheckPoliciesListsFailures(t *testing.T) {
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	good := `[{"id":"` + uuid.NewString() + `","name":"ok","action":"block",` +
		`"condition":{"field":"injection.score","operator":">","value":0.9}}]`
	removed := `[{"id":"` + uuid.NewString() + `","name":"toxic","action":"block",` +
		`"condition":{"field":"toxicity.score","operator":">","value":0.5}}]`
	stale := `[{"id":"` + uuid.NewString() + `","name":"redactor","action":"redact",` +
		`"condition":{"field":"request.tokens","operator":">","value":1}}]`
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	policies := []storedPolicy{
		{ID: ids[0], OrgID: uuid.New(), Name: "good", Enabled: true, Rules: json.RawMessage(good)},
		{ID: ids[1], OrgID: uuid.New(), Name: "removed", Enabled: true, Rules: json.RawMessage(removed)},
		{ID: ids[2], OrgID: uuid.New(), Name: "stale", Enabled: false, Rules: json.RawMessage(stale)},
		{ID: ids[3], OrgID: uuid.New(), Name: "garbage", Enabled: true, Rules: json.RawMessage(`{"x":1}`)},
	}
	var out strings.Builder
	if failed := checkPolicies(eng, policies, &out); failed != 3 {
		t.Errorf("failed = %d, want 3\n%s", failed, out.String())
	}
	report := out.String()
	if strings.Contains(report, ids[0].String()) {
		t.Errorf("good policy listed:\n%s", report)
	}
	for _, want := range []string{ids[1].String(), "toxicity.score", "removed because no detector",
		ids[2].String(), "(disabled)", "not implemented", ids[3].String(), "3 of 4 policies failed"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
}
