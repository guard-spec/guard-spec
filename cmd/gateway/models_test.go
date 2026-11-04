package main

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestRouteApplyModel(t *testing.T) {
	tests := []struct {
		name      string
		r         route
		requested string
		want      string
		err       error
	}{
		{"no upstream", route{}, "gpt-4o", "gpt-4o", nil},
		{"default replaces (no allowlist)", route{model: "m1"}, "gpt-4o", "m1", nil},
		{"listed", route{models: []string{"a", "b"}}, "b", "b", nil},
		{"listed with default", route{model: "a", models: []string{"a", "b"}}, "b", "b", nil},
		{"not listed", route{model: "a", models: []string{"a", "b"}}, "c", "", errModelNotAllowed},
		{"missing gets default", route{model: "a", models: []string{"a", "b"}}, "", "a", nil},
		{"missing, no default", route{models: []string{"a"}}, "", "", errModelNotAllowed},
	}
	for _, tt := range tests {
		got, err := tt.r.applyModel(tt.requested)
		if got != tt.want || !errors.Is(err, tt.err) {
			t.Errorf("%s: got %q %v, want %q %v", tt.name, got, err, tt.want, tt.err)
		}
	}
}

func TestRouteCapTokens(t *testing.T) {
	limit := 100
	r := route{maxTokensCap: &limit}
	body, err := decodeBody([]byte(`{"max_tokens": 5000, "max_completion_tokens": 50}`))
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := r.capTokens(body); !changed || err != nil {
		t.Fatalf("not capped: %v", err)
	}
	out, _ := json.Marshal(body)
	if string(out) != `{"max_completion_tokens":50,"max_tokens":100}` {
		t.Errorf("body %s", out)
	}
	body, _ = decodeBody([]byte(`{"max_tokens": 10}`))
	if changed, _ := r.capTokens(body); changed {
		t.Error("changed a body within the cap")
	}
	if changed, _ := (route{}).capTokens(body); changed {
		t.Error("changed a body without a cap")
	}
	// Other number forms of a large value are capped too (they bypassed an
	// integer-only check).
	for _, raw := range []string{`5000.0`, `1e6`, `100.5e1`, `1E+3`} {
		body, _ := decodeBody([]byte(`{"max_tokens": ` + raw + `}`))
		changed, err := r.capTokens(body)
		if !changed || err != nil || body["max_tokens"] != json.Number("100") {
			t.Errorf("%s: changed %v err %v body %v", raw, changed, err, body)
		}
	}
	// 100.9 floors to the cap: unchanged.
	body, _ = decodeBody([]byte(`{"max_tokens": 100.9}`))
	if changed, err := r.capTokens(body); changed || err != nil {
		t.Errorf("100.9: %v %v", changed, err)
	}
	for _, raw := range []string{`-1`, `1e400`, `"5000"`, `true`} {
		body, _ := decodeBody([]byte(`{"max_tokens": ` + raw + `}`))
		if _, err := r.capTokens(body); !errors.Is(err, errBadTokenLimit) {
			t.Errorf("%s accepted: %v", raw, err)
		}
	}
}
