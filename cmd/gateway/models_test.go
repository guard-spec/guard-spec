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
	if !r.capTokens(body) {
		t.Fatal("not capped")
	}
	out, _ := json.Marshal(body)
	if string(out) != `{"max_completion_tokens":50,"max_tokens":100}` {
		t.Errorf("body %s", out)
	}
	body, _ = decodeBody([]byte(`{"max_tokens": 10}`))
	if r.capTokens(body) || (route{}).capTokens(body) {
		t.Error("changed a body within the cap")
	}
}
