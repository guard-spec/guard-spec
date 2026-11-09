// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// l2OnlyBackend scores SQL the way v3b scored benign SQL in RF-476b4d30:
// the classifier is sure, L1 found only cue words, L3 is low. Other text
// scores low.
type l2OnlyBackend struct{}

func (l2OnlyBackend) Run(_ context.Context, text string) ([]inference.Score, error) {
	if !strings.Contains(text, "TABLE") {
		return []inference.Score{{Label: "BENIGN", Confidence: 0.01, Detail: &inference.Detail{L1: 0.03, L2: 0.01, L3: 0.1}}}, nil
	}
	return []inference.Score{{Label: "jailbreak", Confidence: 0.95, Detail: &inference.Detail{
		L1: fusion.DefaultL1Calibration.Apply(0.17), L2: 0.97, L3: 0.35, Category: "jailbreak",
		Rules: []string{"l2:jailbreak", "l3:obfuscation"}}}}, nil
}

const corroborationSQL = `CREATE TABLE orders (
    id         TEXT PRIMARY KEY,
    total      NUMERIC NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
GRANT SELECT, INSERT ON orders TO app;
-- Seed row for the demo.
INSERT INTO orders (id, total) VALUES ('o1', 10);`

// TestToolCodeCorroboration: a code-like tool result that only L2 flags is
// forwarded by default and refused with TOOL_CODE_CORROBORATION=off; the
// same text as the user's own message is refused either way.
func TestToolCodeCorroboration(t *testing.T) {
	text, _ := json.Marshal(corroborationSQL)
	toolBody := `{"model":"claude-x","max_tokens":9,"messages":[{"role":"user","content":"show the schema"},
		{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"read","input":{}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":` + string(text) + `}]}]}`
	userBody := `{"model":"claude-x","max_tokens":9,"messages":[{"role":"user","content":` + string(text) + `}]}`
	for _, tc := range []struct {
		name    string
		body    string
		off     bool
		blocked bool
	}{
		{"tool result, default on", toolBody, false, false},
		{"tool result, off", toolBody, true, true},
		{"user text", userBody, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
				anthropicJSON(w, messageResponse(`{"type":"text","text":"x"}`))
			})
			cfg := defaultScanConfig()
			cfg.NoCodeCorroboration = tc.off
			h := startGateway(t, "", func(gw *gateway) {
				withAnthropic(up.URL)(gw)
				withScan(cfg, nil)(gw)
				gw.runner = inference.NewRunnerWith(l2OnlyBackend{})
			})
			resp, _ := h.post(t, "/v1/messages", tc.body, nil)
			if blocked := resp.StatusCode == 400; blocked != tc.blocked {
				t.Fatalf("status %d, want blocked %v", resp.StatusCode, tc.blocked)
			}
			row := h.oneRow(t)
			if !tc.blocked && !slices.Contains(row.Indirect.Rules, indirect.CodeCorroborationRule) {
				t.Errorf("rules %v, want %s", row.Indirect.Rules, indirect.CodeCorroborationRule)
			}
		})
	}
}

// TestScanDocumentsCodeCorroboration: /guardrail/scan documents follow the
// same rule.
func TestScanDocumentsCodeCorroboration(t *testing.T) {
	doc, _ := json.Marshal(corroborationSQL)
	for _, off := range []bool{false, true} {
		cfg := defaultScanConfig()
		cfg.NoCodeCorroboration = off
		h := startGateway(t, "", func(gw *gateway) {
			withScan(cfg, nil)(gw)
			gw.runner = inference.NewRunnerWith(l2OnlyBackend{})
		})
		_, got := h.post(t, "/guardrail/scan", `{"documents":[{"id":"d","source":"file","content":`+string(doc)+`}]}`, nil)
		if blocked := strings.Contains(got, `"blocked":true`); blocked != off {
			t.Errorf("off=%v: %s", off, got)
		}
	}
}

// TestLargeToolCodeCorroboration: with MAX_SCAN_TOKENS a long code-like
// tool result takes the long path, which applies the rule per window before
// early exit (no window is skipped then); with the rule off it is refused.
func TestLargeToolCodeCorroboration(t *testing.T) {
	doc := strings.Repeat(corroborationSQL+"\n", 400)
	if inference.FitsShort(doc) {
		t.Fatal("tool result fits the short path")
	}
	for _, off := range []bool{false, true} {
		up := newFakeUpstream(t, okUpstream)
		h := largeGateway(t, up.URL, 500_000, laneConfig(1), func(gw *gateway) {
			gw.scan.NoCodeCorroboration = off
			gw.runner = inference.NewRunnerWith(l2OnlyBackend{})
		})
		skipped := windows("skipped")
		resp, got := h.post(t, "/v1/chat/completions", toolBody(doc), nil)
		if blocked := resp.StatusCode == 400; blocked != off {
			t.Fatalf("off=%v: %d %.200s", off, resp.StatusCode, got)
		}
		if !off && windows("skipped") != skipped {
			t.Error("windows were skipped although no adjusted window reached the threshold")
		}
	}
}
