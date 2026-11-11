// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/policy"
)

const tinyPNG = "data:image/png;base64,iVBORw0KGgo="

// Chat completions: image, file and audio parts are counted; text is not.
func TestUnscannedChatParts(t *testing.T) {
	body := `{"model":"m","messages":[
		{"role":"system","content":[{"type":"image_url","image_url":{"url":"` + tinyPNG + `"}}]},
		{"role":"user","content":[{"type":"text","text":"What is in these?"},
			{"type":"image_url","image_url":{"url":"` + tinyPNG + `"}},
			{"type":"image_url","image_url":{"url":"https://img.example/a.png"}},
			{"type":"file","file":{"file_data":"JVBERi0=","filename":"a.pdf"}},
			{"type":"input_audio","input_audio":{"data":"UklGRg==","format":"wav"}},
			{"type":"future_part","blob":"x"}]},
		{"role":"user","content":"plain text"}]}`
	b, err := decodeBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	g := &textGuard{roles: &indirect.DefaultRoles}
	if err := g.guardBody(b); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"image": 2, "file": 1, "audio": 1, "other": 1}
	if !maps.Equal(g.unscanned, want) {
		t.Errorf("unscanned = %v, want %v", g.unscanned, want)
	}
}

// /v1/messages: images, PDFs (document with a base64, url or file source),
// also inside tool results; text documents and search results are scanned.
// With SCAN_HISTORY=latest only the trailing turn counts.
func TestUnscannedMessagesBlocks(t *testing.T) {
	body := `{"model":"claude-x","max_tokens":10,"messages":[
		{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]},
		{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"shot","input":{}}]},
		{"role":"user","content":[
			{"type":"tool_result","tool_use_id":"t1","content":[{"type":"image","source":{"type":"url","url":"https://img.example/s.png"}}]},
			{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0="}},
			{"type":"document","source":{"type":"file","file_id":"file_1"}},
			{"type":"document","source":{"type":"text","media_type":"text/plain","data":"plain"}},
			{"type":"search_result","source":"https://x.example","title":"t","content":[{"type":"text","text":"r"}]},
			{"type":"text","text":"Summarise"}]}]}`
	for _, tt := range []struct {
		latest bool
		want   map[string]int
	}{
		{true, map[string]int{"image": 1, "file": 2}},
		{false, map[string]int{"image": 2, "file": 2}},
	} {
		b, err := decodeBody([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		g := &textGuard{roles: &indirect.DefaultRoles, latest: tt.latest}
		if err := g.guardMessagesBody(b); err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(g.unscanned, tt.want) {
			t.Errorf("latest %v: unscanned = %v, want %v", tt.latest, g.unscanned, tt.want)
		}
	}
}

// /v1/responses: input_image, input_file and input_audio parts.
func TestUnscannedResponsesParts(t *testing.T) {
	body := `{"model":"m","input":[{"role":"user","content":[
		{"type":"input_text","text":"Read this"},
		{"type":"input_image","image_url":"` + tinyPNG + `"},
		{"type":"input_file","file_id":"file_1"},
		{"type":"input_audio","input_audio":{"data":"UklGRg==","format":"wav"}}]}]}`
	g, _, err := guardResponses(t, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"image": 1, "file": 1, "audio": 1}
	if !maps.Equal(g.unscanned, want) {
		t.Errorf("unscanned = %v, want %v", g.unscanned, want)
	}
}

func TestUnscannedVarsAndTags(t *testing.T) {
	counts := map[string]int{"audio": 1, "image": 2, "other": 1}
	kinds, n := unscannedVars(counts)
	if !slices.Equal(kinds, []string{"image", "audio", "other"}) || n != 4 {
		t.Errorf("vars %v %d", kinds, n)
	}
	tags := unscannedTags(counts)
	if !slices.Equal(tags, []string{"input:unscanned_image=2", "input:unscanned_audio=1", "input:unscanned_other=1"}) {
		t.Errorf("tags %v", tags)
	}
	if kinds, n := unscannedVars(nil); kinds != nil || n != 0 {
		t.Errorf("empty: %v %d", kinds, n)
	}
}

func TestUnscannedModeConfig(t *testing.T) {
	cfg, err := loadScanConfig(func(string) string { return "" })
	if err != nil || cfg.Unscanned != indirect.UnscannedLog {
		t.Fatalf("default %q %v", cfg.Unscanned, err)
	}
	if _, err := loadScanConfig(func(k string) string {
		if k == "UNSCANNED_PARTS" {
			return "strip"
		}
		return ""
	}); err == nil {
		t.Error("UNSCANNED_PARTS=strip accepted")
	}
	str := func(s string) *string { return &s }
	for _, tt := range []struct {
		gateway string
		org     *string
		want    string
	}{
		{"log", nil, "log"},
		{"log", str("block"), "block"},
		{"log", str("allow"), "log"}, // an org cannot loosen the gateway
		{"block", str("log"), "block"},
		{"allow", str("log"), "log"},
	} {
		if got := (indirect.Settings{UnscannedParts: tt.org}).Unscanned(tt.gateway); got != tt.want {
			t.Errorf("gateway %s org %v: %s, want %s", tt.gateway, tt.org, got, tt.want)
		}
	}
	if _, err := indirect.ParseSettings([]byte(`{"unscanned_parts":"strip"}`)); err == nil {
		t.Error("unscanned_parts=strip accepted")
	}
}

// unscannedAPIs are requests with one image on each API.
func unscannedMode(mode string) func(*gateway) {
	return func(gw *gateway) {
		cfg := defaultScanConfig()
		cfg.Unscanned = mode
		gw.scan = &cfg
	}
}

func unscannedAPIs() []piiAPI {
	img := `{"type":"image_url","image_url":{"url":"` + tinyPNG + `"}}`
	return []piiAPI{
		{name: "chat", path: "/v1/chat/completions",
			body:     `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"Describe"},` + img + `]}]}`,
			upstream: okUpstream},
		{name: "messages", path: "/v1/messages", anthropic: true,
			body: `{"model":"claude-x","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"Describe"},` +
				`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
			}},
		{name: "responses", path: "/v1/responses",
			body: `{"model":"m","input":[{"role":"user","content":[{"type":"input_text","text":"Describe"},` +
				`{"type":"input_image","image_url":"` + tinyPNG + `"}]}]}`,
			upstream: func(w http.ResponseWriter, _ *http.Request) { responseJSON(w, responseObject(textItem("ok"))) }},
	}
}

// Each mode on each API: block refuses before the upstream with the API's
// error shape, log forwards and tags the audit row, allow forwards quietly.
func TestUnscannedModesThroughGateway(t *testing.T) {
	for _, api := range unscannedAPIs() {
		for _, mode := range []string{indirect.UnscannedAllow, indirect.UnscannedLog, indirect.UnscannedBlock} {
			t.Run(api.name+"/"+mode, func(t *testing.T) {
				up := newFakeUpstream(t, api.upstream)
				upURL := up.URL
				if api.anthropic {
					upURL = ""
				}
				h := startGateway(t, upURL, func(gw *gateway) {
					if api.anthropic {
						withAnthropic(up.URL)(gw)
					}
					unscannedMode(mode)(gw)
				})
				resp, got := h.post(t, api.path, api.body, nil)
				row := h.oneRow(t)
				tags := inputAuditTags(row)
				switch mode {
				case indirect.UnscannedBlock:
					if resp.StatusCode != 400 || up.hits.Load() != 0 || !strings.Contains(got, "image") {
						t.Errorf("got %d %s, upstream hits %d", resp.StatusCode, got, up.hits.Load())
					}
					if api.anthropic {
						if !strings.Contains(got, `"type":"error"`) {
							t.Errorf("not the Anthropic error shape: %s", got)
						}
					} else if !strings.Contains(got, "unscanned_content") {
						t.Errorf("no unscanned_content code: %s", got)
					}
					if row.Action != actionBlock || row.Detected != layerUnscanned {
						t.Errorf("row action %s detected %s", row.Action, row.Detected)
					}
				default:
					if resp.StatusCode != 200 || up.hits.Load() != 1 {
						t.Errorf("got %d %s, upstream hits %d", resp.StatusCode, got, up.hits.Load())
					}
				}
				wantTag := mode != indirect.UnscannedAllow
				if slices.Contains(tags, "input:unscanned_image=1") != wantTag {
					t.Errorf("mode %s: tags %v", mode, tags)
				}
			})
		}
	}
}

// The org can make the gateway stricter, and a policy rule can act on
// input.unscanned.* whatever the mode.
func TestUnscannedOrgAndPolicy(t *testing.T) {
	api := unscannedAPIs()[0]
	t.Run("org block", func(t *testing.T) {
		up := newFakeUpstream(t, api.upstream)
		h := startGateway(t, up.URL, func(gw *gateway) {
			unscannedMode(indirect.UnscannedLog)(gw)
			gw.settings = func(context.Context, uuid.UUID) (indirect.Settings, error) {
				b := indirect.UnscannedBlock
				return indirect.Settings{UnscannedParts: &b}, nil
			}
		})
		if resp, got := h.post(t, api.path, api.body, nil); resp.StatusCode != 400 || up.hits.Load() != 0 {
			t.Errorf("got %d %s", resp.StatusCode, got)
		}
	})
	t.Run("rule under allow", func(t *testing.T) {
		up := newFakeUpstream(t, api.upstream)
		r := rule(policy.ActionBlock, "input.unscanned.kinds", "contains", "image")
		h := startGateway(t, up.URL, func(gw *gateway) {
			unscannedMode(indirect.UnscannedAllow)(gw)
			withRules(r)(gw)
		})
		resp, got := h.post(t, api.path, api.body, nil)
		row := h.oneRow(t)
		if resp.StatusCode != 400 || up.hits.Load() != 0 || row.Detected != layerPolicy || row.RuleID != r.ID {
			t.Errorf("got %d %s, detected %s", resp.StatusCode, got, row.Detected)
		}
	})
	t.Run("text only", func(t *testing.T) {
		up := newFakeUpstream(t, api.upstream)
		h := startGateway(t, up.URL, unscannedMode(indirect.UnscannedBlock))
		if resp, got := h.post(t, api.path, chatBody(messages("user", "Hello"), ""), nil); resp.StatusCode != 200 {
			t.Errorf("text request: %d %s", resp.StatusCode, got)
		}
	})
}
