// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/policy"
)

func embeddingsUpstream(w http.ResponseWriter, _ *http.Request) {
	responseJSON(w, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],"model":"emb","usage":{"prompt_tokens":2,"total_tokens":2}}`)
}

func withEmbeddingsScan(on bool) func(*gateway) {
	return func(gw *gateway) {
		gw.scan = &scanConfig{Roles: indirect.DefaultRoles, IndirectThreshold: 0.85, IndirectAction: indirect.ActionBlock,
			History: historyLatest, EmbeddingsScan: on}
	}
}

func TestEmbeddingsForwarded(t *testing.T) {
	up := newFakeUpstream(t, embeddingsUpstream)
	h := startGateway(t, up.URL, nil)
	// Not classified by default: an embedding produces no text a model acts on.
	body := `{"model":"emb","input":["hello",` + jsonQuote(toolAttack) + `]}`
	resp, got := h.post(t, "/v1/embeddings", body, map[string]string{"x-api-key": "", "Authorization": "Bearer test"})
	if resp.StatusCode != 200 || !strings.Contains(got, `"embedding":[0.1,0.2]`) {
		t.Fatalf("got %d %s", resp.StatusCode, got)
	}
	up.mu.Lock()
	path, sent, auth := up.path, up.body, up.headers.Get("Authorization")
	up.mu.Unlock()
	if path != "/v1/embeddings" || sent != body || strings.Contains(auth, "test") {
		t.Errorf("upstream got %s %s (auth %q)", path, sent, auth)
	}
	row := h.oneRow(t)
	if row.Action != actionAllow || row.Route != "/v1/embeddings" || row.Model != "emb" || row.Response != "" ||
		row.Indirect.Source != "" {
		t.Errorf("row %+v", row)
	}
}

func TestEmbeddingsScan(t *testing.T) {
	up := newFakeUpstream(t, embeddingsUpstream)
	h := startGateway(t, up.URL, withEmbeddingsScan(true))
	resp, got := h.post(t, "/v1/embeddings", `{"model":"emb","input":["hello",`+jsonQuote(toolAttack)+`]}`, nil)
	assertOpenAIError(t, resp, got, 400, "content_filter")
	if row := h.oneRow(t); row.Detected != layerIndirect || row.Indirect.Source != indirect.SourceDocument {
		t.Errorf("row %+v", row)
	}
	resp, got = h.post(t, "/v1/embeddings", `{"model":"emb","input":"Rivers of Vietnam"}`, nil)
	if resp.StatusCode != 200 {
		t.Errorf("benign: %d %s", resp.StatusCode, got)
	}
	// Token arrays cannot be read as text.
	resp, got = h.post(t, "/v1/embeddings", `{"model":"emb","input":[[1,2,3]]}`, nil)
	assertOpenAIError(t, resp, got, 400, "invalid_request")
	if up.hits.Load() != 1 {
		t.Errorf("upstream hits %d", up.hits.Load())
	}
}

func TestEmbeddingsRoutes(t *testing.T) {
	up := newFakeUpstream(t, embeddingsUpstream)
	h := startGateway(t, up.URL, func(gw *gateway) { gw.upstreamProvider = providerAnthropic })
	resp, got := h.post(t, "/v1/embeddings", `{"model":"emb","input":"x"}`, nil)
	if out := assertOpenAIError(t, resp, got, 400, "unsupported_upstream"); !strings.Contains(out.Error.Message, "UPSTREAM_LLM_URL") {
		t.Errorf("message %q", out.Error.Message)
	}
	// The stub answers without an upstream: one zero vector per input.
	h = startGateway(t, "", nil)
	resp, got = h.post(t, "/v1/embeddings", `{"model":"emb","input":["a","b"]}`, nil)
	if resp.StatusCode != 200 || strings.Count(got, `"object":"embedding"`) != 2 {
		t.Errorf("stub %d %s", resp.StatusCode, got)
	}
	resp, got = h.post(t, "/v1/embeddings", `{"model":"emb","input":"x"}`, map[string]string{"x-api-key": "nope"})
	assertOpenAIError(t, resp, got, 401, "invalid_api_key")
}

func TestEmbeddingsRoutingAndAllowlist(t *testing.T) {
	up := newFakeUpstream(t, embeddingsUpstream)
	f := &fakeUpstreams{}
	u := f.add("emb-upstream", up.URL)
	u.Models = []string{"emb"}
	u.Provider = "ollama"
	rule := rule(policy.ActionRoute, "request.model", "=", "emb")
	rule.RouteTarget = "emb-upstream"
	h := startGateway(t, "", withUpstreams(f, nil, rule))
	resp, got := h.post(t, "/v1/embeddings", `{"model":"emb","input":"x"}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, got)
	}
	if row := h.oneRow(t); row.Action != actionRoute || row.RouteTarget != "emb-upstream" {
		t.Errorf("row %+v", row)
	}
	// Another model: no route rule matches and the org has no default, so the
	// request goes to the stub; with the upstream as org default, the
	// allowlist refuses it.
	f.orgDefault = "emb-upstream"
	resp, got = h.post(t, "/v1/embeddings", `{"model":"other","input":"x"}`, nil)
	assertOpenAIError(t, resp, got, 400, "model_not_allowed")
	if up.hits.Load() != 1 {
		t.Errorf("upstream hits %d", up.hits.Load())
	}
}
