package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/config"
)

// An Anthropic upstream is tested with its own key header and a version, as
// Anthropic's model list wants them.
func TestUpstreamProxyAnthropic(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"data":[{"type":"model","id":"claude-x"}]}`))
	}))
	defer srv.Close()
	org := uuid.New()
	keyOrgs, err := config.ParseKeyOrgs("UPSTREAM_KEY_ANTHROPIC=" + org.String())
	if err != nil {
		t.Fatal(err)
	}
	s := &appSettings{allowPrivate: true, keyOrgs: keyOrgs,
		getenv: func(string) string { return "sk-ant-test" }}
	u := upstream{BaseURL: srv.URL + "/v1", APIKeyEnv: "UPSTREAM_KEY_ANTHROPIC", Provider: "anthropic",
		Headers: map[string]string{"X-Team": "search"}}
	px, keySent, err := upstreamProxy(u, org, s)
	if err != nil || !keySent {
		t.Fatal(keySent, err)
	}
	res := px.Probe(context.Background())
	if !res.OK || len(res.Models) != 1 || res.Models[0] != "claude-x" {
		t.Errorf("probe %+v", res)
	}
	if got.Get("x-api-key") != "sk-ant-test" || got.Get("Authorization") != "" ||
		got.Get("anthropic-version") != "2023-06-01" || got.Get("X-Team") != "search" {
		t.Errorf("headers %v", got)
	}
}
