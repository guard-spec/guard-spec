//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guard-spec/guard-spec/internal/alerts/channels"
)

// PagerDuty and Opsgenie channels through the API and the worker: a firing
// alert opens an incident keyed by the alert id; the routing key and API key
// come from granted variables only.
func TestIncidentChannels(t *testing.T) {
	h := newAlertsHarness(t)
	org, admin := h.privateOrg()
	base := "/v1/organizations/" + org.String()
	project := h.project(org)

	var mu sync.Mutex
	got := map[string][]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		body["_auth"] = r.Header.Get("Authorization")
		mu.Lock()
		got[r.URL.Path] = append(got[r.URL.Path], body)
		mu.Unlock()
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()
	guard := channels.NewGuard(map[string]bool{org.String(): true})
	h.rt.disp.Senders[channels.KindPagerDuty] = &channels.PagerDuty{Guard: guard, BaseURL: srv.URL}
	h.rt.disp.Senders[channels.KindOpsgenie] = &channels.Opsgenie{Guard: guard, BaseURL: srv.URL}

	// Validation.
	for _, bad := range []map[string]any{
		{"name": "pd", "kind": "pagerduty"}, // no secret
		{"name": "pd", "kind": "pagerduty", "secret_env": "WEBHOOK_SECRET_SEC"},
		{"name": "pd", "kind": "pagerduty", "secret_env": "PAGERDUTY_TEST", "config": map[string]any{"region": "apac"}},
		{"name": "og", "kind": "opsgenie", "secret_env": "OPSGENIE_TEST", "config": map[string]any{"url": "https://x"}},
	} {
		if code, body := h.do("POST", base+"/notification-channels", admin, jsonBody(bad)); code != 400 {
			t.Errorf("%v: %d %v", bad, code, body)
		}
	}
	pd := h.expect(201, "POST", base+"/notification-channels", admin, jsonBody(map[string]any{
		"name": "on-call", "kind": "pagerduty", "secret_env": "PAGERDUTY_TEST", "config": map[string]any{"region": "eu"}}))
	og := h.expect(201, "POST", base+"/notification-channels", admin, jsonBody(map[string]any{
		"name": "ops", "kind": "opsgenie", "secret_env": "OPSGENIE_TEST"}))
	h.expect(201, "POST", base+"/alert-rules", admin, jsonBody(map[string]any{
		"name": "blocked", "event_types": []string{"detection.blocked"}, "severity": "critical",
		"channel_ids": []string{pd["id"].(string), og["id"].(string)}}))
	h.blocked(org, project, "jailbreak")
	waitFor(t, 10*time.Second, "incident deliveries", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got["/v2/enqueue"]) == 1 && len(got["/v2/alerts"]) == 1
	})
	mu.Lock()
	defer mu.Unlock()
	ev := got["/v2/enqueue"][0]
	if ev["routing_key"] != "pd-routing-key" || ev["event_action"] != "trigger" || !strings.HasPrefix(ev["dedup_key"].(string), "guardspec-") ||
		ev["payload"].(map[string]any)["severity"] != "critical" {
		t.Fatalf("pagerduty: %v", ev)
	}
	al := got["/v2/alerts"][0]
	if al["_auth"] != "GenieKey og-api-key" || al["priority"] != "P1" || al["alias"] != ev["dedup_key"] {
		t.Fatalf("opsgenie: %v", al)
	}
}
