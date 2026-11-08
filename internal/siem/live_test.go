//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveElasticsearch sends records to a real Elasticsearch
// (SIEM_LIVE_ELASTIC_URL, for example http://localhost:9200 of an
// elasticsearch:8 container with security off) and reads them back. Skipped
// without it.
func TestLiveElasticsearch(t *testing.T) {
	url := os.Getenv("SIEM_LIVE_ELASTIC_URL")
	if url == "" {
		t.Skip("SIEM_LIVE_ELASTIC_URL not set")
	}
	index := "guard-spec-ocsf-test-" + time.Now().Format("150405")
	s := Sink{Kind: KindElastic, Config: map[string]any{"url": url, "index": index}, AllowPrivate: true}
	evs := sampleEvents()
	if err := Deliver(context.Background(), s, evs); err != nil {
		t.Fatal(err)
	}
	// Sending the same batch again is fine (ids: metadata.uid).
	if err := Deliver(context.Background(), s, evs); err != nil {
		t.Fatalf("again: %v", err)
	}
	_, _ = http.Post(url+"/"+index+"/_refresh", "application/json", nil)
	resp, err := http.Get(url + "/" + index + "/_search?q=class_uid:2004&size=0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Hits.Total.Value != 3 {
		t.Fatalf("detection findings in %s: %s", index, b)
	}
	resp2, _ := http.Get(url + "/" + index + "/_count")
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	t.Logf("%s: %s", index, b2)
}
