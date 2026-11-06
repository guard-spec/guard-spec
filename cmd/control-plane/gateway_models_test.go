// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// GET /gateway/models passes on the detector's layers, fusion and L1 floor
// from the gateway's /readyz, and leaves the floor null when an older
// gateway does not report it.
func TestGatewayModelsDetector(t *testing.T) {
	for _, tc := range []struct {
		name, readyz string
		layers       []any
		floor        any
	}{
		{"with floor", `{"detector":{"layers":["l1","l2","l3"],"fusion":"logreg","l1_floor":0.985,
			"models":{"l2_model":"guardspec-classifier@v3b","l2_verified":true,"installed":["v3b"]}}}`,
			[]any{"l1", "l2", "l3"}, 0.985},
		{"floor off", `{"detector":{"layers":["l1"],"fusion":"logreg","l1_floor":0,"models":{}}}`, []any{"l1"}, 0.0},
		{"older gateway", `{"detector":{"models":{"l2_model":"x@1"}}}`, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/readyz" {
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, tc.readyz)
			}))
			defer gw.Close()
			app := fiber.New()
			app.Get("/m", getGatewayModels(&appSettings{gatewayURL: gw.URL, gatewayClient: gw.Client()}))
			resp, err := app.Test(httptest.NewRequest("GET", "/m", nil), -1)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["reachable"] != true {
				t.Fatalf("not reachable: %v", body)
			}
			layers, _ := body["layers"].([]any)
			if len(layers) != len(tc.layers) {
				t.Errorf("layers = %v, want %v", body["layers"], tc.layers)
			}
			if body["l1_floor"] != tc.floor {
				t.Errorf("l1_floor = %v, want %v", body["l1_floor"], tc.floor)
			}
		})
	}
}
