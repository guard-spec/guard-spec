//go:build onnx && cgo

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"testing"

	"github.com/guard-spec/guard-spec/internal/indirect"
)

// TestMultiTurnSetML runs the multi-turn test set through /v1/messages with
// SCAN_HISTORY=latest and L1+L2+L3, with and without the conversation
// window. It skips without the models (see benchStack). Every benign
// conversation must be allowed; nearly every attack blocked with the window.
func TestMultiTurnSetML(t *testing.T) {
	runner := benchStack(t, [3]bool{true, true, true})
	set := loadMultiTurn(t)
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	attacks := 0
	for _, c := range set {
		if c.Kind == "attack" {
			attacks++
		}
	}
	blocked := map[int]int{}
	for _, turns := range []int{0, indirect.DefaultWindowTurns} {
		h := startGateway(t, "", func(gw *gateway) {
			withAnthropic(up.URL)(gw)
			gw.runner = runner
			gw.scan = windowScan(historyLatest, turns)
		})
		for _, c := range set {
			resp, got := h.post(t, "/v1/messages", messagesConversation(c), nil)
			switch {
			case c.Kind == "attack" && resp.StatusCode == 400:
				blocked[turns]++
			case c.Kind == "attack":
				t.Logf("window %d: %s allowed", turns, c.ID)
			case resp.StatusCode != 200:
				t.Errorf("window %d: benign %s refused: %d %s", turns, c.ID, resp.StatusCode, got)
			}
		}
	}
	t.Logf("attacks blocked: %d of %d without the window, %d with it", blocked[0], attacks, blocked[indirect.DefaultWindowTurns])
	if blocked[indirect.DefaultWindowTurns] < attacks-2 || blocked[indirect.DefaultWindowTurns] <= blocked[0] {
		t.Errorf("with the window %d of %d attacks blocked (without: %d)", blocked[indirect.DefaultWindowTurns], attacks, blocked[0])
	}
}
