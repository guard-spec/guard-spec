// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// gatewayError is a non-200 answer of the gateway.
type gatewayError struct{ status int }

func (e gatewayError) Error() string { return fmt.Sprintf("gateway answered %d", e.status) }

// explain is the gateway's "explain" object (cmd/gateway/scan_explain.go).
type explain struct {
	Layers    layers   `json:"layers"`
	DecidedBy string   `json:"decided_by"`
	Reason    string   `json:"reason"`
	Category  string   `json:"category"`
	Rules     []string `json:"rules"`
}

// gatewayScan is the part of a /guardrail/scan or /guardrail/scan/tools
// answer the playground uses.
type gatewayScan struct {
	Verdict        string   `json:"verdict"`
	InjectionScore float64  `json:"injection_score"`
	InjectionLabel string   `json:"injection_label"`
	AnomalyScore   float64  `json:"anomaly_score"`
	HadTagChars    bool     `json:"had_tag_chars"`
	HadBidi        bool     `json:"had_bidi"`
	BytesRemoved   int      `json:"bytes_removed"`
	Explain        *explain `json:"explain"`
	Documents      []struct {
		InjectionScore float64  `json:"injection_score"`
		Category       string   `json:"category"`
		Rules          []string `json:"rules"`
		AnomalyScore   float64  `json:"anomaly_score"`
		Verdict        string   `json:"verdict"`
		Explain        *explain `json:"explain"`
	} `json:"documents"`
	Tools []struct {
		Score    float64  `json:"score"`
		Category string   `json:"category"`
		Rules    []string `json:"rules"`
		Signals  []string `json:"signals"`
		Verdict  string   `json:"verdict"`
		Explain  *explain `json:"explain"`
	} `json:"tools"`
}

// toolName is the name the playground gives the tool it scans.
const toolName = "playground_tool"

// callGateway scans req.Text with the gateway and maps the answer. The text
// goes to the gateway only; it is not kept or logged here.
func (s *server) callGateway(ctx context.Context, req scanRequest) (scanResult, error) {
	path := "/guardrail/scan"
	var body any
	switch req.Kind {
	case kindDocument:
		body = map[string]any{"explain": true, "documents": []map[string]string{
			{"id": "document", "source": "web", "content": req.Text}}}
	case kindTool:
		path = "/guardrail/scan/tools"
		body = map[string]any{"explain": true, "tools": []map[string]string{
			{"name": toolName, "description": req.Text}}}
	default:
		body = map[string]any{"explain": true, "text": req.Text}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return scanResult{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.GatewayURL+path, bytes.NewReader(raw))
	if err != nil {
		return scanResult{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Authorization", "Bearer "+s.cfg.GatewayKey)
	resp, err := s.client.Do(hreq)
	if err != nil {
		return scanResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return scanResult{}, gatewayError{resp.StatusCode}
	}
	var g gatewayScan
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&g); err != nil {
		return scanResult{}, fmt.Errorf("decode gateway answer: %w", err)
	}
	return mapResult(req.Kind, g)
}

// mapResult turns the gateway's answer into the playground's.
func mapResult(kind string, g gatewayScan) (scanResult, error) {
	res := scanResult{Kind: kind}
	var verdict string
	var ex *explain
	switch kind {
	case kindDocument:
		if len(g.Documents) != 1 {
			return res, errors.New("gateway answer without the document")
		}
		d := g.Documents[0]
		verdict, ex = d.Verdict, d.Explain
		res.Score, res.Label, res.Rules = d.InjectionScore, d.Category, d.Rules
		// The gateway reports only the anomaly score for a document.
		res.Sanitizer = &sanitizer{AnomalyScore: d.AnomalyScore, Findings: []string{}}
	case kindTool:
		if len(g.Tools) != 1 {
			return res, errors.New("gateway answer without the tool")
		}
		t := g.Tools[0]
		verdict, ex = t.Verdict, t.Explain
		res.Score, res.Label, res.Rules, res.Signals = t.Score, t.Category, t.Rules, t.Signals
	default:
		verdict, ex = g.Verdict, g.Explain
		res.Score, res.Label = g.InjectionScore, g.InjectionLabel
		res.Sanitizer = &sanitizer{AnomalyScore: g.AnomalyScore, BytesRemoved: g.BytesRemoved, Findings: []string{}}
		if g.HadTagChars {
			res.Sanitizer.Findings = append(res.Sanitizer.Findings, "tag_chars")
		}
		if g.HadBidi {
			res.Sanitizer.Findings = append(res.Sanitizer.Findings, "bidi")
		}
		if g.BytesRemoved > 0 {
			res.Sanitizer.Findings = append(res.Sanitizer.Findings, "removed_chars")
		}
	}
	switch verdict {
	case "block":
		res.Decision = "blocked"
	case "allow":
		res.Decision = "allowed"
	default:
		return res, fmt.Errorf("unknown verdict %q", verdict)
	}
	if ex != nil {
		l := ex.Layers
		res.Layers = &l
		res.DecidedBy, res.Reason = ex.DecidedBy, ex.Reason
		if res.Label == "" {
			res.Label = ex.Category
		}
		if len(res.Rules) == 0 {
			res.Rules = ex.Rules
		}
	}
	if res.DecidedBy == "sanitizer" && (res.Label == "" || res.Label == "BENIGN") {
		// Blocked for hidden characters, not for what the visible text says.
		res.Label = "hidden_characters"
	}
	if res.Label == "" {
		res.Label = "BENIGN"
	}
	if len(res.Rules) > 20 {
		res.Rules = res.Rules[:20]
	}
	return res, nil
}
