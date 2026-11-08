// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Incident tools (RF-656e36ac): PagerDuty and Opsgenie. A firing alert opens
// an incident or alert there, keyed by the Guard Spec alert id, so a repeat
// of the same alert does not open another; the alert's resolution (a rule
// with auto_resolve) closes it. The payload is metadata only, like every
// channel's.

// Kinds of incident channels.
const (
	KindPagerDuty = "pagerduty"
	KindOpsgenie  = "opsgenie"
)

// incidentKey is the dedup key / alias of an alert in the incident tool.
func incidentKey(p *Payload) string {
	if p.Test {
		return "guardspec-test-" + p.EventID
	}
	return "guardspec-" + p.AlertID
}

func region(m *Message) string {
	r, _ := m.Config["region"].(string)
	if r == "eu" {
		return "eu"
	}
	return "us"
}

// details are the alert's metadata for the incident's custom fields.
func details(p *Payload) map[string]any {
	d := map[string]any{
		"rule": p.Rule.Name, "rule_id": p.Rule.ID, "alert_id": p.AlertID, "org_id": p.OrgID,
		"count": p.Count, "window_seconds": p.WindowSeconds,
		"first_at": p.FirstAt.UTC().Format(time.RFC3339), "last_at": p.LastAt.UTC().Format(time.RFC3339),
	}
	if p.ProjectID != nil {
		d["project_id"] = *p.ProjectID
	}
	for k, v := range p.Group {
		d["group."+k] = v
	}
	if len(p.Samples) > 0 {
		d["sample_event_type"] = p.Samples[0].Type
	}
	if p.Links.Alert != "" {
		d["link"] = p.Links.Alert
	}
	return d
}

// PagerDuty sends to the Events API v2. Secret is the integration's routing
// key; config.region is us (default) or eu.
type PagerDuty struct {
	Guard Guard
	// BaseURL replaces the region's endpoint (tests); never from config.
	BaseURL string
}

func pdSeverity(s string) string {
	switch s {
	case "critical", "warning":
		return s
	}
	return "info"
}

// Send delivers m: trigger for a firing alert (and a test), resolve for a
// resolved one.
func (d *PagerDuty) Send(ctx context.Context, m *Message) (Result, error) {
	if m.Secret == "" {
		return Result{}, permanent(0, "pagerduty: routing key is not set")
	}
	base := d.BaseURL
	if base == "" {
		base = "https://events.pagerduty.com"
		if region(m) == "eu" {
			base = "https://events.eu.pagerduty.com"
		}
	}
	p := &m.Payload
	s := Render(p, m.Lang)
	action := "trigger"
	if p.State == "resolved" && !p.Test {
		action = "resolve"
	}
	body := map[string]any{
		"routing_key":  m.Secret,
		"event_action": action,
		"dedup_key":    incidentKey(p),
		"client":       "Guard Spec",
	}
	if p.Links.Alert != "" {
		body["client_url"] = p.Links.Alert
		body["links"] = []map[string]string{{"href": p.Links.Alert, "text": "Open in Guard Spec"}}
	}
	if action == "trigger" {
		body["payload"] = map[string]any{
			"summary":        truncateRunes(s.Title, 1024),
			"source":         "guard-spec",
			"severity":       pdSeverity(p.Severity),
			"timestamp":      p.LastAt.UTC().Format(time.RFC3339),
			"component":      "guard-spec",
			"group":          p.OrgID,
			"class":          p.Rule.Name,
			"custom_details": details(p),
		}
	}
	client := d.Guard.Strict
	if client == nil || d.BaseURL != "" {
		client, _ = d.Guard.pick(d.BaseURL != "", p.OrgID)
	}
	req, err := jsonRequest(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/v2/enqueue", body)
	if err != nil {
		return Result{}, err
	}
	r, err := do(client, req, m.Secret)
	if err != nil {
		return Result{}, AsError(err, m.Secret)
	}
	return Result{Status: r.status, RemoteID: incidentKey(p)}, nil
}

// Opsgenie sends to the Alert API. Secret is an API integration key;
// config.region is us (default) or eu.
type Opsgenie struct {
	Guard Guard
	// BaseURL replaces the region's endpoint (tests); never from config.
	BaseURL string
}

func ogPriority(s string) string {
	switch s {
	case "critical":
		return "P1"
	case "warning":
		return "P3"
	}
	return "P5"
}

// Send delivers m: create for a firing alert (and a test), close for a
// resolved one.
func (o *Opsgenie) Send(ctx context.Context, m *Message) (Result, error) {
	if m.Secret == "" {
		return Result{}, permanent(0, "opsgenie: API key is not set")
	}
	base := o.BaseURL
	if base == "" {
		base = "https://api.opsgenie.com"
		if region(m) == "eu" {
			base = "https://api.eu.opsgenie.com"
		}
	}
	base = strings.TrimRight(base, "/")
	p := &m.Payload
	alias := incidentKey(p)
	var target string
	var body map[string]any
	if p.State == "resolved" && !p.Test {
		target = base + "/v2/alerts/" + url.PathEscape(alias) + "/close?identifierType=alias"
		body = map[string]any{"source": "Guard Spec", "note": "The Guard Spec alert was resolved."}
	} else {
		s := Render(p, m.Lang)
		fields := map[string]string{}
		for k, v := range details(p) {
			fields[k] = fmt.Sprint(v)
		}
		target = base + "/v2/alerts"
		body = map[string]any{
			"message":     truncateRunes(s.Title, 130),
			"alias":       alias,
			"description": truncateRunes(strings.Join(s.Lines, "\n"), 15000),
			"priority":    ogPriority(p.Severity),
			"source":      "Guard Spec",
			"tags":        []string{"guard-spec", p.Severity},
			"details":     fields,
		}
		if p.Rule.Name != "" {
			body["entity"] = truncateRunes(p.Rule.Name, 512)
		}
	}
	client := o.Guard.Strict
	if client == nil || o.BaseURL != "" {
		client, _ = o.Guard.pick(o.BaseURL != "", p.OrgID)
	}
	req, err := jsonRequest(ctx, http.MethodPost, target, body)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "GenieKey "+m.Secret)
	r, err := do(client, req, m.Secret)
	if err != nil {
		return Result{}, AsError(err, m.Secret)
	}
	return Result{Status: r.status, RemoteID: alias}, nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
