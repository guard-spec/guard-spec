// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"net/http"
)

// Teams posts an Adaptive Card to a Power Automate Workflows webhook ("Post
// to a channel when a webhook request is received"). Office 365 connectors
// (MessageCard) are retired and not supported. Secret is the workflow URL.
type Teams struct {
	Guard Guard
}

// adaptiveCard renders the message as an Adaptive Card 1.4 attachment.
func adaptiveCard(s Summary, severity string) map[string]any {
	color := "Default"
	switch severity {
	case "critical":
		color = "Attention"
	case "warning":
		color = "Warning"
	}
	body := []map[string]any{
		{"type": "TextBlock", "text": s.Title, "weight": "Bolder", "size": "Medium", "wrap": true, "color": color},
	}
	for _, l := range s.Lines {
		body = append(body, map[string]any{"type": "TextBlock", "text": l, "wrap": true, "spacing": "Small"})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
	}
	if s.Link != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open", "url": s.Link}}
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	}
}

// Send delivers m.
func (t *Teams) Send(ctx context.Context, m *Message) (Result, error) {
	hook := m.Secret
	if hook == "" {
		return Result{}, permanent(0, "teams: workflow url is not set")
	}
	client, check := t.Guard.pick(true)
	if err := check(hook); err != nil {
		return Result{}, permanent(0, "%s", Redact("teams: "+err.Error(), hook))
	}
	req, err := jsonRequest(ctx, http.MethodPost, hook, adaptiveCard(Render(&m.Payload, m.Lang), m.Payload.Severity))
	if err != nil {
		return Result{}, err
	}
	r, err := do(client, req, hook)
	if err != nil {
		return Result{}, err
	}
	return Result{Status: r.status}, nil
}
