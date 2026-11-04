// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// SlackAPI is the Web API origin.
const SlackAPI = "https://slack.com/api"

// Slack posts with a bot token (chat.postMessage) or to an incoming webhook.
// Config mode "bot" (default for personal DMs) needs Secret = the bot token
// and a channel (Config "channel", or Target: a Slack user id for a DM);
// mode "webhook" needs Secret = the webhook URL.
type Slack struct {
	Base string // SlackAPI; tests point it at a fake
	// Client sends to Slack.s API; incoming webhook URLs go through Guard.
	Client *http.Client
	Guard  Guard
}

// slackBlocks renders Block Kit blocks; text is escaped for mrkdwn.
func slackBlocks(s Summary) []map[string]any {
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(s.Title, 150)}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": esc.Replace(strings.Join(s.Lines, "\n"))}},
	}
	if s.Link != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []map[string]any{{
			"type": "button", "text": map[string]any{"type": "plain_text", "text": "Open"}, "url": s.Link,
		}}})
	}
	return blocks
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

type slackAnswer struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	TS    string `json:"ts"`
	User  struct {
		ID string `json:"id"`
	} `json:"user"`
}

// slackPermanent are Web API errors that a retry cannot fix.
var slackPermanent = map[string]bool{
	"channel_not_found": true, "not_in_channel": true, "is_archived": true, "invalid_auth": true,
	"not_authed": true, "account_inactive": true, "token_revoked": true, "missing_scope": true,
	"users_not_found": true, "user_not_found": true, "invalid_arguments": true, "no_text": true,
	"msg_too_long": true, "restricted_action": true,
}

func (s *Slack) api(ctx context.Context, token, method string, req *http.Request) (slackAnswer, int, error) {
	req.Header.Set("Authorization", "Bearer "+token)
	r, herr := do(s.Client, req, token)
	var a slackAnswer
	_ = json.Unmarshal(r.body, &a)
	if herr != nil {
		return a, r.status, herr
	}
	if !a.OK {
		e := &Error{Status: r.status, Msg: Redact("slack "+method+": "+a.Error, token)}
		e.Permanent = slackPermanent[a.Error]
		return a, r.status, e
	}
	return a, r.status, nil
}

// Send delivers m.
func (s *Slack) Send(ctx context.Context, m *Message) (Result, error) {
	sum := Render(&m.Payload, m.Lang)
	text := sum.Text()
	if configString(m.Config, "mode") == "webhook" {
		hook := m.Secret
		if hook == "" {
			return Result{}, permanent(0, "slack: webhook url is not set")
		}
		client, check := s.Guard.pick(true)
		if err := check(hook); err != nil {
			return Result{}, permanent(0, "%s", Redact("slack webhook: "+err.Error(), hook))
		}
		req, err := jsonRequest(ctx, http.MethodPost, hook, map[string]any{"text": text, "blocks": slackBlocks(sum)})
		if err != nil {
			return Result{}, err
		}
		r, err := do(client, req, hook)
		if err != nil {
			return Result{}, err
		}
		return Result{Status: r.status}, nil
	}
	if m.Secret == "" {
		return Result{}, permanent(0, "slack: bot token is not set")
	}
	channel := m.Target
	if channel == "" {
		channel = configString(m.Config, "channel")
	}
	if channel == "" {
		return Result{}, permanent(0, "slack: no channel")
	}
	req, err := jsonRequest(ctx, http.MethodPost, s.base()+"/chat.postMessage", map[string]any{
		"channel": channel, "text": text, "blocks": slackBlocks(sum), "unfurl_links": false,
	})
	if err != nil {
		return Result{}, err
	}
	a, status, err := s.api(ctx, m.Secret, "chat.postMessage", req)
	if err != nil {
		return Result{}, err
	}
	return Result{Status: status, RemoteID: a.TS}, nil
}

func (s *Slack) base() string {
	if s.Base != "" {
		return s.Base
	}
	return SlackAPI
}

// LookupByEmail returns the Slack user id of an email (users.lookupByEmail).
func (s *Slack) LookupByEmail(ctx context.Context, token, email string) (string, error) {
	if token == "" {
		return "", permanent(0, "slack: bot token is not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.base()+"/users.lookupByEmail?email="+url.QueryEscape(email), nil)
	if err != nil {
		return "", err
	}
	a, _, err := s.api(ctx, token, "users.lookupByEmail", req)
	if err != nil {
		return "", err
	}
	if a.User.ID == "" {
		return "", permanent(0, "slack: no user for this email")
	}
	return a.User.ID, nil
}
