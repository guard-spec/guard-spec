// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package channels sends alert notifications: Telegram, Slack, Microsoft
// Teams (Workflows), signed webhooks, A2A agents and email.
//
// Every sender gets a Message whose payload holds metadata only (the webhook
// payload v1 of docs/alerts.md) and returns a *Error on failure. An Error is
// safe to store and show: its text never holds a token, a secret or a URL
// path or query (Redact).
package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/giaplee/guard-spec/internal/proxy"
)

// Kinds of channels.
const (
	KindTelegram = "telegram"
	KindSlack    = "slack"
	KindTeams    = "teams"
	KindWebhook  = "webhook"
	KindA2A      = "a2a"
	KindEmail    = "email"
)

// Kinds lists every channel kind.
var Kinds = []string{KindTelegram, KindSlack, KindTeams, KindWebhook, KindA2A, KindEmail}

// SchemaV1 is the schema name of the webhook payload.
const SchemaV1 = "guardspec.alert.v1"

// Timeout bounds one delivery attempt; MaxResponse caps what is read back.
const (
	Timeout     = 5 * time.Second
	MaxResponse = 64 << 10
)

// RuleRef names the rule of an alert.
type RuleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Sample is one event of an alert, metadata only.
type Sample struct {
	EventID    string         `json:"event_id"`
	Type       string         `json:"type"`
	OccurredAt time.Time      `json:"occurred_at"`
	Attrs      map[string]any `json:"attrs"`
}

// Links point at the admin UI.
type Links struct {
	Alert    string `json:"alert"`
	Requests string `json:"requests"`
}

// Payload is the webhook payload v1. It is also what every other channel
// renders its message from.
type Payload struct {
	Schema        string            `json:"schema"`
	EventID       string            `json:"event_id"` // the delivery's idempotency key
	AlertID       string            `json:"alert_id"`
	Rule          RuleRef           `json:"rule"`
	State         string            `json:"state"` // firing or resolved
	Severity      string            `json:"severity"`
	OrgID         string            `json:"org_id"`
	ProjectID     *string           `json:"project_id"`
	Count         int               `json:"count"`
	WindowSeconds int               `json:"window_seconds"`
	FirstAt       time.Time         `json:"first_at"`
	LastAt        time.Time         `json:"last_at"`
	Group         map[string]string `json:"group"`
	Samples       []Sample          `json:"samples"`
	Links         Links             `json:"links"`
	Test          bool              `json:"test,omitempty"`
}

// Message is one delivery.
type Message struct {
	Kind string
	// Target is the resolved address: a Telegram chat id, a Slack user or
	// channel id, an email address, or a webhook URL (Config "url").
	Target string
	// Config is the channel's non-secret config; nil for a personal channel.
	Config map[string]any
	// Secret is the value of the channel's secret_env, or of the instance
	// variable of a personal channel. Never logged or stored.
	Secret         string
	Payload        Payload
	IdempotencyKey string
	Lang           string // en or vi
}

// Result of a delivery that succeeded.
type Result struct {
	Status   int
	RemoteID string // the A2A task id, the Slack ts, the Telegram message id
}

// Error is a failed delivery. Permanent errors are not retried.
type Error struct {
	Status     int
	Permanent  bool
	RetryAfter time.Duration
	Msg        string // already redacted
}

func (e *Error) Error() string { return e.Msg }

// AsError returns err as an *Error, wrapping any other error as a temporary
// failure with a redacted message.
func AsError(err error, secrets ...string) *Error {
	var ce *Error
	if errors.As(err, &ce) {
		return ce
	}
	return &Error{Msg: Redact(err.Error(), secrets...)}
}

func permanent(status int, format string, args ...any) *Error {
	return &Error{Status: status, Permanent: true, Msg: fmt.Sprintf(format, args...)}
}

// Sender delivers messages of one kind.
type Sender interface {
	Send(ctx context.Context, m *Message) (Result, error)
}

// urlRe finds URLs in error text.
var urlRe = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)

// botTokenRe finds Telegram bot tokens and Slack tokens that are not part of
// a URL.
var tokenRe = regexp.MustCompile(`\b(\d{5,}:[A-Za-z0-9_-]{30,}|xox[abposr]-[A-Za-z0-9-]+)\b`)

// Redact removes secrets from s: every given secret, anything shaped like a
// bot token, and the userinfo, path and query of every URL (webhook URLs carry
// their tokens there). The result is capped at 500 characters.
func Redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	s = urlRe.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "[url]"
		}
		out := u.Scheme + "://" + u.Host
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			out += "/[redacted]"
		}
		return out
	})
	s = tokenRe.ReplaceAllString(s, "[redacted]")
	if r := []rune(s); len(r) > 500 {
		s = string(r[:500])
	}
	return s
}

// RedactURL is the form of a URL that may be stored and shown: scheme and host.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// httpResult is an HTTP exchange of a sender.
type httpResult struct {
	status     int
	body       []byte
	retryAfter time.Duration
}

// do sends req with client, reads at most MaxResponse bytes of the answer and
// classifies the status: 2xx is success, 408, 429 and 5xx are temporary,
// other 4xx are permanent, 3xx (a redirect, never followed) is permanent.
func do(client *http.Client, req *http.Request, secrets ...string) (httpResult, error) {
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, proxy.ErrAddressNotAllowed) {
			// Never the resolved address: it would turn the test button into
			// a DNS and network probe.
			return httpResult{}, permanent(0, "address not allowed")
		}
		return httpResult{}, &Error{Msg: Redact(err.Error(), secrets...)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponse))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponse))
	r := httpResult{status: resp.StatusCode, body: body, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	return r, statusError(r)
}

func statusError(r httpResult) error {
	s := r.status
	switch {
	case s >= 200 && s < 300:
		return nil
	case s == http.StatusTooManyRequests:
		return &Error{Status: s, RetryAfter: r.retryAfter, Msg: "rate limited (429)"}
	case s == http.StatusRequestTimeout || s >= 500:
		return &Error{Status: s, Msg: fmt.Sprintf("receiver answered %d", s)}
	case s >= 300 && s < 400:
		return permanent(s, "receiver answered %d (redirects are not followed)", s)
	default:
		return permanent(s, "receiver answered %d", s)
	}
}

// parseRetryAfter reads seconds or an HTTP date; 0 when absent or invalid.
// It is capped at one hour.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}
	if d < 0 {
		d = 0
	}
	return min(d, time.Hour)
}

func jsonRequest(ctx context.Context, method, target string, v any) (*http.Request, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, permanent(0, "invalid url")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "guard-spec-alerts/1")
	return req, nil
}

func configBool(cfg map[string]any, key string) bool {
	b, _ := cfg[key].(bool)
	return b
}

// Guard holds the HTTP clients of org-defined URLs (webhooks, A2A agents,
// Slack and Teams webhooks): both refuse redirects, metadata, link-local
// and multicast addresses (internal/proxy); Strict also refuses loopback,
// private and CGNAT addresses. Private is used only for an org the operator
// lists (ALERTS_PRIVATE_ORGS) whose channel asks for it (allow_private).
type Guard struct {
	Strict, Private *http.Client
	// PrivateOrgs are the org ids allowed private addresses.
	PrivateOrgs map[string]bool
}

// NewGuard builds a Guard with Timeout.
func NewGuard(privateOrgs map[string]bool) Guard {
	return Guard{Strict: proxy.SafeClient(true, Timeout), Private: proxy.SafeClient(false, Timeout), PrivateOrgs: privateOrgs}
}

// AllowsPrivate reports whether channels of org may ask for private addresses.
func (g Guard) AllowsPrivate(org string) bool { return g.PrivateOrgs[org] }

// private reports whether a channel of org asking for private URLs gets them.
func (g Guard) private(asked bool, org string) bool { return asked && g.PrivateOrgs[org] }

// pick returns the client and the URL check for a channel of org.
func (g Guard) pick(askedPrivate bool, org string) (*http.Client, func(string) error) {
	private := g.private(askedPrivate, org)
	c := g.Strict
	if private {
		c = g.Private
	}
	if c == nil {
		c = proxy.SafeClient(!private, Timeout)
	}
	return c, func(u string) error { return proxy.ValidateTargetURL(u, private) }
}

// CheckURL validates a channel URL as Send will.
func (g Guard) CheckURL(u string, askedPrivate bool, org string) error {
	return proxy.ValidateTargetURL(u, g.private(askedPrivate, org))
}

func configString(cfg map[string]any, key string) string {
	s, _ := cfg[key].(string)
	return s
}
