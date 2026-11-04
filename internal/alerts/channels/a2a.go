// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// A2A sends the alert to an agent that speaks the Agent2Agent protocol.
//
// Pinned to A2A specification v1.0.0 (https://a2a-protocol.org/latest/specification/,
// checked 2026-11-04): the Agent Card is served at /.well-known/agent-card.json,
// the JSON-RPC binding's method is "SendMessage", parts are {"text": ...} and
// {"data": ..., "mediaType": ...} without a kind discriminator, roles are
// "ROLE_USER", and clients send the A2A-Version header. Agents whose card
// declares protocol version 0.3 get the 0.3 form instead: method
// "message/send", parts with "kind": "text"/"data", role "user".
//
// Card endpoints: v1.0 lists supportedInterfaces [{url, protocolBinding:
// "JSONRPC", protocolVersion}]; 0.3 has a top-level url (and
// preferredTransport JSONRPC). Auth follows the card's securitySchemes: an
// HTTP bearer scheme sends Secret as a bearer token, an apiKey scheme in a
// header sends it in that header.
type A2A struct {
	Guard   Guard
	CardTTL time.Duration // 10 minutes when zero

	mu    sync.Mutex
	cards map[string]cachedCard
}

// SpecVersion is the A2A version this client is written against.
const SpecVersion = "1.0"

const cardPath = "/.well-known/agent-card.json"

type cachedCard struct {
	card    agentCard
	fetched time.Time
}

type agentInterface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion"`
}

type securityScheme struct {
	// v1.0: one of these is set.
	HTTPAuth *struct {
		Scheme string `json:"scheme"`
	} `json:"httpAuthSecurityScheme"`
	APIKey *struct {
		Location string `json:"location"`
		Name     string `json:"name"`
	} `json:"apiKeySecurityScheme"`
	// 0.3 (OpenAPI style).
	Type   string `json:"type"`
	Scheme string `json:"scheme"`
	In     string `json:"in"`
	Name   string `json:"name"`
}

type agentCard struct {
	Name                string                    `json:"name"`
	URL                 string                    `json:"url"`
	ProtocolVersion     string                    `json:"protocolVersion"`
	PreferredTransport  string                    `json:"preferredTransport"`
	SupportedInterfaces []agentInterface          `json:"supportedInterfaces"`
	SecuritySchemes     map[string]securityScheme `json:"securitySchemes"`
}

// endpoint picks the JSON-RPC endpoint and its protocol version.
func (c *agentCard) endpoint() (string, string, error) {
	for _, i := range c.SupportedInterfaces {
		if strings.EqualFold(i.ProtocolBinding, "JSONRPC") && i.URL != "" {
			v := i.ProtocolVersion
			if v == "" {
				v = SpecVersion
			}
			return i.URL, v, nil
		}
	}
	if c.URL != "" && (c.PreferredTransport == "" || strings.EqualFold(c.PreferredTransport, "JSONRPC")) {
		v := c.ProtocolVersion
		if v == "" {
			v = "0.3"
		}
		return c.URL, v, nil
	}
	return "", "", permanent(0, "a2a: the agent card has no JSON-RPC interface")
}

// auth returns the header that carries the secret.
func (c *agentCard) auth(secret string) (string, string, error) {
	if secret == "" {
		return "", "", nil
	}
	names := make([]string, 0, len(c.SecuritySchemes))
	for n := range c.SecuritySchemes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := c.SecuritySchemes[n]
		header := ""
		switch {
		case s.HTTPAuth != nil && strings.EqualFold(s.HTTPAuth.Scheme, "bearer"),
			strings.EqualFold(s.Type, "http") && strings.EqualFold(s.Scheme, "bearer"):
			return "Authorization", "Bearer " + secret, nil
		case s.APIKey != nil && strings.EqualFold(s.APIKey.Location, "header"):
			header = s.APIKey.Name
		case strings.EqualFold(s.Type, "apiKey") && strings.EqualFold(s.In, "header"):
			header = s.Name
		default:
			continue
		}
		if !apiKeyHeaderRe.MatchString(header) || reservedHeaders[strings.ToLower(header)] ||
			strings.HasPrefix(strings.ToLower(header), "proxy-") {
			return "", "", permanent(0, "a2a: the agent card names a header the key cannot be sent in")
		}
		return http.CanonicalHeaderKey(header), secret, nil
	}
	// No scheme we can use: a bearer token is the common case.
	return "Authorization", "Bearer " + secret, nil
}

var apiKeyHeaderRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// reservedHeaders are hop-by-hop and request-framing headers, and those this
// client sets itself: a card cannot have the key sent in them.
var reservedHeaders = map[string]bool{
	"host": true, "content-length": true, "content-type": true, "content-encoding": true, "transfer-encoding": true,
	"connection": true, "keep-alive": true, "upgrade": true, "te": true, "trailer": true, "expect": true,
	"cookie": true, "set-cookie": true, "user-agent": true, "a2a-version": true, "forwarded": true,
	"x-forwarded-for": true, "x-forwarded-host": true, "x-forwarded-proto": true, "x-real-ip": true,
}

// sameOrigin reports whether a and b have the same scheme and host (and port).
func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Host != "" && strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Host, ub.Host)
}

// cardURL is the well-known card location of the configured URL's origin
// (the configured URL may be the card URL itself or the agent's origin).
func cardURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", permanent(0, "a2a: invalid agent_card_url")
	}
	if strings.HasSuffix(u.Path, ".json") {
		return raw, nil
	}
	return u.Scheme + "://" + u.Host + cardPath, nil
}

func (a *A2A) card(ctx context.Context, raw string, client *http.Client, check func(string) error) (agentCard, error) {
	ttl := a.CardTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	cu, err := cardURL(raw)
	if err != nil {
		return agentCard{}, err
	}
	a.mu.Lock()
	if c, ok := a.cards[cu]; ok && time.Since(c.fetched) < ttl {
		a.mu.Unlock()
		return c.card, nil
	}
	a.mu.Unlock()
	if err := check(cu); err != nil {
		return agentCard{}, permanent(0, "%s", Redact("a2a: "+err.Error()))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu, nil)
	if err != nil {
		return agentCard{}, permanent(0, "a2a: invalid agent_card_url")
	}
	req.Header.Set("Accept", "application/json")
	r, err := do(client, req)
	if err != nil {
		ce := AsError(err)
		ce.Msg = "a2a agent card: " + ce.Msg
		return agentCard{}, ce
	}
	var card agentCard
	if err := json.Unmarshal(r.body, &card); err != nil {
		return agentCard{}, &Error{Status: r.status, Msg: "a2a: the agent card is not valid JSON"}
	}
	a.mu.Lock()
	if a.cards == nil {
		a.cards = map[string]cachedCard{}
	}
	if len(a.cards) > 1000 {
		clear(a.cards)
	}
	a.cards[cu] = cachedCard{card: card, fetched: time.Now()}
	a.mu.Unlock()
	return card, nil
}

// buildRequest renders the JSON-RPC request for version.
func buildA2ARequest(version string, m *Message) map[string]any {
	summary := Render(&m.Payload, m.Lang).Text()
	if strings.HasPrefix(version, "0.") {
		return map[string]any{
			"jsonrpc": "2.0", "id": m.IdempotencyKey, "method": "message/send",
			"params": map[string]any{"message": map[string]any{
				"kind": "message", "role": "user", "messageId": m.IdempotencyKey,
				"parts": []map[string]any{
					{"kind": "text", "text": summary},
					{"kind": "data", "data": m.Payload},
				},
			}},
		}
	}
	return map[string]any{
		"jsonrpc": "2.0", "id": m.IdempotencyKey, "method": "SendMessage",
		"params": map[string]any{"message": map[string]any{
			"role": "ROLE_USER", "messageId": m.IdempotencyKey,
			"parts": []map[string]any{
				{"text": summary},
				{"data": m.Payload, "mediaType": "application/json"},
			},
		}},
	}
}

type rpcAnswer struct {
	Result *struct {
		// v1.0: a SendMessageResponse with task or message.
		Task *struct {
			ID string `json:"id"`
		} `json:"task"`
		Message *struct {
			MessageID string `json:"messageId"`
		} `json:"message"`
		// 0.3: the Task or Message itself.
		Kind      string `json:"kind"`
		ID        string `json:"id"`
		MessageID string `json:"messageId"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Send delivers m. RemoteID is the task id (or message id) the agent returned.
func (a *A2A) Send(ctx context.Context, m *Message) (Result, error) {
	raw := configString(m.Config, "agent_card_url")
	if raw == "" {
		return Result{}, permanent(0, "a2a: no agent_card_url")
	}
	client, check := a.Guard.pick(configBool(m.Config, "allow_private"), m.Payload.OrgID)
	card, err := a.card(ctx, raw, client, check)
	if err != nil {
		return Result{}, err
	}
	endpoint, version, err := card.endpoint()
	if err != nil {
		return Result{}, err
	}
	if cu, _ := cardURL(raw); !sameOrigin(endpoint, cu) {
		return Result{}, permanent(0, "a2a: the agent card names an endpoint on another origin than the card")
	}
	if err := check(endpoint); err != nil {
		return Result{}, permanent(0, "%s", Redact("a2a endpoint: "+err.Error(), m.Secret))
	}
	req, err := jsonRequest(ctx, http.MethodPost, endpoint, buildA2ARequest(version, m))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("A2A-Version", majorMinor(version))
	h, v, err := card.auth(m.Secret)
	if err != nil {
		return Result{}, err
	}
	if h != "" {
		req.Header.Set(h, v)
	}
	r, err := do(client, req, m.Secret)
	if err != nil {
		return Result{}, err
	}
	var ans rpcAnswer
	if err := json.Unmarshal(r.body, &ans); err != nil {
		return Result{}, &Error{Status: r.status, Msg: "a2a: the answer is not JSON-RPC"}
	}
	if ans.Error != nil {
		// -32600..-32603 and A2A's own errors: a retry sends the same thing.
		return Result{}, permanent(r.status, "%s", Redact(fmt.Sprintf("a2a error %d: %s", ans.Error.Code,
			truncate(ans.Error.Message, 200)), m.Secret))
	}
	if ans.Result == nil {
		return Result{}, &Error{Status: r.status, Msg: "a2a: no result"}
	}
	res := ans.Result
	id := ""
	switch {
	case res.Task != nil:
		id = res.Task.ID
	case res.Message != nil:
		id = res.Message.MessageID
	case res.Kind == "task":
		id = res.ID
	case res.Kind == "message":
		id = res.MessageID
	}
	return Result{Status: r.status, RemoteID: truncate(id, 200)}, nil
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}
