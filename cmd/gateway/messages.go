package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/valyala/fasthttp"
)

// The Anthropic Messages API (POST /v1/messages), for clients such as Claude
// Code that take ANTHROPIC_BASE_URL. Requests go through the same pipeline as
// chat completions (proxyHandler) and are sent as they are to an upstream with
// provider anthropic, at {base_url}/messages: the provider's base URL is
// https://api.anthropic.com/v1, as for its OpenAI-compatible endpoint. There
// is no translation: an upstream of another provider gets a 400.

// Upstream providers the gateway tells apart.
const (
	providerAnthropic        = "anthropic"
	providerOpenAICompatible = "openai_compatible"
)

const (
	// defaultAnthropicVersion is sent when the client sends no anthropic-version.
	defaultAnthropicVersion = "2023-06-01"
	// maxAnthropicBetas bounds the anthropic-beta values passed on.
	maxAnthropicBetas = 32
)

// anthropicTokenRe is an anthropic-version or one anthropic-beta value.
var anthropicTokenRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var messagesFormat = apiFormat{
	path:          "/messages",
	guardBody:     (*textGuard).guardMessagesBody,
	spotlight:     spotlightMessages,
	injectCanary:  injectMessagesCanary,
	stub:          messagesStub,
	call:          anthropicCall,
	checkRoute:    anthropicRoute,
	guardResponse: (*outputguard.Scanner).MessagesResponse,
	newStream:     func(s *outputguard.Scanner) streamGuard { return s.NewMessageStream() },
	streamError:   anthropicStreamError,
	history:       true,
}

// errNotAnthropic refuses /v1/messages for an upstream of another provider.
var errNotAnthropic = errors.New("not an anthropic upstream")

// anthropicRoute accepts the stub and upstreams with provider anthropic.
func anthropicRoute(r route) error {
	if r.proxy == nil || r.provider == providerAnthropic {
		return nil
	}
	name := r.name
	if name == "" {
		return fmt.Errorf("%w: UPSTREAM_LLM_URL does not serve the Anthropic Messages API; "+
			"set UPSTREAM_LLM_PROVIDER=anthropic if it does, or use /v1/chat/completions", errNotAnthropic)
	}
	return fmt.Errorf("%w: upstream %q (provider %s) does not serve the Anthropic Messages API; "+
		"route /v1/messages to an upstream with provider anthropic, or use /v1/chat/completions",
		errNotAnthropic, name, r.provider)
}

// anthropicCall reads the headers passed on to the upstream: anthropic-version
// (the client's, or 2023-06-01) and anthropic-beta. Nothing else of the
// client's goes upstream, its key least of all; the upstream's key is sent as
// x-api-key. Beta values for OAuth are dropped: the gateway authenticates with
// an API key.
func anthropicCall(c *fiber.Ctx) (proxy.Call, error) {
	h := http.Header{}
	version := strings.TrimSpace(c.Get("anthropic-version"))
	if version == "" {
		version = defaultAnthropicVersion
	}
	if !anthropicTokenRe.MatchString(version) {
		return proxy.Call{}, errors.New("anthropic-version is not valid")
	}
	h.Set("anthropic-version", strings.Clone(version))
	betas, err := anthropicBetas(c.Request().Header.PeekAll("anthropic-beta"))
	if err != nil {
		return proxy.Call{}, err
	}
	if len(betas) > 0 {
		h.Set("anthropic-beta", strings.Join(betas, ","))
	}
	return proxy.Call{KeyHeader: "x-api-key", Header: h}, nil
}

func anthropicBetas(values [][]byte) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, beta := range strings.Split(string(v), ",") {
			beta = strings.TrimSpace(beta)
			if beta == "" || seen[beta] {
				continue
			}
			if !anthropicTokenRe.MatchString(beta) {
				return nil, errors.New("anthropic-beta is not valid")
			}
			seen[beta] = true
			if strings.HasPrefix(strings.ToLower(beta), "oauth-") {
				continue
			}
			if len(out) == maxAnthropicBetas {
				return nil, fmt.Errorf("at most %d anthropic-beta values", maxAnthropicBetas)
			}
			out = append(out, beta)
		}
	}
	return out, nil
}

// guardMessagesBody sanitizes every untrusted text of a Messages API request,
// with the roles of the chat path: user text is rewritten with its sanitized
// form and classified; tool_result content, documents and the readable text
// of web search and web fetch results are classified one by one as
// untrusted content; system text and the input of tool_use blocks
// are classified when their scanning is on but forwarded unchanged; assistant
// text and thinking are left alone, as in chat. Tool definitions are checked
// for poisoning. Images and binary documents are passed on unscanned, as
// image parts are in chat.
//
// With SCAN_HISTORY=latest (g.latest), the turns up to the last assistant
// message are history: they are still sanitized, and their tool results and
// documents are scored through the scan cache (so a block refused or redacted
// before is refused or redacted again, without running the detector), but
// their user text is not classified again: it was when it was the trailing
// turn. The client that holds the gateway key is trusted not to forge history.
func (g *textGuard) guardMessagesBody(body map[string]any) error {
	g.schemaKey = "input_schema"
	if err := rejectShadowKeys(body, "system", "messages", "tools"); err != nil {
		return err
	}
	if err := g.guardSystem(body["system"]); err != nil {
		return err
	}
	if raw := body["messages"]; raw != nil {
		messages, ok := raw.([]any)
		if !ok {
			return errUnsupportedContent
		}
		last := -1 // the last assistant message: the trailing turn follows it
		for i, msg := range messages {
			if m, ok := msg.(map[string]any); ok && m["role"] == "assistant" {
				last = i
			}
		}
		for i, msg := range messages {
			m, ok := msg.(map[string]any)
			if !ok {
				return errUnsupportedContent
			}
			if err := rejectShadowKeys(m, "role", "content"); err != nil {
				return err
			}
			g.history = g.latest && i <= last
			g.msg = i + 1
			err := g.guardAnthropicMessage(m)
			g.history, g.msg = false, 0
			if err != nil {
				return err
			}
		}
	}
	return g.guardMessagesTools(body)
}

// guardSystem classifies the system prompt, a string or text blocks.
func (g *textGuard) guardSystem(raw any) error {
	var texts []string
	switch system := raw.(type) {
	case nil:
		return nil
	case string:
		texts = []string{system}
	case []any:
		for _, item := range system {
			b, ok := item.(map[string]any)
			if !ok {
				return errUnsupportedContent
			}
			text, ok := b["text"].(string)
			if !ok {
				return errUnsupportedContent
			}
			texts = append(texts, text)
		}
	default:
		return errUnsupportedContent
	}
	if !g.scanRoles().System {
		return nil
	}
	return g.scoreOnly(indirect.SourceSystem, texts)
}

func (g *textGuard) guardAnthropicMessage(m map[string]any) error {
	role, _ := m["role"].(string)
	if role == "system" {
		// A system message among the turns (Claude Code sends its environment
		// this way): the integrating application's, as the system prompt.
		return g.guardSystem(m["content"])
	}
	if role == "assistant" {
		return g.guardAssistantMessage(m)
	}
	g.source = indirect.SourceUser
	defer func() { g.source = "" }()
	switch content := m["content"].(type) {
	case nil:
		return nil
	case string:
		cleaned, err := g.clean(content)
		if err != nil {
			return err
		}
		m["content"] = cleaned
		return nil
	case []any:
		return g.guardBlocks(content)
	default:
		return errUnsupportedContent
	}
}

// guardAssistantMessage covers an assistant turn: the input of its tool_use
// and server_tool_use blocks is classified as tool calls when their scanning
// is on, and the results of Anthropic's web tools (web_search_tool_result,
// web_fetch_tool_result) as untrusted content, like tool results. Nothing is
// rewritten, so thinking blocks and their signatures stay valid, unless a
// result is redacted (INDIRECT_ACTION=redact). Assistant text, thinking and
// blocks of other types are left alone: what came from the upstream went
// through the output guard, which refuses block types it does not know
// unless OUTPUT_UNKNOWN_BLOCKS=pass.
func (g *textGuard) guardAssistantMessage(m map[string]any) error {
	if blocks, ok := m["content"].([]any); ok {
		for _, item := range blocks {
			b, ok := item.(map[string]any)
			if !ok {
				return errUnsupportedContent
			}
			if kind, _ := b["type"].(string); outputguard.IsServerToolResult(kind) {
				if err := rejectShadowKeys(b, "type", "content"); err != nil {
					return err
				}
				if err := g.guardServerToolResult(b, m); err != nil {
					return err
				}
			}
		}
	}
	if !g.scanRoles().ToolCalls {
		return nil
	}
	texts, err := toolUseTexts(m["content"])
	if err != nil {
		return err
	}
	return g.scoreOnly(indirect.SourceAssistant, texts)
}

// redactedServerToolErrorCode is the error_code of a redacted server tool
// result: the result is replaced with the tool's own error shape
// ({type}_error), which the upstream accepts in a later turn.
const redactedServerToolErrorCode = "unavailable"

// guardServerToolResult classifies the readable text of a web tool's result
// (titles, URLs, a fetched page: outputguard.ServerToolResultTexts) as one
// untrusted tool output, through the scan cache, without rewriting it.
// Encrypted content is opaque: it is what the upstream reads, so redaction
// replaces the whole result with the tool's error shape (error_code
// unavailable) and drops the citations of the message it is in (msg, nil
// for none), which could point into it.
func (g *textGuard) guardServerToolResult(b, msg map[string]any) error {
	texts := outputguard.ServerToolResultTexts(b)
	if len(texts) == 0 {
		return nil // an error result, or encrypted content only
	}
	kind, _ := b["type"].(string)
	redact := func() {
		b["content"] = map[string]any{"type": kind + "_error", "error_code": redactedServerToolErrorCode}
		dropCitations(msg)
	}
	return g.as(indirect.SourceTool, redact, func() error {
		return g.scoreUntrusted(strings.Join(texts, "\n"))
	})
}

// scoreUntrusted sanitizes an untrusted text for the detector, as the current
// source and redactor, without forwarding the sanitized form.
func (g *textGuard) scoreUntrusted(text string) error {
	n := len(g.texts)
	if _, err := g.clean(text); err != nil {
		return err
	}
	g.texts = g.texts[:n]
	return nil
}

// dropCitations removes the citations of a message's text blocks.
func dropCitations(msg map[string]any) {
	blocks, _ := msg["content"].([]any)
	for _, item := range blocks {
		if b, ok := item.(map[string]any); ok && b["type"] == "text" {
			delete(b, "citations")
		}
	}
}

// guardBlocks sanitizes the text of content blocks in place, as the current
// source; tool_result, document and search_result blocks switch the source,
// and web tool results are classified as tool output (guardServerToolResult).
func (g *textGuard) guardBlocks(blocks []any) error {
	for _, item := range blocks {
		b, ok := item.(map[string]any)
		if !ok {
			return errUnsupportedContent
		}
		if err := rejectShadowKeys(b, "type", "text", "content", "source"); err != nil {
			return err
		}
		kind, _ := b["type"].(string)
		var err error
		switch kind {
		case "tool_result":
			redact := func() {
				b["content"], b["is_error"] = redactedToolOutput, true
			}
			err = g.as(indirect.SourceTool, redact, func() error { return g.guardNested(b, "content") })
		case "document":
			redact := func() {
				b["source"] = map[string]any{"type": "text", "media_type": "text/plain", "data": redactedDocument}
				delete(b, "title")
				delete(b, "context")
			}
			err = g.as(indirect.SourceDocument, redact, func() error { return g.guardDocument(b) })
		case "search_result":
			redact := func() {
				b["title"] = "removed"
				b["content"] = []any{map[string]any{"type": "text", "text": redactedDocument}}
			}
			err = g.as(indirect.SourceDocument, redact, func() error {
				if err := g.guardStrings(b, "title"); err != nil {
					return err
				}
				return g.guardNested(b, "content")
			})
		case outputguard.BlockWebSearchResult, outputguard.BlockWebFetchResult:
			// Anthropic's API takes these in assistant turns only; scanned
			// wherever they are.
			err = g.guardServerToolResult(b, nil)
		default:
			// text, and any block with a text field; images have none.
			// Blocks of other types pass with only their text field scanned.
			err = g.guardStrings(b, "text")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// as runs fn with source and the block's redactor set, then restores the
// previous ones.
func (g *textGuard) as(src indirect.Source, redact func(), fn func() error) error {
	prevSrc, prevRedact := g.source, g.redactFn
	g.source, g.redactFn = src, redact
	defer func() { g.source, g.redactFn = prevSrc, prevRedact }()
	return fn()
}

// guardNested handles a field that is a string or a list of blocks.
func (g *textGuard) guardNested(b map[string]any, key string) error {
	switch v := b[key].(type) {
	case nil:
		return nil
	case string:
		cleaned, err := g.clean(v)
		if err != nil {
			return err
		}
		b[key] = cleaned
		return nil
	case []any:
		return g.guardBlocks(v)
	default:
		return errUnsupportedContent
	}
}

// guardStrings sanitizes the given fields of b when present. Anything but a
// string would reach the upstream unscanned.
func (g *textGuard) guardStrings(b map[string]any, keys ...string) error {
	for _, key := range keys {
		raw, present := b[key]
		if !present || raw == nil {
			continue
		}
		text, ok := raw.(string)
		if !ok {
			return errUnsupportedContent
		}
		cleaned, err := g.clean(text)
		if err != nil {
			return err
		}
		b[key] = cleaned
	}
	return nil
}

// guardDocument covers a document block: its title and context, and its
// content when it is text (source type text or content). A PDF or an image
// (base64, url, file) is passed on unscanned, like an image part.
func (g *textGuard) guardDocument(b map[string]any) error {
	if err := g.guardStrings(b, "title", "context"); err != nil {
		return err
	}
	src, ok := b["source"].(map[string]any)
	if !ok {
		return nil
	}
	if err := rejectShadowKeys(src, "type", "data", "content"); err != nil {
		return err
	}
	switch src["type"] {
	case "text":
		return g.guardStrings(src, "data")
	case "content":
		return g.guardNested(src, "content")
	}
	return nil
}

// toolUseTexts returns the string values of the input of an assistant
// message's tool_use blocks.
func toolUseTexts(content any) ([]string, error) {
	blocks, ok := content.([]any)
	if !ok {
		return nil, nil // a string: assistant text, not scanned
	}
	var out []string
	for _, item := range blocks {
		b, ok := item.(map[string]any)
		if !ok {
			return nil, errUnsupportedContent
		}
		if kind, _ := b["type"].(string); kind == "tool_use" || kind == "server_tool_use" {
			out = append(out, stringLeaves(b["input"])...)
		}
	}
	return out, nil
}

// guardMessagesTools collects the tool definitions (tools[]: name, description,
// input_schema) when their scanning is on. Anthropic's own tools (a type such
// as web_search_20250305, no description or schema) have nothing to scan.
func (g *textGuard) guardMessagesTools(body map[string]any) error {
	raw, present := body["tools"]
	if !present || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return errUnsupportedContent
	}
	if !g.scanRoles().ToolDescriptions {
		return nil
	}
	for _, item := range list {
		def, ok := item.(map[string]any)
		if !ok {
			return errUnsupportedContent
		}
		_, hasDescription := def["description"]
		_, hasSchema := def["input_schema"]
		if !hasDescription && !hasSchema {
			continue
		}
		tool, err := toolFromMap(def, "input_schema")
		if err != nil {
			return err
		}
		if !g.trustedTool(tool.Name) {
			g.tools = append(g.tools, tool)
		}
	}
	return nil
}

// spotlightMessages marks the text of tool_result blocks when the mode is not
// off, and explains the marking in the system prompt.
func spotlightMessages(body map[string]any, mode indirect.Mode) (bool, error) {
	if mode == indirect.ModeOff || mode == "" {
		return false, nil
	}
	messages, ok := body["messages"].([]any)
	if !ok {
		return false, nil
	}
	sl, err := indirect.NewSpotlight(mode)
	if err != nil {
		return false, err
	}
	marked := false
	for _, msg := range messages {
		m, _ := msg.(map[string]any)
		blocks, _ := m["content"].([]any)
		for _, item := range blocks {
			b, _ := item.(map[string]any)
			if b == nil || b["type"] != "tool_result" {
				continue
			}
			switch content := b["content"].(type) {
			case string:
				b["content"] = sl.Mark(content)
				marked = true
			case []any:
				for _, part := range content {
					if p, ok := part.(map[string]any); ok {
						if text, ok := p["text"].(string); ok {
							p["text"] = sl.Mark(text)
							marked = true
						}
					}
				}
			}
		}
	}
	if marked {
		addMessagesSystemNote(body, sl.Note())
	}
	return marked, nil
}

// addMessagesSystemNote appends note to the system prompt: to the string, as
// one more text block, or as the system prompt when there is none. Blocks
// before it keep their cache_control.
func addMessagesSystemNote(body map[string]any, note string) {
	switch system := body["system"].(type) {
	case string:
		if system == "" {
			body["system"] = note
		} else {
			body["system"] = system + "\n\n" + note
		}
	case []any:
		body["system"] = append(system, map[string]any{"type": "text", "text": note})
	default:
		body["system"] = note
	}
}

// injectMessagesCanary puts the canary into the system prompt.
func injectMessagesCanary(body map[string]any, canary string) bool {
	addMessagesSystemNote(body, outputguard.CanaryNote(canary))
	return true
}

func messagesStub(model any) fiber.Map {
	return fiber.Map{
		"id":    "msg_stub",
		"type":  "message",
		"role":  "assistant",
		"model": model,
		"content": []fiber.Map{{
			"type": "text",
			"text": "[guardrail passed — configure an upstream with provider anthropic to proxy to a real model]",
		}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage":         fiber.Map{"input_tokens": 0, "output_tokens": 0},
	}
}

// anthropicErrorType maps an HTTP status to the error type of the Messages API.
func anthropicErrorType(status int) string {
	switch status {
	case fiber.StatusUnauthorized:
		return "authentication_error"
	case fiber.StatusPaymentRequired:
		return "billing_error"
	case fiber.StatusForbidden:
		return "permission_error"
	case fiber.StatusNotFound:
		return "not_found_error"
	case fiber.StatusRequestEntityTooLarge:
		return "request_too_large"
	case fiber.StatusTooManyRequests:
		return "rate_limit_error"
	case fiber.StatusGatewayTimeout:
		return "timeout_error"
	case 529:
		return "overloaded_error"
	}
	if status >= 500 {
		return "api_error"
	}
	return "invalid_request_error"
}

// anthropicErrorBody is the Messages API error shape.
func anthropicErrorBody(errType, message string) fiber.Map {
	return fiber.Map{"type": "error", "error": fiber.Map{"type": errType, "message": message}}
}

// anthropicStreamError is an error event of a Messages API stream.
func anthropicStreamError(message, errType, _ string) []byte {
	if errType == "server_error" {
		errType = "api_error"
	}
	event, _ := json.Marshal(anthropicErrorBody(errType, message))
	return append(append([]byte("\n\nevent: error\ndata: "), event...), '\n', '\n')
}

// isAnthropicRequest reports a request answered in the Anthropic format: the
// Messages API routes, and /v1/models with an anthropic-version header.
func isAnthropicRequest(c *fiber.Ctx) bool {
	path := strings.TrimSuffix(strings.ToLower(c.Path()), "/")
	switch path {
	case "/v1/messages", "/v1/messages/count_tokens":
		return true
	case "/v1/models":
		return c.Get("anthropic-version") != ""
	}
	return false
}

// anthropicErrors rewrites the JSON errors of Anthropic requests, whichever
// handler or middleware wrote them, into the Messages API shape:
// {"type":"error","error":{"type":...,"message":...}}. The status is kept, so a
// refusal is a 400 here as on the chat path. A stream's errors are events,
// written in that shape by the stream itself.
func anthropicErrors() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isAnthropicRequest(c) {
			return c.Next()
		}
		if err := c.Next(); err != nil {
			return err
		}
		toAnthropicError(c.Response())
		return nil
	}
}

func toAnthropicError(resp *fasthttp.Response) {
	status := resp.StatusCode()
	if status < 400 || !strings.HasPrefix(string(resp.Header.ContentType()), fiber.MIMEApplicationJSON) {
		return
	}
	var body struct {
		Type  string          `json:"type"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(resp.Body(), &body) != nil || body.Type == "error" {
		return // not JSON, or already in the Anthropic shape
	}
	var message string
	var nested struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body.Error, &nested) == nil && nested.Message != "" {
		message = nested.Message
	} else if json.Unmarshal(body.Error, &message) != nil || message == "" {
		message = http.StatusText(status)
	}
	out, err := json.Marshal(anthropicErrorBody(anthropicErrorType(status), message))
	if err != nil {
		return
	}
	resp.SetBodyRaw(out)
}

// countTokensHandler forwards POST /v1/messages/count_tokens to the anthropic
// upstream the key's default route picks (project, org, then
// UPSTREAM_LLM_URL). The key and rate limit apply; the body is not scanned:
// the upstream counts its tokens and runs no model on it. Route rules do not
// apply, since they depend on scan results.
func countTokensHandler(gw gateway) fiber.Handler {
	return func(c *fiber.Ctx) error {
		body, err := decodeBody(c.Body())
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		call, err := anthropicCall(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorBody(err.Error(), "invalid_request_error", "invalid_header"))
		}
		orgID, _ := tenant.OrgID(c)
		entry := requestEntry{OrgID: orgID, ProjectID: tenant.ProjectID(c)}
		target, err := gw.resolveRoute(entry, policy.Decision{}, nil)
		if errors.Is(err, errRouteUnavailable) {
			return c.Status(fiber.StatusBadGateway).
				JSON(errorBody("route target unavailable", "server_error", "route_unavailable"))
		}
		if err != nil {
			slog.Error("upstreams unavailable", "org", orgID, "err", err)
			return policyUnavailable(c)
		}
		if err := anthropicRoute(target); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorBody(err.Error(), "invalid_request_error", "unsupported_upstream"))
		}
		if target.proxy == nil {
			// The stub: an estimate, 4 bytes per token as for request.tokens.
			return c.JSON(fiber.Map{"input_tokens": len(c.Body()) / 4})
		}
		requested, _ := body["model"].(string)
		model, err := target.applyModel(requested)
		if errors.Is(err, errModelNotAllowed) {
			return c.Status(fiber.StatusBadRequest).JSON(errorBody(
				"model "+strconv.Quote(requested)+" is not allowed for this upstream", "invalid_request_error", "model_not_allowed"))
		}
		data := c.Body()
		if model != requested {
			body["model"] = model
			if data, err = json.Marshal(body); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
			}
		}
		resp, err := target.proxy.Do(requestContext(c, gw.base), "/messages/count_tokens", data, call)
		if err != nil {
			return upstreamError(c, err)
		}
		defer resp.Close()
		out, err := resp.ReadAll()
		if err != nil {
			return upstreamError(c, err)
		}
		c.Set(fiber.HeaderContentType, resp.ContentType)
		return c.Status(resp.Status).Send(out)
	}
}
