// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/valyala/fasthttp"
)

// The OpenAI Responses API (POST /v1/responses). Requests go through the same
// pipeline as chat completions (proxyHandler) and are sent as they are to
// {base_url}/responses of an upstream that serves it: provider openai,
// azure_openai or openai_compatible. There is no translation: an upstream of
// another provider gets a 400 that names it.
//
// Conversation state kept by the upstream (previous_response_id, conversation,
// item_reference input items) holds turns the gateway does not see in the
// request, so it cannot scan them again; such requests are refused unless
// RESPONSES_SERVER_STATE=allow, and then flagged in the audit row
// (input:server_state=1). Background responses are refused: their result is
// fetched with GET /v1/responses/{id}, which the gateway does not serve, so
// it would never pass the output guard.

var responsesFormat = apiFormat{
	path:          "/responses",
	guardBody:     (*textGuard).guardResponsesBody,
	spotlight:     spotlightResponses,
	injectCanary:  injectResponsesCanary,
	stub:          responsesStub,
	checkRoute:    responsesRoute,
	guardResponse: (*outputguard.Scanner).ResponsesResponse,
	newStream:     func(s *outputguard.Scanner) streamGuard { return s.NewResponseStream() },
	streamError:   responsesStreamError,
	history:       true,
}

// Values of RESPONSES_SERVER_STATE.
const (
	serverStateRefuse = "refuse"
	serverStateAllow  = "allow"
)

// paramError refuses a request for one of its parameters: a 400 with its
// message and code.
type paramError struct{ message, code string }

func (e *paramError) Error() string { return e.message }

// errNotResponses refuses /v1/responses for an upstream that does not serve it.
var errNotResponses = errors.New("upstream does not serve the Responses API")

// responsesRoute accepts the stub and upstreams of the providers that serve
// the Responses API at {base_url}/responses.
func responsesRoute(r route) error {
	switch r.provider {
	case "", providerOpenAICompatible, "openai", "azure_openai":
		return nil
	}
	if r.proxy == nil {
		return nil
	}
	name := r.name
	if name == "" {
		name = "UPSTREAM_LLM_URL"
	}
	return fmt.Errorf("%w: upstream %q (provider %s) does not serve the OpenAI Responses API; "+
		"use /v1/chat/completions, or set the upstream's provider to openai_compatible if it serves /responses",
		errNotResponses, name, r.provider)
}

// serverStateRefs returns the parts of a request that refer to conversation
// state the upstream keeps.
func serverStateRefs(body map[string]any) []string {
	var refs []string
	if id, ok := body["previous_response_id"]; ok && id != nil && id != "" {
		refs = append(refs, "previous_response_id")
	}
	if c, ok := body["conversation"]; ok && c != nil && c != "" {
		refs = append(refs, "conversation")
	}
	if items, ok := body["input"].([]any); ok {
		for _, item := range items {
			if m, ok := item.(map[string]any); ok && m["type"] == "item_reference" {
				refs = append(refs, "item_reference")
				break
			}
		}
	}
	return refs
}

// guardResponsesBody sanitizes every untrusted text of a Responses API
// request, with the roles of the chat path: user text (input as a string,
// user messages, prompt variables) is rewritten with its sanitized form and
// classified; function and custom tool outputs are untrusted content, each
// classified on its own (and redacted with INDIRECT_ACTION=redact); input
// items of other types that carry text (shell and MCP outputs, search results)
// are classified as untrusted tool output without being rewritten, and block
// when they score over the threshold; instructions and system or developer
// messages, and the arguments of function calls, are classified when their
// scanning is on but forwarded unchanged; assistant messages and reasoning
// (encrypted or not) are left alone. Images and files are passed on unscanned,
// as image parts are in chat. Tool definitions are checked for poisoning.
//
// With SCAN_HISTORY=latest (g.latest), the items up to the last one the model
// produced are history, as on /v1/messages.
func (g *textGuard) guardResponsesBody(body map[string]any) error {
	g.schemaKey = "parameters"
	if err := rejectShadowKeys(body, "input", "instructions", "tools", "prompt", "previous_response_id",
		"conversation", "background"); err != nil {
		return err
	}
	if b, _ := body["background"].(bool); b {
		return &paramError{code: "unsupported_parameter",
			message: "background responses are not supported through the gateway: their result is fetched " +
				"with GET /v1/responses/{id}, which would bypass the output guard"}
	}
	if refs := serverStateRefs(body); len(refs) > 0 {
		g.serverState = true
		if !g.allowServerState {
			return &paramError{code: "server_state_refused", message: strings.Join(refs, ", ") +
				" refers to conversation state the upstream keeps, which the gateway cannot scan; " +
				"send the whole conversation in input instead, or ask the operator to set RESPONSES_SERVER_STATE=allow"}
		}
	}
	switch instr := body["instructions"].(type) {
	case nil:
	case string:
		if g.scanRoles().System {
			if err := g.scoreOnly(indirect.SourceSystem, []string{instr}); err != nil {
				return err
			}
		}
	default:
		return errUnsupportedContent
	}
	if err := g.guardPromptVariables(body["prompt"]); err != nil {
		return err
	}
	switch input := body["input"].(type) {
	case nil:
	case string:
		cleaned, err := g.clean(input)
		if err != nil {
			return err
		}
		body["input"] = cleaned
	case []any:
		if err := g.guardInputItems(input); err != nil {
			return err
		}
	default:
		return errUnsupportedContent
	}
	return g.guardResponsesTools(body)
}

func (g *textGuard) guardInputItems(items []any) error {
	last := -1 // the last item the model produced: the trailing turn follows it
	for i, item := range items {
		if m, ok := item.(map[string]any); ok && isModelItem(m) {
			last = i
		}
	}
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return errUnsupportedContent
		}
		if err := rejectShadowKeys(m, "type", "role", "content", "output", "arguments", "input"); err != nil {
			return err
		}
		g.history = g.latest && i <= last
		err := g.guardInputItem(m)
		g.history = false
		if err != nil {
			return err
		}
	}
	return nil
}

// modelItems are input item types the model produced in an earlier turn.
var modelItems = map[string]bool{
	"function_call": true, "custom_tool_call": true, "reasoning": true, "computer_call": true,
	"local_shell_call": true, "shell_call": true, "apply_patch_call": true, "mcp_call": true,
	"mcp_list_tools": true, "mcp_approval_request": true, "web_search_call": true, "file_search_call": true,
	"code_interpreter_call": true, "image_generation_call": true, "tool_search_call": true, "program": true,
	"compaction": true,
}

func isModelItem(m map[string]any) bool {
	kind, _ := m["type"].(string)
	if kind == "" || kind == "message" {
		return m["role"] == "assistant"
	}
	return modelItems[kind]
}

// toolCallItems are model items that ask the client to run something; their
// text is classified as tool calls (SCAN_ROLES tool_calls).
var toolCallItems = map[string]bool{
	"function_call": true, "custom_tool_call": true, "computer_call": true, "local_shell_call": true,
	"shell_call": true, "apply_patch_call": true, "mcp_approval_request": true, "program": true,
}

func (g *textGuard) guardInputItem(m map[string]any) error {
	kind, _ := m["type"].(string)
	switch {
	case kind == "" || kind == "message":
		return g.guardInputMessage(m)
	case kind == "function_call_output" || kind == "custom_tool_call_output":
		redact := func() { m["output"] = redactedToolOutput }
		return g.as(indirect.SourceTool, redact, func() error { return g.guardNested(m, "output") })
	case kind == "reasoning" || kind == "item_reference" || kind == "compaction":
		// The model's own reasoning (opaque when encrypted), a reference to an
		// item the upstream keeps (serverStateRefs), compacted context.
		return nil
	case kind == "function_call":
		if !g.scanRoles().ToolCalls {
			return nil
		}
		texts, err := toolCallTexts(map[string]any{"function_call": map[string]any{"arguments": m["arguments"]}})
		if err != nil {
			return err
		}
		return g.scoreOnly(indirect.SourceAssistant, texts)
	case kind == "custom_tool_call":
		if !g.scanRoles().ToolCalls {
			return nil
		}
		input, ok := m["input"].(string)
		if !ok {
			if m["input"] != nil {
				return errUnsupportedContent
			}
			return nil
		}
		return g.scoreOnly(indirect.SourceAssistant, []string{input})
	case toolCallItems[kind]:
		if !g.scanRoles().ToolCalls {
			return nil
		}
		return g.scoreOnly(indirect.SourceAssistant, readableLeaves(m))
	default:
		// Tool output of another kind (shell, MCP, search results, ...), or
		// an item type the gateway does not know: its text is untrusted. It
		// cannot be redacted, so it blocks when it scores over the threshold.
		texts := readableLeaves(m)
		if len(texts) == 0 {
			return nil
		}
		return g.as(indirect.SourceTool, nil, func() error { return g.scoreUntrusted(strings.Join(texts, "\n")) })
	}
}

func (g *textGuard) guardInputMessage(m map[string]any) error {
	role, _ := m["role"].(string)
	switch role {
	case "system", "developer":
		texts, err := contentTexts(m)
		if err != nil || !g.scanRoles().System {
			return err
		}
		return g.scoreOnly(indirect.SourceSystem, texts)
	case "assistant":
		// The model's earlier answer, as in chat.
		return nil
	}
	g.source = indirect.SourceUser
	defer func() { g.source = "" }()
	return g.guardNested(m, "content")
}

// opaqueItemKeys hold no text a model reads as instructions: identifiers,
// statuses, encrypted content, and image or file data.
var opaqueItemKeys = map[string]bool{
	"type": true, "id": true, "call_id": true, "status": true, "encrypted_content": true, "image_url": true,
	"file_id": true, "file_data": true, "result": true, "signature": true, "container_id": true,
	"item_id": true, "approval_request_id": true, "partial_image_b64": true,
}

// readableLeaves returns the strings of an item a model would read: every
// string but those under opaqueItemKeys and data URLs.
func readableLeaves(v any) []string {
	var out []string
	var walk func(any, int)
	walk = func(v any, depth int) {
		if depth > 32 {
			return
		}
		switch v := v.(type) {
		case string:
			if v != "" && !strings.HasPrefix(v, "data:") {
				out = append(out, v)
			}
		case map[string]any:
			// Sorted keys: the joined text, and so its score and cache key,
			// must not depend on map order.
			for _, k := range slices.Sorted(maps.Keys(v)) {
				if !opaqueItemKeys[k] {
					walk(v[k], depth+1)
				}
			}
		case []any:
			for _, x := range v {
				walk(x, depth+1)
			}
		}
	}
	walk(v, 0)
	return out
}

// guardPromptVariables covers the variables of a stored prompt (prompt.id):
// strings and input_text parts are user text. The stored prompt itself is the
// application's and stays with the upstream.
func (g *textGuard) guardPromptVariables(raw any) error {
	if raw == nil {
		return nil
	}
	prompt, ok := raw.(map[string]any)
	if !ok {
		return errUnsupportedContent
	}
	if err := rejectShadowKeys(prompt, "variables"); err != nil {
		return err
	}
	vars, ok := prompt["variables"].(map[string]any)
	if !ok {
		if prompt["variables"] != nil {
			return errUnsupportedContent
		}
		return nil
	}
	g.source = indirect.SourceUser
	defer func() { g.source = "" }()
	keys := make([]string, 0, len(vars))
	for key := range vars {
		keys = append(keys, key)
	}
	sort.Strings(keys) // the same parts, in the same order, every time
	for _, key := range keys {
		switch val := vars[key].(type) {
		case string:
			cleaned, err := g.clean(val)
			if err != nil {
				return err
			}
			vars[key] = cleaned
		case map[string]any:
			if err := g.guardBlocks([]any{val}); err != nil {
				return err
			}
		default:
			return errUnsupportedContent
		}
	}
	return nil
}

// guardResponsesTools collects the definitions of function and custom tools
// (name, description and parameters at the top level) and the description of
// remote MCP servers when their scanning is on. Built-in tools have nothing to
// scan.
func (g *textGuard) guardResponsesTools(body map[string]any) error {
	raw, present := body["tools"]
	if !present || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return errUnsupportedContent
	}
	for _, item := range list {
		def, ok := item.(map[string]any)
		if !ok {
			return errUnsupportedContent
		}
		if err := rejectShadowKeys(def, "type", "server_description"); err != nil {
			return err
		}
		if !g.scanRoles().ToolDescriptions {
			continue
		}
		var tool indirect.Tool
		switch def["type"] {
		case nil, "function", "custom":
			var err error
			if tool, err = toolFromMap(def, "parameters"); err != nil {
				return err
			}
		case "mcp":
			desc, present := def["server_description"]
			if !present || desc == nil {
				continue
			}
			text, ok := desc.(string)
			if !ok {
				return errUnsupportedContent
			}
			label, _ := def["server_label"].(string)
			tool = indirect.Tool{Name: label, Description: text}
		default:
			continue
		}
		if !g.trustedTool(tool.Name) {
			g.tools = append(g.tools, tool)
		}
	}
	return nil
}

// isToolOutput reports an input item that holds a tool's output.
func isToolOutput(kind string) bool {
	return kind == "function_call_output" || kind == "custom_tool_call_output"
}

// hasToolOutputItem reports a tool output among the input items, for
// is_mcp_response.
func hasToolOutputItem(raw any) bool {
	items, _ := raw.([]any)
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			if kind, _ := m["type"].(string); isToolOutput(kind) {
				return true
			}
		}
	}
	return false
}

// spotlightResponses marks function and custom tool outputs when the mode is
// not off, and explains the marking in the instructions.
func spotlightResponses(body map[string]any, mode indirect.Mode) (bool, error) {
	if mode == indirect.ModeOff || mode == "" {
		return false, nil
	}
	items, ok := body["input"].([]any)
	if !ok {
		return false, nil
	}
	sl, err := indirect.NewSpotlight(mode)
	if err != nil {
		return false, err
	}
	marked := false
	for _, item := range items {
		m, _ := item.(map[string]any)
		if kind, _ := m["type"].(string); m == nil || !isToolOutput(kind) {
			continue
		}
		switch output := m["output"].(type) {
		case string:
			m["output"] = sl.Mark(output)
			marked = true
		case []any:
			for _, part := range output {
				if p, ok := part.(map[string]any); ok {
					if text, ok := p["text"].(string); ok {
						p["text"] = sl.Mark(text)
						marked = true
					}
				}
			}
		}
	}
	if marked {
		addInstructions(body, sl.Note())
	}
	return marked, nil
}

// addInstructions appends note to the instructions, or makes it the
// instructions when there are none.
func addInstructions(body map[string]any, note string) {
	if text, ok := body["instructions"].(string); ok && text != "" {
		body["instructions"] = text + "\n\n" + note
		return
	}
	body["instructions"] = note
}

// injectResponsesCanary puts the canary into the instructions. The output
// guard takes it out of the instructions the response repeats.
func injectResponsesCanary(body map[string]any, canary string) bool {
	addInstructions(body, outputguard.CanaryNote(canary))
	return true
}

func responsesStub(model any) fiber.Map {
	return fiber.Map{
		"id":         "resp_stub",
		"object":     "response",
		"created_at": 0,
		"status":     "completed",
		"model":      model,
		"output": []fiber.Map{{
			"type":   "message",
			"id":     "msg_stub",
			"status": "completed",
			"role":   "assistant",
			"content": []fiber.Map{{
				"type":        "output_text",
				"text":        "[guardrail passed — configure UPSTREAM_LLM_URL to proxy to a real model]",
				"annotations": []any{},
			}},
		}},
		"usage": fiber.Map{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
	}
}

// responsesStreamError is the error event of a Responses API stream when the
// output guard is off and the events are not numbered.
func responsesStreamError(message, _, code string) []byte {
	return outputguard.ResponsesErrorEvent(message, code, -1)
}

// isOpenAIErrorRoute reports a route whose errors all take the OpenAI shape.
func isOpenAIErrorRoute(c *fiber.Ctx) bool {
	switch strings.TrimSuffix(strings.ToLower(c.Path()), "/") {
	case "/v1/responses", "/v1/embeddings":
		return true
	}
	return false
}

// openAIErrors rewrites the JSON errors of /v1/responses and /v1/embeddings
// whose error is a bare string (the key check, rate limit, an unscannable
// body) into the OpenAI shape {"error":{"message","type","param","code"}}.
// The status is kept.
func openAIErrors() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !isOpenAIErrorRoute(c) {
			return c.Next()
		}
		if err := c.Next(); err != nil {
			return err
		}
		toOpenAIError(c.Response())
		return nil
	}
}

func toOpenAIError(resp *fasthttp.Response) {
	status := resp.StatusCode()
	if status < 400 || !strings.HasPrefix(string(resp.Header.ContentType()), fiber.MIMEApplicationJSON) {
		return
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(resp.Body(), &body) != nil {
		return
	}
	var message string
	if json.Unmarshal(body["error"], &message) != nil {
		return // already an object
	}
	if message == "" {
		message = http.StatusText(status)
	}
	errType, code := "invalid_request_error", "invalid_request"
	switch {
	case status == fiber.StatusUnauthorized:
		code = "invalid_api_key"
	case status == fiber.StatusTooManyRequests:
		code = "rate_limit_exceeded"
	case status == fiber.StatusRequestEntityTooLarge:
		code = "request_too_large"
	case status >= 500:
		errType, code = "server_error", "server_error"
	}
	out, err := json.Marshal(fiber.Map{"error": fiber.Map{"message": message, "type": errType, "param": nil, "code": code}})
	if err != nil {
		return
	}
	resp.SetBodyRaw(out)
}
