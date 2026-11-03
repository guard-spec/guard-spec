package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/giaplee/guard-spec/internal/indirect"
	"github.com/giaplee/guard-spec/internal/inference"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// scanConfig decides which parts of a request are classified, how untrusted
// content is marked for the model, and the floor for indirect.score.
type scanConfig struct {
	Roles             indirect.Roles
	Spotlight         indirect.Mode
	IndirectThreshold float64
}

func defaultScanConfig() scanConfig {
	return scanConfig{Roles: indirect.DefaultRoles, Spotlight: indirect.ModeOff,
		IndirectThreshold: indirect.BlockThreshold}
}

// loadScanConfig reads SCAN_ROLES, SPOTLIGHT and INDIRECT_BLOCK_THRESHOLD.
func loadScanConfig(env func(string) string) (scanConfig, error) {
	cfg := defaultScanConfig()
	var err error
	if v := strings.TrimSpace(env("SCAN_ROLES")); v != "" {
		if cfg.Roles, err = indirect.ParseRoles(v); err != nil {
			return scanConfig{}, fmt.Errorf("SCAN_ROLES: %w", err)
		}
	}
	if cfg.Spotlight, err = indirect.ParseMode(env("SPOTLIGHT")); err != nil {
		return scanConfig{}, fmt.Errorf("SPOTLIGHT: %w", err)
	}
	if v := strings.TrimSpace(env("INDIRECT_BLOCK_THRESHOLD")); v != "" {
		t, err := strconv.ParseFloat(v, 64)
		// Above injectionBlockThreshold would make indirect content more trusted
		// than the user's own text.
		if err != nil || t <= 0 || t > injectionBlockThreshold {
			return scanConfig{}, fmt.Errorf("INDIRECT_BLOCK_THRESHOLD must be a number in (0, %.2f]", injectionBlockThreshold)
		}
		cfg.IndirectThreshold = t
	}
	return cfg, nil
}

// settingsLoader returns an organization's scan overrides.
type settingsLoader func(ctx context.Context, orgID uuid.UUID) (indirect.Settings, error)

// dbSettingsLoader reads organizations.guard_settings in the org's RLS scope.
func dbSettingsLoader(db *pgxpool.Pool) settingsLoader {
	return func(ctx context.Context, orgID uuid.UUID) (indirect.Settings, error) {
		var raw []byte
		err := tenant.WithOrg(ctx, db, orgID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT guard_settings FROM organizations WHERE id = $1`, orgID).Scan(&raw)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return indirect.Settings{}, nil
		}
		if err != nil {
			return indirect.Settings{}, err
		}
		return indirect.ParseSettings(raw)
	}
}

// scanConfigFor is the gateway's configuration with the org's overrides. An
// error must fail the request closed: the org may have tightened the defaults.
func (gw gateway) scanConfigFor(orgID uuid.UUID) (scanConfig, error) {
	cfg := defaultScanConfig()
	if gw.scan != nil {
		cfg = *gw.scan
	}
	if gw.settings == nil || orgID == uuid.Nil {
		return cfg, nil
	}
	ctx, cancel := context.WithTimeout(gw.base, policyTimeout)
	defer cancel()
	s, err := gw.settings(ctx, orgID)
	if err != nil {
		return scanConfig{}, err
	}
	cfg.Roles, cfg.Spotlight = s.Apply(cfg.Roles, cfg.Spotlight)
	return cfg, nil
}

// scanPart is one sanitized text the detector will see.
type scanPart struct {
	source indirect.Source
	text   string
}

func (g *textGuard) scanRoles() indirect.Roles {
	if g.roles == nil {
		return indirect.DefaultRoles
	}
	return *g.roles
}

// collect records cleaned text from the current source if that source is
// scanned. Text of a source that is not scanned is still sanitized.
func (g *textGuard) collect(text string) {
	src := g.source
	if src == "" {
		src = indirect.SourceUser
	}
	roles := g.scanRoles()
	switch src {
	case indirect.SourceUser:
		if !roles.User {
			return
		}
	case indirect.SourceTool:
		if !roles.Tool {
			return
		}
	}
	g.parts = append(g.parts, scanPart{source: src, text: text})
}

// guardMessage sanitizes and collects one chat message according to its role.
// User and tool text is rewritten with its sanitized form. System text and
// tool-call arguments belong to the application: when their scanning is on
// they are classified, but forwarded unchanged.
func (g *textGuard) guardMessage(m map[string]any) error {
	role, _ := m["role"].(string)
	roles := g.scanRoles()
	switch role {
	case "system":
		if !roles.System {
			return nil
		}
		texts, err := contentTexts(m)
		if err != nil {
			return err
		}
		return g.scoreOnly(indirect.SourceSystem, texts)
	case "assistant":
		if !roles.ToolCalls {
			return nil
		}
		texts, err := toolCallTexts(m)
		if err != nil {
			return err
		}
		return g.scoreOnly(indirect.SourceAssistant, texts)
	case "tool", "function":
		g.source = indirect.SourceTool
	default:
		g.source = indirect.SourceUser
	}
	defer func() { g.source = "" }()
	return g.guardContent(m)
}

// scoreOnly sanitizes texts for the detector without touching the request.
func (g *textGuard) scoreOnly(src indirect.Source, texts []string) error {
	g.source = src
	defer func() { g.source = "" }()
	for _, t := range texts {
		if _, err := g.clean(t); err != nil {
			return err
		}
	}
	// clean also collected them as forwarded text; they are not.
	g.texts = g.texts[:len(g.texts)-len(texts)]
	return nil
}

// contentTexts returns the text of a message's content, string or parts.
func contentTexts(m map[string]any) ([]string, error) {
	switch content := m["content"].(type) {
	case nil:
		return nil, nil
	case string:
		return []string{content}, nil
	case []any:
		var out []string
		for _, part := range content {
			p, ok := part.(map[string]any)
			if !ok {
				return nil, errUnsupportedContent
			}
			if text, ok := p["text"].(string); ok {
				out = append(out, text)
			}
		}
		return out, nil
	default:
		return nil, errUnsupportedContent
	}
}

// toolCallTexts returns the string values of an assistant message's tool-call
// arguments (tool_calls[].function.arguments, and the older function_call).
// Arguments that are not JSON are scanned as they are.
func toolCallTexts(m map[string]any) ([]string, error) {
	var args []any
	if calls, ok := m["tool_calls"].([]any); ok {
		for _, call := range calls {
			c, _ := call.(map[string]any)
			fn, _ := c["function"].(map[string]any)
			if fn != nil {
				args = append(args, fn["arguments"])
			}
		}
	}
	if fn, ok := m["function_call"].(map[string]any); ok {
		args = append(args, fn["arguments"])
	}
	var out []string
	for _, a := range args {
		switch a := a.(type) {
		case nil:
		case string:
			var decoded any
			if err := json.Unmarshal([]byte(a), &decoded); err == nil {
				out = append(out, stringLeaves(decoded)...)
			} else {
				out = append(out, a)
			}
		default:
			out = append(out, stringLeaves(a)...)
		}
	}
	return out, nil
}

// stringLeaves collects every string in a decoded JSON value.
func stringLeaves(v any) []string {
	var out []string
	var walk func(any, int)
	walk = func(v any, depth int) {
		if depth > 64 {
			return
		}
		switch v := v.(type) {
		case string:
			if v != "" {
				out = append(out, v)
			}
		case map[string]any:
			for _, x := range v {
				walk(x, depth+1)
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

// guardTools collects the tool definitions of a chat request (tools[] in the
// current form, functions[] in the old one) when their scanning is on.
// Anything but the documented shape is refused, since its descriptions would
// reach the model unscanned.
func (g *textGuard) guardTools(body map[string]any) error {
	if err := rejectShadowKeys(body, "tools", "functions"); err != nil {
		return err
	}
	if !g.scanRoles().ToolDescriptions {
		return nil
	}
	for _, key := range []string{"tools", "functions"} {
		raw, present := body[key]
		if !present || raw == nil {
			continue
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
			if key == "tools" {
				if err := rejectShadowKeys(def, "function"); err != nil {
					return err
				}
				fn, present := def["function"]
				if !present {
					continue // a built-in tool type without a description
				}
				if def, ok = fn.(map[string]any); !ok {
					return errUnsupportedContent
				}
			}
			tool, err := toolFromMap(def, "parameters")
			if err != nil {
				return err
			}
			g.tools = append(g.tools, tool)
		}
	}
	return nil
}

// toolFromMap reads name, description and the schema under schemaKey.
func toolFromMap(def map[string]any, schemaKey string) (indirect.Tool, error) {
	if err := rejectShadowKeys(def, "name", "description", schemaKey); err != nil {
		return indirect.Tool{}, err
	}
	var t indirect.Tool
	var ok bool
	if raw, present := def["name"]; present && raw != nil {
		if t.Name, ok = raw.(string); !ok {
			return indirect.Tool{}, errUnsupportedContent
		}
	}
	if raw, present := def["description"]; present && raw != nil {
		if t.Description, ok = raw.(string); !ok {
			return indirect.Tool{}, errUnsupportedContent
		}
	}
	t.Schema = def[schemaKey]
	return t, nil
}

// maxUntrustedBytes bounds the untrusted text of one request. Each part is
// classified on its own (and refused above the runner's window limit), so
// this caps the total work.
const maxUntrustedBytes = 128 << 10

// requestVerdict is the detector's view of a whole request.
type requestVerdict struct {
	Scores     inference.Scores // the strongest finding, for the audit row and injection.*
	Direct     float64          // user, system and tool-call text, classified together
	Indirect   indirect.Verdict // strongest untrusted part; Source "" when there was none
	SourceRole string           // source of the strongest finding
}

// scoreRequest classifies the collected parts. User, system and tool-call
// text is joined and classified as before; each tool result and each tool
// definition is classified on its own, with its category hint.
func (gw gateway) scoreRequest(g *textGuard) (requestVerdict, error) {
	var v requestVerdict
	scanner := indirect.Scanner{Runner: gw.runner}

	var direct []scanPart
	untrustedBytes := 0
	for _, p := range g.parts {
		if p.source.Untrusted() {
			untrustedBytes += len(p.text)
		} else {
			direct = append(direct, p)
		}
	}
	for _, t := range g.tools {
		untrustedBytes += len(t.Description)
	}
	if untrustedBytes > maxUntrustedBytes {
		return v, inference.ErrInputTooLong
	}

	if len(direct) > 0 {
		texts := make([]string, len(direct))
		for i, p := range direct {
			texts[i] = p.text
		}
		scores, err := gw.runner.Scan(gw.base, strings.Join(texts, " "))
		if err != nil {
			return v, err
		}
		v.Scores, v.Direct = scores, float64(scores.Injection.Confidence)
		if v.SourceRole, err = gw.attribute(direct, v.Direct); err != nil {
			return v, err
		}
	}

	for _, p := range g.parts {
		if !p.source.Untrusted() {
			continue
		}
		pv, err := scanner.Score(gw.base, p.text, p.source)
		if err != nil {
			return v, err
		}
		if v.Indirect.Source == "" || pv.Score > v.Indirect.Score {
			v.Indirect = pv
		}
	}
	for _, t := range g.tools {
		tv, err := scanner.ScoreTool(gw.base, t, "parameters", false)
		if err != nil {
			if errors.Is(err, indirect.ErrSchemaTooDeep) {
				return v, errUnsupportedContent
			}
			return v, err
		}
		if v.Indirect.Source == "" || tv.Score > v.Indirect.Score {
			v.Indirect = tv.Verdict
		}
	}

	if v.Indirect.Source != "" && (len(direct) == 0 || v.Indirect.Score > v.Direct) {
		v.Scores = verdictScores(v.Indirect)
		v.SourceRole = string(v.Indirect.Source)
	}
	return v, nil
}

// attribute names the role of the direct text that scored highest. With one
// role it is that role; otherwise, when the joined text scored at all, each
// part is classified again to find it.
func (gw gateway) attribute(parts []scanPart, joined float64) (string, error) {
	role := parts[0].source
	mixed := false
	for _, p := range parts[1:] {
		mixed = mixed || p.source != role
	}
	if !mixed || joined < 0.3 {
		return string(role), nil
	}
	best := -1.0
	for _, p := range parts {
		s, err := gw.runner.Scan(gw.base, p.text)
		if err != nil {
			return "", err
		}
		if c := float64(s.Injection.Confidence); c > best {
			best, role = c, p.source
		}
	}
	return string(role), nil
}

// verdictScores turns an untrusted verdict into the row's scores: its score
// (raised by MCP signals for a tool description) and its hinted category.
func verdictScores(v indirect.Verdict) inference.Scores {
	s := v.Scores
	s.Injection.Confidence = float32(v.Score)
	if v.Category != "" {
		s.Injection.Label = v.Category
	}
	if d := s.Injection.Detail; d != nil {
		detail := *d
		detail.Category = v.Category
		s.Injection.Detail = &detail
	}
	return s
}

// spotlight marks tool results for the model when the mode is not off, and
// explains the marking in the system prompt. It reports whether it changed
// the body.
func spotlight(body map[string]any, mode indirect.Mode) (bool, error) {
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
		if role, _ := m["role"].(string); role != "tool" && role != "function" {
			continue
		}
		switch content := m["content"].(type) {
		case string:
			m["content"] = sl.Mark(content)
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
	if marked {
		addSystemNote(body, sl.Note())
	}
	return marked, nil
}

// addSystemNote appends note to a leading system message, or adds one.
func addSystemNote(body map[string]any, note string) {
	messages, _ := body["messages"].([]any)
	if len(messages) > 0 {
		if m, ok := messages[0].(map[string]any); ok && m["role"] == "system" {
			if text, ok := m["content"].(string); ok {
				m["content"] = text + "\n\n" + note
				return
			}
		}
	}
	body["messages"] = append([]any{map[string]any{"role": "system", "content": note}}, messages...)
}
