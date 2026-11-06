// Package indirect handles content that reaches the model from a third party
// rather than from the user: tool results, retrieved documents and the tool
// descriptions an MCP server supplies. It decides which parts of a request
// are scanned (Roles), scores untrusted text with the injection detector and
// a category hint (Scanner), and marks untrusted text for the model
// (Spotlight).
package indirect

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Source names where a scanned piece of text came from.
type Source string

const (
	SourceUser            Source = "user"             // user turns, legacy prompt and suffix
	SourceSystem          Source = "system"           // system messages
	SourceAssistant       Source = "assistant"        // tool_calls arguments in assistant history
	SourceTool            Source = "tool"             // tool results (role tool or function)
	SourceDocument        Source = "document"         // documents passed to /guardrail/scan
	SourceToolDescription Source = "tool_description" // tools[].function.description and schema descriptions
)

// Untrusted reports whether text from s is third-party content: it is scored
// on its own, with a category hint, and feeds indirect.score.
func (s Source) Untrusted() bool {
	return s == SourceTool || s == SourceDocument || s == SourceToolDescription
}

// Roles selects the parts of a chat request the detector scores. Text of user
// and tool messages is sanitized whatever Roles says; Roles only decides
// whether it is classified.
type Roles struct {
	User             bool `json:"user"`              // user messages, legacy prompt and suffix
	Tool             bool `json:"tool"`              // tool results
	System           bool `json:"system"`            // system messages (scored, never rewritten)
	ToolCalls        bool `json:"tool_calls"`        // assistant tool_calls arguments from history
	ToolDescriptions bool `json:"tool_descriptions"` // tools[] and functions[] descriptions
}

// DefaultRoles scans user turns, tool results and tool descriptions. System
// prompts and earlier tool calls come from the integrating application.
var DefaultRoles = Roles{User: true, Tool: true, ToolDescriptions: true}

// roleNames are the names ParseRoles and String use, in order.
var roleNames = []string{"user", "tool", "system", "tool_calls", "tool_descriptions"}

func (r *Roles) field(name string) *bool {
	switch name {
	case "user":
		return &r.User
	case "tool":
		return &r.Tool
	case "system":
		return &r.System
	case "tool_calls":
		return &r.ToolCalls
	case "tool_descriptions":
		return &r.ToolDescriptions
	}
	return nil
}

// ParseRoles reads a comma-separated list such as "user,tool,tool_descriptions".
// "none" scans nothing; "all" scans every part.
func ParseRoles(s string) (Roles, error) {
	var r Roles
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return r, nil
	case "all":
		return Roles{User: true, Tool: true, System: true, ToolCalls: true, ToolDescriptions: true}, nil
	}
	for _, name := range strings.Split(s, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		f := r.field(name)
		if f == nil {
			return Roles{}, fmt.Errorf("unknown scan role %q (have %s, none, all)", name, strings.Join(roleNames, ", "))
		}
		*f = true
	}
	return r, nil
}

// String is the comma-separated form ParseRoles reads.
func (r Roles) String() string {
	var on []string
	for _, name := range roleNames {
		if *r.field(name) {
			on = append(on, name)
		}
	}
	if len(on) == 0 {
		return "none"
	}
	return strings.Join(on, ",")
}

// Settings is an organization's override of the gateway's scan settings, kept
// in organizations.guard_settings (JSON). A field left out keeps the gateway
// default from the environment.
type Settings struct {
	ScanRoles map[string]bool `json:"scan_roles,omitempty"` // role name -> scanned
	Spotlight *Mode           `json:"spotlight,omitempty"`
	// IndirectAction is block or redact for untrusted content over the
	// threshold (INDIRECT_ACTION).
	IndirectAction *Action `json:"indirect_action,omitempty"`
}

// Action returns the indirect action with the org's override.
func (s Settings) Action(def Action) Action {
	if s.IndirectAction != nil {
		return *s.IndirectAction
	}
	return def
}

// ParseSettings decodes and validates stored or submitted settings. Unknown
// keys are refused, so a typo does not silently leave a default in place.
func ParseSettings(raw []byte) (Settings, error) {
	var s Settings
	if len(raw) == 0 {
		return s, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Settings{}, fmt.Errorf("guard settings: %w", err)
	}
	for name := range s.ScanRoles {
		if !slices.Contains(roleNames, name) {
			return Settings{}, fmt.Errorf("guard settings: unknown scan role %q (have %s)", name, strings.Join(roleNames, ", "))
		}
	}
	if s.Spotlight != nil {
		if _, err := ParseMode(string(*s.Spotlight)); err != nil {
			return Settings{}, fmt.Errorf("guard settings: %w", err)
		}
	}
	if s.IndirectAction != nil {
		a, err := ParseAction(string(*s.IndirectAction))
		if err != nil || *s.IndirectAction == "" {
			return Settings{}, fmt.Errorf("guard settings: indirect_action must be block or redact")
		}
		s.IndirectAction = &a
	}
	return s, nil
}

// Apply returns the roles and spotlight mode with the org's overrides.
func (s Settings) Apply(roles Roles, mode Mode) (Roles, Mode) {
	for name, on := range s.ScanRoles {
		if f := roles.field(name); f != nil {
			*f = on
		}
	}
	if s.Spotlight != nil {
		mode = *s.Spotlight
	}
	return roles, mode
}
