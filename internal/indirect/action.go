// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package indirect

import (
	"fmt"
	"strings"
)

// Action is what the gateway does with untrusted content (a tool result or a
// document) that scores at or above the indirect threshold.
type Action string

const (
	// ActionBlock refuses the whole request (the default).
	ActionBlock Action = "block"
	// ActionRedact replaces the offending block with a placeholder and lets
	// the request go on. Tool descriptions are still refused: a tool cannot
	// be half removed.
	ActionRedact Action = "redact"
)

// ParseAction reads INDIRECT_ACTION or guard_settings.indirect_action; ""
// is block.
func ParseAction(s string) (Action, error) {
	switch a := Action(strings.ToLower(strings.TrimSpace(s))); a {
	case ActionBlock, ActionRedact:
		return a, nil
	case "":
		return ActionBlock, nil
	default:
		return "", fmt.Errorf("indirect action must be block or redact, not %q", s)
	}
}
