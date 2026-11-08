// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
)

// Personal data kept from the upstream (RF-5b9b3aa2, the org's
// input_pii_action). With redact or tokenize, the personal data the input
// check finds (input_pii.go: e-mail, Vietnamese phone, card, CCCD, IPv4) is
// replaced in the request before it goes upstream (outputguard.Pseudonymizer):
//
//   - in user text, tool results and documents, after the text was
//     classified (the detector and the policy see the request as sent);
//   - in the earlier turns the model produced (assistant text and tool-call
//     arguments): with tokenize the client got the values back in those
//     answers and sends them again with the conversation.
//
// Left as they are: system and developer prompts (the operator's text),
// thinking and reasoning blocks (signed by the provider), and results of the
// provider's own server tools (web search and fetch: the provider made them).
//
// With tokenize, the answer has the values put back (Scanner.WithTokens),
// whether the output guard is on or not.

// pseudonymize replaces personal data in text from the current source when
// the org has an action on. Text of other sources is returned as it is.
func (g *textGuard) pseudonymize(text string) string {
	if g.pseudo == nil {
		return text
	}
	src := g.source
	if src == "" {
		src = indirect.SourceUser
	}
	if !piiSource(src) {
		return text
	}
	return g.pseudo.Apply(text)
}

// modelSkipTypes are blocks and items of the model's turns whose text is
// left alone: signed reasoning, and server tool results the provider made.
func modelSkipType(kind string) bool {
	return kind == "thinking" || kind == "redacted_thinking" || kind == "reasoning" ||
		kind == "compaction" || kind == "item_reference" || outputguard.IsServerToolResult(kind)
}

// modelSkipKeys hold identifiers and opaque values, never personal data the
// client wrote.
var modelSkipKeys = map[string]bool{
	"type": true, "id": true, "role": true, "name": true, "call_id": true, "tool_use_id": true,
	"signature": true, "encrypted_content": true, "status": true, "model": true,
}

// pseudonymizeModel replaces personal data in an earlier turn the model
// produced (a chat assistant message, a Messages assistant message, a
// Responses model item), in place.
func (g *textGuard) pseudonymizeModel(v map[string]any) {
	if g.pseudo == nil {
		return
	}
	g.pseudoWalk(v, 0)
}

func (g *textGuard) pseudoWalk(v any, depth int) any {
	if depth > 32 {
		return v
	}
	switch x := v.(type) {
	case string:
		return g.pseudo.Apply(x)
	case []any:
		for i := range x {
			x[i] = g.pseudoWalk(x[i], depth+1)
		}
		return x
	case map[string]any:
		if kind, _ := x["type"].(string); modelSkipType(kind) {
			return x
		}
		for k, val := range x {
			if modelSkipKeys[k] {
				continue
			}
			if s, ok := val.(string); ok && k == "arguments" {
				x[k] = g.pseudoArguments(s)
				continue
			}
			x[k] = g.pseudoWalk(val, depth+1)
		}
		return x
	default:
		return v
	}
}

// pseudoArguments replaces personal data in the string values of a tool
// call's JSON arguments, keeping them valid JSON (a phone number written as
// a JSON number is left alone). Arguments that are not JSON are text.
func (g *textGuard) pseudoArguments(args string) string {
	var parsed any
	dec := json.NewDecoder(strings.NewReader(args))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return g.pseudo.Apply(args)
	}
	out, err := json.Marshal(g.pseudoWalk(parsed, 0))
	if err != nil {
		return args
	}
	return string(out)
}

// piiProtectTags renders what the action replaced for the audit row, as
// "input:pii_<action>_<kind>=<n>" (redacted or tokenized), never the values.
func piiProtectTags(action string, counts outputguard.Counts) []string {
	verb := "redacted"
	if action == outputguard.PIITokenize {
		verb = "tokenized"
	}
	var tags []string
	for _, kind := range outputguard.PIIKinds {
		if n := counts[kind]; n > 0 {
			tags = append(tags, "input:pii_"+verb+"_"+kind+"="+strconv.Itoa(n))
		}
	}
	return tags
}
