// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package indirect

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Input settings of an organization (RF-113cd269, org_input_settings,
// migration 030): what the gateway accepts as input, within the instance's
// limits. An org without them inherits the instance's behaviour unchanged
// (PDF_EXTRACT, UNSCANNED_PARTS, MAX_SCAN_TOKENS).
//
//   - input_mode text_only refuses every image, file and audio part (415);
//     hybrid accepts text and the files whose type is in allowed_file_types.
//   - max_input_tokens refuses a request over it (413) before it is scanned;
//     null: the instance's limit. At most InputTokenCeiling.
//   - allowed_file_types lists the file types hybrid accepts, among
//     ReadableFileTypes (the types the gateway reads); others are refused.
//   - unreadable_file_action says what happens to an allowed file the gateway
//     cannot read (a scanned, encrypted or damaged PDF): block refuses the
//     request, pass forwards it unscanned and tags its audit row.
const (
	InputTextOnly = "text_only"
	InputHybrid   = "hybrid"

	UnreadableBlock = "block"
	UnreadablePass  = "pass"

	// ShortPathTokens is the most tokens one request carries on the short
	// path (MAX_SCAN_TOKENS unset): about 28 KB of direct text and 128 KiB
	// of documents and tool results, 4 bytes a token. It is the ceiling of
	// max_input_tokens when the instance has no MAX_SCAN_TOKENS.
	ShortPathTokens = 40_000
)

// ReadableFileTypes are the file types whose content the gateway reads, the
// only values allowed_file_types takes.
var ReadableFileTypes = []string{"pdf"}

// InputSettings is one organization's input settings.
type InputSettings struct {
	InputMode            string   `json:"input_mode"`
	MaxInputTokens       *int     `json:"max_input_tokens"`
	AllowedFileTypes     []string `json:"allowed_file_types"`
	UnreadableFileAction string   `json:"unreadable_file_action"`
}

// InputTokenCeiling is the most max_input_tokens may be: MAX_SCAN_TOKENS when
// set, else ShortPathTokens.
func InputTokenCeiling(maxScanTokens int) int {
	if maxScanTokens > 0 {
		return maxScanTokens
	}
	return ShortPathTokens
}

// Normalize checks s and puts it in its stored form: defaults filled in
// (unreadable_file_action block), file types lower-case, sorted and unique,
// and no file types in text_only. ceiling bounds max_input_tokens.
func (s *InputSettings) Normalize(ceiling int) error {
	switch s.InputMode {
	case InputTextOnly, InputHybrid:
	case "":
		return errors.New("input_mode is required: text_only or hybrid")
	default:
		return fmt.Errorf("input_mode must be text_only or hybrid, not %q", s.InputMode)
	}
	if s.UnreadableFileAction == "" {
		s.UnreadableFileAction = UnreadableBlock
	}
	if s.UnreadableFileAction != UnreadableBlock && s.UnreadableFileAction != UnreadablePass {
		return fmt.Errorf("unreadable_file_action must be block or pass, not %q", s.UnreadableFileAction)
	}
	if n := s.MaxInputTokens; n != nil {
		if *n < 1 {
			return errors.New("max_input_tokens must be at least 1, or null for the instance's limit")
		}
		if *n > ceiling {
			return fmt.Errorf("max_input_tokens must be at most %d, the instance's limit", ceiling)
		}
	}
	types := []string{}
	for _, t := range s.AllowedFileTypes {
		t = strings.ToLower(strings.TrimSpace(t))
		if !slices.Contains(ReadableFileTypes, t) {
			return fmt.Errorf("allowed_file_types: %q is not a type the gateway can read (%s)", t,
				strings.Join(ReadableFileTypes, ", "))
		}
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	slices.Sort(types)
	if s.InputMode == InputTextOnly {
		types = []string{} // text_only accepts no file at all
	}
	s.AllowedFileTypes = types
	return nil
}

// Equal reports the same settings; nil is the instance's behaviour.
func (s *InputSettings) Equal(o *InputSettings) bool {
	if s == nil || o == nil {
		return s == nil && o == nil
	}
	return s.InputMode == o.InputMode && s.UnreadableFileAction == o.UnreadableFileAction &&
		slices.Equal(s.AllowedFileTypes, o.AllowedFileTypes) &&
		(s.MaxInputTokens == nil) == (o.MaxInputTokens == nil) &&
		(s.MaxInputTokens == nil || *s.MaxInputTokens == *o.MaxInputTokens)
}

// Loosened lists what going from from to to loosens: input_mode (text_only
// to hybrid), max_input_tokens (raised, or back to the instance's limit),
// allowed_file_types (a type added), unreadable_file_action (block to pass),
// or inherit (to is nil: back to the instance's behaviour, which reads no
// org limit at all). From the instance's behaviour (from nil) nothing is
// loosened: every setting is at least as strict.
func Loosened(from, to *InputSettings) []string {
	if from == nil {
		return nil
	}
	if to == nil {
		return []string{"inherit"}
	}
	var out []string
	if from.InputMode == InputTextOnly && to.InputMode == InputHybrid {
		out = append(out, "input_mode")
	}
	if from.MaxInputTokens != nil && (to.MaxInputTokens == nil || *to.MaxInputTokens > *from.MaxInputTokens) {
		out = append(out, "max_input_tokens")
	}
	for _, t := range to.AllowedFileTypes {
		if !slices.Contains(from.AllowedFileTypes, t) {
			out = append(out, "allowed_file_types")
			break
		}
	}
	if from.UnreadableFileAction == UnreadableBlock && to.UnreadableFileAction == UnreadablePass {
		out = append(out, "unreadable_file_action")
	}
	return out
}

// Tightened is from with only the tightening part of to applied: what takes
// effect at once while the loosening part waits for approval. With nothing
// loosened it is to.
func Tightened(from, to *InputSettings) *InputSettings {
	if len(Loosened(from, to)) == 0 {
		return to
	}
	if to == nil {
		return from
	}
	out := *from
	if to.InputMode == InputTextOnly {
		out.InputMode = InputTextOnly
	}
	if to.MaxInputTokens != nil && (from.MaxInputTokens == nil || *to.MaxInputTokens < *from.MaxInputTokens) {
		n := *to.MaxInputTokens
		out.MaxInputTokens = &n
	}
	types := []string{}
	for _, t := range from.AllowedFileTypes {
		if slices.Contains(to.AllowedFileTypes, t) && out.InputMode == InputHybrid {
			types = append(types, t)
		}
	}
	out.AllowedFileTypes = types
	if to.UnreadableFileAction == UnreadableBlock {
		out.UnreadableFileAction = UnreadableBlock
	}
	return &out
}

// MaxTokens returns the request's token cap with the org's max_input_tokens:
// the smaller of the two when both are set (0: none).
func (s *InputSettings) MaxTokens(cap int) int {
	if s == nil || s.MaxInputTokens == nil {
		return cap
	}
	if cap <= 0 {
		return *s.MaxInputTokens
	}
	return min(cap, *s.MaxInputTokens)
}

// Allows reports whether the settings accept a file of type t.
func (s *InputSettings) Allows(t string) bool {
	return s.InputMode == InputHybrid && slices.Contains(s.AllowedFileTypes, t)
}
