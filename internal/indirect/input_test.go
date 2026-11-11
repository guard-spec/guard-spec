// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package indirect

import (
	"slices"
	"strings"
	"testing"
)

func intp(n int) *int { return &n }

func TestInputSettingsNormalize(t *testing.T) {
	s := InputSettings{InputMode: InputHybrid, AllowedFileTypes: []string{" PDF", "pdf"}}
	if err := s.Normalize(100); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.AllowedFileTypes, []string{"pdf"}) || s.UnreadableFileAction != UnreadableBlock {
		t.Errorf("normalized = %+v", s)
	}
	text := InputSettings{InputMode: InputTextOnly, AllowedFileTypes: []string{"pdf"}}
	if err := text.Normalize(100); err != nil || len(text.AllowedFileTypes) != 0 {
		t.Errorf("text_only keeps no file types: %+v %v", text, err)
	}
	for _, tc := range []struct {
		s    InputSettings
		want string
	}{
		{InputSettings{}, "input_mode is required"},
		{InputSettings{InputMode: "files"}, "input_mode must be"},
		{InputSettings{InputMode: InputHybrid, UnreadableFileAction: "skip"}, "unreadable_file_action"},
		{InputSettings{InputMode: InputHybrid, MaxInputTokens: intp(0)}, "at least 1"},
		{InputSettings{InputMode: InputHybrid, MaxInputTokens: intp(101)}, "at most 100"},
		{InputSettings{InputMode: InputHybrid, AllowedFileTypes: []string{"docx"}}, "not a type the gateway can read"},
	} {
		if err := tc.s.Normalize(100); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc.s, err, tc.want)
		}
	}
	if InputTokenCeiling(0) != ShortPathTokens || InputTokenCeiling(500) != 500 {
		t.Error("InputTokenCeiling")
	}
}

func TestInputSettingsLoosenedTightened(t *testing.T) {
	strict := &InputSettings{InputMode: InputTextOnly, MaxInputTokens: intp(1000), AllowedFileTypes: []string{},
		UnreadableFileAction: UnreadableBlock}
	loose := &InputSettings{InputMode: InputHybrid, AllowedFileTypes: []string{"pdf"}, UnreadableFileAction: UnreadablePass}
	for _, tc := range []struct {
		name     string
		from, to *InputSettings
		want     []string
	}{
		{"from inherit", nil, strict, nil},
		{"to inherit", strict, nil, []string{"inherit"}},
		{"all", strict, loose, []string{"input_mode", "max_input_tokens", "allowed_file_types", "unreadable_file_action"}},
		{"tighten", loose, strict, nil},
		{"same", strict, strict, nil},
		{"raise", strict, &InputSettings{InputMode: InputTextOnly, MaxInputTokens: intp(2000), UnreadableFileAction: UnreadableBlock},
			[]string{"max_input_tokens"}},
	} {
		if got := Loosened(tc.from, tc.to); !slices.Equal(got, tc.want) {
			t.Errorf("%s: loosened %v, want %v", tc.name, got, tc.want)
		}
	}
	// Mixed: tokens lowered, unreadable files passed. Only the first applies.
	from := &InputSettings{InputMode: InputHybrid, MaxInputTokens: intp(8000), AllowedFileTypes: []string{"pdf"},
		UnreadableFileAction: UnreadableBlock}
	to := &InputSettings{InputMode: InputHybrid, MaxInputTokens: intp(4000), AllowedFileTypes: []string{"pdf"},
		UnreadableFileAction: UnreadablePass}
	mid := Tightened(from, to)
	if *mid.MaxInputTokens != 4000 || mid.UnreadableFileAction != UnreadableBlock || !slices.Equal(mid.AllowedFileTypes, []string{"pdf"}) {
		t.Errorf("tightened = %+v", mid)
	}
	if len(Loosened(from, mid)) != 0 || !slices.Equal(Loosened(mid, to), []string{"unreadable_file_action"}) {
		t.Error("the tightened step must not loosen, and the rest must be the loosening")
	}
	// text_only to hybrid with a type: stays text_only, no type.
	mid = Tightened(strict, loose)
	if !mid.Equal(strict) {
		t.Errorf("all loosening: tightened %+v, want unchanged", mid)
	}
	if Tightened(strict, nil) != strict || Tightened(loose, strict) != strict {
		t.Error("Tightened of a pure loosening or tightening")
	}
	if !(*InputSettings)(nil).Equal(nil) || strict.Equal(nil) || strict.Equal(loose) {
		t.Error("Equal")
	}
}

func TestInputSettingsLimits(t *testing.T) {
	var none *InputSettings
	if none.MaxTokens(500) != 500 {
		t.Error("nil settings keep the cap")
	}
	s := &InputSettings{InputMode: InputHybrid, MaxInputTokens: intp(300), AllowedFileTypes: []string{"pdf"}}
	if s.MaxTokens(500) != 300 || s.MaxTokens(0) != 300 || s.MaxTokens(200) != 200 {
		t.Error("MaxTokens takes the smaller")
	}
	if !s.Allows("pdf") || s.Allows("png") {
		t.Error("Allows in hybrid")
	}
	if (&InputSettings{InputMode: InputTextOnly, AllowedFileTypes: []string{"pdf"}}).Allows("pdf") {
		t.Error("text_only allows nothing")
	}
}
