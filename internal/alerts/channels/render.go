// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Summary is the text of a notification, rendered from the payload. It holds
// what the payload holds: names, counts and ids, never prompt text.
type Summary struct {
	Title string   // "[CRITICAL] Firing: Jailbreak burst"
	Lines []string // count and window, group, project
	Link  string
}

var words = map[string]map[string]string{
	"en": {
		"firing": "Firing", "resolved": "Resolved", "test": "Test",
		"events": "%d events in %s", "project": "Project", "group": "Group", "first": "First seen", "last": "Last seen",
		"open": "Open alert", "subject": "[Guard Spec] %s",
	},
	"vi": {
		"firing": "Đang cảnh báo", "resolved": "Đã hết", "test": "Thử",
		"events": "%d sự kiện trong %s", "project": "Dự án", "group": "Nhóm", "first": "Lần đầu", "last": "Lần cuối",
		"open": "Mở cảnh báo", "subject": "[Guard Spec] %s",
	},
}

func word(lang, key string) string {
	if w, ok := words[lang]; ok {
		return w[key]
	}
	return words["en"][key]
}

// Render builds the summary of p in lang (en or vi).
func Render(p *Payload, lang string) Summary {
	state := word(lang, p.State)
	if state == "" {
		state = p.State
	}
	if p.Test {
		state = word(lang, "test")
	}
	s := Summary{
		Title: fmt.Sprintf("[%s] %s: %s", strings.ToUpper(p.Severity), state, p.Rule.Name),
		Link:  p.Links.Alert,
	}
	s.Lines = append(s.Lines, fmt.Sprintf(word(lang, "events"), p.Count, window(p.WindowSeconds)))
	if p.ProjectID != nil && *p.ProjectID != "" {
		s.Lines = append(s.Lines, word(lang, "project")+": "+*p.ProjectID)
	}
	if len(p.Group) > 0 {
		keys := make([]string, 0, len(p.Group))
		for k := range p.Group {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+p.Group[k])
		}
		s.Lines = append(s.Lines, word(lang, "group")+": "+strings.Join(parts, ", "))
	}
	if !p.FirstAt.IsZero() {
		s.Lines = append(s.Lines, word(lang, "first")+": "+p.FirstAt.UTC().Format(time.RFC3339)+
			" · "+word(lang, "last")+": "+p.LastAt.UTC().Format(time.RFC3339))
	}
	return s
}

// Text is the summary as plain text.
func (s Summary) Text() string {
	out := s.Title + "\n" + strings.Join(s.Lines, "\n")
	if s.Link != "" {
		out += "\n" + s.Link
	}
	return out
}

func window(sec int) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", sec)
}
