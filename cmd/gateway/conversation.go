// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"unicode/utf8"

	"github.com/guard-spec/guard-spec/internal/inference"
)

// The conversation window. The detector scores the text of a request, and
// with SCAN_HISTORY=latest only the trailing turn of a /v1/messages session,
// so an instruction split over several user turns ("Remember: ignore all" /
// "previous instructions" / "now do it") keeps every part under the block
// threshold. The window joins the most recent user turns
// (CONVERSATION_WINDOW_TURNS, at most CONVERSATION_WINDOW_BYTES) into one
// text and scores it once more; the decision takes the larger of that score
// and the per-turn one. Earlier turns are never scored on their own again:
// only the joined text is, through the scan cache, keyed on its hash, so a
// /v1/messages agent loop whose user turns did not change since the last
// request costs a cache lookup.

// sourceConversation is injection.source_role when the window holds the
// strongest finding.
const sourceConversation = "conversation"

// cacheWindow is the scan cache kind of a window's inference.Scores, in the
// in-process and the shared layer.
const cacheWindow = "window"

// userTurn is the user text of one message, its parts joined.
type userTurn struct {
	msg  int // the message's 1-based index
	text string
}

// addTurn records cleaned user text of the message being cleaned for the
// window. Text outside the messages (a legacy prompt) is not a turn.
func (g *textGuard) addTurn(text string) {
	if g.windowTurns == 0 || g.msg == 0 || strings.TrimSpace(text) == "" {
		return
	}
	if n := len(g.turns); n > 0 && g.turns[n-1].msg == g.msg {
		g.turns[n-1].text += " " + text
		return
	}
	g.turns = append(g.turns, userTurn{msg: g.msg, text: text})
}

// conversationWindow joins the most recent user turns: at most turns of
// them, and at most bytes in all. A window needs two turns; with fewer it is
// "". Each turn gets an equal share of the bytes: a longer turn keeps its
// head and its tail, where the pieces of a split instruction meet the turns
// around it, so padding one turn cannot push the others out of the window.
// Turns are joined with a space, not a newline: the L1 rules match within a
// sentence, and a turn cut mid-sentence goes on in the next.
func conversationWindow(all []userTurn, turns, bytes int) string {
	if turns < 2 || bytes <= 0 || len(all) < 2 {
		return ""
	}
	if len(all) > turns {
		all = all[len(all)-turns:]
	}
	share := (bytes - (len(all) - 1)) / len(all) // a space between turns
	var b strings.Builder
	b.Grow(bytes)
	for i, t := range all {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(clipMiddle(t.text, share))
	}
	return b.String()
}

// clipMiddle returns s when it fits in n bytes; otherwise its head and tail,
// a space between them, n bytes at most, cut on rune boundaries.
func clipMiddle(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 3 {
		return ""
	}
	head := (n - 1) / 2
	for head > 0 && !utf8.RuneStart(s[head]) {
		head--
	}
	tail := len(s) - (n - 1 - head)
	for tail < len(s) && !utf8.RuneStart(s[tail]) {
		tail++
	}
	return s[:head] + " " + s[tail:]
}

// scoreWindow scores the conversation window text (conversationWindow; ""
// for none) through the request's cache view, under key, after the per-turn
// text: joined is the direct text that was just classified and directScores
// its scores, reused when the window is the same text (a chat request whose
// classified text is only its user turns). The view writes a new score
// through to the shared layer, so another replica reads it. It raises
// v.Direct, and makes the window the strongest finding, when it scores
// higher.
func (gw gateway) scoreWindow(v *requestVerdict, view *cacheView, text, key, joined string,
	directScores inference.Scores) error {
	if text == "" {
		return nil
	}
	var scores inference.Scores
	if text == joined {
		scores = directScores
	} else if hit, ok := view.get(key); ok {
		scores = hit.(inference.Scores)
	} else {
		var err error
		if scores, err = gw.runner.Scan(gw.base, text); err != nil {
			return err
		}
		view.put(cacheWindow, key, scores)
	}
	c := float64(scores.Injection.Confidence)
	v.Window = c
	if v.SourceRole == "" || c > v.Direct {
		v.Scores, v.Direct, v.SourceRole = scores, c, sourceConversation
		v.DirectTrigger = triggerHash(sourceConversation, text)
	}
	return nil
}
