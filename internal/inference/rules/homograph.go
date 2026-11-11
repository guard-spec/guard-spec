// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Vietnamese homographs (RF-895d3533 R5).
//
// Rules are written in skeleton form (no diacritics), so that a Vietnamese
// attack written without its marks still matches. The price is that words
// the marks tell apart match the same rule word: "giàu" (rich) reads as
// "giấu" (hide), the secrecy cue of tp.secrecy and ii.hidden_note. In long
// benign Vietnamese documents (bench/long, R3) such words fired a rule in
// windows the classifier also scored high.
//
// When a word is written with marks that make it another word than every
// rule means by its skeleton, the marks are evidence and the word is set
// apart before the skeleton is taken: it is replaced by a token no rule
// contains. A word written without marks still matches as before. Only
// skeletons whose every use in the rule set means one marked word are
// listed ("an" is "ẩn" in one rule and "án" in "đáp án" in another, so it is
// not). Two words also exist unmarked with another meaning, "hay" (or; the
// rules mean "hãy", an imperative) and "ai" (who; the rules mean "AI"): they
// are set apart only among words written with Vietnamese marks, where the
// unmarked spelling is the other word ("hay là" is "or", "không ai" is
// "nobody"); "AI" in capitals stays. "nhưng" (but) is set apart from
// "nhúng" (embed, a send verb) and "những" (a plural marker).

// homographAllowed maps a lowercase skeleton word to the marked spellings
// the rules mean by it. A marked spelling of that skeleton outside the set
// is another word.
var homographAllowed = map[string]map[string]bool{
	"giau":  {"giấu": true},                 // not "giàu" (rich)
	"nhung": {"nhúng": true, "những": true}, // not "nhưng" (but)
}

// unmarkedOther are unmarked words that, among words written with Vietnamese
// marks, are another word than the rules mean (all lowercase; capitals are
// kept, so "AI" stays the model).
var unmarkedOther = map[string]bool{"hay": true, "ai": true}

// homographToken replaces a set-apart word: letters only (so the tokenizer
// keeps it one word), no doubled letters (skeleton.Key squeezes them) and no
// rule word.
const homographToken = "homografx"

// viMarked are the letters only Vietnamese writing uses (đ, ă, â, ê, ô, ơ, ư
// and the vowels with a tone mark), lowercase.
const viMarked = "ăâđêôơưàảãáạằẳẵắặầẩẫấậèẻẽéẹềểễếệìỉĩíịòỏõóọồổỗốộờởỡớợùủũúụừửữứựỳỷỹýỵ"

func isVIMarked(r rune) bool { return strings.ContainsRune(viMarked, unicode.ToLower(r)) }

// stripVI removes the Vietnamese marks of a lowercase word (đ becomes d).
func stripVI(w string) string {
	var b strings.Builder
	for _, r := range w {
		if i := strings.IndexRune(viMarked, r); i >= 0 {
			b.WriteRune(viBase[utf8.RuneCountInString(viMarked[:i])])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// viBase is the unmarked letter of each letter of viMarked, in order.
var viBase = []rune("aadeoou" + strings.Repeat("a", 15) + strings.Repeat("e", 10) + strings.Repeat("i", 5) +
	strings.Repeat("o", 15) + strings.Repeat("u", 10) + strings.Repeat("y", 5))

func init() {
	if len(viBase) != utf8.RuneCountInString(viMarked) {
		panic("rules: viBase and viMarked differ in length")
	}
}

// setApartHomographs returns s with the words that the marks (or, among
// marked words, their absence) make another word than the rules mean
// replaced by homographToken. s is returned unchanged when there are none.
func setApartHomographs(s string) string {
	marked := false
	for _, r := range s {
		if r >= 0x80 && isVIMarked(r) {
			marked = true
			break
		}
	}
	if !marked {
		return s // no marks: nothing to tell apart
	}
	type word struct {
		start, end int
		marked     bool
	}
	var words []word
	start := -1
	for i, r := range s {
		if unicode.IsLetter(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			words = append(words, word{start, i, hasVIMark(s[start:i])})
			start = -1
		}
	}
	if start >= 0 {
		words = append(words, word{start, len(s), hasVIMark(s[start:])})
	}
	var b strings.Builder
	last, changed := 0, false
	for i, w := range words {
		// The neighbourhood of a word is written with marks when at least two
		// of the two words before it and the two after it carry one: a
		// message without marks inside a marked header keeps its "hay" and
		// "ai".
		near := 0
		for j := max(0, i-2); j <= min(len(words)-1, i+2); j++ {
			if j != i && words[j].marked {
				near++
			}
		}
		if other(s[w.start:w.end], near >= 2) {
			b.WriteString(s[last:w.start])
			b.WriteString(homographToken)
			last, changed = w.end, true
		}
	}
	if !changed {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func hasVIMark(w string) bool {
	for _, r := range w {
		if r >= 0x80 && isVIMarked(r) {
			return true
		}
	}
	return false
}

// other reports whether the word w is another word than the rule word its
// skeleton spells; inMarked: its neighbourhood is written with marks.
func other(w string, inMarked bool) bool {
	if len(w) > 12 {
		return false
	}
	lw := strings.ToLower(norm.NFC.String(w))
	if inMarked && lw == w && unmarkedOther[lw] { // lowercase as written: "AI" stays
		return true
	}
	hasMark := false
	for _, r := range lw {
		if isVIMarked(r) {
			hasMark = true
			break
		}
	}
	if !hasMark {
		return false
	}
	allowed, ok := homographAllowed[stripVI(lw)]
	return ok && !allowed[lw]
}
