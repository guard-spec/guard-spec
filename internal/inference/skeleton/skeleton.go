// Package skeleton turns sanitized text into a canonical "skeleton" that rule
// matching can use without caring how an attacker spelled a word.
//
// The skeleton is for matching only. It is lossy on purpose and is never shown
// to a model or a user. Steps, in order:
//
//  1. Drop the gateway's datamarking tokens ([DATA] ... [/DATA]).
//  2. NFKD, then drop combining marks: Vietnamese diacritics go away, and
//     fullwidth or compatibility forms become ASCII. đ/Đ become d.
//  3. Fold confusables: Cyrillic and Greek lookalikes and a few symbols map to
//     the Latin letter they imitate.
//  4. Lowercase.
//  5. Fold leetspeak inside words that also hold a letter
//     (0→o 1→i 3→e 4→a 5→s 7→t @→a $→s |→l). "2024" stays "2024".
//  6. Collapse letters spelled out with separators: "i.g.n.o.r.e",
//     "i g n o r e", "i-g-n-o-r-e" become "ignore".
//  7. Squeeze a run of three or more equal letters to one ("ignoooore").
//  8. Expand common Vietnamese teencode words (ko→khong, dc→duoc, j→gi, ...).
//
// Teencode letter swaps (qu→w, ph→f) are not undone here because doing so would
// change English words. The rules package compares words through Key, which
// applies the same swap to both sides.
package skeleton

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Of returns the skeleton of s.
func Of(s string) string { return Analyze(s).Text }

// Analysis is a skeleton plus counts of the folds that look like evasion.
// Diacritic stripping and teencode are ordinary Vietnamese writing, so they
// are not counted.
type Analysis struct {
	Text        string
	Folded      string // lowercased, diacritics and homoglyphs folded, spelled-out runs joined; no leet or teencode (keeps e-mail addresses and URLs intact)
	Confusables int    // homoglyphs folded
	Leet        int    // leet characters folded
	Spelled     int    // letter-by-letter runs collapsed
	Squeezed    int    // long letter repeats squeezed
}

// Obfuscated reports whether the text needed folding that ordinary writing
// does not: homoglyphs, two or more leet characters, spelled-out words.
func (a Analysis) Obfuscated() bool {
	return a.Confusables > 0 || a.Leet >= 2 || a.Spelled > 0
}

// Analyze returns the skeleton of s with fold counts.
func Analyze(s string) Analysis {
	var a Analysis
	s = stripMarkers(s)
	s, a.Confusables = fold(s)
	a.Folded, _ = collapseSpelled(s)
	s, a.Leet = foldLeet(s)
	s, a.Spelled = collapseSpelled(s)
	s, a.Squeezed = squeeze(s)
	a.Text = expandTeencode(s)
	return a
}

func stripMarkers(s string) string {
	s = strings.ReplaceAll(s, "[DATA]", " ")
	s = strings.ReplaceAll(s, "[/DATA]", " ")
	return strings.ReplaceAll(s, "\uE000", "")
}

// confusables maps lookalike runes (after NFKD and lowercasing) to Latin.
var confusables = map[rune]rune{
	// Cyrillic
	'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o',
	'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i',
	'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'ӏ': 'l', 'ɡ': 'g', 'г': 'r',
	'п': 'n', 'ь': 'b', 'ү': 'y', 'з': '3',
	// Greek
	'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v',
	'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'ς': 's', 'σ': 'o',
	'μ': 'u', 'λ': 'l', 'δ': 'd',
	// Latin lookalikes and symbols
	'ı': 'i', 'ł': 'l', 'ø': 'o', 'ß': 's', 'æ': 'a', 'œ': 'o', 'ð': 'd', 'þ': 'p',
	'ɑ': 'a', 'ɩ': 'i', 'ʟ': 'l', 'ɴ': 'n', 'ʀ': 'r', 'ꜱ': 's', 'ᴀ': 'a', 'ᴇ': 'e',
	'ᴏ': 'o', 'ᴜ': 'u', 'ᴛ': 't', 'ɪ': 'i',
	// Vietnamese đ (has no decomposition)
	'đ': 'd',
}

// fold applies NFKD, drops combining marks, lowercases and folds confusables.
// Every whitespace run becomes one space; a newline becomes "\n" so sentence
// breaks survive.
func fold(s string) (string, int) {
	n := 0
	if !isASCII(s) {
		s = norm.NFKD.String(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		if r < 0x80 {
			if 'A' <= r && r <= 'Z' {
				r += 'a' - 'A'
			}
			b.WriteByte(byte(r))
			continue
		}
		r = unicode.ToLower(r)
		if c, ok := confusables[r]; ok {
			if r != 'đ' {
				n++
			}
			r = c
		}
		b.WriteRune(r)
	}
	return b.String(), n
}

// leet maps leetspeak characters to letters.
var leet = map[rune]rune{
	'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't',
	'@': 'a', '$': 's', '|': 'l',
}

func isLetter(r rune) bool {
	if r < 0x80 {
		return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z'
	}
	return unicode.IsLetter(r)
}

// foldLeet rewrites leet characters inside runs that hold at least one letter.
// A run is a maximal sequence of letters, digits and leet symbols.
func foldLeet(s string) (string, int) {
	out, n := foldLeetPass(s, false)
	if n >= 6 {
		// Clearly leetspeak: short digit-only words are letters too ("4c7 45 4n 41").
		out, n = foldLeetPass(s, true)
	}
	return out, n
}

// foldLeetPass folds leet runs; with digitsToo, digit-only runs of up to
// three characters are folded as well.
func foldLeetPass(s string, digitsToo bool) (string, int) {
	rs := []rune(s)
	n := 0
	out := make([]rune, 0, len(rs))
	for i := 0; i < len(rs); {
		if !isLetter(rs[i]) && !isLeetOrDigit(rs[i]) {
			out = append(out, rs[i])
			i++
			continue
		}
		j, letters := i, 0
		for j < len(rs) && (isLetter(rs[j]) || isLeetOrDigit(rs[j])) {
			if isLetter(rs[j]) {
				letters++
			}
			j++
		}
		fold := letters > 0 || digitsToo && j-i <= 3
		for k := i; k < j; k++ {
			r := rs[k]
			if fold {
				if m, ok := leet[r]; ok {
					r = m
					n++
				}
			}
			out = append(out, r)
		}
		i = j
	}
	return string(out), n
}

func isLeetOrDigit(r rune) bool {
	switch r {
	case '@', '$', '|':
		return true
	}
	return unicode.IsDigit(r)
}

// spelledSep are the separators attackers put between single letters.
func spelledSep(r rune) bool {
	switch r {
	case ' ', '.', '-', '_', '*', '/', '+', '~', '·', '•', ',':
		return true
	}
	return false
}

// collapseSpelled joins runs of single letters separated by separators, e.g.
// "i.g.n.o.r.e" or "i g n o r e". A run needs at least four letters when the
// separator is a space (so "a b c" lists survive) and three otherwise. Inside a
// run, a longer gap (two or more separators) becomes a word break.
func collapseSpelled(s string) (string, int) {
	runs := 0
	rs := []rune(s)
	n := len(rs)
	var out []rune
	single := func(i int) bool { // rs[i] is a letter standing alone
		return isLetter(rs[i]) && (i == 0 || !isLetter(rs[i-1])) && (i+1 == n || !isLetter(rs[i+1]))
	}
	i := 0
	for i < n {
		if !single(i) {
			out = append(out, rs[i])
			i++
			continue
		}
		// Collect letters[k] and the gap that follows each.
		letters := []int{i}
		gaps := [][2]int{}
		onlySpace := true
		j := i + 1
		for {
			k := j
			for k < n && spelledSep(rs[k]) {
				k++
			}
			if k == j || k >= n || !single(k) || k-j > 3 {
				break
			}
			for _, r := range rs[j:k] {
				if r != ' ' {
					onlySpace = false
				}
			}
			gaps = append(gaps, [2]int{j, k})
			letters = append(letters, k)
			j = k + 1
		}
		need := 3
		if onlySpace {
			need = 4
		}
		if len(letters) < need {
			out = append(out, rs[i])
			i++
			continue
		}
		// Most gaps are one separator; longer ones mark word breaks.
		for idx, p := range letters {
			out = append(out, rs[p])
			if idx < len(gaps) && gaps[idx][1]-gaps[idx][0] > 1 {
				out = append(out, ' ')
			}
		}
		i = letters[len(letters)-1] + 1
		runs++
	}
	return string(out), runs
}

// squeeze reduces a run of three or more equal letters to one letter.
func squeeze(s string) (string, int) {
	n := 0
	rs := []rune(s)
	out := make([]rune, 0, len(rs))
	for i := 0; i < len(rs); {
		j := i + 1
		for j < len(rs) && rs[j] == rs[i] {
			j++
		}
		if j-i >= 3 && isLetter(rs[i]) {
			out = append(out, rs[i])
			n++
		} else {
			out = append(out, rs[i:j]...)
		}
		i = j
	}
	return string(out), n
}

// Teencode maps common Vietnamese chat abbreviations (diacritics already
// stripped) to the full word. Only whole words are replaced.
var Teencode = map[string]string{
	"k": "khong", "ko": "khong", "kh": "khong", "kg": "khong", "khg": "khong",
	"hok": "khong", "hk": "khong", "hong": "khong", "kq": "ket qua",
	"j": "gi", "gj": "gi",
	"dc": "duoc", "dk": "duoc", "dx": "duoc",
	"bh": "bay gio", "bjo": "bay gio", "bgio": "bay gio",
	"ng": "nguoi", "ngta": "nguoi ta",
	"mk": "minh", "mik": "minh", "mjk": "minh",
	"ns": "noi", "vs": "voi", "ntn": "nhu the nao", "r": "roi",
	"cx": "cung", "cg": "cung", "ms": "moi", "bt": "biet", "lm": "lam",
	"trc": "truoc", "tr": "truoc", "hdan": "huong dan", "hd": "huong dan",
	"tl": "tra loi", "ttin": "thong tin", "tt": "thong tin",
	"nhg": "nhung", "nc": "nuoc", "wa": "qua", "zay": "vay",
	"vd": "vi du", "bn": "ban", "mn": "moi nguoi", "ae": "anh em",
	"ad": "admin", "h": "gio", "b": "ban", "t": "toi", "iu": "yeu", "chx": "chua", "thui": "thoi",
	"hem": "khong", "kp": "khong phai",
	"gv":   "giao vien",
	"qtac": "quy tac", // not "qt" ("quan trong", "quoc te"), "qdinh" ("quyet dinh") or "cdan" ("cong dan")
}

// expandTeencode replaces teencode words (letters only, whole word).
func expandTeencode(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	start := -1
	flush := func(end int) {
		w := s[start:end]
		if full, ok := Teencode[w]; ok {
			b.WriteString(full)
		} else {
			b.WriteString(w)
		}
		start = -1
	}
	for i, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			flush(i)
		}
		b.WriteRune(r)
	}
	if start >= 0 {
		flush(len(s))
	}
	return b.String()
}

// Key is the form two words are compared in: the skeleton word with
// teencode letter swaps undone on both sides (qu→w, ph→f, initial k before
// a/o/u→c, initial j→gi), l and i made equal in words of four letters or
// more (leet "1" is ambiguous; short words like "all" and "ai" must stay
// apart), and doubled letters squeezed.
func Key(word string) string {
	if word == "" {
		return word
	}
	w := word
	if len(w) > 1 && w[0] == 'k' && (w[1] == 'a' || w[1] == 'o' || w[1] == 'u') {
		w = "c" + w[1:]
	}
	if len(w) > 1 && w[0] == 'j' && w[1] != 'i' {
		w = "gi" + w[1:]
	}
	w = strings.ReplaceAll(w, "qu", "w")
	w = strings.ReplaceAll(w, "ph", "f")
	b := make([]byte, 0, len(w))
	var prev byte
	long := len(w) >= 4
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c == 'l' && long {
			c = 'i'
		}
		if c == prev && c >= 'a' && c <= 'z' {
			continue
		}
		b = append(b, c)
		prev = c
	}
	return string(b)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
