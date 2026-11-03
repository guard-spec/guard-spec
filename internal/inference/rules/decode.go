package rules

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// b64Run finds base64-looking runs long enough to hold a sentence.
var b64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// decodeBase64 returns the readable texts hidden in base64 runs (at most
// three, each capped), so the engine can score what a model would decode.
func decodeBase64(text string) []string {
	var out []string
	for _, m := range b64Run.FindAllString(text, 8) {
		if !hasMixedBase64(m) {
			continue
		}
		s := strings.TrimRight(m, "=")
		var dec []byte
		var err error
		if strings.ContainsAny(s, "-_") {
			dec, err = base64.RawURLEncoding.DecodeString(s)
		} else {
			dec, err = base64.RawStdEncoding.DecodeString(s)
		}
		if err != nil || len(dec) == 0 || !readable(dec) {
			continue
		}
		if len(dec) > maxDecodeLen {
			dec = dec[:maxDecodeLen]
		}
		out = append(out, string(dec))
		if len(out) == 3 {
			break
		}
	}
	return out
}

// hasMixedBase64 skips plain words and numbers: real base64 of text mixes
// upper case, lower case and usually digits.
func hasMixedBase64(s string) bool {
	var up, lo bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		up = up || c >= 'A' && c <= 'Z'
		lo = lo || c >= 'a' && c <= 'z'
	}
	return up && lo
}

// readable reports whether b is UTF-8 text with mostly letters and spaces.
func readable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	good, total := 0, 0
	for _, r := range string(b) {
		total++
		if r == ' ' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r > 0x7f || r >= '0' && r <= '9' || strings.ContainsRune(".,:;!?'\"-()", r) {
			good++
		}
	}
	return total >= 8 && float64(good)/float64(total) > 0.9
}
