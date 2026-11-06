package outputguard

import (
	"strings"
	"testing"
)

// Answers for the output guard benchmarks: a clean answer, and one with links,
// images and personal data to rewrite. `make bench` runs them.
var benchAnswers = []struct{ name, text string }{
	{"clean_2k", strings.Repeat("Banana bread needs ripe bananas, flour, sugar, eggs and butter. ", 32)},
	{"findings_2k", strings.Repeat("Mail a@example.com or call 0912 345 678, card 4111 1111 1111 1111, "+
		"see [docs](https://evil.example/x?d=1) and ![x](https://evil.example/p.png?q=secret). ", 12)},
}

func benchGuard() *Guard {
	return New(Config{LinkAllowlist: []string{"docs.example.com"}, RedactPII: true, RedactIPv4: true, Canary: CanaryRedact})
}

// BenchmarkOutputGuardText guards a whole (non-streamed) answer.
func BenchmarkOutputGuardText(b *testing.B) {
	g := benchGuard()
	for _, in := range benchAnswers {
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.text)))
			b.ReportAllocs()
			for b.Loop() {
				counts := Counts{}
				_ = g.ForRequest("PS-CANARY-0123456789ABCDEF01234567").Text(in.text, counts)
			}
		})
	}
}

// BenchmarkOutputGuardStream guards the same answers sent as 16-byte deltas,
// the way a streamed completion arrives.
func BenchmarkOutputGuardStream(b *testing.B) {
	g := benchGuard()
	for _, in := range benchAnswers {
		var chunks []string
		for s := in.text; s != ""; {
			n := min(16, len(s))
			chunks, s = append(chunks, s[:n]), s[n:]
		}
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.text)))
			b.ReportAllocs()
			for b.Loop() {
				st := g.ForRequest("PS-CANARY-0123456789ABCDEF01234567").NewStream()
				for _, c := range chunks {
					_ = st.Write(c)
				}
				_ = st.Flush()
			}
		})
	}
}
