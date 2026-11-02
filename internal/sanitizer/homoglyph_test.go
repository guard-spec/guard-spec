package sanitizer

import "testing"

func TestCheckHomoglyphs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ── Clean inputs ─────────────────────────────────────────────────────
		{"pure latin", "hello world", false},
		{"pure cyrillic", "привет мир", false},
		{"pure greek", "αβγδ", false},
		{"digits only", "12345", false},
		{"empty", "", false},
		{"punctuation", "!@#$%", false},
		{"mixed scripts separated by space", "hello привет", false}, // different words — fine
		{"CJK passthrough", "你好 world", false},                     // CJK = scriptOther, not flagged

		// ── Homoglyph attacks ────────────────────────────────────────────────
		// Cyrillic 'а' (U+0430) inside an otherwise Latin word
		{"cyrillic-a in latin word", "hеllo", true},   // 'е' U+0435 = Cyrillic
		{"cyrillic-o in latin word", "wоrd", true},    // 'о' U+043E = Cyrillic
		{"latin+cyrillic token", "pаssword", true},    // 'а' U+0430 = Cyrillic
		{"greek-o in latin word", "passωord", true},   // 'ω' U+03C9 = Greek
		{"armenian char in latin", "heլլո", true}, // Armenian letters

		// ── Edge cases ───────────────────────────────────────────────────────
		{"multi-word, only last is attack", "clean кttack", true}, // 'А' U+0410 Cyrillic at start
		{"single mixed char sequence", "aа", true},                // 'а' = Cyrillic immediately after Latin
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkHomoglyphs(tt.in)
			if got != tt.want {
				t.Errorf("checkHomoglyphs(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeHomoglyphRisk(t *testing.T) {
	// Confirm the HomoglyphRisk signal flows through the full Sanitize pipeline.
	attack := "pаssword" // Latin 'p', Cyrillic 'а', Latin 'ssword'
	_, report, err := Sanitize(attack)
	if err != nil {
		t.Fatalf("Sanitize error: %v", err)
	}
	if !report.HomoglyphRisk {
		t.Error("expected HomoglyphRisk=true for mixed-script input")
	}
	// AnomalyScore should include the +0.3 homoglyph contribution
	if report.AnomalyScore < 0.3 {
		t.Errorf("expected AnomalyScore >= 0.3, got %v", report.AnomalyScore)
	}

	// Clean input must not trip the flag
	_, cleanReport, err := Sanitize("hello world")
	if err != nil {
		t.Fatalf("Sanitize error: %v", err)
	}
	if cleanReport.HomoglyphRisk {
		t.Error("expected HomoglyphRisk=false for clean input")
	}
}
