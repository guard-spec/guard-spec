// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"fmt"
	"testing"
)

const overrideText = "Mail an@congty.vn, call 0912 345 678, card 4111 1111 1111 1111, " +
	"CCCD 001203004567, host 10.0.0.7 ok. ![x](https://evil.example/p.png)"

// An org's output_pii_action and output_pii_kinds (WithPII) change only the
// personal data; with neither set the guard is the gateway's own.
func TestWithPII(t *testing.T) {
	gateway := Config{RedactPII: true}
	tests := []struct {
		name   string
		base   Config
		action string
		kinds  []string
		want   string
		counts Counts
	}{
		{"no override", gateway, "", nil,
			"Mail [REDACTED:email], call [REDACTED:phone], card [REDACTED:card], CCCD [REDACTED:cccd], host 10.0.0.7 ok. [REDACTED:image]",
			Counts{KindEmail: 1, KindPhone: 1, KindCard: 1, KindCCCD: 1, KindImage: 1}},
		{"off", gateway, PIIOff, nil,
			"Mail an@congty.vn, call 0912 345 678, card 4111 1111 1111 1111, CCCD 001203004567, host 10.0.0.7 ok. [REDACTED:image]",
			Counts{KindImage: 1}},
		{"off with kinds", gateway, PIIOff, []string{KindEmail},
			"Mail an@congty.vn, call 0912 345 678, card 4111 1111 1111 1111, CCCD 001203004567, host 10.0.0.7 ok. [REDACTED:image]",
			Counts{KindImage: 1}},
		{"redact on a gateway with it off", Config{}, PIIRedact, nil,
			"Mail [REDACTED:email], call [REDACTED:phone], card [REDACTED:card], CCCD [REDACTED:cccd], host 10.0.0.7 ok. [REDACTED:image]",
			Counts{KindEmail: 1, KindPhone: 1, KindCard: 1, KindCCCD: 1, KindImage: 1}},
		{"redact keeps the gateway's IPv4", Config{RedactIPv4: true}, PIIRedact, nil,
			"Mail [REDACTED:email], call [REDACTED:phone], card [REDACTED:card], CCCD [REDACTED:cccd], host [REDACTED:ipv4] ok. [REDACTED:image]",
			Counts{KindEmail: 1, KindPhone: 1, KindCard: 1, KindCCCD: 1, KindIPv4: 1, KindImage: 1}},
		{"kinds only", gateway, "", []string{KindEmail, KindIPv4},
			"Mail [REDACTED:email], call 0912 345 678, card 4111 1111 1111 1111, CCCD 001203004567, host [REDACTED:ipv4] ok. [REDACTED:image]",
			Counts{KindEmail: 1, KindIPv4: 1, KindImage: 1}},
		{"kinds replace the gateway's IPv4", Config{RedactPII: true, RedactIPv4: true}, PIIRedact, []string{KindPhone},
			"Mail an@congty.vn, call [REDACTED:phone], card 4111 1111 1111 1111, CCCD 001203004567, host 10.0.0.7 ok. [REDACTED:image]",
			Counts{KindPhone: 1, KindImage: 1}},
		{"kinds on a gateway with it off", Config{}, "", []string{KindEmail},
			"Mail an@congty.vn, call 0912 345 678, card 4111 1111 1111 1111, CCCD 001203004567, host 10.0.0.7 ok. [REDACTED:image]",
			Counts{KindImage: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(tt.base).WithPII(tt.action, tt.kinds)
			counts := Counts{}
			if got := g.ForRequest("").Text(overrideText, counts); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
			if fmt.Sprint(counts) != fmt.Sprint(tt.counts) {
				t.Errorf("counts %v, want %v", counts, tt.counts)
			}
			// Streamed in small pieces, the same.
			st := g.ForRequest("").NewStream()
			var out string
			for i := 0; i < len(overrideText); i += 3 {
				out += st.Write(overrideText[i:min(i+3, len(overrideText))])
			}
			if out += st.Flush(); out != tt.want {
				t.Errorf("stream got  %q\nwant        %q", out, tt.want)
			}
		})
	}
}

// Without an override the gateway's guard is used as it is.
func TestWithPIINoOverride(t *testing.T) {
	g := New(Config{RedactPII: true})
	if g.WithPII("", nil) != g || g.WithPII("", []string{}) != g {
		t.Error("a new guard without an override")
	}
	o := g.WithPII(PIIOff, nil)
	if o == g || !g.Config().RedactPII || o.Config().RedactPII {
		t.Error("the gateway's guard was changed")
	}
}

// A kind left out is let through whole: another detector does not claim part
// of it, as without the override.
func TestWithPIIKindLeftOutIsKeptWhole(t *testing.T) {
	g := New(Config{RedactPII: true}).WithPII(PIIRedact, []string{KindCCCD, KindPhone})
	for _, text := range []string{"card 4111111111111111 ok", "card 0912 3456 7890 1236 ok"} {
		if got := g.ForRequest("").Text(text, Counts{}); got != text {
			t.Errorf("%q became %q", text, got)
		}
	}
}

// Tokens are put back whatever the override says (Scanner.WithTokens).
func TestWithPIIOffStillRestoresTokens(t *testing.T) {
	p := NewPseudonymizer(PIITokenize, nil)
	sent := p.Apply("write to an@congty.vn")
	if sent == "write to an@congty.vn" {
		t.Fatal("not tokenized")
	}
	g := New(Config{RedactPII: true}).WithPII(PIIOff, nil)
	if got := g.ForRequest("").WithTokens(p.Tokens()).Text("Sent: "+sent[len("write to "):], Counts{}); got != "Sent: an@congty.vn" {
		t.Errorf("got %q", got)
	}
}
