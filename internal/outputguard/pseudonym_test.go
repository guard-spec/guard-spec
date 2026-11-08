// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"strings"
	"testing"
)

const piiText = "Gửi cho jane.doe@acme.example và 0912345678, sao chép jane.doe@acme.example; CCCD 012345678901."

func TestPseudonymizerRedact(t *testing.T) {
	p := NewPseudonymizer(PIIRedact, nil)
	got := p.Apply(piiText)
	want := "Gửi cho [EMAIL] và [PHONE], sao chép [EMAIL]; CCCD [CCCD]."
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if p.Counts[KindEmail] != 2 || p.Counts[KindPhone] != 1 || p.Counts[KindCCCD] != 1 {
		t.Errorf("counts %v", p.Counts)
	}
	if p.Tokens() != nil {
		t.Error("redact keeps tokens")
	}
	if NewPseudonymizer(PIIOff, nil) != nil || NewPseudonymizer("bogus", nil) != nil {
		t.Error("a pseudonymizer for off")
	}
}

func TestPseudonymizerTokenize(t *testing.T) {
	p := NewPseudonymizer(PIITokenize, []string{KindEmail, KindCCCD})
	got := p.Apply(piiText)
	want := "Gửi cho ⟦EMAIL_1⟧ và 0912345678, sao chép ⟦EMAIL_1⟧; CCCD ⟦CCCD_1⟧."
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	// The next text of the same request keeps the numbering.
	if got := p.Apply("và bob@acme.example, jane.doe@acme.example"); got != "và ⟦EMAIL_2⟧, ⟦EMAIL_1⟧" {
		t.Fatalf("second text: %q", got)
	}
	tok := p.Tokens()
	if tok == nil {
		t.Fatal("no tokens")
	}
	answer := "Đã gửi tới ⟦EMAIL_1⟧ và ⟦ email_2 ⟧ (CCCD ⟦CCCD_1⟧), không biết ⟦EMAIL_9⟧ hay ⟦ chưa đóng"
	restored := tok.Restore(answer)
	wantR := "Đã gửi tới jane.doe@acme.example và bob@acme.example (CCCD 012345678901), không biết ⟦EMAIL_9⟧ hay ⟦ chưa đóng"
	if restored != wantR {
		t.Fatalf("restore\n got  %q\n want %q", restored, wantR)
	}
	if p.Apply("không có gì") != "không có gì" {
		t.Error("text without personal data changed")
	}
}

// A token split anywhere across stream writes is put back, by the
// restore-only guard and by a full guard.
func TestStreamRestoresSplitTokens(t *testing.T) {
	p := NewPseudonymizer(PIITokenize, nil)
	p.Apply("mail jane.doe@acme.example, thẻ 4111 1111 1111 1111")
	tok := p.Tokens()
	answer := "Xin chào ⟦EMAIL_1⟧! Thẻ ⟦CARD_1⟧ đã lưu. Còn ⟦X⟧ và ⟦ thì giữ nguyên ⟧."
	want := "Xin chào jane.doe@acme.example! Thẻ 4111 1111 1111 1111 đã lưu. Còn ⟦X⟧ và ⟦ thì giữ nguyên ⟧."
	for name, g := range map[string]*Guard{
		"restore only": RestoreOnly(),
		"full guard":   New(Config{LinkAllowlist: []string{"acme.example"}}),
	} {
		for size := 1; size <= len(answer); size++ {
			st := g.ForRequest("").WithTokens(tok).NewStream()
			var b strings.Builder
			for i := 0; i < len(answer); i += size {
				end := min(i+size, len(answer))
				b.WriteString(st.Write(answer[i:end]))
			}
			b.WriteString(st.Flush())
			if b.String() != want {
				t.Fatalf("%s, %d-byte writes:\n got  %q\n want %q", name, size, b.String(), want)
			}
		}
	}
}

// Restored values pass the output guard afterwards: with OUTPUT_REDACT_PII
// the answer shows the redaction, not the value.
func TestRestoredValuesAreGuarded(t *testing.T) {
	p := NewPseudonymizer(PIITokenize, nil)
	p.Apply("jane.doe@acme.example")
	counts := Counts{}
	got := New(Config{RedactPII: true}).ForRequest("").WithTokens(p.Tokens()).Text("Gửi ⟦EMAIL_1⟧", counts)
	if got != "Gửi [REDACTED:email]" || counts[KindEmail] != 1 {
		t.Fatalf("%q %v", got, counts)
	}
}

// The restore-only guard leaves links, images and HTML alone.
func TestRestoreOnlyPassesEverything(t *testing.T) {
	text := "![x](https://evil.example/a.png?d=1) <a href=\"https://evil.example\">x</a> [y](https://evil.example)"
	if got := RestoreOnly().ForRequest("").Text(text, Counts{}); got != text {
		t.Fatalf("changed: %q", got)
	}
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"Gửi ⟦EMAIL_1⟧"}}]}`)
	p := NewPseudonymizer(PIITokenize, nil)
	p.Apply("jane.doe@acme.example")
	out, err := RestoreOnly().ForRequest("").WithTokens(p.Tokens()).Response(body, Counts{})
	if err != nil || !strings.Contains(string(out), "Gửi jane.doe@acme.example") {
		t.Fatalf("response: %s %v", out, err)
	}
}

func TestFindPII(t *testing.T) {
	m := FindPII(piiText)
	if len(m) != 4 || m[0].Kind != KindEmail || piiText[m[0].Start:m[0].End] != "jane.doe@acme.example" {
		t.Fatalf("%+v", m)
	}
}
