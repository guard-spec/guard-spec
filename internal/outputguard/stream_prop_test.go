package outputguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// Property tests for the stream guard: random answers with personal data,
// links, images and the canary at random places, split into random deltas.
// Whatever the split, a stream must send exactly what the whole-answer guard
// produces, and nothing it sends may run ahead of that output: a value to
// redact is never sent, not even in part, before the guard has decided on it.

// propRand is a small deterministic generator (splitmix64), so that a seed
// always yields the same answer, whatever the Go version.
type propRand struct{ s uint64 }

func (r *propRand) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *propRand) intn(n int) int { return int(r.next() % uint64(n)) }

func (r *propRand) pick(list []string) string { return list[r.intn(len(list))] }

var propWords = []string{
	"the", "bread", "needs", "ripe", "bananas,", "flour", "and", "sugar.", "Bake", "for", "40", "minutes",
	"at", "180°C.", "Xin", "chào,", "đây", "là", "câu", "trả", "lời", "tiếng", "Việt", "có", "dấu.",
	"v1.2.3", "2026", "x-ray", "e.g.", "(see", "below)", "**bold**", "`code`", "[note]", "#1", "50%",
	"user_name", "foo@", "@bar", "http", "www", "<b>ok</b>", "a<b", "1-2", "3 4", "!", "]", "[", ":",
}

var propSecrets = []string{
	// personal data
	"someone@example.com", "john.doe+news@mail.co.uk", "<a@b.vn>",
	"0912 345 678", "+84 912 345 678", "0912.345.678", "0912345678", "84 28 3822 1234",
	"4111 1111 1111 1111", "4111-1111-1111-1111", "5500000000000004", "371449635398431",
	"001203004567", "192.168.1.10", "10.0.0.255",
	testCanary, "(" + testCanary + ")",
	// links and images
	"[docs](https://evil.example/x?d=1)", "[click here](https://evil.com/path/to/page)",
	"![chart](https://evil.com/c.png?d=secret)", "![a](<https://evil.com/a b.png>)",
	"[ok](https://docs.example.com/page)", "![ok](https://docs.example.com/a.png?x=1)",
	"[mail a@b.com](https://evil.com/q)", "[t](https://evil.com/x \"title\")",
	"[wiki](https://en.wikipedia.org/wiki/Foo_(bar))",
	`<img src="https://evil.com/p.gif?d=1">`, `<IMG SRC='https://docs.example.com/a.png'>`,
	"https://evil.com/pixel.png?d=secret", "https://example.org/plain/page", "www.evil.com/a.jpg?x=1",
	"\n[r]: https://evil.com/ref\n", "\n> [r2]:\n> https://evil.com/next\n", "\n[ok]: https://docs.example.com/x\n",
	"[text][r]", "![img][r]",
}

// propAnswer builds a random answer.
func propAnswer(r *propRand) string {
	var b strings.Builder
	for n := 3 + r.intn(60); n > 0; n-- {
		if r.intn(10) < 3 {
			b.WriteString(r.pick(propSecrets))
		} else {
			b.WriteString(r.pick(propWords))
		}
		switch k := r.intn(20); {
		case k < 14:
			b.WriteByte(' ')
		case k < 16:
			b.WriteByte('\n')
		case k < 17:
			b.WriteString("\n\n")
		case k < 18:
			b.WriteString("\n> ")
		case k < 19:
			b.WriteString(", ")
		}
	}
	switch r.intn(12) {
	case 0:
		b.WriteString("![x](https://evil.com/a.png?d=1") // never closed
	case 1:
		b.WriteString("[unfinished link text")
	case 2:
		b.WriteString(testCanary[:12])
	}
	return b.String()
}

// propRemoved is markup the guard removes whole: placed inside a value, it
// joins the parts of the value again in the output.
var propRemoved = []string{"[]()", "[](https://evil.com/x?d=1)", "[](<a b>)", `[](x "t")`, "[](x[]())",
	"[](a)[](b)"}

// propKept is markup that leaves something between the parts of a value: the
// kept text of a link, a marker, an allowed link, or text that is no link.
var propKept = []string{"[x](https://evil.com)", "![](x)", "[](https://docs.example.com/a)", "[]", "](y)",
	"[[]()](z)", "<img src=x>", "[r]"}

// propJoinable are values that markup placed inside them must not let through.
var propJoinable = []string{testCanary, "someone@example.com", "john.doe+news@mail.co.uk", "0912 345 678",
	"+84 912 345 678", "0912345678", "4111 1111 1111 1111", "371449635398431", "001203004567", "192.168.1.10"}

// propSplitValue returns a joinable value with markup at one or two random
// places inside it, between spaces.
func propSplitValue(r *propRand, markup []string) string {
	v := r.pick(propJoinable)
	var b strings.Builder
	last := 0
	for _, at := range []int{1 + r.intn(len(v)-1), 1 + r.intn(len(v)-1)} {
		if at < last || r.intn(2) == 0 {
			continue
		}
		b.WriteString(v[last:at])
		b.WriteString(r.pick(markup))
		last = at
	}
	if last == 0 {
		at := 1 + r.intn(len(v)-1)
		b.WriteString(v[:at])
		b.WriteString(r.pick(markup))
		last = at
	}
	b.WriteString(v[last:])
	return " " + b.String() + " "
}

// propJoinAnswer places one to three values split by markup at word
// boundaries of text.
func propJoinAnswer(r *propRand, text string) string {
	var b strings.Builder
	last := 0
	for n := 1 + r.intn(3); n > 0; n-- {
		at := last + r.intn(len(text)-last+1)
		for at < len(text) && text[at] != ' ' {
			at++
		}
		markup := propRemoved
		if r.intn(3) == 0 {
			markup = propKept
		}
		b.WriteString(text[last:at] + propSplitValue(r, markup))
		last = at
	}
	b.WriteString(text[last:])
	return b.String()
}

// checkNotJoined checks that no value split by markup came out whole: joined
// again by the removal of the markup, it must be redacted as it would be
// without the markup. (A part of a value that the guard redacts on its own,
// such as the "n.doe@mail.co.uk" of "joh[]()n.doe@mail.co.uk", leaves the
// rest as a space there would.)
func checkNotJoined(t *testing.T, text, out string) {
	t.Helper()
	for _, v := range propJoinable {
		if strings.Contains(out, " "+v+" ") {
			t.Fatalf("%q got through in %q, from %q", v, out, text)
		}
	}
}

// propSplit cuts text into deltas of 1 to 64 bytes. Deltas may split a
// multi-byte character, as raw upstream bytes would not, so splits respect
// UTF-8: a delta always ends on a character boundary.
func propSplit(r *propRand, text string) []string {
	var out []string
	for text != "" {
		n := min(1+r.intn(64), len(text))
		for n < len(text) && text[n]&0xC0 == 0x80 {
			n++
		}
		out, text = append(out, text[:n]), text[n:]
	}
	return out
}

func propScanner(mode CanaryMode) *Scanner {
	return New(Config{LinkAllowlist: []string{"docs.example.com"}, RedactPII: true, RedactIPv4: true,
		Canary: mode}).ForRequest(testCanary)
}

// checkStream feeds deltas to a Stream and checks the output against want.
func checkStream(t *testing.T, s *Scanner, deltas []string, want string, wantCounts Counts) {
	t.Helper()
	st := s.NewStream()
	var sent strings.Builder
	for i, d := range deltas {
		sent.WriteString(st.Write(d))
		if !strings.HasPrefix(want, sent.String()) {
			t.Fatalf("after delta %d of %q sent %q, which is not a prefix of %q", i, deltas, sent.String(), want)
		}
	}
	sent.WriteString(st.Flush())
	if sent.String() != want {
		t.Fatalf("deltas %q:\n got  %q\n want %q", deltas, sent.String(), want)
	}
	if fmt.Sprint(st.Counts) != fmt.Sprint(wantCounts) {
		t.Fatalf("deltas %q: counts %v, want %v", deltas, st.Counts, wantCounts)
	}
}

// eventText extracts the text that the events of one stream kind carry.
func eventText(t *testing.T, kind string, out []byte) string {
	t.Helper()
	var b strings.Builder
	for _, raw := range strings.Split(string(out), "\n\n") {
		var data string
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(line, "data: ") {
				data = strings.TrimPrefix(line, "data: ")
			}
		}
		if data == "" || data == "[DONE]" {
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Delta   json.RawMessage
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			t.Fatalf("%s: bad event %q: %v", kind, data, err)
		}
		switch kind {
		case "chat":
			for _, c := range ev.Choices {
				b.WriteString(c.Delta.Content)
			}
		case "messages":
			if ev.Type == "content_block_delta" {
				var d struct{ Text string }
				_ = json.Unmarshal(ev.Delta, &d)
				b.WriteString(d.Text)
			}
		case "responses":
			if ev.Type == "response.output_text.delta" {
				var d string
				_ = json.Unmarshal(ev.Delta, &d)
				b.WriteString(d)
			}
		}
	}
	return b.String()
}

// checkSSE feeds an answer to an event stream of one kind, its bytes split at
// random, and checks the text of the events it sends. In block mode the
// stream must stop before any part of the canary, or its marker, went out.
func checkSSE(t *testing.T, r *propRand, mode CanaryMode, kind, text string, deltas []string, want string, leaked bool) {
	t.Helper()
	var w sseStream
	for _, k := range sseKinds {
		if k.name == kind {
			w = k.open(propScanner(mode))
		}
	}
	upstream := strings.Join(sseUpstream(kind, text, deltas), "")
	var sent strings.Builder
	write := func(out []byte) {
		sent.WriteString(eventText(t, kind, out))
		if !strings.HasPrefix(want, sent.String()) {
			t.Fatalf("%s: sent %q, which is not a prefix of %q", kind, sent.String(), want)
		}
	}
	for upstream != "" {
		n := min(1+r.intn(200), len(upstream))
		write(w.Write([]byte(upstream[:n])))
		upstream = upstream[n:]
	}
	write(w.Close())
	blocked := false
	switch s := w.(type) {
	case *EventStream:
		blocked = s.Blocked()
	case *MessageStream:
		blocked = s.Blocked()
	case *ResponseStream:
		blocked = s.Blocked()
	}
	if mode == CanaryBlock {
		if blocked != leaked {
			t.Fatalf("%s: blocked %v, canary leaked %v", kind, blocked, leaked)
		}
		if leaked {
			if strings.Contains(sent.String(), marker(KindCanary)) {
				t.Fatalf("%s: sent the canary marker before blocking: %q", kind, sent.String())
			}
			return
		}
	}
	if sent.String() != want {
		t.Fatalf("%s, deltas %q:\n got  %q\n want %q", kind, deltas, sent.String(), want)
	}
}

// checkAnswer runs every property on one answer and returns what the
// whole-answer guard made of it.
func checkAnswer(t *testing.T, r *propRand, text string, splits int) string {
	t.Helper()
	s := propScanner(CanaryRedact)
	wantCounts := Counts{}
	want := s.Text(text, wantCounts)
	for range splits {
		checkStream(t, s, propSplit(r, text), want, wantCounts)
	}
	deltas := propSplit(r, text)
	for _, k := range sseKinds {
		checkSSE(t, r, CanaryRedact, k.name, text, deltas, want, false)
		checkSSE(t, r, CanaryBlock, k.name, text, deltas, want, wantCounts[KindCanary] > 0)
	}
	return want
}

func TestStreamPropertyRandomAnswers(t *testing.T) {
	n := 1500
	if testing.Short() {
		n = 200
	}
	for seed := range n {
		r := &propRand{s: uint64(seed)}
		text := propAnswer(r)
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			if want := checkAnswer(t, r, text, 4); strings.Contains(want, testCanary) {
				t.Fatalf("the canary got through: %q", want)
			}
			// The same answer with values split by markup the guard removes.
			joined := propJoinAnswer(r, text)
			want := checkAnswer(t, r, joined, 2)
			if strings.Contains(want, testCanary) {
				t.Fatalf("the joined canary got through: %q", want)
			}
			checkNotJoined(t, joined, want)
		})
	}
}

// FuzzStreamGuard fuzzes the seed of a random answer and of its splits, and a
// short fragment placed at a random spot in it, or inside the canary or a
// value with personal data added to it. The fragment can split the value with
// a link that the guard then removes, joining the parts again: the canary must
// still never get through, and the stream must send what the whole-answer
// guard produces.
func FuzzStreamGuard(f *testing.F) {
	f.Add(uint64(1), "")
	f.Add(uint64(7), "a@b.co")
	f.Add(uint64(42), "0912 345 678")
	f.Add(uint64(99), "![x](https://evil.com/a.png?q=1)")
	f.Add(uint64(3), "\n[r]: https://evil.com/x\n")
	f.Add(uint64(5), "[]()")
	f.Add(uint64(6), "[](https://evil.com/x?d=1)")
	f.Add(uint64(8), "[a](b)")
	f.Fuzz(func(t *testing.T, seed uint64, extra string) {
		if len(extra) > 48 || !utf8.ValidString(extra) {
			return
		}
		r := &propRand{s: seed}
		text := propAnswer(r)
		at := r.intn(len(text) + 1)
		for at < len(text) && text[at]&0xC0 == 0x80 {
			at++
		}
		inside := r.intn(2) == 0
		if inside {
			v := r.pick(propJoinable)
			k := 1 + r.intn(len(v)-1)
			text = text[:at] + " " + v[:k] + extra + v[k:] + " " + text[at:]
		} else {
			text = text[:at] + extra + text[at:]
		}
		want := checkAnswer(t, r, text, 2)
		if strings.Contains(want, testCanary) {
			t.Fatalf("the canary got through: %q", want)
		}
		if inside {
			checkNotJoined(t, text, want)
		}
	})
}

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/stream_golden.txt")

// TestWholeAnswerGolden pins what the whole-answer guard makes of the random
// answers, as recorded with v0.3.0, so that a faster stream cannot quietly
// change what is redacted.
func TestWholeAnswerGolden(t *testing.T) {
	const n = 1500
	var lines []string
	for seed := range n {
		r := &propRand{s: uint64(seed)}
		text := propAnswer(r)
		counts := Counts{}
		out := propScanner(CanaryRedact).Text(text, counts)
		keys := make([]string, 0, len(counts))
		for k, v := range counts {
			keys = append(keys, fmt.Sprintf("%s=%d", k, v))
		}
		sort.Strings(keys)
		sum := sha256.Sum256([]byte(out + "\x00" + strings.Join(keys, ",")))
		lines = append(lines, fmt.Sprintf("%d %s", seed, hex.EncodeToString(sum[:8])))
	}
	path := filepath.Join("testdata", "stream_golden.txt")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recorded := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(recorded) != len(lines) {
		t.Fatalf("recorded %d answers, want %d", len(recorded), len(lines))
	}
	for i := range lines {
		if recorded[i] != lines[i] {
			t.Fatalf("seed %d: whole-answer output changed: got %s, recorded %s", i, lines[i], recorded[i])
		}
	}
}
