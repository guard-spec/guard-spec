// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"fmt"
	"strings"
	"testing"
)

// Markup that the guard removes, placed inside a value, joins the parts of the
// value again in the output. The guard must catch the joined value as if the
// markup had not been there: the canary never reaches the client, and personal
// data is redacted.
var joinCases = []struct {
	name, in, want string
	counts         Counts
}{
	{"canary empty link", "key " + testCanary[:14] + "[]()" + testCanary[14:] + " end",
		"key [REDACTED:canary] end", Counts{KindCanary: 1, KindLink: 1}},
	{"canary link to evil", testCanary[:20] + "[](https://evil.com/x?d=1)" + testCanary[20:],
		"[REDACTED:canary]", Counts{KindCanary: 1, KindLink: 1}},
	{"canary bracketed URL and title", "PS-[](<a b> \"t\")CANARY" + testCanary[9:] + ".",
		"[REDACTED:canary].", Counts{KindCanary: 1, KindLink: 1}},
	{"canary nested parentheses", testCanary[:14] + "[](x[]())" + testCanary[14:],
		"[REDACTED:canary]", Counts{KindCanary: 1, KindLink: 1}},
	{"canary two removals", "(" + testCanary[:3] + "[]()" + testCanary[3:20] + "[](https://evil.com/q 't')" +
		testCanary[20:] + ")", "([REDACTED:canary])", Counts{KindCanary: 1, KindLink: 2}},
	{"canary part kept as link text", testCanary[:12] + "[" + testCanary[12:16] + "](https://evil.com)" +
		testCanary[16:], "[REDACTED:canary]", Counts{KindCanary: 1, KindLink: 1}},
	{"canary ends in link text", "x " + testCanary[:30] + "[" + testCanary[30:] + "](https://evil.com) y",
		"x [REDACTED:canary] y", Counts{KindCanary: 1, KindLink: 1}},
	{"canary across lines of links", testCanary[:10] + "[](a)[](b)[](c)" + testCanary[10:],
		"[REDACTED:canary]", Counts{KindCanary: 1, KindLink: 3}},
	{"email", "mail a@ex[]()ample.com now", "mail [REDACTED:email] now", Counts{KindEmail: 1, KindLink: 1}},
	{"phone", "call 0912[](https://evil.com) 345 678", "call [REDACTED:phone]", Counts{KindPhone: 1, KindLink: 1}},
	{"phone plus", "+84[]() 912 345 678.", "[REDACTED:phone].", Counts{KindPhone: 1, KindLink: 1}},
	{"card", "4111 1111[]() 1111 1111", "[REDACTED:card]", Counts{KindCard: 1, KindLink: 1}},
	{"cccd", "id 0012030[]()04567 x", "id [REDACTED:cccd] x", Counts{KindCCCD: 1, KindLink: 1}},
	{"ipv4", "ip 192.168[]().1.10 x", "ip [REDACTED:ipv4] x", Counts{KindIPv4: 1, KindLink: 1}},
	// Not joined: a marker stays between the parts, or a kept link text
	// makes them a different word, or the link is allowed and stays.
	{"image keeps a marker between", testCanary[:14] + "![](x)" + testCanary[14:],
		testCanary[:14] + "[REDACTED:image]" + testCanary[14:], Counts{KindImage: 1}},
	{"link text in between", testCanary[:14] + "[ab](https://evil.com)" + testCanary[14:],
		testCanary[:14] + "ab" + testCanary[14:], Counts{KindLink: 1}},
	{"allowed link stays", testCanary[:14] + "[](https://docs.example.com/a)" + testCanary[14:],
		testCanary[:14] + "[](https://docs.example.com/a)" + testCanary[14:], Counts{}},
}

func TestJoinedValueWholeAnswer(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range joinCases {
		counts := Counts{}
		if got := s.Text(tc.in, counts); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
		if fmt.Sprint(counts) != fmt.Sprint(tc.counts) {
			t.Errorf("%s: counts %v, want %v", tc.name, counts, tc.counts)
		}
	}
}

func TestJoinedValueStream(t *testing.T) {
	s := propScanner(CanaryRedact)
	for _, tc := range joinCases {
		// Every split, with the filler before and after so that the value
		// sits in the middle of a stream as well as at its edges.
		for _, in := range []string{tc.in, filler + tc.in, tc.in + "\n" + filler, filler + tc.in + filler} {
			wantCounts := Counts{}
			want := s.Text(in, wantCounts)
			for n := 1; n <= 70; n++ {
				checkStream(t, s, streamChunks(in, n), want, wantCounts)
			}
		}
	}
}

// In the three event stream kinds, in redact mode the joined canary is
// replaced; in block mode the stream stops before any part of it went out.
func TestJoinedCanaryEventStreams(t *testing.T) {
	r := &propRand{s: 7}
	for _, tc := range joinCases {
		if tc.counts[KindCanary] == 0 {
			continue
		}
		in := "Here it is: " + tc.in + " and more text after it."
		for _, n := range []int{1, 2, 5, 14, 16, 64} {
			deltas := streamChunks(in, n)
			want := propScanner(CanaryRedact).Text(in, Counts{})
			if strings.Contains(want, testCanary) || !strings.Contains(want, marker(KindCanary)) {
				t.Fatalf("%s: whole answer %q", tc.name, want)
			}
			for _, k := range sseKinds {
				checkSSE(t, r, CanaryRedact, k.name, in, deltas, want, false)
				checkSSE(t, r, CanaryBlock, k.name, in, deltas, want, true)
			}
		}
	}
}

// The whole-answer guard of each API counts the joined canary, which makes
// the gateway refuse the answer in block mode.
func TestJoinedCanaryWholeResponses(t *testing.T) {
	joined := testCanary[:14] + "[]()" + testCanary[14:]
	s := propScanner(CanaryBlock)
	bodies := []struct {
		name  string
		guard func([]byte, Counts) ([]byte, error)
		body  string
	}{
		{"chat", s.Response, `{"id":"c","object":"chat.completion","choices":[{"index":0,` +
			`"message":{"role":"assistant","content":` + jsonString("x "+joined+" y") + `},"finish_reason":"stop"}]}`},
		{"messages", s.MessagesResponse, `{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
			`"content":[{"type":"text","text":` + jsonString("x "+joined+" y") + `}],"stop_reason":"end_turn"}`},
		{"responses", s.ResponsesResponse, `{"id":"resp_1","object":"response","status":"completed","model":"m",` +
			`"output":[{"type":"message","id":"msg_1","role":"assistant","status":"completed",` +
			`"content":[{"type":"output_text","text":` + jsonString("x "+joined+" y") + `,"annotations":[]}]}]}`},
	}
	for _, b := range bodies {
		counts := Counts{}
		out, err := b.guard([]byte(b.body), counts)
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		if counts[KindCanary] != 1 || strings.Contains(string(out), testCanary) {
			t.Errorf("%s: counts %v, out %s", b.name, counts, out)
		}
	}
}

// A long word released before markup must not be held a second time: the
// second pass holds only what a removal may still join.
func TestJoinHoldIsBounded(t *testing.T) {
	st := propScanner(CanaryRedact).NewStream()
	out := st.Write("intro " + strings.Repeat("a", 1000) + " [")
	if len(out) != len("intro ")+1000+1 {
		t.Errorf("emitted %d bytes: %q", len(out), out)
	}
	if rest := st.Flush(); rest != "[" {
		t.Errorf("flushed %q", rest)
	}
}
