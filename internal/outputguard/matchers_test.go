package outputguard

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The scanner runs its expressions only where a match can be: around each "@",
// at each "](", over runs of digits. These references run them over the whole
// text, as the guard did before; both must find exactly the same matches.

var (
	mdTextRef = regexp.MustCompile(`^(!?)\[([^\[\]\n]{0,1000})\]\(`)
	digitRef  = regexp.MustCompile(`\d(?:[ \-]?\d)*`)
)

// mdMatchesRef tries every place in text, left to right, as an unanchored
// expression would: the link text there, then the tail (mdLinkTail).
func mdMatchesRef(text string, full bool) [][]int {
	var out [][]int
	for s := 0; s < len(text); {
		var m []int
		if full {
			m = mdTextRef.FindStringSubmatchIndex(text[s:])
		} else if strings.HasPrefix(text[s:], "](") {
			m = []int{0, 2}
		}
		if m == nil {
			s++
			continue
		}
		urlStart, urlEnd, end, ok, _ := mdLinkTail(text, s+m[1])
		if !ok {
			s++
			continue
		}
		if full {
			out = append(out, []int{s, end, s + m[2], s + m[3], s + m[4], s + m[5], urlStart, urlEnd})
		} else {
			out = append(out, []int{s, end, urlStart, urlEnd})
		}
		s = end
	}
	return out
}

func allBoundedRef(re *regexp.Regexp, text string, inToken func(string, int) bool) [][]int {
	var out [][]int
	for off := 0; off < len(text); {
		m := re.FindStringIndex(text[off:])
		if m == nil {
			break
		}
		start, end := off+m[0], off+m[1]
		if !inToken(text, start-1) && !inToken(text, end) {
			out = append(out, []int{start, end})
			off = end
			continue
		}
		off = start + 1
	}
	return out
}

func digitRuns(text string) [][]int {
	var out [][]int
	for start := 0; ; {
		run, end := nextDigitRun(text, start)
		if run < 0 {
			return out
		}
		out = append(out, []int{run, end})
		start = end
	}
}

func phoneToken(t string, i int) bool { return digitAt(t, i) || (i >= 0 && i < len(t) && t[i] == '+') }

func ipv4Token(t string, i int) bool {
	return digitAt(t, i) || (i >= 0 && i < len(t) && t[i] == '.' && (digitAt(t, i-1) || digitAt(t, i+1)))
}

func checkMatchers(t *testing.T, text string) {
	t.Helper()
	same := func(name string, got, want [][]int) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s on %q:\n got  %v\n want %v", name, text, got, want)
		}
	}
	same("email", emailMatches(text), emailRe.FindAllStringIndex(text, -1))
	same("mdFull", mdMatches(text, true), mdMatchesRef(text, true))
	same("mdTail", mdMatches(text, false), mdMatchesRef(text, false))
	same("digits", digitRuns(text), digitRef.FindAllStringIndex(text, -1))
	same("cccd", allBounded(cccdRe, text, digitAt), allBoundedRef(cccdRe, text, digitAt))
	same("phone", allBounded(phoneRe, text, phoneToken), allBoundedRef(phoneRe, text, phoneToken))
	same("ipv4", allBounded(ipv4Re, text, ipv4Token), allBoundedRef(ipv4Re, text, ipv4Token))
}

var matcherSeeds = []string{
	"",
	"mail a@b.co or x.y+z@mail.example.com, not @, a@, @b.com, a@@b.com",
	strings.Repeat("x", 70) + "@a.com " + strings.Repeat("a", 64) + "@b.org",
	"a@" + strings.Repeat("l.", 12) + "com a@1.2.3.com a@b.c0m",
	"[t](https://evil.com/x) ![i](<https://e.com/a b.png> \"t\") [a [b](c) ](d) [x]](y)",
	"[" + strings.Repeat("t", 1000) + "](u) [" + strings.Repeat("t", 1001) + "](u)",
	"![a](b](c)) [w](https://en.wikipedia.org/wiki/F_(b)) [x](\n y) [x](y 'z')",
	"[t](https://e.com/(x \"t\") [u](a((b))c) [v](a\\)b) [w](<a<b>) [x](a<b>c) [y](<a\\>b>) [z](a (t))",
	"0912 345 678 +84 912 345 678 84-28-3822-1234 0912.345.678 1+84912345678 ++84 912345678",
	"4111 1111 1111 1111 4111-1111-1111-1111 001203004567 0012030045678 1-2 3  4 5- 6",
	"192.168.1.10 10.0.0.255. 1.2.3.4.5 256.1.1.1 1.1.1.1x .1.2.3.4",
}

func TestMatchersMatchExpressions(t *testing.T) {
	for _, s := range matcherSeeds {
		checkMatchers(t, s)
	}
	for seed := range 300 {
		checkMatchers(t, propAnswer(&propRand{s: uint64(seed)}))
	}
}

func FuzzMatchers(f *testing.F) {
	for _, s := range matcherSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 4096 {
			return
		}
		checkMatchers(t, text)
	})
}
