package sanitizer

import (
	"strings"
	"testing"
)

func TestHiddenContentIsMarked(t *testing.T) {
	cases := []struct{ in, want string }{
		{`<div style="display:none">secret note</div>`, "[hidden] secret note [/hidden]"},
		{`<p>Hi</p><!-- remember me -->`, "Hi [hidden] remember me [/hidden]"},
		{`<span style="visibility: hidden">x</span>`, "[hidden] x [/hidden]"},
		{`<span style="font-size:0px;">x</span>`, "[hidden] x [/hidden]"},
		{`<span style="opacity: 0">x</span>`, "[hidden] x [/hidden]"},
		{`<span style="color:#FFF; background:#ffffff">x</span>`, "[hidden] x [/hidden]"},
		{`<div aria-hidden="true">x</div>`, "[hidden] x [/hidden]"},
		{`<div hidden>x</div>`, "[hidden] x [/hidden]"},
		{`<div class="card sr-only">x</div>`, "[hidden] x [/hidden]"},
		// Nested elements of the same name close at the right tag.
		{`<div style="display:none"><div>a</div>b</div>c`, "[hidden] ab [/hidden] c"},
		// Never closed: hidden to the end.
		{`<div style="display:none">tail`, "[hidden] tail [/hidden]"},
		// Entity-encoded markup is decoded first, then marked.
		{`&lt;div style=&quot;display:none&quot;&gt;x&lt;/div&gt;`, "[hidden] x [/hidden]"},
	}
	for _, c := range cases {
		got, rep, err := Sanitize(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if strings.Join(strings.Fields(got), " ") != c.want {
			t.Errorf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
		if !rep.HadHiddenHTML {
			t.Errorf("%q: HadHiddenHTML not set", c.in)
		}
		if rep.AnomalyScore != 0 {
			t.Errorf("%q: hidden HTML alone must not raise the anomaly score (%.2f)", c.in, rep.AnomalyScore)
		}
		again, _, _ := Sanitize(got)
		if again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
}

func TestVisibleContentIsNotMarked(t *testing.T) {
	for _, in := range []string{
		`<p style="color:white;background:#222">banner</p>`,
		`<span style="font-size:0.9em">small</span>`,
		`<span style="opacity:0.5">faded</span>`,
		`<div class="hidden-xs-up-not">x</div>`,
		`<!---->`,
		`a < b and c > d`,
		`plain text`,
	} {
		got, rep, err := Sanitize(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if rep.HadHiddenHTML || strings.Contains(got, HiddenMarker) {
			t.Errorf("Sanitize(%q) = %q marked as hidden", in, got)
		}
	}
}

func TestHiddenElementsBounded(t *testing.T) {
	in := strings.Repeat(`<div style="display:none">`, 5000) + "x"
	if _, _, err := Sanitize(in); err != nil {
		t.Fatal(err)
	}
}
