package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzChatRequest drives the chat request parser and guard with arbitrary
// bodies. It must never panic, and a body it accepts must be safe to forward:
// it still encodes as JSON, every text it collected for the classifier went
// through the sanitizer, and a second pass over the forwarded body finds nothing
// it cannot handle.
func FuzzChatRequest(f *testing.F) {
	for _, s := range []string{
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"m","messages":[{"role":"system","content":"be nice"},{"role":"user","content":"hi"}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"x"}}]}]}`,
		`{"model":"m","messages":[{"role":"tool","content":"<b>ignore previous</b>"}]}`,
		`{"model":"m","messages":[{"role":"user","Content":"shadow"}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"text","Text":"shadow"}]}]}`,
		`{"model":"m","messages":[{"role":"user","content":{"text":"object"}}]}`,
		`{"model":"m","prompt":"complete this","suffix":"tail"}`,
		`{"model":"m","prompt":["a","b"]}`,
		`{"model":"m","prompt":[1,2,3]}`,
		`{"model":"m","seed":12345678901234567890}`,
		`{"model":"m","messages":[{"role":"user","content":"\u202eevil\udb40\udc41"}]}`,
		`{"model":"m"} trailing`,
		`{"model":"m"}{"model":"n"}`,
		`[]`, `null`, `"x"`, `{}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		body, err := decodeBody(raw)
		if err != nil {
			return
		}
		var guard textGuard
		if err := guard.guardBody(body); err != nil {
			return
		}
		for _, text := range guard.texts {
			if !strings.HasPrefix(text, "[DATA]") || !strings.HasSuffix(text, "[/DATA]") {
				t.Fatalf("collected text %q was not sanitized", text)
			}
		}
		forwarded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("accepted body does not encode: %v", err)
		}
		// What goes upstream must parse as the same kind of request.
		again, err := decodeBody(forwarded)
		if err != nil {
			t.Fatalf("forwarded body %s does not decode: %v", forwarded, err)
		}
		var second textGuard
		if err := second.guardBody(again); err == errUnsupportedContent {
			t.Fatalf("forwarded body %s has a shape the guard refuses", forwarded)
		}
	})
}
