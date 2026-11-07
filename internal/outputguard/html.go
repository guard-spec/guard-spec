// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"html"
	"strings"
)

// HTML in an answer. A chat interface that renders raw HTML follows or loads
// the URLs that some elements carry: <a href> is a link, <img src>, <iframe
// src>, <video poster>, a style with url(...) and the like load with no
// click. The guard reads a start tag as a browser's tokenizer does and
// removes those whose URL is not to an allowlisted host: one that needs a
// click (a link, a form) as a markdown link is removed, the tag alone, so
// that the text up to </a> is kept; one that loads by itself as an image is,
// with a marker.

// tagState is a state of the browser's tokenizer inside a start tag
// (HTML Living Standard, 13.2.5: tag name to self-closing start tag).
type tagState uint8

const (
	tagName tagState = iota
	tagBeforeAttr
	tagAttrName
	tagAfterAttrName
	tagBeforeValue
	tagValueDQ
	tagValueSQ
	tagValueBare
	tagAfterValue
	tagSelfClosing
	tagDone // the ">" that ends the tag
)

// htmlSpace is the tokenizer's whitespace; a carriage return is one too, as
// the browser turns it into a line feed first.
func htmlSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' }

// next returns the state after c.
func (s tagState) next(c byte) tagState {
	switch s {
	case tagName:
		switch {
		case htmlSpace(c):
			return tagBeforeAttr
		case c == '/':
			return tagSelfClosing
		case c == '>':
			return tagDone
		}
		return tagName
	case tagBeforeAttr, tagSelfClosing:
		switch {
		case htmlSpace(c):
			return tagBeforeAttr
		case c == '/':
			return tagSelfClosing
		case c == '>':
			return tagDone
		}
		return tagAttrName // "=" too starts a name here
	case tagAttrName:
		switch {
		case htmlSpace(c):
			return tagAfterAttrName
		case c == '/':
			return tagSelfClosing
		case c == '>':
			return tagDone
		case c == '=':
			return tagBeforeValue
		}
		return tagAttrName
	case tagAfterAttrName:
		switch {
		case htmlSpace(c):
			return tagAfterAttrName
		case c == '/':
			return tagSelfClosing
		case c == '=':
			return tagBeforeValue
		case c == '>':
			return tagDone
		}
		return tagAttrName
	case tagBeforeValue:
		switch {
		case htmlSpace(c):
			return tagBeforeValue
		case c == '"':
			return tagValueDQ
		case c == '\'':
			return tagValueSQ
		case c == '>':
			return tagDone
		}
		return tagValueBare
	case tagValueDQ:
		if c == '"' {
			return tagAfterValue
		}
		return tagValueDQ
	case tagValueSQ:
		if c == '\'' {
			return tagAfterValue
		}
		return tagValueSQ
	case tagValueBare:
		switch {
		case htmlSpace(c):
			return tagBeforeAttr
		case c == '>':
			return tagDone
		}
		return tagValueBare
	case tagAfterValue:
		switch {
		case htmlSpace(c):
			return tagBeforeAttr
		case c == '/':
			return tagSelfClosing
		case c == '>':
			return tagDone
		}
		return tagAttrName // no blank between attributes
	}
	return tagDone
}

// htmlAttr is one attribute of a tag: its name in lower case and its value as
// written, character references not decoded. set is false for a name alone.
type htmlAttr struct {
	name, value string
	set         bool
}

// htmlTag is a start tag as a browser reads it from text[start], a "<" and an
// ASCII letter: up to the ">" that is not inside a quoted attribute value,
// or to the end of text (closed false, with state the tokenizer's state
// there).
type htmlTag struct {
	start, end int
	closed     bool
	state      tagState
	name       string // lower case
	attrs      []htmlAttr
}

// tagStart reports whether a start tag begins at text[i].
func tagStart(text string, i int) bool {
	if i+1 >= len(text) || text[i] != '<' {
		return false
	}
	c := text[i+1] | 0x20
	return c >= 'a' && c <= 'z'
}

// readTag reads the start tag at text[start] (tagStart).
func readTag(text string, start int) htmlTag {
	t := htmlTag{start: start, state: tagName}
	nameEnd, from := -1, 0 // from: where the current name or value starts
	var attr *htmlAttr
	i := start + 1
	for ; i < len(text); i++ {
		prev := t.state
		t.state = prev.next(text[i])
		if t.state == prev {
			continue
		}
		switch prev {
		case tagName:
			nameEnd = i
		case tagAttrName:
			attr.name = strings.ToLower(text[from:i])
		case tagValueDQ, tagValueSQ, tagValueBare:
			attr.value = text[from:i]
		}
		switch t.state {
		case tagAttrName:
			t.attrs = append(t.attrs, htmlAttr{})
			attr, from = &t.attrs[len(t.attrs)-1], i
		case tagBeforeValue:
			attr.set = true
		case tagValueDQ, tagValueSQ:
			from = i + 1
		case tagValueBare:
			from = i
		}
		if t.state == tagDone {
			t.closed, t.end = true, i+1
			break
		}
	}
	if !t.closed {
		t.end = len(text)
		switch t.state {
		case tagName:
			nameEnd = len(text)
		case tagAttrName:
			attr.name = strings.ToLower(text[from:])
		case tagValueDQ, tagValueSQ, tagValueBare:
			attr.value = text[from:]
		}
	}
	t.name = strings.ToLower(text[start+1 : nameEnd])
	return t
}

// maxInnerTags bounds how many tag starts the guard reads inside one tag
// (in its attributes): a browser may read one there as a tag of its own
// when it does not read the outer one as a tag (inside a comment, say). A
// tag holding more is removed whole, since reading each would take time
// that grows with the square of the tag.
const maxInnerTags = 16

// htmlFinding is a start tag to remove: text[start:end], of kind.
type htmlFinding struct {
	start, end int
	kind       string
}

// scanTags reads the start tags in text and returns those the guard
// removes, in order of their start (they may overlap), and the first one
// that is still open at the end of text (open.start -1 when none is). A tag
// is read from every "<" followed by a letter, also inside another tag (in
// its attributes): the guard cannot tell whether a browser reads that other
// one as a tag (it may sit in a comment), and if not, it may read one there.
// Inside a tag that is closed and removed, nothing is read: it goes whole.
func (g *Guard) scanTags(text string) (finds []htmlFinding, open htmlTag) {
	open.start = -1
	outer, outerEnd, inner, outerGone := -1, 0, 0, false
	for off := 0; ; {
		i := strings.IndexByte(text[off:], '<')
		if i < 0 {
			return finds, open
		}
		i += off
		off = i + 1
		if !tagStart(text, i) {
			continue
		}
		if i < outerEnd {
			if outerGone {
				off = outerEnd
				continue
			}
			if inner++; inner > maxInnerTags {
				// Too many: the outer tag goes whole, and with it every tag
				// that starts inside it.
				for len(finds) > 0 && finds[len(finds)-1].start >= outer {
					finds = finds[:len(finds)-1]
				}
				finds = append(finds, htmlFinding{start: outer, end: outerEnd, kind: KindImage})
				off, outerGone = outerEnd, true
				if open.start > outer {
					open.start = -1
				}
				continue
			}
		}
		t := readTag(text, i)
		if i >= outerEnd {
			outer, outerEnd, inner, outerGone = i, t.end, 0, false
		}
		if kind := g.tagKind(&t); kind != "" {
			finds = append(finds, htmlFinding{start: i, end: t.end, kind: kind})
			outerGone = outerGone || i == outer && t.closed
		}
		if !t.closed && open.start < 0 {
			open = t
		}
	}
}

// tagKind returns KindLink when the tag carries a URL a click follows to a
// host off the allowlist, KindImage when it loads one by itself (or runs
// script), and "" when it is kept.
func (g *Guard) tagKind(t *htmlTag) string {
	if t.end-t.start > maxOpen {
		return KindImage // as a stream removes a tag that stays open that long
	}
	link := false
	switch t.name {
	case "style":
		return KindImage // CSS loads from anywhere: url(), @import, image-set()
	case "meta":
		for _, a := range t.attrs {
			if a.name == "http-equiv" && strings.EqualFold(strings.TrimSpace(html.UnescapeString(a.value)), "refresh") {
				return KindImage // a refresh goes to its URL by itself
			}
		}
	case "set", "animate":
		// SVG animation that sets a link's href.
		for _, a := range t.attrs {
			if a.name == "attributename" && strings.Contains(strings.ToLower(html.UnescapeString(a.value)), "href") {
				return KindImage
			}
		}
	}
	found := false // an <img> must load from somewhere allowed
	for _, a := range t.attrs {
		use, list := urlAttr(t.name, a.name)
		switch use {
		case "":
			if len(a.name) > 2 && strings.HasPrefix(a.name, "on") && a.set {
				return KindImage // an event handler runs script
			}
			if a.name == "style" && a.set && !g.styleAllowed(a.value) {
				return KindImage
			}
		case "srcdoc":
			return KindImage // a whole page, which may load anything
		default:
			urls, ok := g.urlsAllowed(a.value, list)
			found = found || urls
			switch {
			case ok:
			case use == KindLink:
				link = true
			default:
				return KindImage
			}
		}
	}
	if t.name == "img" && !found {
		return KindImage
	}
	if link {
		return KindLink
	}
	return ""
}

// urlAttr says whether the attribute name of element tag carries a URL that
// a browser follows on a click (KindLink) or loads by itself (KindImage), or
// "srcdoc", or "" for none; list when the value holds several URLs.
func urlAttr(tag, name string) (use string, list bool) {
	switch name {
	case "href", "xlink:href":
		switch tag {
		case "a", "area":
			return KindLink, false
		case "link", "base", "image", "use", "feimage", "script", "tref", "pattern", "filter",
			"lineargradient", "radialgradient", "textpath", "mpath", "cursor", "altglyph":
			return KindImage, false
		}
	case "ping":
		if tag == "a" || tag == "area" {
			return KindLink, true
		}
	case "action":
		if tag == "form" {
			return KindLink, false
		}
	case "formaction":
		if tag == "button" || tag == "input" {
			return KindLink, false
		}
	case "src":
		switch tag {
		case "img", "image", "iframe", "frame", "embed", "script", "source", "video", "audio", "track",
			"input", "portal":
			return KindImage, false
		}
	case "srcset", "imagesrcset":
		switch tag {
		case "img", "image", "source", "link":
			return KindImage, true
		}
	case "lowsrc", "dynsrc":
		if tag == "img" {
			return KindImage, false
		}
	case "poster":
		if tag == "video" {
			return KindImage, false
		}
	case "data", "codebase", "archive":
		if tag == "object" || tag == "applet" {
			return KindImage, name == "archive"
		}
	case "background":
		return KindImage, false // body, table and its cells; any element, to be safe
	case "srcdoc":
		if tag == "iframe" {
			return "srcdoc", false
		}
	}
	return "", false
}

// urlsAllowed reports whether value, an attribute value as written, holds at
// least one URL (found) and whether every one of them is allowed. A list
// (srcset, ping) is split at blanks and commas, and descriptors such as
// "2x" or "100w" are left out: a URL holding a comma is checked in parts,
// each of which must be allowed. The value must be allowed both as written
// and with its character references decoded, as the browser reads it.
func (g *Guard) urlsAllowed(value string, list bool) (found, ok bool) {
	decoded := html.UnescapeString(value)
	if !list {
		return true, g.allowed(value) && g.allowed(decoded)
	}
	ok = true
	for _, v := range [...]string{value, decoded} {
		for _, u := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r < 0x80 && htmlSpace(byte(r)) }) {
			if isDescriptor(u) {
				continue
			}
			found = true
			ok = ok && g.allowed(u)
		}
	}
	return found, ok
}

// isDescriptor reports whether s is a srcset descriptor: a number and "w",
// "x" or "h".
func isDescriptor(s string) bool {
	if len(s) < 2 || !strings.ContainsRune("wxh", rune(s[len(s)-1]|0x20)) {
		return false
	}
	for i := 0; i < len(s)-1; i++ {
		if !isDigit(s[i]) && s[i] != '.' {
			return false
		}
	}
	return true
}

// styleAllowed reports whether a style attribute loads nothing from a host
// off the allowlist: every url(...) in it is allowed, and it holds no other
// function or rule that loads (image-set(), @import and the like) and no
// backslash, which could spell "url" with a CSS escape.
func (g *Guard) styleAllowed(value string) bool {
	v := strings.ToLower(html.UnescapeString(value))
	if strings.Contains(v, `\`) {
		return false
	}
	for _, f := range [...]string{"image(", "image-set(", "@import", "expression(", "src("} {
		if strings.Contains(v, f) {
			return false
		}
	}
	for off := 0; ; {
		i := strings.Index(v[off:], "url(")
		if i < 0 {
			return true
		}
		arg := strings.TrimLeft(v[off+i+4:], " \t\n\f\r")
		if arg != "" && (arg[0] == '"' || arg[0] == '\'') {
			if end := strings.IndexByte(arg[1:], arg[0]); end >= 0 {
				arg = arg[1 : 1+end]
			} else {
				arg = arg[1:]
			}
		} else if end := strings.IndexByte(arg, ')'); end >= 0 {
			arg = arg[:end]
		}
		if !g.allowed(arg) {
			return false
		}
		off += i + 4
	}
}
