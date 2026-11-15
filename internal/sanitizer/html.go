// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"regexp"
	"strings"
)

var (
	// htmlTag matches a well-formed start or end tag: a name that starts with
	// an ASCII letter, then attributes with quoted, unquoted or no values.
	// Group 1 holds the attributes. Text that only looks like a tag in part
	// ("a < b", "<QUAN_TRỌNG>", "x<-y") does not match and is left as it is.
	htmlTag = regexp.MustCompile(`(?i)</?[a-z][a-z0-9:_.-]*((?:\s+[^\s"'<>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'<>=` + "`" + `]+))?)*)\s*/?>`)
	// htmlAttr matches one attribute of htmlTag's group 1; group 1 is the name,
	// groups 2 to 4 the value (double-quoted, single-quoted, unquoted).
	htmlAttr = regexp.MustCompile(`([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>=` + "`" + `]+)))?`)
	// htmlDecl matches a doctype, a processing instruction and the brackets of
	// a CDATA section, whose content is kept.
	htmlDecl = regexp.MustCompile(`(?i)<!doctype[^<>]*>|<\?[^<>]*\?>|<!\[CDATA\[|\]\]>`)
)

// skipAttrs are attributes whose values are addresses, layout or identifiers
// rather than text a model would read as an instruction. The values of every
// other attribute (title, alt, aria-label, placeholder, value, content,
// data-*, event handlers and any unknown one) stay in the scan view, since the
// model reads the raw markup it is forwarded.
var skipAttrs = map[string]bool{
	"href": true, "src": true, "srcset": true, "class": true, "classname": true, "id": true, "style": true, "key": true,
	"width": true, "height": true, "type": true, "rel": true, "for": true, "lang": true,
	"dir": true, "xmlns": true, "viewbox": true, "d": true, "fill": true, "stroke": true,
	"transform": true, "points": true, "role": true, "tabindex": true, "target": true,
	"method": true, "charset": true, "crossorigin": true, "integrity": true,
	"loading": true, "decoding": true, "sizes": true, "media": true, "colspan": true, "rowspan": true,
}

// stripTags replaces each tag with the text of its attributes, separated by
// spaces, and drops doctypes and processing instructions. Element content is
// never removed: an HTML parser treats the content of script, style,
// textarea or plaintext as raw text or drops it, which would hide what
// follows a mere mention of such a tag. Comments and hidden elements were
// marked before (markHidden).
func stripTags(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	s = htmlDecl.ReplaceAllString(s, "")
	return htmlTag.ReplaceAllStringFunc(s, func(tag string) string {
		attrs := htmlTag.FindStringSubmatch(tag)[1]
		if strings.TrimSpace(attrs) == "" {
			return ""
		}
		var b strings.Builder
		for _, m := range htmlAttr.FindAllStringSubmatch(attrs, -1) {
			if skipAttrs[strings.ToLower(m[1])] {
				continue
			}
			v := m[2] + m[3] + m[4]
			if strings.TrimSpace(v) == "" {
				continue
			}
			b.WriteByte(' ')
			b.WriteString(v)
		}
		if b.Len() == 0 {
			return ""
		}
		b.WriteByte(' ')
		return b.String()
	})
}
