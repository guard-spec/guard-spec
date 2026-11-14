// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package jsonpath is the small JSONPath subset custom backends declare their
// scanned fields with (upstreams.backend, migration 031):
//
//	$                 the whole document
//	.name             an object member; name is letters, digits, _ and -
//	[n]               the n-th array element, from 0
//	[*]               every array element
//	.*                every member of an object
//
// for example $.query, $.messages[*].content or $.items[0].text. Filters,
// recursive descent (..), slices, unions and quoted names are not supported:
// a path either parses into this subset or is refused.
//
// Doc keeps the byte offsets of every value, so that a caller can replace a
// few string values and leave every other byte of the document as it came.
package jsonpath

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MaxLen is the longest path Parse accepts, and MaxSteps the most steps.
const (
	MaxLen   = 256
	MaxSteps = 32
)

// StepKind is what one step of a path selects.
type StepKind uint8

const (
	// Field selects the member Name of an object.
	Field StepKind = iota
	// Index selects element Index of an array.
	Index
	// Wildcard selects every element of an array or member of an object.
	Wildcard
)

// Step is one step of a path.
type Step struct {
	Kind  StepKind
	Name  string
	Index int
}

// Path is a parsed path; the empty path is $.
type Path []Step

func nameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// Parse reads a path of the subset. Errors say what is wrong and where.
func Parse(s string) (Path, error) {
	if s == "" {
		return nil, errors.New("empty path; start with $")
	}
	if len(s) > MaxLen {
		return nil, fmt.Errorf("path is longer than %d characters", MaxLen)
	}
	if s[0] != '$' {
		return nil, fmt.Errorf("path %q must start with $", s)
	}
	var p Path
	for i := 1; i < len(s); {
		if len(p) >= MaxSteps {
			return nil, fmt.Errorf("path %q has more than %d steps", s, MaxSteps)
		}
		switch s[i] {
		case '.':
			i++
			if i < len(s) && s[i] == '.' {
				return nil, fmt.Errorf("path %q: recursive descent (..) is not supported", s)
			}
			if i < len(s) && s[i] == '*' {
				p = append(p, Step{Kind: Wildcard})
				i++
				continue
			}
			j := i
			for j < len(s) && nameByte(s[j]) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("path %q: expected a field name at position %d (letters, digits, _ and -)", s, i)
			}
			p = append(p, Step{Kind: Field, Name: s[i:j]})
			i = j
		case '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("path %q: [ at position %d is not closed", s, i)
			}
			inner := s[i+1 : i+end]
			switch {
			case inner == "*":
				p = append(p, Step{Kind: Wildcard})
			case inner != "" && strings.Trim(inner, "0123456789") == "":
				if len(inner) > 1 && inner[0] == '0' {
					return nil, fmt.Errorf("path %q: index %s has a leading zero", s, inner)
				}
				n, err := strconv.Atoi(inner)
				if err != nil || n > 1<<20 {
					return nil, fmt.Errorf("path %q: index %s is too large", s, inner)
				}
				p = append(p, Step{Kind: Index, Index: n})
			default:
				return nil, fmt.Errorf("path %q: [%s] is not supported; use [n] or [*]", s, inner)
			}
			i += end + 1
		default:
			return nil, fmt.Errorf("path %q: unexpected %q at position %d; use .name, [n] or [*]", s, s[i], i)
		}
	}
	return p, nil
}

// String renders the path in the form Parse reads.
func (p Path) String() string {
	var b strings.Builder
	b.WriteByte('$')
	for _, st := range p {
		switch st.Kind {
		case Field:
			b.WriteByte('.')
			b.WriteString(st.Name)
		case Index:
			b.WriteString("[" + strconv.Itoa(st.Index) + "]")
		case Wildcard:
			b.WriteString("[*]")
		}
	}
	return b.String()
}

// Kind is the type of a JSON value.
type Kind uint8

const (
	Object Kind = iota
	Array
	String
	Scalar // number, true, false or null
)

// Node is one value of a document, with its byte range in the raw document.
type Node struct {
	Kind       Kind
	Start, End int
	// Keys and Children: an object's members in document order, or an
	// array's elements (Keys nil).
	Keys     []string
	Children []*Node
	// Str is a string's decoded value.
	Str string
}

// Doc is a parsed JSON document.
type Doc struct {
	raw  []byte
	Root *Node
}

// MaxDepth is how deeply ParseDoc lets values nest.
const MaxDepth = 128

// Errors of ParseDoc and Select.
var (
	ErrInvalid      = errors.New("body is not valid JSON")
	ErrDuplicateKey = errors.New("body has an object with a duplicate key")
	ErrTooDeep      = fmt.Errorf("body nests deeper than %d levels", MaxDepth)
	// ErrShadowKey is a member whose name differs from a selected one only
	// in case: a backend that matches names without case (Go's
	// encoding/json does) would read the text the guard did not.
	ErrShadowKey = errors.New("body has a key that differs from a scanned field only in case")
)

// ParseDoc parses raw. It refuses invalid JSON, trailing data, duplicate
// keys (backends disagree on which one wins) and nesting past MaxDepth.
func ParseDoc(raw []byte) (*Doc, error) {
	if !json.Valid(raw) {
		return nil, ErrInvalid
	}
	p := parser{raw: raw}
	p.space()
	root, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(raw) {
		return nil, ErrInvalid
	}
	return &Doc{raw: raw, Root: root}, nil
}

type parser struct {
	raw []byte
	i   int
}

func (p *parser) space() {
	for p.i < len(p.raw) {
		switch p.raw[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// value parses the value at p.i; the document is known to be valid JSON.
func (p *parser) value(depth int) (*Node, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	if p.i >= len(p.raw) {
		return nil, ErrInvalid
	}
	start := p.i
	switch p.raw[p.i] {
	case '{':
		n := &Node{Kind: Object, Start: start, Keys: []string{}}
		seen := map[string]bool{}
		p.i++
		p.space()
		if p.raw[p.i] == '}' {
			p.i++
			n.End = p.i
			return n, nil
		}
		for {
			p.space()
			key, err := p.str()
			if err != nil {
				return nil, err
			}
			if seen[key.Str] {
				return nil, ErrDuplicateKey
			}
			seen[key.Str] = true
			p.space()
			p.i++ // ':'
			p.space()
			child, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			n.Keys = append(n.Keys, key.Str)
			n.Children = append(n.Children, child)
			p.space()
			if p.raw[p.i] == '}' {
				p.i++
				n.End = p.i
				return n, nil
			}
			p.i++ // ','
		}
	case '[':
		n := &Node{Kind: Array, Start: start}
		p.i++
		p.space()
		if p.raw[p.i] == ']' {
			p.i++
			n.End = p.i
			return n, nil
		}
		for {
			p.space()
			child, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, child)
			p.space()
			if p.raw[p.i] == ']' {
				p.i++
				n.End = p.i
				return n, nil
			}
			p.i++ // ','
		}
	case '"':
		return p.str()
	default:
		for p.i < len(p.raw) {
			c := p.raw[p.i]
			if c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				break
			}
			p.i++
		}
		return &Node{Kind: Scalar, Start: start, End: p.i}, nil
	}
}

// str parses the string at p.i.
func (p *parser) str() (*Node, error) {
	start := p.i
	if p.i >= len(p.raw) || p.raw[p.i] != '"' {
		return nil, ErrInvalid
	}
	p.i++
	escaped := false
	for ; p.i < len(p.raw); p.i++ {
		c := p.raw[p.i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			p.i++
			n := &Node{Kind: String, Start: start, End: p.i}
			if err := json.Unmarshal(p.raw[start:p.i], &n.Str); err != nil {
				return nil, ErrInvalid
			}
			return n, nil
		}
	}
	return nil, ErrInvalid
}

// Select returns the values path selects, in document order. A step that
// does not apply (a field of an array, an index past the end) selects
// nothing. It returns ErrShadowKey when an object on the way has a member
// that differs from a selected field only in case.
func (d *Doc) Select(path Path) ([]*Node, error) {
	cur := []*Node{d.Root}
	for _, st := range path {
		var next []*Node
		for _, n := range cur {
			switch st.Kind {
			case Field:
				if n.Kind != Object {
					continue
				}
				for i, k := range n.Keys {
					if k == st.Name {
						next = append(next, n.Children[i])
					} else if strings.EqualFold(k, st.Name) {
						return nil, ErrShadowKey
					}
				}
			case Index:
				if n.Kind == Array && st.Index < len(n.Children) {
					next = append(next, n.Children[st.Index])
				}
			case Wildcard:
				if n.Kind == Array || n.Kind == Object {
					next = append(next, n.Children...)
				}
			}
		}
		cur = next
	}
	return cur, nil
}

// Strings returns the string values at or under n, in document order:
// n itself when it is a string, else every string inside it. Object keys
// are not included.
func Strings(n *Node) []*Node {
	var out []*Node
	var walk func(*Node)
	walk = func(n *Node) {
		switch n.Kind {
		case String:
			out = append(out, n)
		case Object, Array:
			for _, c := range n.Children {
				walk(c)
			}
		}
	}
	walk(n)
	return out
}

// Collect returns the distinct string values the paths select, each string
// once even when several paths reach it, in document order. A selected
// object or array contributes every string inside it.
func (d *Doc) Collect(paths []Path) ([]*Node, error) {
	seen := map[*Node]bool{}
	var out []*Node
	for _, p := range paths {
		nodes, err := d.Select(p)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			for _, s := range Strings(n) {
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// Replace returns the document with the given string values replaced, and
// every other byte unchanged. The nodes must be string nodes of d.
func (d *Doc) Replace(values map[*Node]string) ([]byte, error) {
	if len(values) == 0 {
		return bytes.Clone(d.raw), nil
	}
	nodes := make([]*Node, 0, len(values))
	for n := range values {
		if n.Kind != String {
			return nil, errors.New("jsonpath: only string values can be replaced")
		}
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Start < nodes[j].Start })
	var b bytes.Buffer
	last := 0
	for _, n := range nodes {
		if n.Start < last {
			return nil, errors.New("jsonpath: overlapping replacements")
		}
		b.Write(d.raw[last:n.Start])
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(values[n]); err != nil {
			return nil, err
		}
		b.Truncate(b.Len() - 1) // Encode's newline
		last = n.End
	}
	b.Write(d.raw[last:])
	return b.Bytes(), nil
}
