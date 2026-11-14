// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package backend is the configuration of a custom backend: an upstream of
// provider "custom" (migration 031) that is an organization's own JSON API,
// reached through the gateway's /v1/backend/{upstream}/{path}. The control
// plane validates it when it is saved, and the gateway validates it again
// when it reads it, so a row written to the database directly cannot widen
// what passes.
package backend

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/guard-spec/guard-spec/internal/jsonpath"
)

// Provider is the upstreams.provider value of a custom backend.
const Provider = "custom"

// Limits of a configuration.
const (
	MaxPrefixes = 20
	MaxPaths    = 50
	maxPrefix   = 256
)

// Methods are the HTTP methods a backend may allow.
var Methods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// Scan says which parts of a request and of a response are checked.
type Scan struct {
	// Request and Response are JSONPaths (package jsonpath) of the fields
	// scanned. A path that selects an object or array covers every string
	// inside it.
	Request  []string `json:"request" yaml:"request"`
	Response []string `json:"response" yaml:"response"`
	// AllStrings scans every string value of a JSON body whose side
	// (request or response) declares no path. Off unless set.
	AllStrings bool `json:"all_strings" yaml:"all_strings"`
	// RawText accepts bodies that are not JSON and scans them as one text
	// (text/plain, say). Without it such a request is refused (415) and
	// such a response is passed through unchecked.
	RawText bool `json:"raw_text" yaml:"raw_text"`
}

// Config is upstreams.backend.
type Config struct {
	// PathPrefixes are the paths the gateway forwards, matched by whole
	// segments: /orders allows /orders and /orders/7, not /orders-admin.
	// "/" allows every path.
	PathPrefixes []string `json:"path_prefixes" yaml:"path_prefixes"`
	// Methods are the methods the gateway forwards; empty means POST.
	Methods []string `json:"methods" yaml:"methods"`
	// KeyHeader, when set, sends the api_key_env value in this header as
	// is, instead of as Authorization: Bearer.
	KeyHeader string `json:"key_header,omitempty" yaml:"key_header,omitempty"`
	Scan      Scan   `json:"scan" yaml:"scan"`

	request, response []jsonpath.Path
}

var (
	prefixRe    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	keyHeaderRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
)

// keyHeaderDenied are names the key cannot go in: the transport's and the
// gateway's own headers.
var keyHeaderDenied = map[string]bool{
	"host": true, "content-length": true, "content-type": true, "content-encoding": true,
	"transfer-encoding": true, "connection": true, "upgrade": true, "te": true, "trailer": true,
	"keep-alive": true, "cookie": true, "set-cookie": true, "forwarded": true, "via": true,
	"traceparent": true, "tracestate": true, "baggage": true, "expect": true, "user-agent": true,
}

// Validate checks c and normalizes it: methods upper case and deduplicated,
// POST when none is given, nil lists made empty. Its errors name the field.
func (c *Config) Validate() error {
	if len(c.PathPrefixes) == 0 {
		return errors.New(`backend.path_prefixes: list at least one path prefix ("/" allows every path)`)
	}
	if len(c.PathPrefixes) > MaxPrefixes {
		return fmt.Errorf("backend.path_prefixes: at most %d prefixes", MaxPrefixes)
	}
	prefixes := make([]string, 0, len(c.PathPrefixes))
	for _, p := range c.PathPrefixes {
		p = strings.TrimSpace(p)
		if len(p) > maxPrefix || !prefixRe.MatchString(p) {
			return fmt.Errorf("backend.path_prefixes: %q must start with / and hold only letters, digits and . _ ~ - /, "+
				"at most %d characters", p, maxPrefix)
		}
		if p != "/" && (strings.Contains(p, "//") || hasDotSegment(p)) {
			return fmt.Errorf("backend.path_prefixes: %q must not have empty, . or .. segments", p)
		}
		if p != "/" {
			p = strings.TrimSuffix(p, "/")
		}
		if !slices.Contains(prefixes, p) {
			prefixes = append(prefixes, p)
		}
	}
	c.PathPrefixes = prefixes
	if len(c.Methods) == 0 {
		c.Methods = []string{http.MethodPost}
	}
	methods := make([]string, 0, len(c.Methods))
	for _, m := range c.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !slices.Contains(Methods, m) {
			return fmt.Errorf("backend.methods: %q is not one of %s", m, strings.Join(Methods, ", "))
		}
		if !slices.Contains(methods, m) {
			methods = append(methods, m)
		}
	}
	c.Methods = methods
	if c.KeyHeader != "" {
		lower := strings.ToLower(c.KeyHeader)
		if !keyHeaderRe.MatchString(c.KeyHeader) || keyHeaderDenied[lower] || strings.HasPrefix(lower, "x-forwarded-") ||
			strings.HasPrefix(lower, "proxy-") {
			return fmt.Errorf("backend.key_header: %q cannot carry the key; leave it empty for Authorization: Bearer", c.KeyHeader)
		}
	}
	var err error
	if c.request, err = parsePaths("backend.scan.request", c.Scan.Request); err != nil {
		return err
	}
	if c.response, err = parsePaths("backend.scan.response", c.Scan.Response); err != nil {
		return err
	}
	if c.Scan.Request == nil {
		c.Scan.Request = []string{}
	}
	if c.Scan.Response == nil {
		c.Scan.Response = []string{}
	}
	if len(c.request) == 0 && !c.Scan.AllStrings {
		return errors.New("backend.scan.request: list the JSONPaths of the fields to scan (for example $.query), " +
			"or turn on scan.all_strings to scan every string")
	}
	return nil
}

func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

func parsePaths(field string, raw []string) ([]jsonpath.Path, error) {
	if len(raw) > MaxPaths {
		return nil, fmt.Errorf("%s: at most %d paths", field, MaxPaths)
	}
	var out []jsonpath.Path
	for i, s := range raw {
		p, err := jsonpath.Parse(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		raw[i] = p.String()
		out = append(out, p)
	}
	return out, nil
}

// RequestPaths and ResponsePaths are the parsed paths; Validate sets them.
func (c *Config) RequestPaths() []jsonpath.Path  { return c.request }
func (c *Config) ResponsePaths() []jsonpath.Path { return c.response }

// AllowsMethod reports whether method is forwarded.
func (c *Config) AllowsMethod(method string) bool { return slices.Contains(c.Methods, method) }

// AllowsPath reports whether path, already checked by CleanPath, is under
// one of the prefixes, by whole segments.
func (c *Config) AllowsPath(path string) bool {
	for _, p := range c.PathPrefixes {
		if p == "/" || path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// ErrBadPath refuses a request path that could mean something else to the
// backend than to the gateway's prefix check.
var ErrBadPath = errors.New("path has an empty, . or .. segment, an encoded slash, dot or backslash, or a control character")

// CleanPath checks the raw (still percent-encoded) path a client sent after
// /v1/backend/{upstream}. It must be "" or start with "/", and must not hold
// what a server could resolve to another path: empty, . and .. segments,
// encoded / \ . and NUL, backslashes, control characters. The path is
// forwarded exactly as checked.
func CleanPath(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	if raw[0] != '/' {
		return "", ErrBadPath
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x21 || c == 0x7f || c == '\\' || c == '#' || c == '?' {
			return "", ErrBadPath
		}
		if c == '%' {
			if i+2 >= len(raw) {
				return "", ErrBadPath
			}
			switch strings.ToLower(raw[i+1 : i+3]) {
			case "2f", "5c", "2e", "00", "23", "3f":
				return "", ErrBadPath
			}
		}
	}
	if raw != "/" && (strings.Contains(raw, "//") || hasDotSegment(raw)) {
		return "", ErrBadPath
	}
	return raw, nil
}
