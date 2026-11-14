// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"slices"
	"strings"
	"testing"
)

func valid() Config {
	return Config{PathPrefixes: []string{"/search"}, Scan: Scan{Request: []string{"$.query"}}}
}

func TestValidateNormalizes(t *testing.T) {
	c := Config{PathPrefixes: []string{" /api/v1/ ", "/api/v1", "/"}, Methods: []string{"post", "GET", "POST"},
		Scan: Scan{Request: []string{" $.messages.*.content "}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.PathPrefixes, []string{"/api/v1", "/"}) {
		t.Errorf("prefixes = %v", c.PathPrefixes)
	}
	if !slices.Equal(c.Methods, []string{"POST", "GET"}) {
		t.Errorf("methods = %v", c.Methods)
	}
	if c.Scan.Request[0] != "$.messages[*].content" || c.Scan.Response == nil {
		t.Errorf("scan = %+v", c.Scan)
	}
	d := valid()
	if err := d.Validate(); err != nil || !slices.Equal(d.Methods, []string{"POST"}) {
		t.Errorf("default methods = %v, %v", d.Methods, err)
	}
	all := Config{PathPrefixes: []string{"/"}, Scan: Scan{AllStrings: true}}
	if err := all.Validate(); err != nil {
		t.Errorf("all_strings without paths: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"no prefix", func(c *Config) { c.PathPrefixes = nil }, "backend.path_prefixes: list at least one"},
		{"relative prefix", func(c *Config) { c.PathPrefixes = []string{"search"} }, "must start with /"},
		{"query in prefix", func(c *Config) { c.PathPrefixes = []string{"/a?b"} }, "must start with /"},
		{"dot segment", func(c *Config) { c.PathPrefixes = []string{"/a/../b"} }, "segments"},
		{"empty segment", func(c *Config) { c.PathPrefixes = []string{"/a//b"} }, "segments"},
		{"too many prefixes", func(c *Config) { c.PathPrefixes = slices.Repeat([]string{"/a"}, 21) }, "at most 20"},
		{"bad method", func(c *Config) { c.Methods = []string{"TRACE"} }, `backend.methods: "TRACE"`},
		{"no scan", func(c *Config) { c.Scan.Request = nil }, "backend.scan.request: list the JSONPaths"},
		{"bad request path", func(c *Config) { c.Scan.Request = []string{"$..x"} }, "backend.scan.request[0]: path"},
		{"bad response path", func(c *Config) { c.Scan.Response = []string{"$.ok", "x"} }, "backend.scan.response[1]"},
		{"too many paths", func(c *Config) { c.Scan.Request = slices.Repeat([]string{"$.a"}, 51) }, "at most 50"},
		{"host key header", func(c *Config) { c.KeyHeader = "Host" }, "backend.key_header"},
		{"bad key header", func(c *Config) { c.KeyHeader = "x key" }, "backend.key_header"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.edit(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	c := valid()
	c.KeyHeader = "X-Backend-Key"
	if err := c.Validate(); err != nil {
		t.Errorf("key header: %v", err)
	}
}

func TestAllowsPath(t *testing.T) {
	c := Config{PathPrefixes: []string{"/orders", "/api/v1/"}, Scan: Scan{AllStrings: true}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"/orders": true, "/orders/7": true, "/orders/": true, "/orders-admin": false, "/order": false,
		"/api/v1/x": true, "/api/v1": true, "/api/v2": false, "/": false,
	} {
		if got := c.AllowsPath(path); got != want {
			t.Errorf("AllowsPath(%q) = %v", path, got)
		}
	}
	root := Config{PathPrefixes: []string{"/"}, Scan: Scan{AllStrings: true}}
	_ = root.Validate()
	if !root.AllowsPath("/anything/at/all") {
		t.Error("/ does not allow every path")
	}
}

func TestCleanPath(t *testing.T) {
	ok := map[string]string{"": "/", "/": "/", "/orders/7": "/orders/7", "/a%20b": "/a%20b", "/x/": "/x/",
		"/a.b/c~d": "/a.b/c~d"}
	for in, want := range ok {
		if got, err := CleanPath(in); err != nil || got != want {
			t.Errorf("CleanPath(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"orders", "/a/../b", "/a/./b", "/..", "/a//b", "/a%2fb", "/a%2Fb", "/%2e%2e/x",
		"/a%5cb", `/a\b`, "/a%00", "/a b", "/a\tb", "/a%", "/a%2", "/a?x", "/a#x", "/a%3fx"} {
		if _, err := CleanPath(in); err == nil {
			t.Errorf("CleanPath(%q) accepted", in)
		}
	}
}
