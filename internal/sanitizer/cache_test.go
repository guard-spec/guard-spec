// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"container/list"
	"crypto/sha256"
	"strings"
	"testing"
)

// A large input's result comes from the cache and equals a fresh one.
func TestCleanCache(t *testing.T) {
	in := strings.Repeat("Hello <b>world</b> \u202e reversed \x1b[31mred\x1b[0m &amp; more. ", 1000)
	first, err := Clean(in)
	if err != nil {
		t.Fatal(err)
	}
	scan, report, _ := Sanitize(in)
	want := Result{Scan: scan, Forward: forward(in, report.HadFakeMarker), Report: report}
	again, _ := Clean(in)
	if first != want || again != want {
		t.Fatal("cached result differs from a fresh one")
	}
	k := len(cleaned.items)
	if _, err := Clean("small input"); err != nil || len(cleaned.items) != k {
		t.Fatal("a small input was cached")
	}
	if _, err := Clean(string([]byte{0xff}) + in); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestCleanCacheBound(t *testing.T) {
	c := &cleanCache{ll: list.New(), items: map[[sha256.Size]byte]*list.Element{}}
	big := strings.Repeat("x", cleanCacheBytes/8)
	for i := range 20 {
		c.put([sha256.Size]byte{byte(i)}, Result{Scan: big, Forward: big})
	}
	if c.bytes > cleanCacheBytes || c.ll.Len() != 4 {
		t.Fatalf("%d bytes in %d entries", c.bytes, c.ll.Len())
	}
	if _, ok := c.get([sha256.Size]byte{19}); !ok {
		t.Fatal("newest entry evicted")
	}
}
