// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyMigrations(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{"001_a.up.sql": "a", "001_a.down.sql": "b", "README": "x"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if code := copyMigrations([]string{dst, src}, &out, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.String() != "001_a.down.sql\n001_a.up.sql\n" {
		t.Fatalf("listed %q", out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "001_a.up.sql")); string(b) != "a" {
		t.Fatalf("copied %q", b)
	}
	if _, err := os.Stat(filepath.Join(dst, "README")); err == nil {
		t.Fatal("copied a non-sql file")
	}
	if code := copyMigrations([]string{dst, t.TempDir()}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("empty source: exit %d, want 1", code)
	}
	if code := copyMigrations(nil, io.Discard, io.Discard); code != exitUsage {
		t.Fatalf("no args: exit %d", code)
	}
}
