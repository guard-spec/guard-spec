// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestString(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "0.1.0"
	if got := String(); got != "0.1.0" {
		t.Fatalf("got %q", got)
	}
	Version = ""
	if got := String(); got == "" {
		t.Fatal("empty version")
	}
	for _, a := range []string{"version", "-version", "--version"} {
		if !IsFlag(a) {
			t.Errorf("%s: not a version flag", a)
		}
	}
	if IsFlag("health") {
		t.Error("health is not a version flag")
	}
}
