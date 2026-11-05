// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package version reports the release a binary was built from.
package version

import "runtime/debug"

// Version is set at link time by release builds:
//
//	-ldflags "-X github.com/guard-spec/guard-spec/internal/version.Version=0.1.0"
var Version string

// String returns Version, else the module version Go stamped from the VCS
// tag, else "dev".
func String() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// IsFlag reports whether arg asks a command for its version.
func IsFlag(arg string) bool {
	return arg == "version" || arg == "-version" || arg == "--version"
}
