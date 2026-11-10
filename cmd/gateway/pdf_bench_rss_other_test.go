//go:build !unix

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

// maxRSS is not measured on this platform.
func maxRSS() int64 { return 0 }
