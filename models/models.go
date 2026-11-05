// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package models embeds manifest.yaml, so that the gateway knows the
// recommended models (and cmd/models works) without the file on disk.
// The model files themselves are never part of the source or the binaries.
package models

import _ "embed"

// Manifest is the content of models/manifest.yaml.
//
//go:embed manifest.yaml
var Manifest []byte
