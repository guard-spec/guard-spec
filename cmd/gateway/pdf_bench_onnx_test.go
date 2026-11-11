//go:build onnx && cgo

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/guard-spec/guard-spec/internal/inference"
)

// BenchmarkPDFDocumentML is BenchmarkPDFDocument with the model layers
// behind ml.Live, as the gateway runs them (L1+L2+L3 installed; the long
// path scores 256-token windows with L1+L2, one ONNX thread per run): the
// cost of scanning every window of a 200k-token PDF. It skips without the
// models or libonnxruntime, like the other model tests.
func BenchmarkPDFDocumentML(b *testing.B) {
	runPDFBenchAll(b, func(b *testing.B) *inference.Runner { return liveRunner(b) })
}
