// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build onnx && cgo

package onnx

import (
	"errors"
	"path/filepath"
	"testing"

	ort "github.com/yalue/onnxruntime_go"
)

func needRuntime(t *testing.T) {
	t.Helper()
	if LibraryPath() == "" {
		for _, ext := range []string{"so", "dylib"} {
			if p := filepath.Join(repoRoot(), ".onnx", "lib", "libonnxruntime."+ext); fileExists(p) {
				t.Setenv(EnvLibraryPath, p)
			}
		}
	}
	if LibraryPath() == "" {
		t.Skipf("libonnxruntime not found; set %s", EnvLibraryPath)
	}
	if err := initEnvironment(); err != nil {
		t.Fatal(err)
	}
}

// The hand-encoded probe model loads and runs on the CPU provider.
func TestProbeModelRunsOnCPU(t *testing.T) {
	needRuntime(t)
	opts, err := ort.NewSessionOptions()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opts.Destroy() }()
	if err := runProbe(opts); err != nil {
		t.Fatal(err)
	}
}

// With the CPU build of ONNX Runtime (CI, the CPU image) the real CUDA probe
// fails: cuda refuses to start, auto runs on the CPU.
func TestCUDAProbeOnCPURuntime(t *testing.T) {
	needRuntime(t)
	if probeCUDAProvider(0) == nil {
		t.Skip("this ONNX Runtime has a working CUDA provider")
	}
	withProvider(t, probeCUDAProvider, EnvProvider, "cuda")
	if _, err := InitProvider(); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("cuda: err = %v", err)
	}
	withProvider(t, probeCUDAProvider, EnvProvider, "auto")
	st, err := InitProvider()
	if err != nil || st.Active != ProviderCPU || st.Fallback == "" {
		t.Fatalf("auto: %+v %v", st, err)
	}
	t.Logf("fallback: %s", st.Fallback)
}
