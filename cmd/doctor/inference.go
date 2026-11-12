// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// ortProviderCUDA is the ONNX Runtime library of the CUDA execution
// provider, next to libonnxruntime.so in the GPU build only.
const ortProviderCUDA = "libonnxruntime_providers_cuda.so"

// ortVersionFile is written next to libonnxruntime by build/onnx-deps.sh.
const ortVersionFile = "VERSION.onnxruntime"

// checkInference reports the execution provider (INFERENCE_PROVIDER), the
// GPU, the CUDA and ONNX Runtime versions and the classifier file the
// gateway will load. doctor does not load ONNX Runtime: for cuda it checks
// what the gateway's start-up probe needs (a GPU the driver lists, the GPU
// build of ONNX Runtime); the gateway's /readyz reports what actually runs.
func (d *doctor) checkInference(context.Context) Result {
	cfg, err := onnx.ProviderConfigFromEnv(d.get)
	if err != nil {
		return Result{Status: Fail, Detail: err.Error(), Hint: "the gateway refuses to start with this value"}
	}
	rep := d.evaluateLayers()
	modelFile := func(p onnx.Provider) string {
		if rep.cfgErr != nil || !rep.cfg.Layers[fusion.L2] {
			return ""
		}
		for _, lm := range rep.ml {
			if lm.layer == "L2" && lm.dir != "" {
				return filepath.Base(onnx.ResolveModelFile(lm.dir, onnx.Options{Provider: p}))
			}
		}
		return ""
	}
	lib := strings.TrimSpace(d.get(onnx.EnvLibraryPath))
	parts := []string{"provider " + string(cfg.Provider)}
	if v := ortVersion(lib); v != "" {
		parts = append(parts, "ONNX Runtime "+v)
	}
	if cfg.Provider == onnx.ProviderCPU {
		if f := modelFile(onnx.ProviderCPU); f != "" {
			parts = append(parts, "L2 model file "+f)
		}
		return Result{Status: OK, Detail: strings.Join(parts, ", ") + " (the default)"}
	}

	gi := d.gpuInfo
	if gi == nil {
		gi = onnx.GPUInfo
	}
	var problems []string
	gpu, driver := gi(cfg.DeviceID)
	if gpu == "" {
		problems = append(problems, fmt.Sprintf("no NVIDIA GPU %d found (nvidia-smi, /proc/driver/nvidia)", cfg.DeviceID))
	} else {
		parts = append(parts, fmt.Sprintf("GPU %d %s, driver %s", cfg.DeviceID, gpu, orUnknown(driver)))
	}
	if v := strings.TrimSpace(d.get("CUDA_VERSION")); v != "" {
		parts = append(parts, "CUDA "+v)
	}
	if lib != "" {
		if _, err := os.Stat(filepath.Join(filepath.Dir(lib), ortProviderCUDA)); err != nil {
			problems = append(problems, fmt.Sprintf("%s is the CPU build of ONNX Runtime (no %s next to it)", lib, ortProviderCUDA))
		}
	}
	f := modelFile(onnx.ProviderCUDA)
	if f != "" {
		parts = append(parts, "L2 model file "+f)
	}
	detail := strings.Join(parts, ", ")
	if len(problems) > 0 {
		detail += "; " + strings.Join(problems, "; ")
		if cfg.Provider == onnx.ProviderCUDA {
			return Result{Status: Fail, Detail: detail,
				Hint: "INFERENCE_PROVIDER=cuda: the gateway refuses to start without CUDA. Use an image built from build/gateway-gpu.Dockerfile on a node with an NVIDIA GPU " +
					"(driver 525 or newer) and the NVIDIA container runtime, or set INFERENCE_PROVIDER=cpu (the default)"}
		}
		return Result{Status: Warn, Detail: detail, Hint: "INFERENCE_PROVIDER=auto: the gateway will run on the CPU"}
	}
	if f != "" && f != onnx.ModelFP16File {
		return Result{Status: Warn, Detail: detail, Hint: "no " + onnx.ModelFP16File + " for the classifier: CUDA runs the INT8 model, " +
			"slowly (most quantized operators fall back to the CPU). Pull it with: ./models pull -provider cuda (docs/models.md)"}
	}
	return Result{Status: OK, Detail: detail}
}

// ortVersion reads the version file next to the ONNX Runtime library, "" when absent.
func ortVersion(lib string) string {
	if lib == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(lib), ortVersionFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
