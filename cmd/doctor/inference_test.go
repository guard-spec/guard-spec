// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// inferenceResult runs the inference check with a fake GPU lookup.
func inferenceResult(t *testing.T, env map[string]string, gpu, driver string) Result {
	t.Helper()
	d := &doctor{get: getter(env), opts: Options{Timeout: 2 * time.Second},
		gpuInfo: func(int) (string, string) { return gpu, driver }}
	return d.checkInference(context.Background())
}

// gpuRuntime is an ONNX Runtime directory of the GPU build: the provider
// library and the version file next to libonnxruntime.so.
func gpuRuntime(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"libonnxruntime.so": "", ortProviderCUDA: "",
		ortVersionFile: "1.31.1 (gpu_cuda12)\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "libonnxruntime.so")
}

func TestInferenceCPUDefault(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	install(t, testClassifier, filepath.Join(dir, "cache", "testclf", "v1"))
	env := modelEnv(t, dir)
	env["MODELS_MANIFEST"] = man
	r := inferenceResult(t, env, "", "")
	want(t, r, OK, "provider cpu")
	want(t, r, OK, "L2 model file model_int8.onnx")
	want(t, r, OK, "(the default)")
}

func TestInferenceInvalid(t *testing.T) {
	want(t, inferenceResult(t, map[string]string{"INFERENCE_PROVIDER": "tensorrt"}, "", ""), Fail, "INFERENCE_PROVIDER")
	want(t, inferenceResult(t, map[string]string{"INFERENCE_BATCH_SIZE": "0"}, "", ""), Fail, "INFERENCE_BATCH_SIZE")
}

// cuda without a GPU or with the CPU build of ONNX Runtime: the gateway
// would refuse to start, so doctor fails; auto only warns.
func TestInferenceCUDAWithoutGPU(t *testing.T) {
	env := modelEnv(t, t.TempDir()) // ONNXRUNTIME_LIB: a CPU build (no CUDA provider next to it)
	env["INFERENCE_PROVIDER"] = "cuda"
	r := inferenceResult(t, env, "", "")
	want(t, r, Fail, "no NVIDIA GPU 0 found")
	want(t, r, Fail, "CPU build of ONNX Runtime")
	want(t, r, Fail, "refuses to start")

	env["INFERENCE_PROVIDER"] = "auto"
	want(t, inferenceResult(t, env, "", ""), Warn, "will run on the CPU")
}

func TestInferenceCUDA(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	l2 := filepath.Join(dir, "cache", "testclf", "v1")
	install(t, testClassifier, l2)
	env := modelEnv(t, dir)
	env["MODELS_MANIFEST"] = man
	env["INFERENCE_PROVIDER"] = "cuda"
	env["ONNXRUNTIME_LIB"] = gpuRuntime(t)
	env["CUDA_VERSION"] = "12.9.2"

	// No FP16 model: CUDA would run the INT8 one, slowly.
	r := inferenceResult(t, env, "NVIDIA L4", "580.82.07")
	want(t, r, Warn, "no model_fp16.onnx")
	for _, s := range []string{"GPU 0 NVIDIA L4, driver 580.82.07", "CUDA 12.9.2", "ONNX Runtime 1.31.1 (gpu_cuda12)", "L2 model file model_int8.onnx"} {
		want(t, r, Warn, s)
	}

	if err := os.WriteFile(filepath.Join(l2, "model_fp16.onnx"), []byte("fp16"), 0o644); err != nil {
		t.Fatal(err)
	}
	want(t, inferenceResult(t, env, "NVIDIA L4", "580.82.07"), OK, "L2 model file model_fp16.onnx")
}
