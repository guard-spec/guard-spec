// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func envMap(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

// noGPU is the CUDA probe of a host without a GPU, as ONNX Runtime reports it.
func noGPU(int) error {
	return errors.New("CUDA failure 100: no CUDA-capable device is detected")
}

func probeMustNotRun(t *testing.T) func(int) error {
	return func(int) error { t.Fatal("the CUDA probe ran for the CPU provider"); return nil }
}

func noInfo(int) (string, string) { return "", "" }

func TestParseProvider(t *testing.T) {
	for in, want := range map[string]Provider{"": ProviderCPU, "cpu": ProviderCPU, " CPU ": ProviderCPU,
		"cuda": ProviderCUDA, "CUDA": ProviderCUDA, "auto": ProviderAuto} {
		if got, err := ParseProvider(in); err != nil || got != want {
			t.Errorf("ParseProvider(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"gpu", "tensorrt", "rocm", "coreml", "cuda:0"} {
		if _, err := ParseProvider(in); err == nil || !strings.Contains(err.Error(), EnvProvider) {
			t.Errorf("ParseProvider(%q) err = %v, want an error naming %s", in, err, EnvProvider)
		}
	}
}

func TestProviderConfigFromEnv(t *testing.T) {
	c, err := ProviderConfigFromEnv(envMap())
	if err != nil || c != (ProviderConfig{Provider: ProviderCPU}) {
		t.Fatalf("unset: %+v %v", c, err)
	}
	c, err = ProviderConfigFromEnv(envMap(EnvProvider, "cuda", EnvCUDADeviceID, "1", EnvBatchSize, "32"))
	if err != nil || c != (ProviderConfig{Provider: ProviderCUDA, DeviceID: 1, BatchSize: 32}) {
		t.Fatalf("set: %+v %v", c, err)
	}
	for _, kv := range [][2]string{{EnvCUDADeviceID, "-1"}, {EnvCUDADeviceID, "x"}, {EnvBatchSize, "0"},
		{EnvBatchSize, "100000"}, {EnvBatchSize, "eight"}, {EnvProvider, "gpu"}} {
		if _, err := ProviderConfigFromEnv(envMap(kv[0], kv[1])); err == nil || !strings.Contains(err.Error(), kv[0]) {
			t.Errorf("%s=%s: err %v, want one naming the variable", kv[0], kv[1], err)
		}
	}
}

// The CPU is the default: no probe, nothing else changes.
func TestResolveProviderCPU(t *testing.T) {
	for _, v := range []string{"", "cpu"} {
		_, st, err := resolveProvider(envMap(EnvProvider, v), probeMustNotRun(t), noInfo)
		if err != nil || st != (ProviderState{Requested: ProviderCPU, Active: ProviderCPU}) {
			t.Fatalf("%q: %+v %v", v, st, err)
		}
	}
}

// cuda on a host without a GPU (the probe fails, injected here so that CI
// needs no GPU): a clear error, which stops the gateway.
func TestResolveProviderCUDAWithoutGPU(t *testing.T) {
	_, st, err := resolveProvider(envMap(EnvProvider, "cuda"), noGPU, noInfo)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	for _, want := range []string{"INFERENCE_PROVIDER=cuda", "device 0", "no CUDA-capable device", "-gpu image", "INFERENCE_PROVIDER=cpu"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if st.Active != ProviderCPU {
		t.Fatalf("state %+v", st)
	}
}

// auto on a host without a GPU: the CPU, with the reason.
func TestResolveProviderAutoFallsBack(t *testing.T) {
	_, st, err := resolveProvider(envMap(EnvProvider, "auto", EnvCUDADeviceID, "1"), noGPU, noInfo)
	if err != nil {
		t.Fatal(err)
	}
	if st.Requested != ProviderAuto || st.Active != ProviderCPU || !strings.Contains(st.Fallback, "no CUDA-capable device") {
		t.Fatalf("state %+v", st)
	}
}

func TestResolveProviderCUDA(t *testing.T) {
	var probed []int
	probe := func(d int) error { probed = append(probed, d); return nil }
	info := func(int) (string, string) { return "NVIDIA L4", "550.54.15" }
	for _, v := range []string{"cuda", "auto"} {
		probed = nil
		_, st, err := resolveProvider(envMap(EnvProvider, v, EnvCUDADeviceID, "2", "CUDA_VERSION", "12.8.1"), probe, info)
		if err != nil {
			t.Fatal(err)
		}
		want := ProviderState{Requested: Provider(v), Active: ProviderCUDA, DeviceID: 2, GPU: "NVIDIA L4", Driver: "550.54.15", CUDA: "12.8.1"}
		if st != want || !slices.Equal(probed, []int{2}) {
			t.Fatalf("%s: %+v (probed %v), want %+v", v, st, probed, want)
		}
	}
}

// withProvider resolves the process-wide provider from env with probe, and
// restores it after the test.
func withProvider(t *testing.T, probe func(int) error, kv ...string) {
	t.Helper()
	for _, k := range []string{EnvProvider, EnvCUDADeviceID, EnvBatchSize, EnvMaxConcurrency} {
		t.Setenv(k, "")
	}
	for i := 0; i+1 < len(kv); i += 2 {
		t.Setenv(kv[i], kv[i+1])
	}
	oldProbe, oldInfo := probeCUDA, gpuInfo
	probeCUDA, gpuInfo = probe, noInfo
	resetProvider()
	t.Cleanup(func() {
		probeCUDA, gpuInfo = oldProbe, oldInfo
		resetProvider()
	})
}

func TestInitProviderOnce(t *testing.T) {
	n := 0
	withProvider(t, func(int) error { n++; return nil }, EnvProvider, "cuda")
	for range 3 {
		if st, err := InitProvider(); err != nil || st.Active != ProviderCUDA {
			t.Fatalf("%+v %v", st, err)
		}
	}
	if n != 1 {
		t.Fatalf("probed %d times, want 1", n)
	}
}

func TestDefaultsFollowProvider(t *testing.T) {
	withProvider(t, probeMustNotRun(t))
	if BatchSize() != defaultBatchSize || LongBatchSize(16) != 16 || MaxConcurrencyFromEnv() != runtime.NumCPU() {
		t.Fatalf("cpu: batch %d long %d conc %d", BatchSize(), LongBatchSize(16), MaxConcurrencyFromEnv())
	}

	withProvider(t, probeMustNotRun(t), EnvBatchSize, "12")
	if BatchSize() != 12 || LongBatchSize(16) != 12 {
		t.Fatalf("cpu, INFERENCE_BATCH_SIZE=12: batch %d long %d", BatchSize(), LongBatchSize(16))
	}

	withProvider(t, func(int) error { return nil }, EnvProvider, "cuda")
	if BatchSize() != DefaultCUDABatchSize || LongBatchSize(16) != DefaultCUDABatchSize || MaxConcurrencyFromEnv() != 2 {
		t.Fatalf("cuda: batch %d long %d conc %d", BatchSize(), LongBatchSize(16), MaxConcurrencyFromEnv())
	}

	withProvider(t, func(int) error { return nil }, EnvProvider, "cuda", EnvBatchSize, "128", EnvMaxConcurrency, "3")
	if BatchSize() != 128 || LongBatchSize(16) != 128 || MaxConcurrencyFromEnv() != 3 {
		t.Fatalf("cuda, set: batch %d long %d conc %d", BatchSize(), LongBatchSize(16), MaxConcurrencyFromEnv())
	}

	withProvider(t, noGPU, EnvProvider, "auto")
	if BatchSize() != defaultBatchSize || MaxConcurrencyFromEnv() != runtime.NumCPU() {
		t.Fatalf("auto without GPU: batch %d conc %d", BatchSize(), MaxConcurrencyFromEnv())
	}
}

func TestResolveModelFileByProvider(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{ModelInt8File, ModelFP16File} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	withProvider(t, probeMustNotRun(t))
	if got := filepath.Base(ResolveModelFile(dir, Options{})); got != ModelInt8File {
		t.Fatalf("cpu: %s", got)
	}
	if got := filepath.Base(ResolveModelFile(dir, Options{Provider: ProviderCUDA})); got != ModelFP16File {
		t.Fatalf("Options.Provider cuda: %s", got)
	}
	withProvider(t, func(int) error { return nil }, EnvProvider, "cuda")
	if got := filepath.Base(ResolveModelFile(dir, Options{})); got != ModelFP16File {
		t.Fatalf("cuda: %s", got)
	}
	if got := filepath.Base(ResolveModelFile(dir, Options{Provider: ProviderCPU})); got != ModelInt8File {
		t.Fatalf("Options.Provider cpu: %s", got)
	}
	if got := filepath.Base(ResolveModelFile(dir, Options{ModelFile: "x.onnx"})); got != "x.onnx" {
		t.Fatalf("ModelFile: %s", got)
	}
	// auto without a GPU runs the CPU model.
	withProvider(t, noGPU, EnvProvider, "auto")
	if got := filepath.Base(ResolveModelFile(dir, Options{})); got != ModelInt8File {
		t.Fatalf("auto, no GPU: %s", got)
	}
	// CUDA without the FP16 file still loads the INT8 one.
	if err := os.Remove(filepath.Join(dir, ModelFP16File)); err != nil {
		t.Fatal(err)
	}
	withProvider(t, func(int) error { return nil }, EnvProvider, "cuda")
	if got := filepath.Base(ResolveModelFile(dir, Options{})); got != ModelInt8File {
		t.Fatalf("cuda, no fp16: %s", got)
	}
}

// Without the onnx tag (CI's plain go test), cuda cannot start: the stub has
// no runtime, and the error says so.
func TestStubCUDAProbe(t *testing.T) {
	if Available() {
		t.Skip("onnx build")
	}
	withProvider(t, probeCUDAProvider, EnvProvider, "cuda")
	if _, err := InitProvider(); !errors.Is(err, ErrProviderUnavailable) || !strings.Contains(err.Error(), "not compiled in") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseSMIAndProc(t *testing.T) {
	if g, d, ok := parseSMI("NVIDIA L4, 550.54.15\n"); !ok || g != "NVIDIA L4" || d != "550.54.15" {
		t.Fatalf("%q %q %v", g, d, ok)
	}
	if _, _, ok := parseSMI(""); ok {
		t.Fatal("empty output parsed")
	}
	root := t.TempDir()
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "version"), "NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.15  Tue Mar  5 22:23:56 UTC 2024\nGCC version:  gcc 12\n")
	write(filepath.Join(root, "gpus", "0000:00:04.0", "information"), "Model: \t\t Tesla T4\nIRQ:   36\n")
	write(filepath.Join(root, "gpus", "0000:00:05.0", "information"), "Model: \t\t NVIDIA L4\n")
	if g, d := procGPUInfo(root, 1); g != "NVIDIA L4" || d != "550.54.15" {
		t.Fatalf("%q %q", g, d)
	}
	if g, _ := procGPUInfo(root, 5); g != "" {
		t.Fatalf("device 5: %q", g)
	}
}

func TestProbeModelEncoding(t *testing.T) {
	m := probeModel()
	// ir_version 7 first, then the graph with the Add node and the opset.
	if m[0] != 0x08 || m[1] != 7 {
		t.Fatalf("header % x", m[:2])
	}
	for _, s := range []string{"Add", "provider_probe", "x", "y"} {
		if !strings.Contains(string(m), s) {
			t.Fatalf("probe model lacks %q", s)
		}
	}
	if got := appendUvarint(nil, 300); !slices.Equal(got, []byte{0xac, 0x02}) {
		t.Fatalf("varint 300 = % x", got)
	}
}
