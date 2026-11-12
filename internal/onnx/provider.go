// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package onnx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Execution providers. The CPU is the default and needs nothing else: the
// INT8 model on ONNX Runtime's CPU provider, as in every release so far. The
// CUDA execution provider is an option for hosts with an NVIDIA GPU: the same
// gateway binary, with the ONNX Runtime GPU build (an image built from
// build/gateway-gpu.Dockerfile; none is published) and the
// FP16 model (model_fp16.onnx). INFERENCE_PROVIDER selects it:
//
//	cpu   (default) the CPU provider; nothing changes.
//	cuda  the CUDA provider on INFERENCE_CUDA_DEVICE_ID; when it cannot start
//	      (no GPU, no CUDA libraries, a CPU-only ONNX Runtime) the gateway
//	      refuses to start with an error that says so.
//	auto  CUDA when it starts, else the CPU with a warning.
//
// The choice is made once per process (InitProvider) and every model session
// follows it.

// Provider is an ONNX Runtime execution provider.
type Provider string

// Execution providers.
const (
	ProviderCPU  Provider = "cpu"
	ProviderCUDA Provider = "cuda"
	// ProviderAuto is a request only: it resolves to ProviderCUDA or ProviderCPU.
	ProviderAuto Provider = "auto"
)

// Environment variables of the execution provider.
const (
	// EnvProvider is cpu (default), cuda or auto.
	EnvProvider = "INFERENCE_PROVIDER"
	// EnvCUDADeviceID is the CUDA device of the CUDA provider (default 0).
	EnvCUDADeviceID = "INFERENCE_CUDA_DEVICE_ID"
	// EnvBatchSize is the number of token windows per model run, on the
	// short path and the long path (default: 8 and 16 on the CPU,
	// DefaultCUDABatchSize on CUDA).
	EnvBatchSize = "INFERENCE_BATCH_SIZE"
)

// ModelFP16File is the FP16 model file used with the CUDA provider. The INT8
// model runs badly on CUDA: most of its quantized operators fall back to the
// CPU.
const ModelFP16File = "model_fp16.onnx"

const (
	// DefaultCUDABatchSize is the windows per run on CUDA, short and long
	// path, when INFERENCE_BATCH_SIZE is unset. On an L4 with the FP16
	// classifier, 8 was the fastest of 8/32/64/128 (1.2 ms per window
	// against 1.7 to 1.9; docs/sizing.md, "GPU option").
	DefaultCUDABatchSize = 8
	// defaultCUDAMaxConcurrency is INFERENCE_MAX_CONCURRENCY on CUDA when
	// unset: one GPU runs a few large batches at a time better than many.
	defaultCUDAMaxConcurrency = 2
	maxBatchSize              = 1024
)

// ErrProviderUnavailable means INFERENCE_PROVIDER=cuda and the CUDA provider
// cannot start.
var ErrProviderUnavailable = errors.New("onnx: execution provider unavailable")

// ParseProvider reads an INFERENCE_PROVIDER value; "" is ProviderCPU.
func ParseProvider(s string) (Provider, error) {
	switch p := Provider(strings.ToLower(strings.TrimSpace(s))); p {
	case "", ProviderCPU:
		return ProviderCPU, nil
	case ProviderCUDA, ProviderAuto:
		return p, nil
	}
	return "", fmt.Errorf("%s=%q: want cpu (the default), cuda or auto", EnvProvider, s)
}

// ProviderConfig is the execution provider the environment asks for.
type ProviderConfig struct {
	Provider Provider
	DeviceID int
	// BatchSize is INFERENCE_BATCH_SIZE; 0 when unset.
	BatchSize int
}

// ProviderConfigFromEnv reads INFERENCE_PROVIDER, INFERENCE_CUDA_DEVICE_ID
// and INFERENCE_BATCH_SIZE.
func ProviderConfigFromEnv(get func(string) string) (ProviderConfig, error) {
	var c ProviderConfig
	var err error
	if c.Provider, err = ParseProvider(get(EnvProvider)); err != nil {
		return c, err
	}
	if s := strings.TrimSpace(get(EnvCUDADeviceID)); s != "" {
		if c.DeviceID, err = strconv.Atoi(s); err != nil || c.DeviceID < 0 {
			return c, fmt.Errorf("%s=%q: want a CUDA device number (0, 1, ...)", EnvCUDADeviceID, s)
		}
	}
	if s := strings.TrimSpace(get(EnvBatchSize)); s != "" {
		if c.BatchSize, err = strconv.Atoi(s); err != nil || c.BatchSize < 1 || c.BatchSize > maxBatchSize {
			return c, fmt.Errorf("%s=%q: want a whole number from 1 to %d", EnvBatchSize, s, maxBatchSize)
		}
	}
	return c, nil
}

// ProviderState is the execution provider in use, as logged at start and
// reported by /readyz.
type ProviderState struct {
	// Requested is INFERENCE_PROVIDER: cpu, cuda or auto.
	Requested Provider `json:"requested"`
	// Active is the provider the models run on: cpu or cuda.
	Active Provider `json:"provider"`
	// Fallback says why auto runs on the CPU.
	Fallback string `json:"fallback,omitempty"`
	// DeviceID, GPU, Driver and CUDA describe the device when Active is cuda.
	// GPU and Driver come from nvidia-smi or /proc/driver/nvidia (best
	// effort); CUDA is the CUDA runtime of the image (CUDA_VERSION).
	DeviceID int    `json:"cuda_device_id,omitempty"`
	GPU      string `json:"gpu,omitempty"`
	Driver   string `json:"driver,omitempty"`
	CUDA     string `json:"cuda,omitempty"`
	// ORT is the ONNX Runtime version, when it is loaded.
	ORT string `json:"onnxruntime,omitempty"`
}

// LogAttrs are the state as slog key-value pairs.
func (s ProviderState) LogAttrs() []any {
	out := []any{"requested", s.Requested, "provider", s.Active}
	for _, kv := range [][2]string{{"fallback", s.Fallback}, {"gpu", s.GPU}, {"driver", s.Driver},
		{"cuda", s.CUDA}, {"onnxruntime", s.ORT}} {
		if kv[1] != "" {
			out = append(out, kv[0], kv[1])
		}
	}
	if s.Active == ProviderCUDA {
		out = append(out, "cuda_device_id", s.DeviceID)
	}
	return out
}

var (
	providerMu    sync.Mutex
	providerDone  bool
	providerState ProviderState
	providerCfg   ProviderConfig
	providerErr   error

	// probeCUDA starts the CUDA provider on a device and runs a one-node
	// model on it (backend_ort.go); ErrUnavailable without the onnx tag.
	// Tests replace it to simulate a host without a GPU.
	probeCUDA = probeCUDAProvider
	// gpuInfo names the GPU and the driver of a device (best effort).
	gpuInfo = nvidiaGPUInfo
)

// InitProvider resolves INFERENCE_PROVIDER once per process: cpu needs
// nothing; cuda and auto start the CUDA provider on a one-node model to see
// whether it works. For cuda a failure is returned (wrapping
// ErrProviderUnavailable) and the gateway must not start; for auto it is
// logged as a warning and the models run on the CPU. An invalid variable is
// an error too. Model loading calls it; the gateway calls it first, so that
// it fails before anything else.
func InitProvider() (ProviderState, error) {
	providerMu.Lock()
	defer providerMu.Unlock()
	if !providerDone {
		providerCfg, providerState, providerErr = resolveProvider(os.Getenv, probeCUDA, gpuInfo)
		providerDone = true
	}
	return providerState, providerErr
}

// resetProvider forgets the resolved provider (tests).
func resetProvider() {
	providerMu.Lock()
	defer providerMu.Unlock()
	providerDone, providerState, providerCfg, providerErr = false, ProviderState{}, ProviderConfig{}, nil
}

// activeProvider is the resolved provider and its configuration; on an
// error, the CPU (the caller that matters, the gateway, has already stopped).
func activeProvider() (ProviderState, ProviderConfig) {
	st, err := InitProvider()
	providerMu.Lock()
	cfg := providerCfg
	providerMu.Unlock()
	if err != nil || st.Active == "" {
		st.Active = ProviderCPU
	}
	return st, cfg
}

func resolveProvider(get func(string) string, probe func(device int) error,
	info func(device int) (gpu, driver string)) (ProviderConfig, ProviderState, error) {
	cfg, err := ProviderConfigFromEnv(get)
	st := ProviderState{Requested: cfg.Provider, Active: ProviderCPU}
	if err != nil {
		return ProviderConfig{Provider: ProviderCPU}, st, err
	}
	if cfg.Provider == ProviderCPU {
		return cfg, st, nil
	}
	if err := probe(cfg.DeviceID); err != nil {
		if cfg.Provider == ProviderCUDA {
			return cfg, st, fmt.Errorf("%w: %s=cuda, but the CUDA execution provider cannot start on device %d: %v. "+
				"The GPU option needs an image built from build/gateway-gpu.Dockerfile (ONNX Runtime GPU, CUDA 12), an NVIDIA GPU with driver 525 or newer "+
				"and the NVIDIA container runtime; set %s=cpu (the default) or auto to run on the CPU",
				ErrProviderUnavailable, EnvProvider, cfg.DeviceID, strings.TrimRight(err.Error(), ". "), EnvProvider)
		}
		st.Fallback = err.Error()
		slog.Warn(EnvProvider+"=auto: the CUDA execution provider cannot start; the models run on the CPU",
			"cuda_device_id", cfg.DeviceID, "err", err)
		return cfg, st, nil
	}
	st.Active, st.DeviceID = ProviderCUDA, cfg.DeviceID
	st.GPU, st.Driver = info(cfg.DeviceID)
	st.CUDA = strings.TrimSpace(get("CUDA_VERSION"))
	return cfg, st, nil
}

// CurrentProvider is the resolved provider, with the ONNX Runtime version
// once a model has loaded it, for /readyz. It never loads the runtime itself.
func CurrentProvider() ProviderState {
	st, _ := activeProvider()
	st.ORT = loadedRuntimeVersion()
	return st
}

// BatchSize is the number of token windows per model run on the short path:
// INFERENCE_BATCH_SIZE, else DefaultCUDABatchSize on CUDA, else 8.
func BatchSize() int { return batchSizeFor(defaultBatchSize) }

// LongBatchSize is the windows per model run on the long path:
// INFERENCE_BATCH_SIZE, else DefaultCUDABatchSize on CUDA, else cpuDefault.
func LongBatchSize(cpuDefault int) int { return batchSizeFor(cpuDefault) }

func batchSizeFor(cpuDefault int) int {
	st, cfg := activeProvider()
	switch {
	case cfg.BatchSize > 0:
		return cfg.BatchSize
	case st.Active == ProviderCUDA:
		return DefaultCUDABatchSize
	}
	return cpuDefault
}

// ---------------------------------------------------------------------------
// The probe model: one Add node, y = x + x, float[1]. Hand-encoded ONNX
// (protobuf) so that no model file is needed to test a provider.

func probeModel() []byte {
	dim := pbBytes(1, pbVarint(1, 1))                      // Dimension{dim_value: 1}
	shape := pbBytes(2, pbBytes(1, dim))                   // TensorShapeProto{dim}
	tensor := pbBytes(1, append(pbVarint(1, 1), shape...)) // Tensor{elem_type: FLOAT, shape}
	valueInfo := func(name string) []byte {                // ValueInfoProto{name, type}
		return append(pbString(1, name), pbBytes(2, tensor)...) // TypeProto{tensor_type}
	}
	node := cat(pbString(1, "x"), pbString(1, "x"), pbString(2, "y"), pbString(4, "Add"))
	graph := cat(pbBytes(1, node), pbString(2, "provider_probe"), pbBytes(11, valueInfo("x")), pbBytes(12, valueInfo("y")))
	opset := pbVarint(2, 13)
	return cat(pbVarint(1, 7), pbBytes(7, graph), pbBytes(8, opset)) // ir_version 7, graph, opset_import
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func pbKey(field, wire int) []byte { return appendUvarint(nil, uint64(field<<3|wire)) }

func pbVarint(field int, v uint64) []byte { return appendUvarint(pbKey(field, 0), v) }

func pbBytes(field int, b []byte) []byte {
	return append(appendUvarint(pbKey(field, 2), uint64(len(b))), b...)
}

func pbString(field int, s string) []byte { return pbBytes(field, []byte(s)) }

func appendUvarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// ---------------------------------------------------------------------------
// GPU description (best effort, for logs, /readyz and doctor)

// nvidiaGPUInfo names the GPU and driver of a CUDA device: nvidia-smi when
// it is on PATH (the NVIDIA container runtime mounts it), else
// /proc/driver/nvidia. Empty strings when neither says.
func nvidiaGPUInfo(device int) (gpu, driver string) {
	if runtime.GOOS != "linux" {
		return "", ""
	}
	if smi, err := exec.LookPath("nvidia-smi"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, smi, "--query-gpu=name,driver_version", "--format=csv,noheader",
			"-i", strconv.Itoa(device)).Output()
		if err == nil {
			if g, d, ok := parseSMI(string(out)); ok {
				return g, d
			}
		}
	}
	return procGPUInfo("/proc/driver/nvidia", device)
}

// parseSMI reads "NVIDIA L4, 550.54.15".
func parseSMI(out string) (gpu, driver string, ok bool) {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	gpu, driver, ok = strings.Cut(line, ",")
	gpu, driver = strings.TrimSpace(gpu), strings.TrimSpace(driver)
	return gpu, driver, ok && gpu != ""
}

// procGPUInfo reads root/version ("NVRM version: NVIDIA UNIX x86_64 Kernel
// Module  550.54.15  ...") and root/gpus/<pci>/information ("Model: NVIDIA
// L4"). Devices are taken in PCI bus order, which is CUDA's order only with
// CUDA_DEVICE_ORDER=PCI_BUS_ID; on one-GPU hosts it is the same.
func procGPUInfo(root string, device int) (gpu, driver string) {
	if b, err := os.ReadFile(filepath.Join(root, "version")); err == nil {
		f := strings.Fields(string(b))
		for i, w := range f {
			if w == "Module" && i+1 < len(f) {
				driver = f[i+1]
				break
			}
		}
	}
	dirs, _ := filepath.Glob(filepath.Join(root, "gpus", "*", "information"))
	sort.Strings(dirs)
	if device < len(dirs) {
		if fh, err := os.Open(dirs[device]); err == nil {
			defer func() { _ = fh.Close() }()
			sc := bufio.NewScanner(fh)
			for sc.Scan() {
				if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.TrimSpace(k) == "Model" {
					gpu = strings.TrimSpace(v)
					break
				}
			}
		}
	}
	return gpu, driver
}

// GPUInfo is nvidiaGPUInfo for the doctor command, which does not load ONNX
// Runtime.
func GPUInfo(device int) (gpu, driver string) { return gpuInfo(device) }
