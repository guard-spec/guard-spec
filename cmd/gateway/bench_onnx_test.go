//go:build onnx && cgo

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// benchStack loads the model layers like the gateway does. Models come from
// MODEL_DIR or ./models at the repository root, libonnxruntime from
// ONNXRUNTIME_LIB or .onnx/lib; the benchmark skips without them.
func benchStack(b testing.TB, layers [3]bool) *inference.Runner {
	b.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		b.Fatal(err)
	}
	if onnx.LibraryPath() == "" {
		for _, ext := range []string{"so", "dylib"} {
			if p := filepath.Join(root, ".onnx", "lib", "libonnxruntime."+ext); fileExists(p) {
				b.Setenv(onnx.EnvLibraryPath, p)
			}
		}
	}
	models := os.Getenv(ml.EnvModelDir)
	if models == "" {
		models = filepath.Join(root, "models")
	}
	cfg := ml.Config{ModelDir: models, Layers: layers, Fusion: "logreg"}
	l3, l3err := ml.ResolveL3Dir(cfg)
	if onnx.LibraryPath() == "" || ml.DefaultL2Dir(models) == "" ||
		l3err != nil || !fileExists(filepath.Join(l3, "model.onnx")) {
		b.Skip("models or libonnxruntime absent; see models/manifest.yaml and `make onnx-deps`")
	}
	s, err := ml.Build(context.Background(), cfg, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })
	if s.Degraded() {
		b.Fatalf("problems: %v", s.Problems)
	}
	return inference.NewRunnerWith(inference.FusedBackend{F: s.Fuser})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// BenchmarkGatewayHTTPML is BenchmarkGatewayHTTP with the model layers:
// L1+L2+L3 (the default with models) and L1+L2.
func BenchmarkGatewayHTTPML(b *testing.B) {
	b.Run("l1_l2_l3", func(b *testing.B) { runHTTPBench(b, benchStack(b, [3]bool{true, true, true})) })
	b.Run("l1_l2", func(b *testing.B) { runHTTPBench(b, benchStack(b, [3]bool{true, true, false})) })
}

// BenchmarkConversationWindowML is BenchmarkConversationWindow with
// L1+L2+L3.
func BenchmarkConversationWindowML(b *testing.B) {
	runWindowBench(b, benchStack(b, [3]bool{true, true, true}))
}
