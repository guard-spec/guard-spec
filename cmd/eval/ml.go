package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/guard-spec/guard-spec/internal/evalset"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
)

// mlDetector is the gateway's detector with the model layers (L2, L3) as
// configured by the DETECTOR_* variables; it needs a binary built with
// -tags onnx and the model files.
const mlDetector = "fusion-ml"

// newMLDetector builds the fusion-ml detector. Its report name carries the
// layers, the fusion method and the cascade, so a baseline is only compared
// with the same configuration.
func newMLDetector(layers string, cascade bool, method string) (evalset.Detector, string, error) {
	cfg, err := ml.ConfigFromEnv(os.Getenv)
	if err != nil {
		return nil, "", err
	}
	if layers != "" {
		if cfg.Layers, err = ml.ParseLayers(layers); err != nil {
			return nil, "", err
		}
	}
	if cascade && cfg.Cascade == nil {
		c := ml.DefaultCascade
		cfg.Cascade = &c
	}
	if method != "" {
		cfg.Fusion = method
	}
	stack, err := ml.Build(context.Background(), cfg, nil)
	if err != nil {
		return nil, "", err
	}
	if stack.Degraded() {
		_ = stack.Close()
		return nil, "", errors.New("model layers unavailable:\n  " + strings.Join(stack.Problems, "\n  "))
	}
	name := mlDetector + ":" + ml.LayerKey(stack.Active) + "/" + stack.Fusion
	if cfg.Cascade != nil {
		name += "/cascade"
	}
	r := inference.NewRunnerWith(inference.FusedBackend{F: stack.Fuser})
	return evalset.RunnerDetector{Runner: r}, name, nil
}
