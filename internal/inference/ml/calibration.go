package ml

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/giaplee/guard-spec/internal/inference/fusion"
)

// Calibrations below are fitted by `go run -tags onnx ./cmd/calibrate fit` on
// the classifiers' validation splits (train/data/val.jsonl + val_hard.jsonl,
// 3,258 rows), never on eval/. Those splits also chose v1's threshold and
// early stopping, so L2 v1 looks a little better on them than on unseen data.

// CalibrationFile is the calibration of one classifier: the Platt scaling of
// its risk score and the logistic-regression combiners fitted with it, keyed
// by layer set ("l1,l2", "l1,l2,l3"). `cmd/calibrate fit -write` stores one
// as calibration.json next to the classifier; it overrides the built-in one.
type CalibrationFile struct {
	Model    string                   `json:"model"`
	FittedOn string                   `json:"fitted_on"`
	Platt    fusion.Calibration       `json:"platt"`
	LogReg   map[string]fusion.LogReg `json:"logreg,omitempty"`
}

// BuiltinCalibrations are the calibrations of the classifiers we ship.
var BuiltinCalibrations = map[string]CalibrationFile{
	// v2: fitted on val + val_hard + val_vi_variants (5,885 rows); the
	// combiners use the built-in L1 and L3 scalings, as at run time.
	"guardspec-classifier-v2": {
		Model:    "guardspec-classifier-v2",
		FittedOn: "train/data/val.jsonl + val_hard.jsonl + val_vi_variants.jsonl (5885 rows), 5-fold CV for the method choice",
		Platt:    fusion.Calibration{A: 0.9364, B: -0.5280},
		LogReg: map[string]fusion.LogReg{
			"l1,l2":    {W: [3]float64{0.6367, 0.9369, 0}, B: 0.4053},
			"l1,l2,l3": {W: [3]float64{0.5836, 0.8924, 0.5913}, B: 0.6526},
		},
	},
	"guardspec-classifier-v1": {
		Model:    "guardspec-classifier-v1",
		FittedOn: "train/data/val.jsonl + val_hard.jsonl (3258 rows), 5-fold CV for the method choice",
		Platt:    fusion.Calibration{A: 1.0687, B: -0.2110},
		LogReg: map[string]fusion.LogReg{
			"l1,l2":    {W: [3]float64{0.5777, 0.9337, 0}, B: 0.4423},
			"l1,l2,l3": {W: [3]float64{0.4897, 0.8928, 0.5913}, B: 0.6115},
		},
	},
	"guardspec-classifier-v0": {
		Model:    "guardspec-classifier-v0",
		FittedOn: "train/data/val.jsonl + val_hard.jsonl (3258 rows), 5-fold CV for the method choice",
		Platt:    fusion.Calibration{A: 0.7815, B: -1.4051},
		LogReg: map[string]fusion.LogReg{
			"l1,l2":    {W: [3]float64{1.1098, 1.0710, 0}, B: 0.8796},
			"l1,l2,l3": {W: [3]float64{0.9283, 1.0786, 0.8627}, B: 1.1240},
		},
	},
}

// DefaultL3Calibration is the Platt scaling of the L3 raw score
// sigmoid(margin / DefaultTemperature) for multilingual-e5-small and the
// built-in exemplar set.
var DefaultL3Calibration = fusion.Calibration{A: 3.2567, B: -0.9815}

// LayerKey names a layer set the way CalibrationFile.LogReg does.
func LayerKey(active [3]bool) string {
	var parts []string
	for i, on := range active {
		if on {
			parts = append(parts, "l"+string(rune('1'+i)))
		}
	}
	return strings.Join(parts, ",")
}

// calibrationFor is dir/calibration.json, else the built-in calibration for
// the model name; src is "" when there is none.
func calibrationFor(dir, name string) (cal CalibrationFile, src string) {
	if data, err := os.ReadFile(filepath.Join(dir, calibrationFile)); err == nil {
		var f CalibrationFile
		if err := json.Unmarshal(data, &f); err == nil && f.Platt.A != 0 {
			return f, filepath.Join(dir, calibrationFile)
		}
		slog.Warn("L2: ignoring unreadable calibration file", "dir", dir)
	}
	if c, ok := BuiltinCalibrations[name]; ok {
		return c, "built-in"
	}
	return CalibrationFile{Platt: fusion.Identity}, ""
}
