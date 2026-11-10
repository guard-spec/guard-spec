package ml

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// Calibrations below are fitted by `go run -tags onnx ./cmd/calibrate fit` on
// each classifier's validation splits (see FittedOn), never on eval/ and never
// on the hold-out splits. Those splits also chose each model's epoch and
// threshold, so the L2 layer looks a little better on them than on unseen data.

// CalibrationFile is the calibration of one classifier: the Platt scaling of
// its risk score and the logistic-regression combiners fitted with it, keyed
// by layer set ("l1,l2", "l1,l2,l3"). `cmd/calibrate fit -write` stores one
// as calibration.json next to the classifier; it overrides the built-in one.
type CalibrationFile struct {
	Model    string                   `json:"model"`
	FittedOn string                   `json:"fitted_on"`
	Platt    fusion.Calibration       `json:"platt"`
	LogReg   map[string]fusion.LogReg `json:"logreg,omitempty"`
	// L2UntrustedMax caps the classifier's calibrated score on untrusted
	// content (tool results and documents, on the short and the long path):
	// above it L2 alone cannot block, L1 or L3 must add lift (CapL2). 0 or
	// absent: no cap, which is how every built-in calibration but v5's and the
	// shipped v3b file behave. `cmd/calibrate fit` derives it from the
	// combiners (see untrustedMax there).
	L2UntrustedMax float64 `json:"l2_untrusted_max,omitempty"`
}

// BuiltinCalibrations are the calibrations of the classifiers we ship.
var BuiltinCalibrations = map[string]CalibrationFile{
	// v5 (a shadow candidate; v3b stays the default): the calibration.json
	// published with the model, byte for byte. Fitted on the v4 validation
	// splits plus the v5 validation rows (12,775 rows; the owner-supplied
	// and OTP/KYC rows are not in this repository). L2UntrustedMax caps the
	// classifier on tool results and documents (see CapL2); cmd/calibrate fit
	// derived it, it was not tuned on eval/.
	"guardspec-classifier-v5": {
		Model:    "guardspec-classifier-v5",
		FittedOn: "v4-A build val.jsonl + val_hard.jsonl + val_vi_variants.jsonl + val_v3.jsonl + val_v4.jsonl, with the owner-supplied and OTP/KYC validation rows, plus v5_val.jsonl + val_v5.jsonl of the v5 build (12775 rows), 2026-11-10",
		Platt:    fusion.Calibration{A: 0.8489312515915471, B: -0.11755286323468132},
		LogReg: map[string]fusion.LogReg{
			"l1,l2":    {W: [3]float64{0.4947140541685473, 0.9370249166895036, 0}, B: 0.4440996363676115},
			"l1,l2,l3": {W: [3]float64{0.4747397791899296, 0.9043821900309187, 0.3988532867214517}, B: 0.6362707521682777},
		},
		L2UntrustedMax: 0.88,
	},
	// v4 (a candidate; v3b stays the default): fitted on the v4 validation
	// splits (val + val_hard + val_vi_variants + val_v3 + val_v4) plus the
	// owner-supplied and OTP/KYC rows that the group hash sends to validation
	// (8,342 rows; those external rows are not in this repository).
	"guardspec-classifier-v4": {
		Model:    "guardspec-classifier-v4",
		FittedOn: "train/data/val.jsonl + val_hard.jsonl + val_vi_variants.jsonl + val_v3.jsonl + val_v4.jsonl, with the owner-supplied and OTP/KYC validation rows (8342 rows), 5-fold CV for the method choice",
		Platt:    fusion.Calibration{A: 0.8444, B: -0.6348},
		LogReg: map[string]fusion.LogReg{
			"l1,l2":    {W: [3]float64{0.6185, 0.9375, 0}, B: 0.4156},
			"l1,l2,l3": {W: [3]float64{0.5746, 0.8915, 0.5591}, B: 0.6783},
		},
	},
	// v3b (the default): fitted on val + val_hard + val_vi_variants + val_v3
	// plus the owner-supplied and OTP/KYC rows that the group hash sends to
	// validation (7,572 rows; those external rows are not in this repository).
	"guardspec-classifier-v3b": {
		Model:    "guardspec-classifier-v3b",
		FittedOn: "train/data/val.jsonl + val_hard.jsonl + val_vi_variants.jsonl + val_v3.jsonl, with the owner-supplied and OTP/KYC validation rows (7572 rows), 5-fold CV for the method choice",
		Platt:    fusion.Calibration{A: 0.9731, B: 0.1567},
		LogReg: map[string]fusion.LogReg{
			"l1,l2":    {W: [3]float64{0.4887, 0.9473, 0}, B: 0.3963},
			"l1,l2,l3": {W: [3]float64{0.4582, 0.9094, 0.2769}, B: 0.4955},
		},
	},
	// v3: never shipped (failed the eval set); kept for L2_MODEL_DIR use.
	// Fitted on val + val_hard + val_vi_variants + val_v3 (7,494 rows;
	// never val_v3_holdout or val_realistic_holdout); the combiners use the
	// built-in L1 and L3 scalings, as at run time.
	"guardspec-classifier-v3": {
		Model:    "guardspec-classifier-v3",
		FittedOn: "train/data/val.jsonl + val_hard.jsonl + val_vi_variants.jsonl + val_v3.jsonl (7494 rows), 5-fold CV for the method choice",
		Platt:    fusion.Calibration{A: 0.9853, B: 0.3199},
		LogReg: map[string]fusion.LogReg{
			"l1,l2":    {W: [3]float64{0.6242, 0.9610, 0}, B: 0.4544},
			"l1,l2,l3": {W: [3]float64{0.6047, 0.9279, 0.2477}, B: 0.5491},
		},
	},
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
