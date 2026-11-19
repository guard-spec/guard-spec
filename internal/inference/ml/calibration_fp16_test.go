// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guard-spec/guard-spec/internal/onnx"
)

// The FP16 block of calibration.json applies to model_fp16.onnx only; the
// INT8 model (the CPU default) keeps the top-level calibration.
func TestCalibrationForModelFile(t *testing.T) {
	base := CalibrationFile{Model: "m", L2UntrustedMax: 0.88,
		FP16: &CalibrationFile{L2UntrustedMax: 0.9}}
	base.Platt.A, base.Platt.B = 0.86, -0.25
	base.FP16.Platt.A, base.FP16.Platt.B = 0.9, -0.3

	got, fp16 := base.forModelFile(onnx.ModelInt8File)
	if fp16 || got.Platt.A != 0.86 || got.L2UntrustedMax != 0.88 || got.FP16 != nil {
		t.Fatalf("int8: %+v %v", got, fp16)
	}
	got, fp16 = base.forModelFile(onnx.ModelFP16File)
	if !fp16 || got.Platt.A != 0.9 || got.Platt.B != -0.3 || got.L2UntrustedMax != 0.9 || got.Model != "m" || got.FP16 != nil {
		t.Fatalf("fp16: %+v %v", got, fp16)
	}
	// The FP16 block takes the top-level long document rule unless it has its own.
	base.LongDoc = &LongDoc{MinWindows: 30, CorroborateL1: 0.75, MinL2: 0.95}
	if got, _ = base.forModelFile(onnx.ModelFP16File); got.LongDoc == nil || got.LongDoc.MinL2 != 0.95 {
		t.Fatalf("fp16 long_doc: %+v", got.LongDoc)
	}
	base.FP16.LongDoc = &LongDoc{MinWindows: 30, MinL2: 0.97}
	if got, _ = base.forModelFile(onnx.ModelFP16File); got.LongDoc.MinL2 != 0.97 {
		t.Fatalf("fp16 own long_doc: %+v", got.LongDoc)
	}
	base.LongDoc = nil
	// Without a block the FP16 file uses the top-level calibration.
	base.FP16 = nil
	if got, fp16 = base.forModelFile(onnx.ModelFP16File); fp16 || got.Platt.A != 0.86 {
		t.Fatalf("fp16 without block: %+v %v", got, fp16)
	}
}

// On the CPU a calibration.json with an FP16 block reads as before.
func TestCalibrationForCPUIgnoresFP16(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		onnx.ModelInt8File: "int8", onnx.ModelFP16File: "fp16",
		calibrationFile: `{"model":"x","platt":{"A":1,"B":0},"fp16":{"platt":{"A":2,"B":1}}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cal, src := calibrationFor(dir, "x")
	if cal.Platt.A != 1 || cal.FP16 != nil || src != filepath.Join(dir, calibrationFile) {
		t.Fatalf("%+v from %s", cal, src)
	}
}

// The built-in calibrations with an FP16 block (v8e, v8g): model_fp16.onnx gets the block's Platt and
// logistic regression, keeps the cap, and takes the top-level long document rule; model_int8.onnx gets the
// top level.
func TestBuiltinFP16Blocks(t *testing.T) {
	for _, name := range []string{"guardspec-classifier-v8e", "guardspec-classifier-v8g"} {
		c := BuiltinCalibrations[name]
		if c.FP16 == nil {
			t.Fatalf("%s: no fp16 block", name)
		}
		got, fp16 := c.forModelFile(onnx.ModelFP16File)
		if !fp16 || got.Platt != c.FP16.Platt || got.LogReg["l1,l2,l3"] != c.FP16.LogReg["l1,l2,l3"] ||
			got.L2UntrustedMax != 0.88 || got.LongDoc == nil || got.LongDoc.MinL2 != c.LongDoc.MinL2 ||
			got.LongDoc.MinWindows != c.LongDoc.MinWindows || got.Model != name {
			t.Errorf("%s fp16: %+v %v", name, got, fp16)
		}
		got, fp16 = c.forModelFile(onnx.ModelInt8File)
		if fp16 || got.Platt != c.Platt || got.FP16 != nil {
			t.Errorf("%s int8: %+v %v", name, got, fp16)
		}
	}
}
