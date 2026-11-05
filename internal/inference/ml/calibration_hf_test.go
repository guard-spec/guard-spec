// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// train/hf/calibration.json ships with the published classifier and is baked
// into the gateway-full image, where it overrides the built-in calibration. It
// must stay identical to the built-in one.
func TestHFCalibrationMatchesBuiltin(t *testing.T) {
	path := filepath.Join("..", "..", "..", "train", "hf", calibrationFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got CalibrationFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := BuiltinCalibrations["guardspec-classifier-v3b"]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s differs from BuiltinCalibrations[v3b]:\n got  %+v\n want %+v", path, got, want)
	}
	// The loader reads it the same way.
	cal, src := calibrationFor(filepath.Dir(path), "guardspec-classifier-v3b")
	if src != path || !reflect.DeepEqual(cal, want) {
		t.Fatalf("calibrationFor = %+v from %q", cal, src)
	}
}
