// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// modelState is what doctor found for one ML layer.
type modelState int

const (
	modelNotRequested modelState = iota
	modelMissing                 // no model where the gateway looks
	modelVerified                // every file matches the manifest
	modelUnverified              // a model is there, but no manifest entry matches it
	modelBad                     // partial files or a wrong SHA-256
)

// layerModel is one ML layer (L2 or L3).
type layerModel struct {
	layer, kind string
	state       modelState
	dir         string
	ref         string // manifest name@version when matched
	detail      string // why missing or bad
}

// layerReport is the detector configuration and the state of its models.
type layerReport struct {
	cfgErr   error
	cfg      ml.Config
	required bool // DETECTOR_REQUIRE_ML outside dev: a missing layer is fatal
	ml       []*layerModel
	ortIssue string // ONNX Runtime library problem, "" when fine or not needed
}

// evaluateLayers resolves and verifies the ML models once.
func (d *doctor) evaluateLayers() *layerReport {
	if d.layers != nil {
		return d.layers
	}
	rep := &layerReport{}
	d.layers = rep
	cfg, err := ml.ConfigFromEnv(d.get)
	if err != nil {
		rep.cfgErr = err
		return rep
	}
	rep.cfg = cfg
	rep.required = cfg.RequireML && !d.devMode()
	man, merr := d.loadManifest()
	for _, l := range []struct {
		name, kind string
		idx        int
		resolve    func(ml.Config) (string, error)
	}{
		{"L2", "classifier", fusion.L2, ml.ResolveL2Dir},
		{"L3", "embedder", fusion.L3, ml.ResolveL3Dir},
	} {
		lm := &layerModel{layer: l.name, kind: l.kind}
		rep.ml = append(rep.ml, lm)
		if !cfg.Layers[l.idx] {
			continue
		}
		dir, err := l.resolve(cfg)
		if err != nil {
			lm.state, lm.detail = modelMissing, err.Error()
			continue
		}
		lm.dir = dir
		if merr != nil {
			lm.state, lm.detail = modelUnverified, "manifest: "+merr.Error()
			continue
		}
		verifyLayer(lm, man, filepath.Join(cfg.ModelDir, ml.ModelCacheSubdir))
	}
	if cfg.Layers[fusion.L2] || cfg.Layers[fusion.L3] {
		rep.ortIssue = ortProblem(d.get)
	}
	return rep
}

// verifyLayer finds the manifest entry of lm.dir and checks its files.
func verifyLayer(lm *layerModel, man *onnx.Manifest, cache string) {
	// <cache>/<name>/<version>: the entry is known from the path.
	if rel, err := filepath.Rel(cache, lm.dir); err == nil {
		if parts := strings.Split(filepath.ToSlash(rel), "/"); len(parts) == 2 && parts[0] != ".." {
			if mod, ok := man.FindVersion(parts[0], parts[1]); ok {
				lm.ref = mod.Ref()
				lm.state, lm.detail = checkFiles(mod, lm.dir)
				return
			}
		}
	}
	// Any other directory (L2_MODEL_DIR, the gateway-full image, the layout
	// from before versions): the entry of the same kind whose files are there
	// with the manifest sizes.
	var candidates []*onnx.ManifestModel
	for i := range man.Models {
		mod := &man.Models[i]
		if mod.Kind == lm.kind && sizesMatch(mod, lm.dir) {
			candidates = append(candidates, mod)
		}
	}
	var problems []string
	for _, mod := range candidates {
		state, detail := checkFiles(mod, lm.dir)
		if state == modelVerified {
			lm.ref, lm.state, lm.detail = mod.Ref(), state, ""
			return
		}
		problems = append(problems, mod.Ref()+": "+detail)
	}
	if len(problems) > 0 {
		lm.state, lm.detail = modelBad, strings.Join(problems, "; ")
		return
	}
	if _, err := os.Stat(filepath.Join(lm.dir, onnx.ConfigFile)); err != nil {
		lm.state, lm.detail = modelMissing, "no model in "+lm.dir
		return
	}
	lm.state, lm.detail = modelUnverified, lm.dir+" matches no model of the manifest; its files cannot be verified"
}

// sizesMatch reports whether every file of mod is in dir with its manifest size.
func sizesMatch(mod *onnx.ManifestModel, dir string) bool {
	for _, f := range mod.Files {
		if f.SkipIfAbsent(dir) {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, f.Dest))
		if err != nil || !fi.Mode().IsRegular() || (f.Size > 0 && fi.Size() != f.Size) {
			return false
		}
	}
	return true
}

// checkFiles verifies every file of mod in dir against the manifest.
func checkFiles(mod *onnx.ManifestModel, dir string) (modelState, string) {
	var missing, bad []string
	files := 0
	for _, f := range mod.Files {
		if f.SkipIfAbsent(dir) {
			continue // a GPU-only file (model_fp16.onnx) of a CPU install
		}
		files++
		err := onnx.VerifyFile(filepath.Join(dir, f.Dest), f)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrNotExist):
			missing = append(missing, f.Dest)
		default:
			bad = append(bad, fmt.Sprintf("%s: %v", f.Dest, err))
		}
	}
	switch {
	case len(missing) == files:
		return modelMissing, "no files in " + dir
	case len(bad) > 0:
		return modelBad, strings.Join(bad, "; ")
	case len(missing) > 0:
		return modelBad, "incomplete, missing " + strings.Join(missing, ", ")
	}
	return modelVerified, ""
}

// ortProblem says why the ONNX Runtime library cannot be found, or "".
func ortProblem(get func(string) string) string {
	if p := get(onnx.EnvLibraryPath); p != "" {
		if _, err := os.Stat(p); err != nil {
			return fmt.Sprintf("%s=%s: %v", onnx.EnvLibraryPath, p, errors.Unwrap(err))
		}
		return ""
	}
	for _, p := range []string{".onnx/lib/libonnxruntime.so", "/usr/local/lib/libonnxruntime.so", "/usr/lib/libonnxruntime.so",
		"/opt/homebrew/lib/libonnxruntime.dylib", "/usr/local/lib/libonnxruntime.dylib"} {
		if _, err := os.Stat(p); err == nil {
			return ""
		}
	}
	return onnx.EnvLibraryPath + " is not set and no libonnxruntime was found (the static L1-only build runs no model layer)"
}

func (d *doctor) checkModels(context.Context) Result {
	rep := d.evaluateLayers()
	if rep.cfgErr != nil {
		return Result{Status: Fail, Detail: "detector configuration: " + rep.cfgErr.Error()}
	}
	var ok, lines []string
	worst := OK
	raise := func(s Status) {
		if s == Fail || worst == OK {
			worst = s
		}
	}
	requested := 0
	for _, lm := range rep.ml {
		switch lm.state {
		case modelNotRequested:
			continue
		case modelVerified:
			ok = append(ok, fmt.Sprintf("%s %s", lm.layer, lm.ref))
		case modelMissing:
			if rep.required {
				raise(Fail)
			} else {
				raise(Warn)
			}
			lines = append(lines, fmt.Sprintf("%s missing: %s", lm.layer, lm.detail))
		case modelUnverified:
			raise(Warn)
			lines = append(lines, fmt.Sprintf("%s unverified: %s", lm.layer, lm.detail))
		case modelBad:
			raise(Fail)
			lines = append(lines, fmt.Sprintf("%s does not match the manifest: %s", lm.layer, lm.detail))
		}
		requested++
	}
	if requested == 0 {
		return Result{Status: OK, Detail: "no model layer requested (DETECTOR_LAYERS)"}
	}
	if worst == OK {
		return Result{Status: OK, Detail: "SHA-256 verified: " + strings.Join(ok, ", ")}
	}
	detail := strings.Join(lines, "; ")
	if len(ok) > 0 {
		detail += "; verified: " + strings.Join(ok, ", ")
	}
	hint := "pull and verify them: ./models pull -manifest manifest.yaml -dir $MODEL_DIR/cache (docs/models.md)"
	if worst == Fail && rep.required {
		hint += "\nDETECTOR_REQUIRE_ML=true: the gateway refuses to start without them"
	}
	return Result{Status: worst, Detail: detail, Hint: hint}
}

func (d *doctor) checkLayers(context.Context) Result {
	rep := d.evaluateLayers()
	if rep.cfgErr != nil {
		return Result{Status: Fail, Detail: "detector configuration: " + rep.cfgErr.Error()}
	}
	var parts, off []string
	if rep.cfg.Layers[fusion.L1] {
		parts = append(parts, "L1 on")
	}
	for _, lm := range rep.ml {
		switch {
		case lm.state == modelNotRequested:
			continue
		case lm.state == modelMissing || lm.state == modelBad:
			off = append(off, lm.layer)
			parts = append(parts, lm.layer+" off (no usable "+lm.kind+")")
		case rep.ortIssue != "":
			off = append(off, lm.layer)
			parts = append(parts, lm.layer+" off (no ONNX Runtime)")
		default:
			name := lm.ref
			if name == "" {
				name = lm.dir
			}
			parts = append(parts, fmt.Sprintf("%s on (%s)", lm.layer, name))
		}
	}
	detail := strings.Join(parts, ", ")
	if len(off) == 0 {
		return Result{Status: OK, Detail: detail}
	}
	status := Warn
	hint := "the gateway runs without " + strings.Join(off, ", ") + " and /readyz reports degraded"
	if rep.required {
		status = Fail
		hint = "DETECTOR_REQUIRE_ML=true: the gateway refuses to start without " + strings.Join(off, ", ")
	}
	if rep.ortIssue != "" {
		hint += "\n" + rep.ortIssue
	}
	return Result{Status: status, Detail: detail, Hint: hint}
}
