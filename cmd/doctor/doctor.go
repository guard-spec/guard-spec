// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/guard-spec/guard-spec/internal/onnx"
	"github.com/guard-spec/guard-spec/internal/version"
	"github.com/guard-spec/guard-spec/models"
)

// Status is the outcome of one check.
type Status string

// Check outcomes.
const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Exit codes.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// checkNames are the checks in the order they run.
var checkNames = []string{"database", "migrations", "models", "layers", "upstream", "security"}

func isCheckName(s string) bool {
	for _, n := range checkNames {
		if n == s {
			return true
		}
	}
	return false
}

// Options are the command-line settings.
type Options struct {
	// Manifest is the model manifest file; empty: the built-in copy.
	Manifest string
	// MigrationsDir holds the *.up.sql files; empty: the migration version
	// is reported without comparing it.
	MigrationsDir string
	Timeout       time.Duration
	Skip          map[string]bool
	JSON, Strict  bool
}

// Result is the outcome of one check.
type Result struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	// Hint says what to do; several lines are separated by "\n".
	Hint string `json:"hint,omitempty"`
}

// Summary counts the results by status.
type Summary struct {
	OK       int `json:"ok"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
}

// Report is the whole output, as printed by -json.
type Report struct {
	Version string   `json:"version"`
	Checks  []Result `json:"checks"`
	Summary Summary  `json:"summary"`
}

// doctor holds what the checks share.
type doctor struct {
	get      func(string) string
	opts     Options
	manifest *onnx.Manifest

	conn  *pgx.Conn // set when the database check connected
	dbErr bool      // the database check did not connect

	layers *layerReport // computed once, used by models and layers
}

// Run runs every check that is not skipped, prints the report and returns
// the exit code.
func Run(ctx context.Context, get func(string) string, opts Options, out io.Writer) int {
	rep := Collect(ctx, get, opts)
	if opts.JSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printText(out, rep)
	}
	return exitCode(rep, opts.Strict)
}

// Collect runs the checks and returns their results.
func Collect(ctx context.Context, get func(string) string, opts Options) Report {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	d := &doctor{get: get, opts: opts}
	defer func() {
		if d.conn != nil {
			_ = d.conn.Close(context.Background())
		}
	}()
	rep := Report{Version: version.String()}
	run := map[string]func(context.Context) Result{
		"database":   d.checkDatabase,
		"migrations": d.checkMigrations,
		"models":     d.checkModels,
		"layers":     d.checkLayers,
		"upstream":   d.checkUpstream,
		"security":   d.checkSecurity,
	}
	for _, name := range checkNames {
		var r Result
		if opts.Skip[name] {
			r = Result{Status: Skip, Detail: "skipped (-skip)"}
		} else {
			r = run[name](ctx)
		}
		r.Name = name
		r.Detail = oneLine(r.Detail)
		rep.Checks = append(rep.Checks, r)
		switch r.Status {
		case OK:
			rep.Summary.OK++
		case Warn:
			rep.Summary.Warnings++
		case Fail:
			rep.Summary.Failed++
		default:
			rep.Summary.Skipped++
		}
	}
	return rep
}

func exitCode(rep Report, strict bool) int {
	if rep.Summary.Failed > 0 || strict && rep.Summary.Warnings > 0 {
		return exitFail
	}
	return exitOK
}

var labels = map[Status]string{OK: "[ OK ]", Warn: "[WARN]", Fail: "[FAIL]", Skip: "[SKIP]"}

func printText(out io.Writer, rep Report) {
	_, _ = fmt.Fprintf(out, "guard-spec doctor %s\n\n", rep.Version)
	for _, r := range rep.Checks {
		_, _ = fmt.Fprintf(out, "%s %-11s %s\n", labels[r.Status], r.Name, r.Detail)
		if r.Hint != "" {
			for _, l := range strings.Split(r.Hint, "\n") {
				_, _ = fmt.Fprintf(out, "%19s%s\n", "", l)
			}
		}
	}
	s := rep.Summary
	_, _ = fmt.Fprintf(out, "\nsummary: %d ok, %d warnings, %d failed, %d skipped\n", s.OK, s.Warnings, s.Failed, s.Skipped)
}

// loadManifest reads -manifest, or the copy built into the binary.
func (d *doctor) loadManifest() (*onnx.Manifest, error) {
	if d.manifest != nil {
		return d.manifest, nil
	}
	var err error
	if d.opts.Manifest != "" {
		d.manifest, err = onnx.LoadManifest(d.opts.Manifest)
	} else {
		d.manifest, err = onnx.ParseManifest(models.Manifest)
	}
	return d.manifest, err
}

// devMode is GUARD_ENV=dev, read through the getter.
func (d *doctor) devMode() bool {
	return strings.EqualFold(strings.TrimSpace(d.get("GUARD_ENV")), "dev")
}

// oneLine folds the lines of a multi-line error (pgx lists every address it
// tried) into one.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ; ")), " ")
}

// plural is "1 warning", "2 warnings".
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
