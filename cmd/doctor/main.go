// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Command doctor checks a Guard Spec installation from the inside: run it in
// the gateway or control-plane container (both images ship it as
// /app/doctor), with the same environment as the service.
//
//	doctor [-json] [-strict] [-skip upstream,...] [-timeout 5s]
//	       [-manifest manifest.yaml] [-migrations migrations]
//	doctor copy-migrations DEST [SRC]   (copy the image's *.sql migrations)
//
// Checks, in order:
//
//	database    DATABASE_URL is set and the server answers (PGPASSWORD as pgx reads it)
//	migrations  schema_migrations is clean and at the newest migration in -migrations
//	models      the model files of the requested ML layers match the manifest's SHA-256
//	layers      which detection layers (L1, L2, L3) the gateway would load
//	upstream    UPSTREAM_LLM_URL answers HTTP
//	security    secrets set and strong, GUARD_ENV not dev, TLS hints
//	secrets     where the secret settings come from (env, file, Vault), that
//	            the files and Vault references read, and the mutual TLS files
//	encryption  stored content is encrypted: the KEK works, every data key's
//	            KEK is configured, no content in the clear
//	advisories  no published security advisory affects this version (GitHub;
//	            -skip advisories without internet access)
//
// Each check prints OK, WARN, FAIL or SKIP with a short detail and, for
// problems, a hint. Exit codes:
//
//	0  no check failed (warnings are allowed)
//	1  at least one check failed (with -strict, a warning counts as a failure)
//	2  usage error
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/guard-spec/guard-spec/internal/version"
)

func main() {
	if len(os.Args) > 1 && version.IsFlag(os.Args[1]) {
		fmt.Println("doctor", version.String())
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "copy-migrations" {
		os.Exit(copyMigrations(os.Args[2:], os.Stdout, os.Stderr))
	}
	opts, err := parseFlags(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(exitUsage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(Run(ctx, os.Getenv, opts, os.Stdout))
}

// parseFlags reads the command line. Defaults that depend on the working
// directory (manifest, migrations) are resolved here.
func parseFlags(args []string, errOut io.Writer) (Options, error) {
	var o Options
	var skip string
	fset := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fset.SetOutput(errOut)
	fset.StringVar(&o.Manifest, "manifest", "", "model manifest (default: ./manifest.yaml, else models/manifest.yaml, else the built-in copy)")
	fset.StringVar(&o.MigrationsDir, "migrations", "", "migrations directory to compare the database with (default: ./migrations when present)")
	fset.DurationVar(&o.Timeout, "timeout", 5*time.Second, "timeout of each network check")
	fset.StringVar(&skip, "skip", "", "comma-separated checks to skip: "+strings.Join(checkNames, ","))
	fset.BoolVar(&o.JSON, "json", false, "print the result as JSON")
	fset.BoolVar(&o.Strict, "strict", false, "exit 1 on warnings too")
	fset.Usage = func() {
		_, _ = fmt.Fprintln(errOut, `usage: doctor [flags]

Checks the installation with the service's environment (DATABASE_URL,
MODEL_DIR, DETECTOR_LAYERS, UPSTREAM_LLM_URL, GUARD_ENV, ...).

checks: `+strings.Join(checkNames, ", ")+`

exit codes: 0 no failure (warnings allowed), 1 a check failed (or warned,
with -strict), 2 usage error

flags:`)
		fset.PrintDefaults()
	}
	if err := fset.Parse(args); err != nil {
		return o, err
	}
	fset.Visit(func(f *flag.Flag) { o.ManifestFlag = o.ManifestFlag || f.Name == "manifest" })
	if fset.NArg() > 0 {
		fset.Usage()
		return o, fmt.Errorf("unexpected argument %q", fset.Arg(0))
	}
	if o.Timeout <= 0 {
		return o, errors.New("-timeout must be positive")
	}
	o.Skip = map[string]bool{}
	for _, s := range strings.Split(skip, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if !isCheckName(s) {
			return o, fmt.Errorf("-skip: unknown check %q (have %s)", s, strings.Join(checkNames, ", "))
		}
		o.Skip[s] = true
	}
	if o.Manifest == "" {
		for _, p := range []string{"manifest.yaml", "models/manifest.yaml"} {
			if fileExists(p) {
				o.Manifest = p
				break
			}
		}
	}
	if o.MigrationsDir == "" {
		if fi, err := os.Stat("migrations"); err == nil && fi.IsDir() {
			o.MigrationsDir = "migrations"
		}
	}
	return o, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
