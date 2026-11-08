// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// copyMigrations is the "copy-migrations DEST [SRC]" subcommand: it copies
// the *.sql files of SRC (default: migrations next to the working directory,
// /app/migrations in the images) into DEST and lists them. The Helm chart's
// migration job uses it to hand the image's migrations to the migrate
// container; the images have no shell or cp.
func copyMigrations(args []string, out, errOut io.Writer) int {
	if len(args) < 1 || len(args) > 2 {
		_, _ = fmt.Fprintln(errOut, "usage: doctor copy-migrations DEST [SRC]")
		return exitUsage
	}
	dst, src := args[0], "migrations"
	if len(args) == 2 {
		src = args[1]
	}
	files, err := filepath.Glob(filepath.Join(src, "*.sql"))
	if err != nil || len(files) == 0 {
		_, _ = fmt.Fprintf(errOut, "copy-migrations: no *.sql files in %s\n", src)
		return 1
	}
	sort.Strings(files)
	for _, f := range files {
		if err := copyFile(f, filepath.Join(dst, filepath.Base(f))); err != nil {
			_, _ = fmt.Fprintln(errOut, "copy-migrations:", err)
			return 1
		}
		_, _ = fmt.Fprintln(out, filepath.Base(f))
	}
	return 0
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
