// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"os"
	"testing"
	"time"
)

// The CI database is migrated to the newest migration: doctor connects as
// the application role and finds the version current.
func TestDatabaseAndMigrationsIntegration(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec?sslmode=disable"
	}
	env := map[string]string{"DATABASE_URL": url}
	res := collect(t, env, Options{Timeout: 5 * time.Second, MigrationsDir: "../../migrations", Skip: only("database", "migrations")})
	want(t, res["database"], OK, "connected to")
	want(t, res["migrations"], OK, "up to date")

	// A build that expects a newer migration reports it pending.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/999_future.up.sql", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	res = collect(t, env, Options{Timeout: 5 * time.Second, MigrationsDir: dir, Skip: only("database", "migrations")})
	want(t, res["migrations"], Fail, "migrations pending")
}
