package config

import (
	"strings"
	"testing"
)

const strong = "3f9a1c7e5b2d4f6a8c0e1b3d5f7a9c2e" // 32 bytes, not a default

func TestCheckerRefusesDefaultsOutsideDev(t *testing.T) {
	t.Setenv(EnvVar, "")
	t.Setenv("PGPASSWORD", "")
	t.Setenv("PGPASSFILE", "/nonexistent")

	cases := []struct {
		name  string
		check func(*Checker)
		want  string // substring of the error; empty means no error
	}{
		{"jwt empty", func(c *Checker) { c.Secret("JWT_SECRET", "") }, "JWT_SECRET is not set"},
		{"jwt default", func(c *Checker) { c.Secret("JWT_SECRET", "change-me-in-production") }, "known default"},
		{"jwt dev value", func(c *Checker) { c.Secret("JWT_SECRET", "dev-only-jwt-secret-0123456789abcdef") }, "known default"},
		{"jwt short", func(c *Checker) { c.Secret("JWT_SECRET", "abc123") }, "too short"},
		{"jwt ok", func(c *Checker) { c.Secret("JWT_SECRET", strong) }, ""},
		{"admin default", func(c *Checker) { c.Password("ADMIN_PASSWORD", "change-on-first-login") }, "set ADMIN_PASSWORD"},
		{"admin short", func(c *Checker) { c.Password("ADMIN_PASSWORD", "hunter2") }, "too short"},
		{"admin empty", func(c *Checker) { c.Password("ADMIN_PASSWORD", "") }, ""},
		{"admin ok", func(c *Checker) { c.Password("ADMIN_PASSWORD", "correct horse battery") }, ""},
		{"db default", func(c *Checker) {
			c.DatabaseURL("DATABASE_URL", "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec")
		}, "known default"},
		{"db short", func(c *Checker) {
			c.DatabaseURL("DATABASE_URL", "postgres://guardspec_app:abc@localhost:5432/guardspec")
		}, "too short"},
		{"db ok", func(c *Checker) {
			c.DatabaseURL("DATABASE_URL", "postgres://guardspec_app:"+strong+"@localhost:5432/guardspec")
		}, ""},
		{"db no password", func(c *Checker) {
			c.DatabaseURL("DATABASE_URL", "postgres://guardspec_app@localhost:5432/guardspec")
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Checker
			tc.check(&c)
			err := c.Err()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), EnvVar+"=dev") {
				t.Errorf("error does not mention the dev escape hatch: %v", err)
			}
		})
	}
}

func TestCheckerReadsPGPASSWORD(t *testing.T) {
	t.Setenv(EnvVar, "")
	t.Setenv("PGPASSWORD", "guardspec_app")
	var c Checker
	c.DatabaseURL("DATABASE_URL", "postgres://guardspec_app@localhost:5432/guardspec")
	if err := c.Err(); err == nil {
		t.Fatal("default PGPASSWORD was accepted")
	}
}

func TestCheckerAcceptsDefaultsInDev(t *testing.T) {
	t.Setenv(EnvVar, "dev")
	var c Checker
	c.Secret("JWT_SECRET", "change-me-in-production")
	c.Password("ADMIN_PASSWORD", "change-on-first-login")
	if err := c.Err(); err != nil {
		t.Fatalf("dev mode refused defaults: %v", err)
	}
}

func TestDevModeIsExplicit(t *testing.T) {
	for _, v := range []string{"", "prod", "production", "development", "1", "true"} {
		t.Setenv(EnvVar, v)
		if DevMode() {
			t.Errorf("%s=%q enabled dev mode", EnvVar, v)
		}
	}
	t.Setenv(EnvVar, "DEV")
	if !DevMode() {
		t.Error("GUARD_ENV=DEV did not enable dev mode")
	}
}
