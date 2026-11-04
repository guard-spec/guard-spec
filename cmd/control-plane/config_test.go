package main

import (
	"strings"
	"testing"
)

func TestConfigCheck(t *testing.T) {
	t.Setenv("PGPASSWORD", "")
	t.Setenv("PGPASSFILE", "/nonexistent")
	const db = "postgres://guardspec_app:Zq8vN3kL0pR7xW2m@localhost:5432/guardspec"
	const jwt = "9c1e7a3f5b2d4e6a8c0b1d3f5e7a9c2b"
	good := appConfig{DatabaseURL: db, JWTSecret: jwt, AdminEmail: "a@example.com", AdminPassword: "a long admin passphrase"}

	cases := []struct {
		name string
		mod  func(*appConfig)
		want string
	}{
		{"good", func(*appConfig) {}, ""},
		{"no database", func(c *appConfig) { c.DatabaseURL = "" }, "set DATABASE_URL"},
		{"no jwt", func(c *appConfig) { c.JWTSecret = "" }, "set JWT_SECRET"},
		{"default jwt", func(c *appConfig) { c.JWTSecret = "change-me-in-production" }, "JWT_SECRET is a known default"},
		{"default admin", func(c *appConfig) { c.AdminPassword = "change-on-first-login" }, "set ADMIN_PASSWORD"},
		{"no admin bootstrap", func(c *appConfig) { c.AdminEmail, c.AdminPassword = "", "" }, ""},
		{"dev mfa key", func(c *appConfig) { c.MFAEncKey = "ZGV2LW9ubHktaW5zZWN1cmUtbWZhLWtleS0wMDAwMDA=" }, "MFA_ENC_KEY is the development key"},
		{"random mfa key", func(c *appConfig) { c.MFAEncKey = "q5V0b2v8YH8b0M1n4e9mF2Wc7ZrT1kLpQxS3uA6dJ0E=" }, ""},
		{"public url with path", func(c *appConfig) { c.PublicBaseURL = "https://guard.example.com/x" }, "PUBLIC_BASE_URL"},
		{"public url", func(c *appConfig) { c.PublicBaseURL = "https://guard.example.com" }, ""},
		{"default db", func(c *appConfig) {
			c.DatabaseURL = "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec"
		}, "database password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GUARD_ENV", "")
			cfg := good
			tc.mod(&cfg)
			err := cfg.check()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("dev accepts defaults", func(t *testing.T) {
		t.Setenv("GUARD_ENV", "dev")
		cfg := appConfig{
			DatabaseURL:   "postgres://guardspec_app:guardspec_app@localhost:5432/guardspec",
			JWTSecret:     "change-me-in-production",
			AdminEmail:    "admin@localhost",
			AdminPassword: "change-on-first-login",
		}
		if err := cfg.check(); err != nil {
			t.Fatal(err)
		}
	})
}
