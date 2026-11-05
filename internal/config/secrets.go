// Package config holds the startup checks the services share.
//
// Outside development every service refuses to start with a secret that is
// empty, too short or publicly known (a value from this repository, its
// examples or a common default). Development mode is opted into explicitly with
// GUARD_ENV=dev, which the compose override file sets.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// EnvVar selects the deployment mode. Only the value "dev" relaxes the checks.
const EnvVar = "GUARD_ENV"

// Minimum lengths outside development.
const (
	MinSecretLen   = 32 // signing keys, such as JWT_SECRET
	MinPasswordLen = 12 // passwords for people and database roles
)

// devPrefix marks the throwaway values in docker-compose.override.yml and
// .env.example. Any value starting with it is treated as a known default.
const devPrefix = "dev-only-"

// knownDefaults are values that shipped in this repository or are common
// defaults. They are compared case-insensitively.
var knownDefaults = map[string]bool{
	"change-me-in-production": true,
	"change-on-first-login":   true,
	"changeme":                true,
	"change-me":               true,
	"secret":                  true,
	"password":                true,
	"admin":                   true,
	"postgres":                true,
	"ps":                      true,
	"guardspec_app":           true,
	"guardspec":               true,
	"test":                    true,
	"dev":                     true,
}

// DevMode reports whether GUARD_ENV=dev is set.
func DevMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(EnvVar)), "dev")
}

// IsKnownDefault reports whether v is a value nobody should rely on as a secret.
func IsKnownDefault(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	return knownDefaults[l] || strings.HasPrefix(l, devPrefix)
}

// Checker collects secret problems so that one startup error lists them all.
type Checker struct {
	problems []string
}

func (c *Checker) addf(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

// Secret checks a signing key or token that must be long and random.
func (c *Checker) Secret(name, value string) {
	switch {
	case value == "":
		c.addf("%s is not set; set %s to a random value of at least %d bytes (for example: openssl rand -hex 32)",
			name, name, MinSecretLen)
	case IsKnownDefault(value):
		c.addf("%s is a known default value; set %s to a random value of at least %d bytes (for example: openssl rand -hex 32)",
			name, name, MinSecretLen)
	case len(value) < MinSecretLen:
		c.addf("%s is too short (%d bytes); set %s to a random value of at least %d bytes (for example: openssl rand -hex 32)",
			name, len(value), name, MinSecretLen)
	}
}

// Password checks a password that must not be a default or short. An empty
// value is accepted, because the caller decides whether the password is needed.
func (c *Checker) Password(name, value string) {
	switch {
	case value == "":
	case IsKnownDefault(value):
		c.addf("%s is a known default value; set %s to a unique password of at least %d characters",
			name, name, MinPasswordLen)
	case len(value) < MinPasswordLen:
		c.addf("%s is too short; set %s to a unique password of at least %d characters",
			name, name, MinPasswordLen)
	}
}

// DatabaseURL checks the password the service will connect with: the one in the
// URL, or else PGPASSWORD or the password file, as pgx resolves them. An empty
// password is accepted because certificate or trust authentication needs none.
// A URL that does not parse is left for the connection to report.
func (c *Checker) DatabaseURL(name, url string) {
	cfg, err := pgconn.ParseConfig(url)
	if err != nil || cfg.Password == "" {
		return
	}
	switch {
	case IsKnownDefault(cfg.Password):
		c.addf("the database password in %s (or PGPASSWORD) is a known default value; "+
			"set GUARDSPEC_APP_PASSWORD (compose) or the password in %s to a unique value of at least %d characters",
			name, name, MinPasswordLen)
	case len(cfg.Password) < MinPasswordLen:
		c.addf("the database password in %s (or PGPASSWORD) is too short; "+
			"set GUARDSPEC_APP_PASSWORD (compose) or the password in %s to a unique value of at least %d characters",
			name, name, MinPasswordLen)
	}
}

// Err returns the problems found, or nil. With GUARD_ENV=dev the problems are
// logged as warnings and Err returns nil.
func (c *Checker) Err() error {
	if len(c.problems) == 0 {
		return nil
	}
	if DevMode() {
		for _, p := range c.problems {
			slog.Warn("insecure configuration accepted because "+EnvVar+"=dev", "problem", p)
		}
		return nil
	}
	return errors.New("refusing to start with insecure configuration:\n  - " +
		strings.Join(c.problems, "\n  - ") +
		"\n(for local development only, set " + EnvVar + "=dev to accept these values)")
}
