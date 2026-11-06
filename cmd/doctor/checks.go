// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/config"
)

func (d *doctor) checkDatabase(ctx context.Context) Result {
	d.dbErr = true
	raw := strings.TrimSpace(d.get("DATABASE_URL"))
	if raw == "" {
		return Result{Status: Fail, Detail: "DATABASE_URL is not set",
			Hint: "set DATABASE_URL to the application role's URL, such as postgres://guardspec_app@host:5432/guardspec?sslmode=require"}
	}
	cfg, err := pgx.ParseConfig(raw)
	if err != nil {
		// pgx's parse errors never echo the password.
		return Result{Status: Fail, Detail: "DATABASE_URL does not parse: " + err.Error()}
	}
	cfg.ConnectTimeout = d.opts.Timeout
	where := fmt.Sprintf("%s:%d/%s as %s", cfg.Host, cfg.Port, cfg.Database, cfg.User)
	ctx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()
	start := time.Now()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err == nil {
		if err = conn.Ping(ctx); err != nil {
			_ = conn.Close(context.Background())
		}
	}
	if err != nil {
		return Result{Status: Fail, Detail: "cannot reach " + where + ": " + err.Error(),
			Hint: "check the host, the network policy, the password (PGPASSWORD / GUARDSPEC_APP_PASSWORD) and sslmode"}
	}
	d.conn, d.dbErr = conn, false
	return Result{Status: OK, Detail: fmt.Sprintf("connected to %s (%dms)", where, time.Since(start).Milliseconds())}
}

var migrationFile = regexp.MustCompile(`^(\d+)_.*\.up\.sql$`)

// latestMigration is the highest version among dir's *.up.sql files.
func latestMigration(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var latest int64 = -1
	for _, e := range entries {
		m := migrationFile.FindStringSubmatch(e.Name())
		if m == nil || e.IsDir() {
			continue
		}
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err == nil && v > latest {
			latest = v
		}
	}
	if latest < 0 {
		return 0, fmt.Errorf("no *.up.sql files in %s", dir)
	}
	return latest, nil
}

func (d *doctor) checkMigrations(ctx context.Context) Result {
	if d.conn == nil {
		return Result{Status: Skip, Detail: "no database connection"}
	}
	ctx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()
	var ver int64
	var dirty bool
	err := d.conn.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations LIMIT 1`).Scan(&ver, &dirty)
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr) && pgErr.Code == "42P01":
		return Result{Status: Fail, Detail: "not migrated: no schema_migrations table",
			Hint: "run the migrations (migrations/ with golang-migrate, or the chart's migrations.enabled hook)"}
	case errors.As(err, &pgErr) && pgErr.Code == "42501":
		return Result{Status: Warn, Detail: "cannot read schema_migrations as this role: " + pgErr.Message,
			Hint: "run doctor with the owner role's DATABASE_URL to check the version"}
	case errors.Is(err, pgx.ErrNoRows):
		return Result{Status: Fail, Detail: "not migrated: schema_migrations is empty", Hint: "run the migrations"}
	case err != nil:
		return Result{Status: Fail, Detail: "reading schema_migrations: " + err.Error()}
	}
	if dirty {
		return Result{Status: Fail, Detail: fmt.Sprintf("version %d is dirty: a migration failed half-way", ver),
			Hint: "fix the database by hand, then `migrate force <version>` and run the migrations again"}
	}
	if d.opts.MigrationsDir == "" {
		return Result{Status: Warn, Detail: fmt.Sprintf("version %d (no migrations directory to compare with)", ver),
			Hint: "pass -migrations <dir> (the images ship /app/migrations)"}
	}
	latest, err := latestMigration(d.opts.MigrationsDir)
	if err != nil {
		return Result{Status: Warn, Detail: fmt.Sprintf("version %d; cannot read the migrations: %v", ver, err)}
	}
	switch {
	case ver < latest:
		return Result{Status: Fail, Detail: fmt.Sprintf("version %d, this build needs %d: migrations pending", ver, latest),
			Hint: "run the migrations before starting the services"}
	case ver > latest:
		return Result{Status: Warn, Detail: fmt.Sprintf("version %d is newer than this build's %d", ver, latest),
			Hint: "the database was migrated by a newer release; upgrade the services"}
	}
	return Result{Status: OK, Detail: fmt.Sprintf("version %d, up to date", ver)}
}

func (d *doctor) checkUpstream(ctx context.Context) Result {
	raw := strings.TrimSpace(d.get("UPSTREAM_LLM_URL"))
	if raw == "" {
		return Result{Status: Warn, Detail: "UPSTREAM_LLM_URL is not set: the gateway answers with stub responses",
			Hint: "set UPSTREAM_LLM_URL to an OpenAI-compatible base URL (named upstreams are configured per org)"}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Result{Status: Fail, Detail: "UPSTREAM_LLM_URL is not an http(s) URL"}
	}
	target := strings.TrimRight(raw, "/") + "/models"
	ctx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Result{Status: Fail, Detail: err.Error()}
	}
	if key := d.get("UPSTREAM_LLM_KEY"); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	client := &http.Client{Timeout: d.opts.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Status: Fail, Detail: "cannot reach " + redactURL(u) + ": " + unwrapURLError(err),
			Hint: "check DNS, the egress network policy and proxies"}
	}
	_ = resp.Body.Close()
	r := Result{Status: OK, Detail: fmt.Sprintf("%s reachable (GET /models: HTTP %d)", redactURL(u), resp.StatusCode)}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		r.Hint = "the upstream refused the key: check UPSTREAM_LLM_KEY"
	}
	return r
}

// redactURL drops user info from a URL for output.
func redactURL(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	return c.String()
}

// unwrapURLError keeps the cause, not the url.Error's echo of the URL.
func unwrapURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// securityFindings are problems (refused by the services outside dev) and
// warnings (hints).
type securityFindings struct {
	problems, warnings, notes []string
}

func (f *securityFindings) problem(format string, a ...any) {
	f.problems = append(f.problems, fmt.Sprintf(format, a...))
}

func (f *securityFindings) warn(format string, a ...any) {
	f.warnings = append(f.warnings, fmt.Sprintf(format, a...))
}

// secretProblem mirrors config.Checker.Secret; "" when the value is fine.
func secretProblem(name, v string) string {
	switch {
	case config.IsKnownDefault(v):
		return name + " is a known default value"
	case len(v) < config.MinSecretLen:
		return fmt.Sprintf("%s is too short (%d bytes, need %d)", name, len(v), config.MinSecretLen)
	}
	return ""
}

// passwordProblem mirrors config.Checker.Password.
func passwordProblem(name, v string) string {
	switch {
	case v == "":
		return ""
	case config.IsKnownDefault(v):
		return name + " is a known default value"
	case len(v) < config.MinPasswordLen:
		return fmt.Sprintf("%s is too short (need %d characters)", name, config.MinPasswordLen)
	}
	return ""
}

// dbPassword is the password in a postgres:// URL, else PGPASSWORD.
func dbPassword(raw string, get func(string) string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		if p, ok := u.User.Password(); ok {
			return p
		}
	}
	return get("PGPASSWORD")
}

// sslMode is the sslmode of a URL or key=value DSN, "" when not given.
func sslMode(raw string) string {
	if u, err := url.Parse(raw); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		return u.Query().Get("sslmode")
	}
	for _, kv := range strings.Fields(raw) {
		if v, ok := strings.CutPrefix(kv, "sslmode="); ok {
			return v
		}
	}
	return ""
}

// localHost reports a loopback or in-cluster host name, where plain http is usual.
func localHost(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" || strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".internal") || !strings.Contains(h, ".") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return false
}

func (d *doctor) checkSecurity(context.Context) Result {
	var f securityFindings
	dev := d.devMode()
	if dev {
		f.warn("GUARD_ENV=dev: weak and default secrets are accepted; never use it in production")
	}
	dbURL := d.get("DATABASE_URL")
	if p := passwordProblem("the database password (DATABASE_URL or PGPASSWORD)", dbPassword(dbURL, d.get)); p != "" {
		f.problem("%s", p)
	}
	if v := d.get("JWT_SECRET"); v != "" {
		if p := secretProblem("JWT_SECRET", v); p != "" {
			f.problem("%s", p)
		}
	} else {
		f.notes = append(f.notes, "JWT_SECRET not set here (control plane only)")
	}
	if p := passwordProblem("ADMIN_PASSWORD", d.get("ADMIN_PASSWORD")); p != "" {
		f.problem("%s", p)
	}
	if v := d.get("MFA_ENC_KEY"); v != "" {
		if _, err := auth.NewSecretBox(v); err != nil {
			f.problem("%v", err)
		}
	} else if d.get("JWT_SECRET") != "" {
		f.warn("MFA_ENC_KEY is not set: two-factor authentication cannot be turned on")
	}
	if !dev {
		if dbURL != "" {
			switch m := sslMode(dbURL); m {
			case "require", "verify-ca", "verify-full":
			case "":
				f.warn("DATABASE_URL has no sslmode (libpq's default, prefer, falls back to plain text): use sslmode=verify-full or require")
			default:
				f.warn("DATABASE_URL uses sslmode=%s: use verify-full or require", m)
			}
		}
		if u, err := url.Parse(d.get("UPSTREAM_LLM_URL")); err == nil && u.Scheme == "http" && !localHost(u.Hostname()) {
			f.warn("UPSTREAM_LLM_URL is plain http to %s: prompts and the key cross the network unencrypted", u.Hostname())
		}
		if u, err := url.Parse(d.get("PUBLIC_BASE_URL")); err == nil && u.Scheme == "http" && !localHost(u.Hostname()) {
			f.warn("PUBLIC_BASE_URL is plain http: serve the admin UI over TLS (Ingress or Route)")
		}
	}
	if b, _ := strconv.ParseBool(d.get("AUDIT_STORE_CONTENT")); b {
		f.warn("AUDIT_STORE_CONTENT=true: prompt and response content is stored in the audit log")
	}

	issues := append([]string{}, f.problems...)
	issues = append(issues, f.warnings...)
	hint := ""
	if len(issues) > 0 {
		hint = "- " + strings.Join(issues, "\n- ")
	}
	switch {
	case len(f.problems) > 0 && !dev:
		return Result{Status: Fail, Detail: plural(len(f.problems), "problem") + " the services refuse, " + plural(len(f.warnings), "warning"), Hint: hint}
	case len(issues) > 0:
		return Result{Status: Warn, Detail: plural(len(issues), "warning"), Hint: hint}
	}
	detail := "secrets set and strong, non-dev mode, TLS settings look right"
	if len(f.notes) > 0 {
		detail += "; " + strings.Join(f.notes, "; ")
	}
	return Result{Status: OK, Detail: detail}
}
