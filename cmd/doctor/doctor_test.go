// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeModel is a model of the test manifest: dest name -> content.
type fakeModel struct {
	name, kind string
	files      map[string]string
}

var (
	testClassifier = fakeModel{"testclf", "classifier", map[string]string{
		"model_int8.onnx": "classifier weights", "tokenizer.json": `{"t":1}`, "config.json": `{"c":1}`}}
	testEmbedder = fakeModel{"testemb", "embedder", map[string]string{
		"model.onnx": "embedder weights", "tokenizer.json": `{"t":2}`, "config.json": `{"c":2}`}}
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// writeManifest writes a manifest with both test models and returns its path.
func writeManifest(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("models:\n")
	for _, m := range []fakeModel{testClassifier, testEmbedder} {
		fmt.Fprintf(&b, "  - name: %s\n    version: v1\n    recommended: true\n    kind: %s\n", m.name, m.kind)
		fmt.Fprintf(&b, "    repo: example/%s\n    revision: %s\n    license: Apache-2.0\n    files:\n", m.name, strings.Repeat("a", 40))
		for dest, content := range m.files {
			fmt.Fprintf(&b, "      - {src: %s, dest: %s, size: %d, sha256: %s}\n", dest, dest, len(content), sha(content))
		}
	}
	p := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// install writes the model's files into dir.
func install(t *testing.T, m fakeModel, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for dest, content := range m.files {
		if err := os.WriteFile(filepath.Join(dir, dest), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// modelEnv is an environment where L2 and L3 name the test models under modelDir.
func modelEnv(t *testing.T, modelDir string) map[string]string {
	t.Helper()
	ort := filepath.Join(t.TempDir(), "libonnxruntime.so")
	if err := os.WriteFile(ort, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"MODEL_DIR":       modelDir,
		"L2_MODEL":        "testclf@v1",
		"L3_MODEL":        "testemb@v1",
		"DETECTOR_LAYERS": "l1,l2,l3",
		"ONNXRUNTIME_LIB": ort,
	}
}

func getter(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

// only runs the named checks.
func only(names ...string) map[string]bool {
	skip := map[string]bool{}
	for _, n := range checkNames {
		skip[n] = true
	}
	for _, n := range names {
		delete(skip, n)
	}
	return skip
}

func collect(t *testing.T, env map[string]string, opts Options) map[string]Result {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	rep := Collect(context.Background(), getter(env), opts)
	out := map[string]Result{}
	for _, r := range rep.Checks {
		out[r.Name] = r
	}
	return out
}

func want(t *testing.T, r Result, s Status, substr string) {
	t.Helper()
	if r.Status != s {
		t.Errorf("%s: status %s, want %s (%s; %s)", r.Name, r.Status, s, r.Detail, r.Hint)
	}
	if substr != "" && !strings.Contains(r.Detail+"\n"+r.Hint, substr) {
		t.Errorf("%s: %q does not mention %q", r.Name, r.Detail+"\n"+r.Hint, substr)
	}
}

func TestModelsVerified(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	install(t, testClassifier, filepath.Join(dir, "cache", "testclf", "v1"))
	install(t, testEmbedder, filepath.Join(dir, "cache", "testemb", "v1"))
	res := collect(t, modelEnv(t, dir), Options{Manifest: man, Skip: only("models", "layers")})
	want(t, res["models"], OK, "testclf@v1")
	want(t, res["layers"], OK, "L3 on (testemb@v1)")
}

// A directory outside the cache, like the gateway-full image's
// L2_MODEL_DIR, is matched to its manifest entry by its files.
func TestModelsExplicitDir(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	l2 := filepath.Join(dir, "local", "my-classifier")
	install(t, testClassifier, l2)
	env := modelEnv(t, dir)
	delete(env, "L2_MODEL")
	env["L2_MODEL_DIR"] = l2
	env["DETECTOR_LAYERS"] = "l1,l2"
	res := collect(t, env, Options{Manifest: man, Skip: only("models", "layers")})
	want(t, res["models"], OK, "L2 testclf@v1")
	want(t, res["layers"], OK, "L2 on (testclf@v1)")
}

func TestModelMissing(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	install(t, testClassifier, filepath.Join(dir, "cache", "testclf", "v1"))
	env := modelEnv(t, dir) // no embedder installed
	res := collect(t, env, Options{Manifest: man, Skip: only("models", "layers")})
	want(t, res["models"], Warn, "L3 missing")
	want(t, res["layers"], Warn, "L3 off")

	// DETECTOR_REQUIRE_ML=true: the gateway would refuse to start.
	env["DETECTOR_REQUIRE_ML"] = "true"
	res = collect(t, env, Options{Manifest: man, Skip: only("models", "layers")})
	want(t, res["models"], Fail, "L3 missing")
	want(t, res["layers"], Fail, "refuses to start")

	// ... except in dev mode, where the gateway only warns.
	env["GUARD_ENV"] = "dev"
	res = collect(t, env, Options{Manifest: man, Skip: only("models", "layers")})
	want(t, res["models"], Warn, "")
}

func TestModelWrongSHA256(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	l2 := filepath.Join(dir, "cache", "testclf", "v1")
	install(t, testClassifier, l2)
	install(t, testEmbedder, filepath.Join(dir, "cache", "testemb", "v1"))
	// Same size, other content: only the digest can tell.
	bad := strings.Repeat("x", len(testClassifier.files["model_int8.onnx"]))
	if err := os.WriteFile(filepath.Join(l2, "model_int8.onnx"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	res := collect(t, modelEnv(t, dir), Options{Manifest: man, Skip: only("models", "layers")})
	want(t, res["models"], Fail, "model_int8.onnx")
	want(t, res["models"], Fail, "verified: L3 testemb@v1")
	want(t, res["layers"], Warn, "L2 off")
}

func TestModelIncomplete(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	l2 := filepath.Join(dir, "cache", "testclf", "v1")
	install(t, testClassifier, l2)
	if err := os.Remove(filepath.Join(l2, "tokenizer.json")); err != nil {
		t.Fatal(err)
	}
	env := modelEnv(t, dir)
	env["DETECTOR_LAYERS"] = "l1,l2"
	res := collect(t, env, Options{Manifest: man, Skip: only("models")})
	want(t, res["models"], Fail, "incomplete, missing tokenizer.json")
}

func TestOnlyL1(t *testing.T) {
	res := collect(t, map[string]string{"DETECTOR_LAYERS": "l1"}, Options{Skip: only("models", "layers")})
	want(t, res["models"], OK, "no model layer requested")
	want(t, res["layers"], OK, "L1 on")
}

func TestBadDetectorConfig(t *testing.T) {
	res := collect(t, map[string]string{"DETECTOR_LAYERS": "l9"}, Options{Skip: only("models", "layers")})
	want(t, res["models"], Fail, "unknown layer")
	want(t, res["layers"], Fail, "unknown layer")
}

func TestMissingONNXRuntime(t *testing.T) {
	man, dir := writeManifest(t), t.TempDir()
	install(t, testClassifier, filepath.Join(dir, "cache", "testclf", "v1"))
	env := modelEnv(t, dir)
	env["DETECTOR_LAYERS"] = "l1,l2"
	env["ONNXRUNTIME_LIB"] = filepath.Join(dir, "absent.so")
	res := collect(t, env, Options{Manifest: man, Skip: only("layers")})
	want(t, res["layers"], Warn, "no ONNX Runtime")
}

// closedAddr is a localhost address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestDatabaseUnreachable(t *testing.T) {
	env := map[string]string{"DATABASE_URL": "postgres://guardspec_app:s3cret-password-123@" + closedAddr(t) + "/guardspec?sslmode=disable"}
	start := time.Now()
	res := collect(t, env, Options{Timeout: 2 * time.Second, Skip: only("database", "migrations")})
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	want(t, res["database"], Fail, "cannot reach")
	want(t, res["migrations"], Skip, "no database connection")
	if strings.Contains(res["database"].Detail, "s3cret") {
		t.Errorf("the password leaked: %s", res["database"].Detail)
	}
}

func TestDatabaseUnset(t *testing.T) {
	res := collect(t, map[string]string{}, Options{Skip: only("database", "migrations")})
	want(t, res["database"], Fail, "DATABASE_URL is not set")
	want(t, res["migrations"], Skip, "")
}

func TestLatestMigration(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"001_a.up.sql", "001_a.down.sql", "012_b.up.sql", "007_c.up.sql", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := latestMigration(dir); err != nil || v != 12 {
		t.Fatalf("got %d, %v; want 12", v, err)
	}
	if _, err := latestMigration(t.TempDir()); err == nil {
		t.Fatal("empty directory: no error")
	}
	// The repository's own migrations parse.
	if v, err := latestMigration("../../migrations"); err != nil || v < 16 {
		t.Fatalf("repository migrations: %d, %v", v, err)
	}
}

func TestUpstream(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer srv.Close()
	res := collect(t, map[string]string{"UPSTREAM_LLM_URL": srv.URL + "/v1/", "UPSTREAM_LLM_KEY": "k"}, Options{Skip: only("upstream")})
	want(t, res["upstream"], OK, "HTTP 200")
	if gotPath != "/v1/models" || gotAuth != "Bearer k" {
		t.Errorf("request %s with %q", gotPath, gotAuth)
	}

	res = collect(t, map[string]string{"UPSTREAM_LLM_URL": "http://" + closedAddr(t) + "/v1"}, Options{Skip: only("upstream")})
	want(t, res["upstream"], Fail, "cannot reach")

	res = collect(t, map[string]string{}, Options{Skip: only("upstream")})
	want(t, res["upstream"], Warn, "stub responses")

	res = collect(t, map[string]string{"UPSTREAM_LLM_URL": "ftp://x"}, Options{Skip: only("upstream")})
	want(t, res["upstream"], Fail, "not an http(s) URL")
}

func TestSecurity(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	good := map[string]string{
		"DATABASE_URL":     "postgres://guardspec_app@db:5432/guardspec?sslmode=verify-full",
		"PGPASSWORD":       "a-long-unique-db-password",
		"JWT_SECRET":       strings.Repeat("k", 40),
		"MFA_ENC_KEY":      key,
		"UPSTREAM_LLM_URL": "https://api.example.com/v1",
		"PUBLIC_BASE_URL":  "https://guard.example.com",
	}
	clone := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	sec := func(env map[string]string) Result {
		return collect(t, env, Options{Skip: only("security")})["security"]
	}

	want(t, sec(good), OK, "")
	want(t, sec(clone(map[string]string{"JWT_SECRET": "change-me"})), Fail, "JWT_SECRET is a known default")
	want(t, sec(clone(map[string]string{"PGPASSWORD": "short"})), Fail, "database password")
	want(t, sec(clone(map[string]string{"MFA_ENC_KEY": "bm90IDMyIGJ5dGVz"})), Fail, "MFA_ENC_KEY")
	want(t, sec(clone(map[string]string{"MFA_ENC_KEY": ""})), Warn, "two-factor")
	want(t, sec(clone(map[string]string{"DATABASE_URL": "postgres://guardspec_app@db/guardspec?sslmode=disable"})), Warn, "sslmode=disable")
	want(t, sec(clone(map[string]string{"DATABASE_URL": "postgres://guardspec_app@db/guardspec"})), Warn, "no sslmode")
	want(t, sec(clone(map[string]string{"UPSTREAM_LLM_URL": "http://api.example.com/v1"})), Warn, "plain http")
	want(t, sec(clone(map[string]string{"UPSTREAM_LLM_URL": "http://ollama.ai.svc:11434/v1"})), OK, "")
	want(t, sec(clone(map[string]string{"AUDIT_STORE_CONTENT": "true"})), Warn, "AUDIT_STORE_CONTENT")
	// Dev mode: problems become warnings, and dev mode itself is one.
	want(t, sec(clone(map[string]string{"GUARD_ENV": "dev", "JWT_SECRET": "dev"})), Warn, "GUARD_ENV=dev")
	// The gateway has no JWT_SECRET: only noted.
	want(t, sec(clone(map[string]string{"JWT_SECRET": "", "MFA_ENC_KEY": ""})), OK, "control plane only")
}

func TestExitCode(t *testing.T) {
	for _, c := range []struct {
		s      Summary
		strict bool
		code   int
	}{
		{Summary{OK: 3}, false, exitOK},
		{Summary{OK: 2, Warnings: 1}, false, exitOK},
		{Summary{OK: 2, Warnings: 1}, true, exitFail},
		{Summary{Failed: 1}, false, exitFail},
		{Summary{Skipped: 6}, true, exitOK},
	} {
		if got := exitCode(Report{Summary: c.s}, c.strict); got != c.code {
			t.Errorf("%+v strict=%v: %d, want %d", c.s, c.strict, got, c.code)
		}
	}
}

func TestRunOutput(t *testing.T) {
	env := map[string]string{"DETECTOR_LAYERS": "l1", "UPSTREAM_LLM_URL": ""}
	var buf bytes.Buffer
	code := Run(context.Background(), getter(env), Options{Timeout: time.Second, JSON: true, Skip: only("layers", "upstream")}, &buf)
	if code != exitOK {
		t.Errorf("exit %d", code)
	}
	var rep Report
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if len(rep.Checks) != len(checkNames) || rep.Summary != (Summary{OK: 1, Warnings: 1, Skipped: 4}) {
		t.Errorf("report %+v", rep)
	}

	buf.Reset()
	code = Run(context.Background(), getter(env), Options{Timeout: time.Second, Strict: true, Skip: only("layers", "upstream")}, &buf)
	if code != exitFail {
		t.Errorf("strict with a warning: exit %d", code)
	}
	for _, s := range []string{"guard-spec doctor", "[ OK ] layers", "[WARN] upstream", "[SKIP] database", "summary: 1 ok, 1 warnings, 0 failed, 4 skipped"} {
		if !strings.Contains(buf.String(), s) {
			t.Errorf("output lacks %q:\n%s", s, buf.String())
		}
	}
}

func TestParseFlags(t *testing.T) {
	o, err := parseFlags([]string{"-skip", "upstream, database", "-json", "-timeout", "2s"}, io.Discard)
	if err != nil || !o.Skip["upstream"] || !o.Skip["database"] || !o.JSON || o.Timeout != 2*time.Second {
		t.Fatalf("%+v, %v", o, err)
	}
	for _, args := range [][]string{{"-skip", "nope"}, {"-timeout", "0s"}, {"extra"}, {"-bogus"}} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
