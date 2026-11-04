package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var unitSecret = []byte("unit-test-secret-0123456789abcdef0123")

// offlineApp builds the app with a pool that never connects: the routes
// tested here do not touch the database.
func offlineApp(t *testing.T, opts ...appOption) *fiber.App {
	t.Helper()
	db, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	return newApp(db, unitSecret, eng, "", opts...)
}

func withUI(files fstest.MapFS) appOption {
	return func(s *appSettings) { s.ui = files }
}

func get(t *testing.T, app *fiber.App, method, path, token, body string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(data)
}

func TestUIServing(t *testing.T) {
	files := fstest.MapFS{
		"index.html":         {Data: []byte("<!doctype html><title>ui</title>")},
		"assets/app-1a2b.js": {Data: []byte("console.log(1)")},
		"favicon.svg":        {Data: []byte("<svg/>")},
	}
	app := offlineApp(t, withUI(files))

	status, h, _ := get(t, app, "GET", "/", "", "")
	if status != 302 || h.Get("Location") != "/ui/" {
		t.Errorf("/ -> %d %v", status, h.Get("Location"))
	}
	status, h, _ = get(t, app, "GET", "/ui", "", "")
	if status != 302 || h.Get("Location") != "/ui/" {
		t.Errorf("/ui -> %d %v", status, h.Get("Location"))
	}

	tests := []struct {
		path, body, ctype, cache string
		status                   int
	}{
		{"/ui/", "<!doctype html><title>ui</title>", "text/html", "no-cache", 200},
		{"/ui/policies/123/edit", "<!doctype html><title>ui</title>", "text/html", "no-cache", 200}, // client route
		{"/ui/assets/app-1a2b.js", "console.log(1)", "javascript", "immutable", 200},
		{"/ui/favicon.svg", "<svg/>", "image/svg+xml", "no-cache", 200},
		{"/ui/assets/missing.js", "not found", "", "", 404},
		{"/ui/assets", "<!doctype html><title>ui</title>", "text/html", "no-cache", 200}, // a directory is a client route
		{"/ui/../go.mod", "not found", "", "", 404},
		{"/ui/%2e%2e/%2e%2e/go.mod", "not found", "", "", 404},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			status, h, body := get(t, app, "GET", tt.path, "", "")
			if status != tt.status || body != tt.body {
				t.Errorf("got %d %q", status, body)
			}
			if tt.ctype != "" && !strings.Contains(h.Get("Content-Type"), tt.ctype) {
				t.Errorf("content type %q", h.Get("Content-Type"))
			}
			if tt.cache != "" && !strings.Contains(h.Get("Cache-Control"), tt.cache) {
				t.Errorf("cache control %q", h.Get("Cache-Control"))
			}
			csp := h.Get("Content-Security-Policy")
			for _, want := range []string{"default-src 'self'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"} {
				if !strings.Contains(csp, want) {
					t.Errorf("CSP %q lacks %q", csp, want)
				}
			}
			if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
				t.Errorf("CSP allows inline code: %q", csp)
			}
			if h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" ||
				h.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("headers: %v", h)
			}
		})
	}
}

// The committed placeholder is embedded, so go build works without Node.
func TestUIPlaceholderEmbedded(t *testing.T) {
	app := offlineApp(t)
	status, h, body := get(t, app, "GET", "/ui/", "", "")
	if status != 200 || !strings.Contains(body, "<html") {
		t.Fatalf("got %d %q", status, body)
	}
	if h.Get("Content-Security-Policy") == "" {
		t.Error("no CSP on the placeholder")
	}
}

func TestPolicyTextEndpoints(t *testing.T) {
	app := offlineApp(t)
	token, err := auth.IssueToken(unitSecret, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := get(t, app, "GET", "/v1/policy/schema", "", ""); status != 401 {
		t.Errorf("schema without token: %d", status)
	}
	status, _, body := get(t, app, "GET", "/v1/policy/schema", token, "")
	var schema policy.Schema
	if status != 200 || json.Unmarshal([]byte(body), &schema) != nil || len(schema.Fields) == 0 ||
		len(schema.Operators["double"]) == 0 || len(schema.Actions) != 4 {
		t.Errorf("schema: %d %s", status, body)
	}

	status, _, body = get(t, app, "POST", "/v1/policy/parse", token,
		`{"text":"scores.l2 > 0.8 && injection.category == \"jailbreak\""}`)
	var parsed struct {
		Condition json.RawMessage `json:"condition"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &parsed) != nil || len(parsed.Condition) == 0 {
		t.Fatalf("parse: %d %s", status, body)
	}

	status, _, body = get(t, app, "POST", "/v1/policy/format", token,
		`{"condition":`+string(parsed.Condition)+`}`)
	var formatted struct {
		Text string `json:"text"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &formatted) != nil ||
		formatted.Text != `scores.l2 > 0.8 && injection.category == "jailbreak"` {
		t.Errorf("format: %d %s", status, body)
	}

	status, _, body = get(t, app, "POST", "/v1/policy/parse", token, `{"text":"scores.l2 > 0.8 &&& x"}`)
	var refusal struct {
		Error    string `json:"error"`
		Position *int   `json:"position"`
	}
	if status != 422 || json.Unmarshal([]byte(body), &refusal) != nil || refusal.Error == "" || refusal.Position == nil {
		t.Errorf("bad parse: %d %s", status, body)
	}
	status, _, body = get(t, app, "POST", "/v1/policy/parse", token, `{"text":"size(request.model) > 3"}`)
	if status != 422 || !strings.Contains(body, "size") {
		t.Errorf("function call: %d %s", status, body)
	}
	status, _, body = get(t, app, "POST", "/v1/policy/format", token, `{"condition":{"field":"nope","operator":"=","value":1}}`)
	if status != 422 {
		t.Errorf("bad tree: %d %s", status, body)
	}
	if status, _, _ := get(t, app, "POST", "/v1/policy/parse", token, `{}`); status != 400 {
		t.Errorf("no text: %d", status)
	}
}
