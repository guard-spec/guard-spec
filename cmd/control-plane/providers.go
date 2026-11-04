package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/giaplee/guard-spec/internal/config"
	"github.com/giaplee/guard-spec/internal/proxy"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Model provider presets for the UI's catalog picker. The gateway speaks the
// OpenAI chat-completions format to every one of them: Anthropic and Gemini
// are reached through their OpenAI-compatible endpoints.

type providerPreset struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"display_name"`
	DefaultBaseURL  string   `json:"default_base_url"`
	KeyRequired     bool     `json:"key_required"`
	KeyEnvHint      string   `json:"key_env_hint"`
	NeedsAPIVersion bool     `json:"needs_api_version"`
	OpenAICompat    bool     `json:"openai_compatible_endpoint"` // the preset uses the provider's OpenAI-compatible API
	KnownModels     []string `json:"known_models"`
	DocsURL         string   `json:"docs_url"`
	Notes           string   `json:"notes"`
}

var providerCatalog = []providerPreset{
	{ID: "openai", DisplayName: "OpenAI", DefaultBaseURL: "https://api.openai.com/v1", KeyRequired: true,
		KeyEnvHint: "UPSTREAM_KEY_OPENAI", KnownModels: []string{"gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini"},
		DocsURL: "https://platform.openai.com/docs/api-reference/chat"},
	{ID: "anthropic", DisplayName: "Anthropic", DefaultBaseURL: "https://api.anthropic.com/v1", KeyRequired: true,
		KeyEnvHint: "UPSTREAM_KEY_ANTHROPIC", OpenAICompat: true,
		KnownModels: []string{"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"},
		DocsURL:     "https://docs.claude.com/en/api/openai-sdk",
		Notes:       "Uses Anthropic's OpenAI SDK compatibility endpoint."},
	{ID: "azure_openai", DisplayName: "Azure OpenAI", DefaultBaseURL: "https://<resource>.openai.azure.com/openai/v1",
		KeyRequired: true, KeyEnvHint: "UPSTREAM_KEY_AZURE_OPENAI", NeedsAPIVersion: true,
		DocsURL: "https://learn.microsoft.com/azure/ai-services/openai/reference",
		Notes:   "The key is sent in the api-key header; api_version is added to every request."},
	{ID: "gemini", DisplayName: "Google Gemini", DefaultBaseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
		KeyRequired: true, KeyEnvHint: "UPSTREAM_KEY_GEMINI", OpenAICompat: true,
		KnownModels: []string{"gemini-2.5-pro", "gemini-2.5-flash"},
		DocsURL:     "https://ai.google.dev/gemini-api/docs/openai",
		Notes:       "Uses Gemini's OpenAI compatibility endpoint."},
	{ID: "ollama", DisplayName: "Ollama", DefaultBaseURL: "http://localhost:11434/v1",
		KnownModels: []string{"llama3.1", "qwen2.5", "mistral"},
		DocsURL:     "https://github.com/ollama/ollama/blob/main/docs/openai.md",
		Notes:       "A private address needs UPSTREAM_ALLOW_PRIVATE=true."},
	{ID: "vllm", DisplayName: "vLLM", DefaultBaseURL: "http://localhost:8000/v1", KeyEnvHint: "UPSTREAM_KEY_VLLM",
		DocsURL: "https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html",
		Notes:   "A private address needs UPSTREAM_ALLOW_PRIVATE=true."},
	{ID: "openai_compatible", DisplayName: "OpenAI-compatible", KeyEnvHint: "UPSTREAM_KEY_<NAME>",
		DocsURL: "https://platform.openai.com/docs/api-reference/chat"},
}

func providerCatalogHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"items": providerCatalog})
}

// probeTimeout bounds an upstream connection test.
const probeTimeout = 5 * time.Second

// upstreamProxy builds the proxy the gateway would use for org's upstream u,
// with the same checks: base URL, UPSTREAM_KEY_ORGS, the key variable, and
// the dialer's refusal of private addresses unless UPSTREAM_ALLOW_PRIVATE.
func upstreamProxy(u upstream, org uuid.UUID, s *appSettings) (*proxy.Proxy, error) {
	if err := proxy.ValidateBaseURL(u.BaseURL); err != nil {
		return nil, err
	}
	key := ""
	if u.APIKeyEnv != "" {
		if err := s.keyOrgs.Check(u.APIKeyEnv, org); err != nil {
			return nil, err
		}
		if !config.UpstreamKeyVarRe.MatchString(u.APIKeyEnv) {
			return nil, errors.New("api_key_env is not an UPSTREAM_KEY_ variable")
		}
		getenv := s.getenv
		if getenv == nil {
			getenv = os.Getenv
		}
		if key = getenv(u.APIKeyEnv); key == "" {
			return nil, errors.New(u.APIKeyEnv + " is not set in the control plane's environment; " +
				"set the same UPSTREAM_KEY_* variables as the gateway to test connections")
		}
	}
	keyHeader := ""
	if u.Provider == "azure_openai" {
		keyHeader = "api-key"
	}
	return proxy.New(proxy.Config{BaseURL: u.BaseURL, Key: key, KeyHeader: keyHeader, APIVersion: u.APIVersion,
		Headers: u.Headers, Timeout: probeTimeout, DenyPrivate: !s.allowPrivate})
}

// testUpstream sends GET {base_url}/models and reports what came back. The
// answer holds model ids only, never the upstream's body.
func testUpstream(db *pgxpool.Pool, s *appSettings) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid upstream id"})
		}
		var u upstream
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			u, err = scanUpstreamRow(tx.QueryRow(c.Context(), upstreamSelect+` WHERE id = $1 AND org_id = $2`, id, org))
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		px, err := upstreamProxy(u, org, s)
		if err != nil {
			return c.JSON(proxy.ProbeResult{Models: []string{}, Error: err.Error()})
		}
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		res := px.Probe(ctx)
		logActivity(c, db, &org, "upstream.tested", u.Name, map[string]any{"ok": res.OK, "status": res.Status})
		return c.JSON(res)
	}
}
